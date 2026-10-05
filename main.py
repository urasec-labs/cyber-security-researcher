"""
BOT ORKESTRATONU
===============
Uc modulu birlikte calistiran ana dongu ve bot sinifi.

Dongu akisi (her CHECK_INTERVAL saniyede bir):
    1. CISA KEV cek                                     -> feeds.fetch_cisa_kev
    2. Veritabanina yaz, YENI olanlari ayir            -> db.insert_many
    3. Yeni CVE'ler icin CVSS zenginlestirme (NVD)     -> feeds.NVDClient
    4. LLM triaj (Modul 2)                              -> llm_triage.LLMTriager
    5. Kritik + kapsamda olanlar icin tarama (Modul 3)  -> scanner.ReconEngine
    6. Telegram raporu                                  -> notifier.TelegramNotifier
    7. uyku

Neden 3 ve 4 bu sirada?
  Modul 3 "CVSS > esik" kapisina bagli. CVSS kaynagi Modul 2'nin girdisi de.
  Ikisi de NVD'den besleniyor; once zenginlestirme, sonra triaj, sonra tarama
  dogru sira. Aksi halde esik her zaman NULL'a dustugu icin hicbir tarama
  calismaz ya da eksik CVSS ile yanlis karar verilir.

Neden `async with` zinciri?
  Bir istisna olursa (ornegin Telegram cokertmesi) session ve veritabani
  yari acik kalmaz. `..py`deki `init_session` deseni bu garantiyi vermiyordu.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from pathlib import Path

import aiohttp

from config import CONFIG, AppConfig
from db import CVE, Database, ScanStatus, TriageStatus
from feeds import CVSSInfo, NVDClient, fetch_cisa_kev
from llm_triage import LLMTriager, TriageResult
from notifier import TelegramNotifier
from scanner import ReconEngine, ScanResult

LOGGER = logging.getLogger("cyber.bot")


# ------------------------------------------------------------- loglama ayari


def setup_logging(cfg: AppConfig) -> None:
    """Dosya + konsol loglamasi.

    RotatingFileHandler kullanilir: saatlerce calisan bir botta log dosyasi
    sinirsiz buyuyor olmamali (5MB x 5 kopya).
    """
    from logging.handlers import RotatingFileHandler

    cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)-14s %(message)s"

    root = logging.getLogger()
    root.setLevel(cfg.log_level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    file_handler = RotatingFileHandler(
        cfg.log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter(fmt))

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(fmt))

    root.addHandler(file_handler)
    root.addHandler(console)

    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# ------------------------------------------------------------- rapor bicimi


class ReportBuilder:
    """Telegram mesajini HTML olarak uretir.

    HTML kullanma sebebi: feed metni kacinabilir karakter iceriyor. Tum
    disaridan gelen metin once `escape` edilir, sonra bicimlendirme eklenir.
    (Markdown modunda `_`, `*`, `` ` `` karakterleri ciktida hataya yol acar.)
    """

    def __init__(self, notifier: TelegramNotifier) -> None:
        self._esc = notifier.escape

    def new_cve(self, cve: CVE, triage: TriageResult | None = None,
                scans: list[ScanResult] | None = None) -> str:
        e = self._esc
        score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "NVD'den alınamadı"

        L: list[str] = [
            "🚨 <b>KRİTİK ZAFİYET TESPİT EDİLDİ (CISA KEV)</b>",
            "",
            f"🆔 <b>CVE:</b> <code>{e(cve.cve_id)}</code>",
            f"🏢 <b>Ürün:</b> {e(cve.vendor_project)} - {e(cve.product)}",
            f"📊 <b>CVSS:</b> {score} ({e(cve.severity or 'n/a')})",
            f"🧬 <b>CWE:</b> {e(cve.cwes or 'belirtilmemiş')}",
            f"📅 <b>KEV eklenme:</b> {e(cve.date_added)} &nbsp;|&nbsp; <b>Termin:</b> {e(cve.due_date)}",
        ]

        if cve.known_ransomware.lower() == "known":
            L.append("🧨 <b>Ransomware:</b> bu zafiyet ile ilişkilendirildi")

        if cve.description:
            L += ["", f"⚠️ <b>Açıklama:</b> {e(cve.description)}"]

        if cve.required_action:
            L += ["", f"🎯 <b>Üretici Eylemi:</b> {e(cve.required_action)}"]

        if cve.notes:
            L += ["", f"🔗 <b>Referanslar:</b> {e(cve.notes)}"]

        if triage is not None:
            # Blok basligi olmadan eklenirse mesaj "..." ile kesilmis gibi gorunur.
            L += ["", triage.as_report_block()]
        else:
            L += ["", "🤖 <b>LLM Triaj Özeti</b>\n<i>Bu CVE için triaj "
                    "sonucu yok (LLM kapalı veya çağrı başarısız).</i>"]

        if scans:
            L += ["", self.scan_block(scans)]

        return "\n".join(L)

    def scan_block(self, scans: list[ScanResult]) -> str:
        """Tarama sonuclarini ozetler."""
        e = self._esc
        icons = {
            ScanStatus.SUCCESS: "⚠️",
            ScanStatus.CLEAN: "✅",
            ScanStatus.FAILED: "❌",
            ScanStatus.SKIPPED: "⏭️",
        }

        L = ["🔬 <b>Otomatik Doğrulama (Nuclei)</b>"]
        for r in scans:
            icon = icons.get(r.status, "•")
            L.append(f"{icon} <b>{e(r.cve_id)}</b> → <code>{e(r.status)}</code>")
            L.append(f"   ├ Hedef: {e(', '.join(r.targets)) or '-'}")
            L.append(f"   ├ Bulgular: <b>{r.findings}</b> &nbsp;|&nbsp; Süre: {r.duration_ms} ms")
            if r.template:
                L.append(f"   ├ Şablon: {e(Path(r.template).name)}")
            if r.command:
                L.append(f"   └ Komut: <code>{e(r.command)}</code>")
            if r.error:
                L.append(f"   └ Not: {e(r.error)}")
        return "\n".join(L)

    def summary(self, stats: dict, extra: str = "") -> str:
        """Donem sonu ozeti."""
        L = [
            "📊 <b>DÖNGÜ ÖZETİ</b>",
            f"├ Toplam CVE kaydı: <b>{stats.get('total_cves', 0)}</b>",
            f"├ Kritik (CVSS ≥ {CONFIG.nuclei.min_cvss}): <b>{stats.get('critical', 0)}</b>",
            f"├ Taranmış: <b>{stats.get('scanned', 0)}</b>",
        ]
        if extra:
            L.append(f"├ Bu döngü: {extra}")
        L.append(f"└ Son kayıt: {stats.get('newest_seen_at', '-')}")
        return "\n".join(L)


# ------------------------------------------------------------------- bot


class CyberResearchBot:
    """Uc modulu birlikte calistiren bot."""

    def __init__(self, cfg: AppConfig | None = None) -> None:
        self._cfg = cfg or CONFIG
        self._session: aiohttp.ClientSession | None = None
        self._db: Database | None = None
        self._notifier: TelegramNotifier | None = None
        self._reporter: ReportBuilder | None = None
        self._triager: LLMTriager | None = None
        self._recon: ReconEngine | None = None
        self._nvd: NVDClient | None = None
        self._stop = asyncio.Event()

    # ----------------------------------------------------------- yasam dongusu

    async def start(self) -> None:
        """Tum bilesenleri ac. Idempotenttir."""
        if self._session is not None:
            return

        # Tek oturum: butun HTTP cagrilari icin yeniden kullanilir. Her cagri
        # icin ayri session acmak TLS el sikisma maliyeti ve soket sizintisi demektir.
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._cfg.feeds.request_timeout),
            headers={"User-Agent": "cyber-research-bot/1.0 (+internal threat intel)"},
            raise_for_status=False,
        )

        # MODUL 1: veritabani
        self._db = Database(self._cfg.database)
        await self._db.connect()

        # Bildirim + rapor
        self._notifier = TelegramNotifier(self._session, self._cfg.telegram)
        self._reporter = ReportBuilder(self._notifier)

        # MODUL 2: LLM triaj
        self._triager = LLMTriager(self._session, self._cfg.llm)

        # MODUL 3: kesif
        self._recon = ReconEngine(self._db, self._cfg.nuclei)

        # CVSS zenginlestirme
        self._nvd = NVDClient(self._session, self._cfg.feeds)

        LOGGER.info("Bilesenler hazir.")
        LOGGER.info("  Varlik kapsami : %s", self._recon._registry.summary())
        LOGGER.info("  Nuclei binary  : %s",
                    "bulundu" if self._recon._runner.is_available() else "BULUNAMADI")
        LOGGER.info("  LLM saglayici  : %s", self._triager.provider_name)
        await self._send(
            "🟢 <b>Bot aktif</b>\n"
            f"├ LLM: {self._triager.provider_name}\n"
            f"├ Varlık: {self._recon._registry.summary()}\n"
            f"├ Nuclei: {'DRY-RUN' if self._cfg.nuclei.dry_run else 'AKTİF'}\n"
            f"├ Veritabanı: {self._cfg.database.path.name}\n"
            f"└ Aralık: {self._cfg.feeds.check_interval} sn"
        )

    async def shutdown(self) -> None:
        """Tum bilesenleri deterministik sekilde kapat."""
        if self._session is None and self._db is None:
            return
        LOGGER.info("Kapatiliyor...")

        if self._recon is not None:
            await self._recon.shutdown(timeout=15)
        if self._session is not None:
            await self._session.close()      # $..py'de bu hic yapilmamisti
            self._session = None
        if self._db is not None:
            await self._db.close()
            self._db = None
        LOGGER.info("Kapatildi.")

    async def __aenter__(self) -> "CyberResearchBot":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> bool:
        await self.shutdown()
        return False

    def request_stop(self) -> None:
        """SIGINT / SIGTERM yakalayicisi."""
        LOGGER.info("Durdurma sinyali alindi, mevcut dongu tamamlanacak...")
        self._stop.set()

    # ------------------------------------------------------------- yardimcilar

    async def _send(self, text: str) -> bool:
        if self._notifier is None or not self._notifier.enabled:
            LOGGER.debug("Telegram devre disi, mesaj atlandi:\n%s", text)
            return False
        return await self._notifier.send(text)

    # ------------------------------------------------------ Modul 3 tetikleyici

    async def report_scan_result(self, result: ScanResult) -> None:
        """Tarama bitince ayri bildirim gonder.

        Tarama arka planda dondugu icin sonuc, CVE bildiriminden SONRA ve
        ayri mesaj olarak gelir. Boylece 10 dakikalik bir tarama, kritik zafiyet
        bildirimini geciktirmez.
        """
        if self._reporter is None:
            return
        await self._send(self._reporter.scan_block([result]))


# ============================================================================
#  ANA DONGU ADIMLARI
# ============================================================================


async def cycle_collect(bot: CyberResearchBot) -> list[CVE]:
    """ADIM 1-3: istihbarat topla, kaydet, CVSS ile zenginlestir."""
    cfg = bot._cfg
    session, db = bot._session, bot._db

    # --- ADIM 1: KEV cek
    kev_list = await fetch_cisa_kev(session, cfg.feeds)
    if not kev_list:
        LOGGER.warning("KEV cekilemedi; bu dongu atlaniyor.")
        return []

    # --- ADIM 2: veritabanina yaz, yeni olanlari al
    new_cves = await db.insert_many(kev_list)
    LOGGER.info("Yeni bulgu sayisi: %d", len(new_cves))
    if not new_cves:
        LOGGER.info("Yeni zafiyet yok (%d kayit kontrol edildi).", len(kev_list))
        return []

    await bot._send(
        f"🆕 <b>{len(new_cves)} yeni KEV zafiyeti</b>\n"
        + "\n".join(f"• <code>{c.cve_id}</code> — {c.vendor_project} {c.product}"
                    for c in new_cves[:20])
        + (f"\n… ve {len(new_cves) - 20} tane daha" if len(new_cves) > 20 else "")
    )

    # --- ADIM 3: CVSS zenginlestirme (NVD)
    # CISA KEV CVSS ICERMEZ; Modul 3'un esiginin dolmasi icin bu ADIM ZORUNLU.
    pending = [c for c in new_cves if c.cvss_score is None]

    async def _write(cve_id: str, info: CVSSInfo) -> None:
        await db.update_cvss(cve_id, info.score, info.vector, info.severity)

    if pending:
        LOGGER.info("CVSS bilgisi eksik: %d CVE icin NVD sorgulanacak.", len(pending))
        enriched = await bot._nvd.enrich_many([c.cve_id for c in pending], on_result=_write)
        for cve in new_cves:
            info = enriched.get(cve.cve_id)
            if info:
                cve.apply_cvss(info.score, info.vector, info.severity)
        missing = [c.cve_id for c in new_cves if c.cvss_score is None]
        if missing:
            LOGGER.warning(
                "CVSS alinamayan %d CVE (NVD kaydi yok olabilir): %s",
                len(missing), ", ".join(missing[:10]),
            )
    else:
        LOGGER.info("Tum yeni kayitlarda CVSS mevcut.")

    return new_cves


async def cycle_triage(bot: CyberResearchBot, cves: list[CVE]) -> dict[str, TriageResult]:
    """ADIM 4: LLM triaj (Modul 2)."""
    db, triager = bot._db, bot._triager

    if not bot._cfg.llm.enabled:
        LOGGER.info("LLM devre disi (LLM_ENABLED=false); kuyruk isaretleniyor.")
        await db.mark_triage_skipped([c.cve_id for c in cves])
        return {}

    LOGGER.info("LLM triaj: %d CVE", len(cves))
    results = await triager.triage_many(cves)

    out: dict[str, TriageResult] = {}
    for cve, res in zip(cves, results):
        # Sonucu KALICI olarak sakla: bot yeniden baslasa bile tekrar cagri yapmaz.
        await db.save_triage(
            cve.cve_id,
            res.as_text(),
            res.provider,
            TriageStatus.DONE if res.ok else TriageStatus.FAILED,
        )
        out[cve.cve_id] = res
    return out


async def cycle_scan(bot: CyberResearchBot, cves: list[CVE],
                     triages: dict[str, TriageResult]) -> list[ScanResult]:
    """ADIM 5: tarama karari + bildirim (Modul 3).

    UYARI: NVD kotasindan tasmamak icin zenginlestirme ASILIR yapilir; tarama
    yalnizca yeni CVE'ler icin tetiklenir. Eski CVE'ler icin `run_pending`
    ayrica cagrilabilir (bkz. `rescan_pending`).
    """
    recon = bot._recon

    queued: list[asyncio.Task] = []
    for cve in cves:
        # Karar burada verilir (senkron, hizli) ama tarama ARKA PLANDA baslar.
        decision = await recon.decide(cve)
        if not decision.should_scan:
            LOGGER.info("Atlandi %s: %s", cve.cve_id, decision.reason)
            if cve.scan_status == ScanStatus.PENDING:
                await bot._db.mark_scan_finished(cve.cve_id, ScanStatus.SKIPPED, decision.reason)
            continue

        # Kuyruga al. `enqueue` icindeki `scan_one` DB kilidini alir; iki kez
        # kilitlemek yaris yaratir.
        task = recon.enqueue(cve, decision)
        if task is not None:
            queued.append(task)

        # Yeni CVE'yi LLM ozetiyle birlikte HEMEN bildir. Tarama sonucunu
        # BEKLEMIYORUZ: 10 dakikalik bir tarama istihbarat bildirimini
        # geciktirmemeli; sonuc ayri mesaj olarak gelir.
        await bot._send(bot._reporter.new_cve(cve, triage=triages.get(cve.cve_id)))

    LOGGER.info("Kuyruga alinan tarama: %d", len(queued))
    return []


async def rescan_pending(bot: CyberResearchBot, limit: int = 10) -> list[ScanResult]:
    """Onceki kosularda atlanmis ancak kriterleri artik saglayan CVE'leri tarar.

    Ornek: NVD sketi gec geldi, ya da bir varlik `assets.txt`e sonradan eklendi.
    Elle ya da zamanlanmis gorevle cagrilabilir.
    """
    if bot._recon is None:
        return []
    return await bot._recon.run_pending(limit=limit)


# ------------------------------------------------------------------- giris


async def main() -> None:
    cfg = CONFIG
    setup_logging(cfg)

    LOGGER.info("=" * 72)
    LOGGER.info("Cyber Research Bot baslatiliyor")
    LOGGER.info("  Veritabani : %s", cfg.database.path)
    LOGGER.info("  LLM        : %s / %s", cfg.llm.provider, cfg.llm.model)
    LOGGER.info("  Nuclei     : %s", "DRY-RUN" if cfg.nuclei.dry_run else "AKTIF")
    LOGGER.info("  Aralik     : %d sn", cfg.feeds.check_interval)
    LOGGER.info("=" * 72)

    async with CyberResearchBot(cfg) as bot:
        loop = asyncio.get_running_loop()

        # Graceful shutdown: Ctrl+C / SIGTERM yakala.
        # Windows'ta add_signal_handler desteklenmez -> NotImplementedError yutulur.
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, bot.request_stop)

        LOGGER.info("Bot aktif. Ctrl+C ile durdurun.")
        cycle_no = 0

        while not bot._stop.is_set():
            cycle_no += 1
            LOGGER.info("--- Dongu #%d basliyor ---", cycle_no)
            started = asyncio.get_running_loop().time()

            try:
                # 1) istihbarat topla + kaydet + zenginlestir
                new_cves = await cycle_collect(bot)

                if new_cves:
                    # 2) LLM triaj
                    triages = await cycle_triage(bot, new_cves)
                    # 3) tarama tetikle + bildir
                    await cycle_scan(bot, new_cves, triages)
                else:
                    triages = {}

                # 4) dongu ozeti
                stats = await bot._db.stats()
                await bot._send(bot._reporter.summary(
                    stats,
                    extra=f"{len(new_cves)} yeni, {len(triages)} triaj",
                ))

            except asyncio.CancelledError:
                raise
            except Exception as exc:              # noqa: BLE001
                # ANA DONGU ASLA OLMEMELI. Tek bir hata (gecici ag hatasi,
                # LLM cokertmesi, bozuk JSON) butun botu dusurmemeli.
                LOGGER.exception("Dongu #%d hatasi; bir sonraki donguye devam.", cycle_no)
                # Telegram'a yalnizca OZET: tam traceback log dosyasinda kalir.
                # (30 satirlik iz Telegram'da okunamaz hale gelir.)
                await bot._send(
                    f"⚠️ <b>Döngü #{cycle_no} hatası</b>\n"
                    f"<code>{type(exc).__name__}: {str(exc)[:280]}</code>\n"
                    "<i>Ayrıntı için log dosyasına bakın.</i>"
                )

            elapsed = asyncio.get_running_loop().time() - started
            wait = max(1.0, self._cfg.feeds.check_interval - elapsed)
            LOGGER.info("--- Dongu #%d bitti (%.1fs) | %.0fs bekleniyor ---",
                        cycle_no, elapsed, wait)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(bot._stop.wait(), timeout=wait)

        LOGGER.info("Durdurma istegi tamamlandi.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOGGER.info("Kullanici tarafindan durduruldu.")