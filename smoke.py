"""
CANLI DUMAN (SMOKE) TESTI
=========================
Uc modulun GERCEK ag/SQLite/LLM yolu ile birlikte calistigini dogrular.
Nuclei CALISTIRILMAZ (dry-run). Telegram'a gonderim yapilmaz.

    python smoke.py
    python smoke.py --llm          # Ollama/OpenAI de denenir

Telegram bildirimi uretmek icin `smoke.py` icindeki `render_demo_report`
kullanilir; sadece metin uretir, ag cagrisi yapmaz.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Windows konsol varsayilan olarak cp1254 (Turkce) kodlamasini kullanir ve emoji
# yazdirilamaz -> UnicodeEncodeError. ZORUNLU cikti kodlamasini UTF-8'e sabitliyoruz.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import aiohttp

from config import CONFIG, DatabaseConfig, LLMConfig
from db import CVE, Database, ScanStatus, TriageStatus
from feeds import NVDClient, fetch_cisa_kev
from llm_triage import LLMTriager
from main import ReportBuilder, setup_logging
from notifier import TelegramNotifier
from scanner import Asset, AssetRegistry, NucleiConfig, ReconEngine

EXIT = 0


def banner(text: str) -> None:
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="LLM saglayicisini da dene")
    args = ap.parse_args()

    setup_logging(CONFIG)
    banner("CANLI DUMAN TESTI")

    async with aiohttp.ClientSession() as session:
        # ============================================================ MODUL 1+2
        banner("ADIM 1 — CISA KEV canli cekiliyor")
        kev = await fetch_cisa_kev(session)
        print(f"KEV kayit: {len(kev)}")
        if not kev:
            print("[HATA] KEV cekilemedi; ag baglantisini kontrol edin.")
            return 1
        for c in kev[:5]:
            print(f"  {c.cve_id}  {c.date_added}  CVSS={c.cvss_score}  {c.vendor_project} {c.product}")

        newest = kev[0]
        print(f"\nEn yeni: {newest.cve_id} ({newest.date_added})")
        print(f"En eski: {kev[-1].cve_id} ({kev[-1].date_added})")
        print("Siralama kontrolu: " + ("GECERLI" if kev[0].date_added >= kev[-1].date_added else "HATALI"))

        # --- gercek veritabani (gectici)
        db_path = Path("data") / "smoke_test.db"
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(db_path) + suffix)
            if p.exists():
                p.unlink()

        async with Database(DatabaseConfig(path=db_path)) as db:
            banner("ADIM 2 — Veritabani (ilk yukleme)")
            new = await db.insert_many(kev)
            print(f"Yeni kayit: {len(new)}")

            banner("ADIM 3 — Veritabani (ikinci yukleme, idempotency)")
            again = await db.insert_many(kev)
            print(f"Yeni kayit (tekrar): {len(again)}  "
                  f"{'GECERLI - idempotent' if len(again) == 0 else 'HATALI'}")

            stats = await db.stats()
            print(f"Toplam: {stats['total_cves']}")

            banner("ADIM 4 — NVD CVSS zenginlestirme (ilk 5 kayit)")
            nvd = NVDClient(session)
            sample = kev[:5]

            async def _write(cve_id: str, info) -> None:
                await db.update_cvss(cve_id, info.score, info.vector, info.severity)

            enriched = await nvd.enrich_many([c.cve_id for c in sample], on_result=_write)
            for c in sample:
                row = await db.get(c.cve_id)
                score = f"{row.cvss_score:.1f} ({row.severity})" if row and row.cvss_score else "ALINAMADI"
                print(f"  {c.cve_id}: CVSS {score}")

            # Tek sorguda oku (N+1 tuzagindan kacin)
            rows = await db.get_many([c.cve_id for c in sample])
            scored = sum(1 for r in rows.values() if r.cvss_score is not None)
            print(f"\nZenginlestirilen: {scored}/{len(sample)}")

            banner("ADIM 5 — LLM triaj")
            triage_result = None
            target = sample[0]
            triager = LLMTriager(session, CONFIG.llm)
            print(f"Saglayici: {triager.provider_name}")

            # once sunucuya erisilebiliyor mu?
            reachable = True
            if isinstance(getattr(triager, "_provider", None), object):
                if CONFIG.llm.provider == "ollama":
                    reachable = await triager._provider.is_available()   # type: ignore[attr-defined]
                    print(f"Ollama erisilebilir mi: {reachable}")
                    if not reachable:
                        print(f"  -> Ollama calismiyor. `ollama serve` ve `ollama pull {CONFIG.llm.model}`")
                elif CONFIG.llm.provider == "openai":
                    reachable = bool(CONFIG.llm.api_key or CONFIG.llm.base_url)
                    print(f"OpenAI yapilandirilmis mi: {reachable}")

            if args.llm and reachable:
                triage_result = await triager.triage_cve(target)
                print(f"\nok={triage_result.ok}  fallback={triage_result.fallback}  "
                      f"{triage_result.latency_ms}ms")
                for i, b in enumerate(triage_result.bullets(), 1):
                    print(f"  {i}. {b}")
            else:
                from llm_triage import fallback_summary
                triage_result = fallback_summary(target, "LLM denenmedi (--llm kullanin)")
                print("--llm verilmedi; kural tabanli ozet gosteriliyor:")
                for i, b in enumerate(triage_result.bullets(), 1):
                    print(f"  {i}. {b}")

            # --- sonuc kalici mi?
            await db.save_triage(target.cve_id, triage_result.as_text(),
                                 triage_result.provider,
                                 TriageStatus.DONE if triage_result.ok else TriageStatus.FAILED)
            row = await db.get(target.cve_id)
            print(f"\nDB'de saklandi: status={row.triage_status} provider={row.triage_provider}")
            print("Tekrar cagri yapmamak icin kaydedildi: EVET")

            banner("ADIM 6 — Modul 3 karar mantigi (canli veriyle)")
            # Gecici varlik listesi (kendi altyapinizi yazin)
            reg = AssetRegistry([
                Asset("vpn.example.com", {"vpn", "cisco", "citrix"}),
                Asset("mail.example.com", {"exchange"}),
            ])
            engine = ReconEngine(
                db,
                NucleiConfig(dry_run=True, confirm_scan=False,
                             min_cvss=8.0, template_dir=Path("nuclei-templates")),
                registry=reg,
            )

            tested = 0
            for c in kev[:40]:
                c.cvss_score = (await db.get(c.cve_id)).cvss_score
                d = await engine.decide(c)
                tested += 1
                print(f"  {c.cve_id}  CVSS={c.cvss_score}  -> "
                      f"{'TARA' if d.should_scan else 'ATLA'}  ({d.reason})")
                if tested >= 12:
                    break

            banner("ADIM 7 — Kapsam guvenligi (canli test)")
            try:
                engine.validate_target("google.com")
                print("[HATA] Izinsiz hedef KABUL EDILDI - guvenlik acigi!")
                return 1
            except Exception as exc:
                print(f"Izinsiz hedef reddedildi: {type(exc).__name__}")
                print("  -> google.com taranmaz. Guvenlik seridi calisiyor.")

            banner("ADIM 8 — Rapor bicimi (Telegram'a GONDERILMEZ)")
            demo = None
            for c in kev[:30]:
                row = await db.get(c.cve_id)
                if row and row.cvss_score and row.cvss_score >= 9.0:
                    demo = row
                    break
            demo = demo or (await db.get(kev[0].cve_id))

            notifier = TelegramNotifier(session)
            reporter = ReportBuilder(notifier)
            msg = reporter.new_cve(demo, triage=triage_result)
            print(f"Mesaj uzunlugu: {len(msg)} karakter (Telegram limiti 4096)")
            print(f"Bolme gerekir mi: {len(msg) > 4096}")
            print(f"Parca sayisi: {len(notifier.split_message(msg))}")
            print("\n--- ORNEK RAPOR ---")
            print(msg[:1_500])
            print("--- RAPOR SONU ---")

    banner("DUMAN TESTI TAMAMLANDI")
    print("Not: Nuclei CALISTIRILMADI (dry-run). Telegram'a GONDERILMEDI.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))