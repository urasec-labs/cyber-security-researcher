"""
MODUL 3: OTOMATIK KESIF (RECON / NUCLEI TARAMASI)
=================================================
Yeni ve kritik (CVSS > esik) bir zafiyet, onceden tanimladiginiz VARLIKLARIN
(kendi altyapiniz) bir kismini etkiliyorsa, arka planda bir Nuclei sablonu
tetiklenir.

>>> YETKI NOTU <<<
Bu modul yalnizca `assets.txt` icinde acikca listelediginiz hostlara karsi
calisir. Liste disindaki hicbir hedef taranmaz; `AssetRegistry.resolve_targets()`
bunu zorunlu kilar. Amac, kendi altyapinizdaki acikliklari KENDI onleminiz icin
tespit etmektir.

Neden guvenlik seridi koyuyoruz:
  * `dry_run` -> komutu sadece kurar ve loglar, calistirmaz (varsayilan).
  * `confirm_scan` -> gercek calistirma icin ayrica bilincli onay gerekir.
  * `max_targets_per_scan` / `rate_limit` -> kendi altyapinizi yuklemeyin.
  * `scan_events` tablosu -> her komut denetim izine yazilir.

Neden `subprocess.run` degil de `asyncio.create_subprocess_exec`?
  * `subprocess` SENKRON'dir -> event loop bloklanir, botun diger isleri durur.
  * `shell=False` varsayilandigindan girdi enjeksiyonu yok.
    `create_subprocess_exec` yalnizca argv listesi alir; hedef adi
    `"a.com; rm -rf /"` olsa bile tek arguman olarak kalir.

Neden tarama bir ARKA PLAN GOREVIDIR?
  Bir Nuclei taramasi dakikalar surebilir. Ana donguyu bloklamamak icin
  `asyncio.create_task` ile baslatilir ve `self._tasks` icinde tutulur.
  (Task'i bir degiskende saklamazsak GC onu toplayip calismayi bitirir.)
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import logging
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from config import CONFIG, NucleiConfig
from db import CVE, Database, ScanStatus

LOGGER = logging.getLogger("cyber.scan")


class ScopeError(Exception):
    """Hedef izinli varlik listesinde degil -> guvenlik seridi reddi."""


# ============================================================================
#  Varlik kaydi (allowlist)
# ============================================================================


@dataclass(slots=True)
class Asset:
    """Taranabilir tek bir varlik."""

    host: str
    tags: set[str] = field(default_factory=set)
    note: str = ""

    def matches_keyword(self, keyword: str) -> bool:
        """Anahtar kelime bu varlikla eslesiyor mu (etiket, not veya host)?"""
        if not keyword:
            return False
        kw = keyword.strip().lower()
        if not kw or len(kw) < 3:
            return False
        haystack = " ".join([self.host, self.note, *self.tags]).lower()
        return kw in haystack

    def __str__(self) -> str:
        return f"{self.host}{' #' + ','.join(sorted(self.tags)) if self.tags else ''}"


class AssetRegistry:
    """`assets.txt` dosyasini okur ve hedef listesini uretir.

    Format (satir basina bir varlik, '#' sonrasi yorum):
        vpn.example.com            # vpn, perimeter, cisco-asa
        *.corp.example.com          # joker: tum alt domain'ler
        # aciklama satiridir, atlanir

    JOKER GUVENLIGI: `*.example.com` yazdiginizda, `example.com` ALTINDAKI
    tum domain'ler taranabilir hale gelir. Bu genis bir kapsamdir; bilincli
    kullanin. Alt domain listesi `cve_asset_map.json` veya statik dosyadan
    gelmezse joker yalnizca KENDISI olarak hedef olur (asagida `expand`).
    """

    def __init__(self, assets: Sequence[Asset] | None = None) -> None:
        self._assets: list[Asset] = list(assets or [])
        # Elle yazilmis CVE -> hedef eslesmeleri. Anahtar kural: '_' ile baslayan
        # anahtarlar yorum sayilir (dosya icinde aciklama tutabilmek icin).
        self._explicit: dict[str, list[str]] = {}

    def load_explicit_map(self, path: Path) -> int:
        """`cve_asset_map.json` dosyasini yukler.

        Neden gerekli? Uretici adlari tutarsizdir: CISA KEV'te "Citrix" yazan
        bir CVE, sizin varlik kaydinizda "netscaler" olarak gecebilir. Boyle bir
        durumda otomatik etiket eslestirmesi sessizce basarisiz olur ve tarama
        hic calismaz. Elle eslesme bu boslugu kapatir.

        Dosyadaki her hedef yine de `validate_target` ile DENETLENIR; izin
        listesinde olmayan hedef kabul edilmez.
        """
        if not path.exists():
            LOGGER.info("Elle eslesme dosyasi yok (istege bagli): %s", path.name)
            return 0

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            LOGGER.error("cve_asset_map.json bozuk JSON: %s", exc)
            return 0
        except OSError as exc:
            LOGGER.error("cve_asset_map.json okunamadi: %s", exc)
            return 0

        if not isinstance(raw, dict):
            LOGGER.error("cve_asset_map.json kok nesnesi sozluk olmali.")
            return 0

        count = 0
        for key, value in raw.items():
            if key.startswith("_"):
                continue                       # yorum anahtarlari
            if not isinstance(value, list):
                LOGGER.warning("Gecersiz eslesme (%s): liste bekleniyordu, atlandi.", key)
                continue
            targets = [str(v).strip().lower() for v in value if str(v).strip()]
            if targets:
                self._explicit[key.upper()] = targets
                count += 1

        LOGGER.info("Elle eslesme yuklendi: %d CVE (%s)", count, path.name)
        return count

    # ------------------------------------------------------------- yukleme

    @classmethod
    def from_file(cls, path: Path) -> "AssetRegistry":
        assets: list[Asset] = []
        if not path.exists():
            LOGGER.warning("Varlik dosyasi bulunamadi: %s -> kapsam BOS, hicbir tarama yapilmayacak.", path)
            return cls(assets)

        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue

            # Satiri iki parcaya bol: host + "# etiketler"
            head, _, tail = raw.partition("#")
            host = head.strip().lower()
            if not host:
                continue
            note = tail.strip()
            tags = {t.strip().lower() for t in note.replace(",", " ").split() if t.strip()}

            # Sadece gecerli bir host/IP/maskeleme izin ver
            if not cls._is_valid_host(host):
                LOGGER.warning("Gecersiz host atlandi (satir %d): %r", lineno, host)
                continue

            assets.append(Asset(host=host, tags=tags, note=note))

        LOGGER.info("Varlik kaydi yuklendi: %d varlik (%s)", len(assets), path.name)
        return cls(assets)

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        """Kaba host dogrulamasi: domain, IP veya joker. Boylece dosyaya
        kastedilen disi bir sey yazilirsa aninda fark edilir."""
        if not host or len(host) > 253:
            return False
        if host.startswith("*."):
            host = host[2:]
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            return all(0 <= int(o) <= 255 for o in host.split("."))
        return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", host))

    @property
    def assets(self) -> list[Asset]:
        return list(self._assets)

    def __len__(self) -> int:
        return len(self._assets)

    # --------------------------------------------------------- eslestirme

    def candidate_assets(self, cve: CVE) -> list[Asset]:
        """Bu CVE ile iliskili olabilecek varliklari kesin adaylara indirger.

        Iki katmanli eslestirme (guvenilirlik sirasiyla):
          1. ETIKET: varlikta acikca yazilmis etiket/anahtar kelime
             (orn. `vpn.example.com # cisco asa perimeter` ile `Cisco ASA`
             uretici adi eslesir). EN GUVENILIR yontem.
          2. ACIKLAMA ISIMLERI: `cve_asset_map.json` dosyasindaki elle
             yazilmis eslesme. Uretici adi varyantlari (Citrix/ADC/NetScaler)
             otomatik eslesmeyi kacirabildiginden bu dosya onemlidir.

        String eslestirmesi TEK BASINA yeterli degildir; bu yuzden sadece
        "aday" uretir ve nihai onay icin insan/operator karari beklenir.
        """
        keywords = self._cve_keywords(cve)
        if not keywords:
            return []

        cands = [a for a in self._assets if any(a.matches_keyword(k) for k in keywords)]
        if cands:
            LOGGER.info("Varlik adayi bulundu (%s): %s", cve.cve_id, ", ".join(str(a) for a in cands))
        return cands

    @staticmethod
    def _cve_keywords(cve: CVE) -> list[str]:
        """CVE metninden eslestirme anahtarlarini cikarir (3+ karakter, dedup)."""
        blob = " ".join([cve.vendor_project, cve.product, cve.vuln_name])
        tokens = re.split(r"[^A-Za-z0-9.\-]+", blob.lower())
        extra = re.split(r"[^a-z0-9.\-]+", (cve.cwes or "").lower())
        out: set[str] = set()
        for tok in [*tokens, *extra]:
            tok = tok.strip(".-")
            if len(tok) >= 3:
                out.add(tok)
        return sorted(out)

    # --------------------------------------------------------- hedef uretimi

    def resolve_targets(self, cve: CVE, max_targets: int) -> list[str]:
        """Taranacak kesin hedefleri doner ve KAPSAM DOGRULAR.

        Iki kaynak birlestirilir (tekrarsiz):
          1. `cve_asset_map.json` icindeki elle eslesme (varsa)
          2. otomatik etiket/anahtar kelimi eslestirmesi

        DONUS KURALI: Her hedef MUTLAKA kayitli bir varlik olmalidir. Bu satir
        tum guvenlik seridinin kalbidir; `validate_target` her hedefi tek tek
        dener ve listede yoksa ScopeError firlatir.
        """
        targets: list[str] = []
        errors: list[str] = []

        # --- 1) elle eslesme (oncelikli: insan karari)
        for host in self._explicit.get(cve.cve_id.upper(), []):
            try:
                self.validate_target(host)
                targets.append(host)
            except ScopeError as exc:
                # Dosyadaki hedef izin listesinde degilse REDDET, sessizce gecme.
                LOGGER.error("Elle eslesme reddedildi: %s", exc)
                errors.append(str(exc))

        # --- 2) otomatik eslestirme
        for asset in self.candidate_assets(cve):
            if asset.host.startswith("*."):
                # Joker kaydi: alt domainleri statik listeden bulamayiz, bu
                # yuzden jokerin kendisini hedef olarak kullanmayiz (aksi
                # halde beklenmedik kapsam genislemesi olur). Operator
                # gercek alt domainleri `assets.txt`e acikca yazmalidir.
                LOGGER.info("Joker kayit genisletilmedi (kapsam guvenligi): %s", asset.host)
                continue
            try:
                self.validate_target(asset.host)
                targets.append(asset.host)
            except ScopeError as exc:      # kayitli varliklar icin aslinda imkansiz, savunmaci
                LOGGER.error("Otomatik eslesme reddedildi: %s", exc)
                errors.append(str(exc))

        # tekrarlari kaldir, sirayi koru, limite kirp
        unique = list(dict.fromkeys(targets))
        if len(unique) > max_targets:
            LOGGER.warning("Hedefler limite kirpildi: %d -> %d (%s)",
                           len(unique), max_targets, cve.cve_id)
            unique = unique[:max_targets]
        return unique

    def validate_target(self, host: str) -> None:
        """Hedefin izin listesinde oldugunu DOGRULAR; degilse ScopeError firlatir.

        Bu fonksiyon modulun en onemli guvenlik fonksiyonudur: `assets.txt`i
        tanimadigi her hedef icin surekli cagrilir.
        """
        host_l = host.strip().lower()
        allowed = any(a.host == host_l or fnmatch.fnmatch(host_l, a.host) for a in self._assets)
        if not allowed:
            raise ScopeError(
                f"Hedef izinli varlik listesinde degil: {host!r}. "
                "Yalnizca assets.txt icindeki varliklar taranabilir."
            )

    def summary(self) -> str:
        if not self._assets:
            return "Varlik tanimli degil (kapsam bos)"
        tagged = sum(1 for a in self._assets if a.tags)
        return f"{len(self._assets)} varlik, {tagged} tanesi etiketli"


# ============================================================================
#  Nuclei calistirici
# ============================================================================


@dataclass(slots=True)
class ScanResult:
    """Tek bir taramanin sonucu."""

    cve_id: str
    status: str
    findings: int = 0
    output: str = ""
    command: str = ""
    template: str = ""
    targets: list[str] = field(default_factory=list)
    duration_ms: int = 0
    error: str = ""
    dry_run: bool = True


class NucleiRunner:
    """Nuclei'yi alt surec olarak calistirir (asenkron, zaman asimli)."""

    def __init__(self, config: NucleiConfig | None = None) -> None:
        self._cfg = config or CONFIG.nuclei

    # ------------------------------------------------- hazirlik / dogrulama

    def validate_target(self, host: str) -> None:
        """Varlik izin listesinde degilse ScopeError firlatir.

        DIKKAT: `ReconEngine` bu kontrolu zaten yapiyor; burada TEKRAR
        yapiliyor. Iki katmanli kapsam kontrolu BILINCLI: `NucleiRunner`
        motoru tek basina da cagrilabilir (orn. CLI araci). Guvenlik
        kontrolleri tek bir cagri noktaya bagli olmamali.
        """
        host_l = host.strip().lower()
        if not host_l:
            raise ScopeError("Bos hedef reddedildi.")
        if not self._is_valid_host(host_l):
            raise ScopeError(f"Gecersiz hedef bicimi: {host!r}")

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        """Sadece domain/IP/joker kabul et. Liste dosyasi enjeksiyonunu ve
        komut argumani kirliliğini onler."""
        bare = host[2:] if host.startswith("*.") else host
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", bare):
            return all(0 <= int(o) <= 255 for o in bare.split("."))
        return bool(re.fullmatch(
            r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", bare
        ))

    def is_available(self) -> bool:
        """Nuclei binary'si PATH'te veya yapilandirilan konumda mi?"""
        return shutil.which(self._cfg.binary) is not None

    def resolve_template(self, cve_id: str) -> Path | None:
        """CVE icin uygun Nuclei sablonunu bulur.

        Nuclei sablon adlandirmasi: `http/cves/<yil>/CVE-<yil>-<no>.yaml`
        (dogrulandi: nuclei-templates/http/cves/2021/CVE-2021-44228.yaml).
        Yil, CVE'nin yil KISMI olmak zorundadir.
        """
        if not cve_id.upper().startswith("CVE-"):
            return None
        parts = cve_id.upper().split("-")
        if len(parts) < 3:
            return None
        year = parts[1]
        filename = f"{cve_id.upper()}.yaml"

        # Birden fazla olasi kok: kullanici dizini, resmi paket dizini, calisma dizini
        roots = [
            self._cfg.template_dir,
            Path.home() / "nuclei-templates",
            Path.cwd() / "nuclei-templates",
        ]
        for root in roots:
            for sub in (f"http/cves/{year}", f"cves/{year}", f"network/cves/{year}",
                        f"http/vulnerabilities/{year}", ""):
                candidate = (root / sub / filename) if sub else (root / filename)
                if candidate.is_file():
                    return candidate
        LOGGER.info("Sablon bulunamadi: %s (Nuclei taramasi atlanacak)", filename)
        return None

    def build_command(self, template: Path, targets: Sequence[str]) -> tuple[list[str], Path | None]:
        """Nuclei komutunu argv LISTESI olarak kurar (shell=False zorunlu).

        Donus: (argv, gecici_hedef_dosyasi)
        Gecici dosya None ise tek hedef vardir (-u ile verilmistir).
        Dosya `run()` icinde finally ile silinir.
        """
        targets = list(targets)
        if not targets:
            raise ValueError("Hedef listesi bos.")
        if len(targets) > self._cfg.max_targets_per_scan:
            raise ValueError(
                f"Hedef sayisi limiti asildi: {len(targets)} > {self._cfg.max_targets_per_scan}"
            )

        args = [
            self._cfg.binary,
            "-t", str(template),
            "-jsonl",                        # sonuclari satir satir JSON olarak yaz
            "-silent",                       # yalnizca bulgulari yaz, dekor yok
            "-no-color",
            "-disable-update-check",         # her calistirmada git'e gitmesin
            "-rate-limit", str(self._cfg.rate_limit),
            "-bulk-size", "10",
            "-c", str(self._cfg.concurrency),
            "-timeout", str(self._cfg.timeout),
            "-retries", str(self._cfg.retries),
        ]

        # Birden fazla hedef varsa -l (liste) kullan; tek hedef varsa -u.
        # Duz komut zinciri kurmak yerine liste dosyasi: daha hizli, daha guvenli.
        list_path: Path | None = None
        if len(targets) == 1:
            args += ["-u", targets[0]]
        else:
            # Gecici liste dosyasi. Hedefler satir satir yazilir; boylece hicbir
            # hedef adi komut argumani olarak cozumlenemez.
            fd, name = tempfile.mkstemp(prefix="cyber_targets_", suffix=".txt")
            list_path = Path(name)
            with open(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets))
            args += ["-l", str(list_path)]
            LOGGER.debug("Gecici hedef listesi: %s", list_path)

        return args, list_path

    # ------------------------------------------------------------- calistirma

    async def run(self, cve: CVE, targets: Sequence[str],
                  template: Path | None = None) -> ScanResult:
        """Taramayi calistirir. Hata durumunda ScanResult.done=True doner (firlatmaz)."""
        started = time.perf_counter()
        targets = list(targets)

        # --- guvenlik kapisi 1: kapsam dogrulama
        for t in targets:
            try:
                self.validate_target(t)
            except ScopeError as exc:
                LOGGER.error("KAPSAM REDDI: %s", exc)
                return ScanResult(cve_id=cve.cve_id, status=ScanStatus.SKIPPED,
                                  error=str(exc), targets=targets)

        # --- guvenlik kapisi 2: sablon
        template = template or self.resolve_template(cve.cve_id)
        if template is None:
            LOGGER.info("Sablon yok, tarama atlandi: %s", cve.cve_id)
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.SKIPPED,
                              error="Uygun Nuclei sablonu bulunamadi.", targets=targets)

        # --- komutu kur
        list_path: Path | None = None
        try:
            args, list_path = self.build_command(template, targets)
        except ValueError as exc:
            LOGGER.error("Komut kurulamadi: %s", exc)
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.FAILED,
                              error=str(exc), targets=targets, template=str(template))

        command_str = " ".join(shlex.quote(a) for a in args)   # loglanabilir temiz surum
        LOGGER.info("Nuclei tarama: %s | %d hedef | sablon=%s",
                    cve.cve_id, len(targets), template.name)

        # --- guvenlik kapisi 3: kuru mod
        if self._cfg.dry_run or not self._cfg.confirm_scan:
            LOGGER.warning("[DRY-RUN] komut calistirilmadi: %s", command_str)
            return ScanResult(
                cve_id=cve.cve_id, status=ScanStatus.SKIPPED, command=command_str,
                template=str(template), targets=targets, dry_run=True,
                error="DRY-RUN modu.",
            )

        # --- guvenlik kapisi 4: binary var mi
        if not self.is_available():
            LOGGER.error("Nuclei bulunamadi: %s", self._cfg.binary)
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.FAILED,
                              command=command_str, template=str(template),
                              targets=targets, dry_run=False,
                              error=f"Nuclei binary bulunamadi: {self._cfg.binary}")

        # --- gercek calistirma (asenkron alt surec)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                # Windows'ta surec kendi surec grubunda acilir; timeout'ta
                # cocuk sureclere de sinyal gonderebilmek icin.
                **(
                    {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                    if sys.platform == "win32" else {}
                ),
            )
        except FileNotFoundError:
            LOGGER.error("Nuclei calistirilamadi (FileNotFound): %s", self._cfg.binary)
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.FAILED,
                              command=command_str, template=str(template),
                              targets=targets, dry_run=False,
                              error="Nuclei binary bulunamadi.")
        except OSError as exc:
            LOGGER.exception("Alt surec baslatilamadi: %s", exc)
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.FAILED,
                              command=command_str, template=str(template),
                              targets=targets, dry_run=False, error=f"OSError: {exc}")
        finally:
            # Gecici hedef dosyasini HER ZAMAN temizle (hata durumunda da).
            # Nuclei dosyayi okuduktan sonra artik gerek yok.
            if list_path is not None:
                with contextlib.suppress(OSError):
                    list_path.unlink(missing_ok=True)

        # --- zaman asimi ile bekle
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self._cfg.scan_timeout)
        except asyncio.TimeoutError:
            LOGGER.error("Zaman asimi (%.0fs), surec sonlandiriliyor: %s",
                         self._cfg.scan_timeout, cve.cve_id)
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            return ScanResult(cve_id=cve.cve_id, status=ScanStatus.FAILED,
                              command=command_str, template=str(template),
                              targets=targets, dry_run=False,
                              duration_ms=int((time.perf_counter() - started) * 1000),
                              error=f"Zaman asimi: {self._cfg.scan_timeout}s")

        duration_ms = int((time.perf_counter() - started) * 1000)
        text = (stdout or b"").decode("utf-8", errors="replace")
        findings = self._count_findings(text)

        if proc.returncode == 0:
            status = ScanStatus.SUCCESS if findings else ScanStatus.CLEAN
            LOGGER.info("Tarama bitti: %s -> %s (%d bulgu, %dms)",
                        cve.cve_id, status, findings, duration_ms)
        else:
            status = ScanStatus.FAILED
            LOGGER.error("Tarama basarisiz: %s (rc=%s)\n%s",
                         cve.cve_id, proc.returncode, text[-800:])

        return ScanResult(
            cve_id=cve.cve_id, status=status, findings=findings, output=text,
            command=command_str, template=str(template), targets=list(targets),
            duration_ms=duration_ms, dry_run=False,
        )

    @staticmethod
    def _count_findings(jsonl_text: str) -> int:
        """-jsonl ciktisindaki gecerli JSON satir sayisini hesaplar.

        Nuclei bazen uyarilar/istatistik satirlari de yazabilir; JSON parse
        edilemeyen satirlar sayilmaz (sessizce yutulmaz, atlanir).
        """
        count = 0
        for line in jsonl_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
                count += 1
            except json.JSONDecodeError:
                continue
        return count


# ============================================================================
#  Otorite motoru
# ============================================================================


@dataclass(slots=True)
class ScanDecision:
    """Tarama karari ve gerekcesi (seffaflik icin her zaman gerekce yazilir)."""

    should_scan: bool
    reason: str
    targets: list[str] = field(default_factory=list)
    template: str = ""


class ReconEngine:
    """Zafiyet -> karar -> tarama yonlendiricisi.

    Ana akis:
        DB'den is_scanned=0 & kritik CVE'leri al
        -> esik + kapsam kontrolu
        -> mark_scan_started (yaris kilidi)
        -> arka planda Nuclei calistir
        -> mark_scan_finished + denetim izi
    """

    def __init__(self, db: Database, config: NucleiConfig | None = None,
                 registry: AssetRegistry | None = None) -> None:
        self._db = db
        self._cfg = config or CONFIG.nuclei
        self._registry = registry or AssetRegistry.from_file(self._cfg.assets_file)
        # Elle yazilmis CVE -> hedef eslesmeleri (varsa yuklenir).
        self._registry.load_explicit_map(self._cfg.cve_asset_map)
        self._runner = NucleiRunner(self._cfg)
        self._sem = asyncio.Semaphore(max(1, self._cfg.max_scans_per_cycle))
        self._tasks: set[asyncio.Task] = set()   # GC'den korunmak icin referans sart
        self._scanned_this_cycle = 0

    def validate_target(self, host: str) -> None:
        self._registry.validate_target(host)

    # ---------------------------------------------------------- karar katmani

    async def decide(self, cve: CVE) -> ScanDecision:
        """Bu CVE taranmali mi? Gerekceyi her zaman dondurur."""
        # 1) CVSS esigi -- KEV bu alani icermez, NVD zenginlestirme yapilmadiysa
        #    skor NULL'dir ve bu adimda elenir.
        if cve.cvss_score is None:
            return ScanDecision(False, "CVSS bilgisi yok (NVD zenginlestirme bekleniyor).")
        if cve.cvss_score < self._cfg.min_cvss:
            return ScanDecision(
                False,
                f"CVSS {cve.cvss_score:.1f} < esik {self._cfg.min_cvss}.")

        # 2) daha once tarandi mi?
        if cve.is_scanned:
            return ScanDecision(False, "Daha once islenmis (is_scanned=1).")
        if cve.scan_status in (ScanStatus.RUNNING, ScanStatus.SUCCESS, ScanStatus.CLEAN):
            return ScanDecision(False, f"Tarama durumu zaten '{cve.scan_status}'.")

        # 3) KEV kisiti (varsayilan acik)
        if self._cfg.require_kev and cve.source != "CISA-KEV":
            return ScanDecision(False, f"KEV disi kaynak ({cve.source}).")

        # 4) varlik kapsami
        targets = self._registry.resolve_targets(cve, self._cfg.max_targets_per_scan)
        if not targets:
            return ScanDecision(False, "Kayitli varliklar arasinda eslesen hedef yok.")

        # 5) sablon
        template = self._runner.resolve_template(cve.cve_id)
        if template is None:
            return ScanDecision(False, "Uygun Nuclei sablonu bulunamadi.")

        reason = (f"CVSS {cve.cvss_score:.1f} >= {self._cfg.min_cvss} ve "
                  f"{len(targets)} varlik etkileniyor.")
        return ScanDecision(True, reason, targets, str(template))

    # ------------------------------------------------------ calistirma katmani

    async def scan_one(self, cve: CVE, decision: ScanDecision | None = None) -> ScanResult | None:
        """Tek bir CVE icin tarama yapar ve sonucu DB'ye yazar.

        `is_scanned` kilidi sayesinde ayni CVE icin iki tarama calismaz.
        """
        decision = decision or await self.decide(cve)
        if not decision.should_scan:
            LOGGER.debug("Tarama yok: %s -> %s", cve.cve_id, decision.reason)
            return None

        # Yarisi onle: DB seviyesinde kilitle. False donerse baska bir gorev
        # (veya baska bir process) bu CVE'yi zaten islemis demektir.
        acquired = await self._db.mark_scan_started(cve.cve_id)
        if not acquired:
            LOGGER.info("CVE baska bir gorev/process tarafindan isleniyor, atlaniyor: %s", cve.cve_id)
            return None

        LOGGER.info("Tarama tetikleniyor: %s | %s", cve.cve_id, decision.reason)

        template = Path(decision.template) if decision.template else None
        async with self._sem:
            result = await self._runner.run(cve, decision.targets, template)

        # Sonucu kalici yaz
        await self._db.mark_scan_finished(cve.cve_id, result.status, result.output)
        await self._db.log_scan_event(
            cve_id=cve.cve_id,
            targets=result.targets or decision.targets,
            template=result.template or decision.template,
            command=result.command,
            status=result.status,
            findings=result.findings,
            dry_run=result.dry_run,
            duration_ms=result.duration_ms,
            error=result.error,
        )
        return result

    def enqueue(self, cve: CVE, decision: ScanDecision | None = None) -> asyncio.Task | None:
        """Taramayi ARKA PLANDA baslatir ve Task referansini dondurur.

        `asyncio.create_task` ile: ana dongu BEKLEMEZ, istihbarat toplama devam
        eder. Task, `self._tasks` icinde tutulur; aksi halde GC hatta onu
        toplayip tarama yarisinda oldurebilir.

        ONEMLI: `job` ici `self._sem` KAZANMAZ. Semaphore `scan_one` icinde
        alinir. Ikisi de ayni semaphore'u alsaydi ve limit 1 olsaydi
        (varsayilan `max_scans_per_cycle=5` ama 1'e inebilir) iki kez bekleyip
        DEADLOCK olurduk. Tek noktada almak bu hatayi yapısal olarak imkansiz
        kilar.
        """
        async def job() -> None:
            try:
                await self.scan_one(cve, decision)
            except asyncio.CancelledError:
                raise
            except Exception:                     # noqa: BLE001
                # Arka plan gorevi: istisna sessizce kaybolmamali, loglanmali.
                LOGGER.exception("Arka plan taramasi basarisiz: %s", cve.cve_id)
                # Basarisizlik kalici olarak isaretlenir ki kuyrukta kalmasin.
                with contextlib.suppress(Exception):
                    await self._db.mark_scan_finished(
                        cve.cve_id, ScanStatus.FAILED, "Arka plan gorevi istisnasi."
                    )

        task = asyncio.create_task(job(), name=f"scan-{cve.cve_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def run_pending(self, limit: int | None = None) -> list[ScanResult]:
        """DB'deki tarama kuyrugunu isler.

        Bu, botun "ana dongu" tarafindan cagrilan tetikleyicidir. Once karar
        verilir, sonra secilen CVE'ler es zamanli arka planda calistirilir.
        """
        limit = limit or self._cfg.max_scans_per_cycle
        candidates = await self._db.pending_scans(min_cvss=self._cfg.min_cvss, limit=limit * 3)

        results: list[ScanResult] = []
        self._scanned_this_cycle = 0

        for cve in candidates:
            if self._scanned_this_cycle >= limit:
                LOGGER.info("Dongu basi tarama limiti doldu (%d), kalanlar bir sonraki donguye.", limit)
                break

            decision = await self.decide(cve)
            if not decision.should_scan:
                LOGGER.info("Atlandi %s: %s", cve.cve_id, decision.reason)
                # Basarisiz/atlanan taramalari isaretle ki tekrar tekrar denerken duralim
                # (sadece kalici reddedilenler icin).
                if cve.scan_status == ScanStatus.PENDING:
                    await self._db.mark_scan_finished(cve.cve_id, ScanStatus.SKIPPED, decision.reason)
                continue

            self._scanned_this_cycle += 1
            result = await self.scan_one(cve, decision)
            if result:
                results.append(result)

        LOGGER.info("Tarama dongusu bitti: %d tarama calisti, %d sonuc", len(results), len(results))
        return results

    async def shutdown(self, timeout: float = 30.0) -> None:
        """Bekleyen arka plan taramalarini sureli bitirir."""
        if not self._tasks:
            return
        LOGGER.info("%d arka plan tarama gorevi bekleniyor...", len(self._tasks))
        done, pending = await asyncio.wait(self._tasks, timeout=timeout)
        if pending:
            LOGGER.warning("%d tarama zaman asimiyla iptal edildi.", len(pending))
            for t in pending:
                t.cancel()


# ============================================================================
#  Ornek kullanim
# ============================================================================
#
#   async with Database() as db:
#       engine = ReconEngine(db)
#       print(engine._registry.summary())
#       if engine._runner.is_available():
#           results = await engine.run_pending(limit=3)
#           for r in results:
#               print(r.cve_id, r.status, r.findings)