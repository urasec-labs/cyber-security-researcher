"""
MODUL 1: VERI TABANI KATMANI (PERSISTENCE)
=========================================
`self.seen_cves = set()` yerine SQLite kullanan yonetim sinifi.

Neden set degil de SQLite?
  * set yalnizca RAM'de yasar -> bot yeniden baslayinca "yeni" olan tum CVE'ler
    tekrar bildirilir, ya da crash sonrasi durum kaybolur.
  * 'is_scanned' durumu ve tarama ciktisi tutulacak bir yere ihtiyac var.
  * Gecmis veri uzerinde sorgulama (rapor, denetim izi) gerekiyor.

Tasarim kararlari:
  1. sqlite3 SENKRON bir kutuphanedir; dogrudan async fonksiyon icinde
     cagrilirsa event loop'u bloklar ve asenkron mimariyi bozar. Bu yuzden
     tum DB islemleri `asyncio.to_thread` uzerinden TEK bir worker thread'e
     aktarilir (asagida `Database._run`). Boylece event loop nefes alir.
  2. Tek worker thread = SQLite baglantisi tek is parcaciginda kalir; boylece
     `check_same_thread` ihlali olmaz ve ayrica bir Lock kullanmaya gerek kalmaz.
  3. WAL modu + busy_timeout: birden fazla surec (bot + CLI analizi) ayni DB'yi
     acarsa yazma cakismasi kontrollu sekilde beklemek yerine aninda hata vermez.
  4. `INSERT OR IGNORE` + `cursor.rowcount`: "bu CVE yeni miydi?" sorusunu
     tek bir atomik islemle cevaplar (once oku -> sonra yaz yarisi degil).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, TypeVar

from config import CONFIG, DatabaseConfig

LOGGER = logging.getLogger("cyber.db")

T = TypeVar("T")

# ---------------------------------------------- alan sinirlari (DB şişmesin)

MAX_DESC_CHARS = 8_000
MAX_ACTION_CHARS = 4_000
MAX_TRIAGE_CHARS = 4_000
MAX_SCAN_OUTPUT_CHARS = 16_000
MAX_NOTES_CHARS = 2_000


# ------------------------------------------------------------- durum sabitleri


class ScanStatus:
    """`cves.is_scanned` yanindaki durum makinesi."""

    PENDING = "pending"    # henuz taranmadi
    RUNNING = "running"    # su an tarama iceride
    SUCCESS = "success"    # tarama bitti, bulgu var
    CLEAN = "clean"        # tarama bitti, bulgu yok
    FAILED = "failed"      # hata / timeout / sablon yok
    SKIPPED = "skipped"    # kapiyi gecmedi (kapsam disi, esik alti, kuru mod)

    ALL = (PENDING, RUNNING, SUCCESS, CLEAN, FAILED, SKIPPED)


class TriageStatus:
    """LLM triaj durumu."""

    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    DISABLED = "disabled"   # LLM kapaliysa

    ALL = (PENDING, DONE, FAILED, SKIPPED, DISABLED)


# ------------------------------------------------------------------ veri sinifi


def _now_utc() -> str:
    """Tüm zaman damgaları ISO-8601 UTC. Yerel saat dilimi karışıklığını önler."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: Any, limit: int) -> str:
    """Metni güvenli şekilde kırp (None -> '', str dışı -> str)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


@dataclass(slots=True)
class CVE:
    """`cves` tablosunun tek satırlık Python karşılığı.

    Alan adları feed'deki anahtarlarla birebir eşleşir; böylece KEV -> veritabanı
    eşlemesi `vuln["cveID"] -> cve.cve_id` dışında alan adı değiştirmek de
    gerekmez.
    """

    cve_id: str
    source: str = "CISA-KEV"

    vendor_project: str = ""
    product: str = ""
    vuln_name: str = ""
    description: str = ""
    required_action: str = ""
    cvss_score: float | None = None      # KEV bu alani ICERMEZ -> NVD'den zenginlestirilir
    cvss_vector: str = ""
    severity: str = ""
    date_added: str = ""
    due_date: str = ""
    known_ransomware: str = ""            # "Known" -> ransomware ile ilişkilendirilmiş
    cwes: str = ""                        # virgülle birleştirilmiş liste
    notes: str = ""

    is_scanned: int = 0                   # 0 = hayır, 1 = evet  (istenen bayrak)
    scan_status: str = ScanStatus.PENDING
    scan_output: str = ""
    scan_started_at: str = ""
    scan_finished_at: str = ""

    triage_status: str = TriageStatus.PENDING
    triage_summary: str = ""
    triage_provider: str = ""

    first_seen_at: str = ""
    updated_at: str = ""

    # -------------------------------------------------- yardimci donusumler

    @classmethod
    def from_kev(cls, vuln: dict[str, Any]) -> "CVE":
        """CISA KEV JSON kaydini CVE nesnesine cevirir.

        `$..py` icindeki `vulnerabilities[-3:]` diliminin yerine gecen, tum
        listeyi tarayan ve alanlari guvenli sekilde okuyan surum.
        """
        cwes = vuln.get("cwes") or []
        return cls(
            cve_id=str(vuln.get("cveID", "")).strip(),
            source="CISA-KEV",
            vendor_project=_clip(vuln.get("vendorProject"), 200),
            product=_clip(vuln.get("product"), 200),
            vuln_name=_clip(vuln.get("vulnerabilityName"), 500),
            description=_clip(vuln.get("shortDescription"), MAX_DESC_CHARS),
            required_action=_clip(vuln.get("requiredAction"), MAX_ACTION_CHARS),
            date_added=str(vuln.get("dateAdded") or "")[:10],
            due_date=str(vuln.get("dueDate") or "")[:10],
            known_ransomware=_clip(vuln.get("knownRansomwareCampaignUse"), 50),
            cwes=",".join(str(c) for c in cwes if c),
            notes=_clip(vuln.get("notes"), MAX_NOTES_CHARS),
        )

    def apply_cvss(self, score: float | None, vector: str, severity: str) -> "CVE":
        """NVD zenginleştirmesinden gelen CVSS verisini uygular.

        Kısa vadede KEV kaydı CVSS içermediği için tarama eşiği bu adımdan
        sonra anlamlı hâle gelir.
        """
        if score is not None:
            self.cvss_score = float(score)
            self.cvss_vector = _clip(vector, 120)
            self.severity = _clip(severity, 20) or self._severity_from_score(float(score))
        return self

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    @property
    def is_critical(self) -> bool:
        return (self.cvss_score or 0.0) >= CONFIG.nuclei.min_cvss

    def to_row(self) -> tuple[Any, ...]:
        """INSERT parametrelerini sirayla uretir.

        KRITIK: Bu siranin `INSERT_COLUMNS` ile BIREBIR ayni olmasi zorunludur.
        Kolonlar adla belirtilse bile degerler konumla eslesir; iki liste
        kayarsa `date_added` yerine `cvss_score` alanina yazilir ve satir
        sessizce reddedilir. Test (`test_db`) bu srayi dogrular.
        """
        return (
            # --- INSERT_COLUMNS[0:2]
            self.cve_id,
            self.source,
            # --- feed'den gelen ham veri  INSERT_COLUMNS[2:11]
            self.vendor_project,
            self.product,
            self.vuln_name,
            self.description,
            self.required_action,
            self.date_added,
            self.due_date,
            self.known_ransomware,
            self.cwes,
            self.notes,
            # --- NVD zenginlestirme   INSERT_COLUMNS[11:14]
            self.cvss_score,
            self.cvss_vector,
            self.severity,
            # --- tarama durumu        INSERT_COLUMNS[14:20]
            self.is_scanned,
            self.scan_status,
            self.scan_output[:MAX_SCAN_OUTPUT_CHARS],
            self.scan_started_at,
            self.scan_finished_at,
            # --- LLM triaj durumu     INSERT_COLUMNS[20:23]
            self.triage_status,
            self.triage_summary[:MAX_TRIAGE_CHARS],
            self.triage_provider,
            # --- zaman damgalari      INSERT_COLUMNS[23:25]
            _now_utc(),          # first_seen_at
            _now_utc(),          # updated_at
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "CVE":
        """sqlite3.Row -> CVE (kolon adlarıyla, sıra bağımsız)."""
        keys = row.keys()
        return cls(**{k: row[k] for k in keys if k in {f.name for f in fields(cls)}})


# ------------------------------------------------------------------ sema

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id           TEXT PRIMARY KEY,
    source           TEXT    NOT NULL DEFAULT 'CISA-KEV',

    -- feed'den gelen ham veri
    vendor_project   TEXT    NOT NULL DEFAULT '',
    product          TEXT    NOT NULL DEFAULT '',
    vuln_name        TEXT    NOT NULL DEFAULT '',
    description      TEXT    NOT NULL DEFAULT '',
    required_action  TEXT    NOT NULL DEFAULT '',
    date_added       TEXT    NOT NULL DEFAULT '',
    due_date         TEXT    NOT NULL DEFAULT '',
    known_ransomware TEXT    NOT NULL DEFAULT '',
    cwes             TEXT    NOT NULL DEFAULT '',
    notes            TEXT    NOT NULL DEFAULT '',

    -- NVD zenginlestirme (KEV bu alanlari icermez)
    cvss_score       REAL,
    cvss_vector      TEXT    NOT NULL DEFAULT '',
    severity         TEXT    NOT NULL DEFAULT '',

    -- tarama durumu (Modul 3)
    is_scanned       INTEGER NOT NULL DEFAULT 0 CHECK (is_scanned IN (0, 1)),
    scan_status      TEXT    NOT NULL DEFAULT 'pending',
    scan_output      TEXT    NOT NULL DEFAULT '',
    scan_started_at  TEXT    NOT NULL DEFAULT '',
    scan_finished_at TEXT    NOT NULL DEFAULT '',

    -- LLM triaj durumu (Modul 2)
    triage_status    TEXT    NOT NULL DEFAULT 'pending',
    triage_summary   TEXT    NOT NULL DEFAULT '',
    triage_provider  TEXT    NOT NULL DEFAULT '',

    first_seen_at    TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL
);

-- Tarama kuyrugu sorgusu: WHERE is_scanned = 0 AND ... (indeks olmadan tam tablo taranir)
CREATE INDEX IF NOT EXISTS idx_cves_scan_queue
    ON cves (is_scanned, scan_status, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_triage_queue
    ON cves (triage_status, first_seen_at);
CREATE INDEX IF NOT EXISTS idx_cves_date_added
    ON cves (date_added DESC);

CREATE TABLE IF NOT EXISTS scan_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id       TEXT    NOT NULL,
    targets      TEXT    NOT NULL DEFAULT '',
    template     TEXT    NOT NULL DEFAULT '',
    command      TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL,
    findings     INTEGER NOT NULL DEFAULT 0,
    dry_run      INTEGER NOT NULL DEFAULT 1,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    error        TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_events_cve
    ON scan_events (cve_id, created_at DESC);
"""

SCHEMA_VERSION = "1"

# INSERT kolon sirasi -- sema ile BIREBIR ayni olmak zorunda
INSERT_COLUMNS = (
    "cve_id", "source",
    "vendor_project", "product", "vuln_name", "description", "required_action",
    "date_added", "due_date", "known_ransomware", "cwes", "notes",
    "cvss_score", "cvss_vector", "severity",
    "is_scanned", "scan_status", "scan_output", "scan_started_at", "scan_finished_at",
    "triage_status", "triage_summary", "triage_provider",
    "first_seen_at", "updated_at",
)


# ============================================================================
#  Yonetici
# ============================================================================


class Database:
    """SQLite veri tabani yoneticisi.

    Kullanim (async context manager):

        async with Database(CONFIG.database) as db:
            yeni = await db.insert_many(cves)

    Ya da acik/a kapali:

        db = Database(CONFIG.database)
        await db.connect()
        ...
        await db.close()
    """

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self._cfg = config or CONFIG.database
        self._path = Path(self._cfg.path)
        self._conn: sqlite3.Connection | None = None
        self._closed = False
        # max_workers=1 -> butun DB cagrilari TEK is parcaciginda serilenir.
        # Event loop bloklanmaz, baglanti is parcacigi degistirmez.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sqlite")
        self._stmt_lock = asyncio.Lock()   # yalnizca sema uygulamak icin (PRAGMA)

    # ------------------------------------------------------------- yasam dongusu

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        # False = hatayi yutmadan yukariyoruz
        await self.close()
        return False

    async def connect(self) -> None:
        """Baglantiyi ac ve semayi uygula. Idempotenttir."""
        if self._conn is not None:
            LOGGER.debug("Baglanti zaten acik: %s", self._cfg.path)
            return
        async with self._stmt_lock:
            if self._conn is not None:
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            await self._run(self._connect_sync)
            LOGGER.info("Veritabani hazir: %s", self._cfg.path)

    async def close(self) -> None:
        """Baglantiyi ve worker thread'i kapat."""
        if self._closed:
            return
        self._closed = True
        with suppress(Exception):
            await self._run(self._close_sync)
        self._executor.shutdown(wait=True)
        LOGGER.info("Veritabani kapatildi.")

    # ----------------------------------------------------- worker yardimcilari

    async def _run(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Senkron bir DB islemini worker thread'de calistirir (event loop'u bloklamaz)."""
        if self._closed:
            raise RuntimeError("Database zaten kapatildi.")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, functools.partial(fn, *args, **kwargs))

    def _retrying(self, fn: Callable[[], T], what: str) -> T:
        """'database is locked/busy' hatasina karsi ustel geri cekilme.

        Yalnizca kilitlenme hatasini yakalar; butun exception'lari yutmaz,
        boylece gercek hatalar sessizce kaybolmaz.
        """
        last: Exception | None = None
        for attempt in range(1, self._cfg.retry_attempts + 1):
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if "locked" not in msg and "busy" not in msg:
                    raise
                last = exc
                wait = 0.2 * (2 ** (attempt - 1))
                LOGGER.warning("%s: veritabani kilitli, %.2fs sonra tekrar denenecek (%d/%d)",
                               what, wait, attempt, self._cfg.retry_attempts, )
        raise RuntimeError(f"{what}: veritabani kilitli, {self._cfg.retry_attempts} deneme sonrasi: {last}")

    # ----------------------------------------------------- senkron (worker) katman

    def _connect_sync(self) -> None:
        assert self._conn is None
        conn = sqlite3.connect(
            str(self._cfg.path),
            timeout=self._cfg.timeout,
            # is parcacigi sabit oldugu icin bu zaten True kalabilirdi;
            # yine de acikca False yazip bagimlilik oldugunu gosteriyoruz.
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL")          # okuma/yazma birbirini bloklamaz
        cur.execute(f"PRAGMA busy_timeout = {self._cfg.busy_timeout_ms}")
        cur.execute("PRAGMA synchronous = NORMAL")         # WAL ile iyi bir denge
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA temp_store = MEMORY")
        cur.close()

        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SCHEMA_VERSION,),
        )
        conn.commit()
        self._conn = conn
        LOGGER.debug("Sema uygulandi (v%s), journal_mode=%s", SCHEMA_VERSION,
                     conn.execute("PRAGMA journal_mode").fetchone()[0])

    def _close_sync(self) -> None:
        if self._conn is not None:
            with suppress(sqlite3.Error):
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            with suppress(sqlite3.Error):
                self._conn.close()
            LOGGER.debug("Baglanti kapatildi.")
        self._conn = None

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Baglanti yok. Once await db.connect() cagrin.")
        return self._conn

    # ------------------------------------------------------------- yazma islemleri

    def _insert_sync(self, cve: CVE) -> bool:
        """Tek CVE yaz. Yeni eklendiyse True, zaten vardiysa False doner."""
        placeholders = ", ".join("?" for _ in INSERT_COLUMNS)
        sql = f"INSERT OR IGNORE INTO cves ({', '.join(INSERT_COLUMNS)}) VALUES ({placeholders})"
        cur = self._db.execute(sql, cve.to_row())
        is_new = cur.rowcount == 1
        if not is_new:
            # Kayit zaten vardi: sadece eksik zenginlestirme alanlarini tamamla.
            # NULL'a esitlenmesin diye COALESCE kullanilir.
            self._db.execute(
                """
                UPDATE cves
                   SET cvss_score  = COALESCE(cvss_score, ?),
                       cvss_vector = CASE WHEN cvss_vector = '' THEN ? ELSE cvss_vector END,
                       severity    = CASE WHEN severity = '' THEN ? ELSE severity END,
                       updated_at  = ?
                 WHERE cve_id = ?
                """,
                (cve.cvss_score, cve.cvss_vector, cve.severity, _now_utc(), cve.cve_id),
            )
        return is_new

    def _insert_many_sync(self, cves: Sequence[CVE]) -> list[CVE]:
        """Toplu yazim: TEK transaction. 1700+ CVE'yi tek tek yazmak yerine
        tek seferde yaziyoruz; 500x daha hizli ve kismi yazim olmuyor."""
        new_items: list[CVE] = []
        conn = self._db
        try:
            conn.execute("BEGIN IMMEDIATE")     # yazan kilidini bastan al
            for cve in cves:
                if self._insert_sync(cve):
                    new_items.append(cve)
            conn.commit()
        except Exception:
            conn.rollback()
            LOGGER.exception("Toplu yazim geri alindi (%d kayit).", len(new_items))
            raise
        return new_items

    async def insert_cve(self, cve: CVE) -> bool:
        """Tek CVE ekle. Yeni miydi? -> bool doner."""
        return await self._run(self._insert_sync, cve)

    async def insert_many(self, cves: Sequence[CVE]) -> list[CVE]:
        """Coklu CVE ekle, yalnızca YENI olanları liste olarak dondurur.

        Donus listesi dogrudan "bu dongude bildirilecek bulgular" olarak kullanilir;
        set'te gormek zorunda kalmayiz.
        """
        if not cves:
            return []
        new_items = await self._run(self._retrying,
                                    functools.partial(self._insert_many_sync, list(cves)),
                                    f"insert_many({len(cves)} kayit)")
        LOGGER.info("DB yazimi: %d kayit islendi, %d YENI bulgu", len(cves), len(new_items))
        return new_items

    async def update_cvss(self, cve_id: str, score: float | None,
                          vector: str = "", severity: str = "") -> None:
        """NVD'den gelen CVSS verisini tek CVE'ye yazar."""
        await self._run(
            self._retrying,
            functools.partial(self._update_cvss_sync, cve_id, score, vector, severity),
            f"update_cvss({cve_id})",
        )

    def _update_cvss_sync(self, cve_id: str, score: float | None, vector: str, severity: str) -> None:
        if score is None:
            return
        if not severity:
            severity = CVE._severity_from_score(score)
        self._db.execute(
            """
            UPDATE cves
               SET cvss_score = COALESCE(cvss_score, ?),
                   cvss_vector = COALESCE(NULLIF(cvss_vector, ''), ?),
                   severity    = COALESCE(NULLIF(severity, ''), ?),
                   updated_at  = ?
             WHERE cve_id = ?
            """,
            (float(score), vector[:120], severity[:20], _now_utc(), cve_id),
        )
        self._db.commit()

    async def save_triage(self, cve_id: str, summary: str, provider: str,
                          status: str = TriageStatus.DONE) -> None:
        """LLM triaj sonucunu kalici olarak saklar (Modul 2 cikisi).

        Saklamanin sebebi: ayni CVE icin LLM'e tekrar para/jeton odemeyelim;
        bot yeniden baslasa bile ozet hatirlansin.
        """
        await self._run(
            self._retrying,
            functools.partial(self._save_triage_sync, cve_id, summary, provider, status),
            f"save_triage({cve_id})",
        )

    def _save_triage_sync(self, cve_id: str, summary: str, provider: str, status: str) -> None:
        self._db.execute(
            """
            UPDATE cves
               SET triage_status = ?, triage_summary = ?, triage_provider = ?, updated_at = ?
             WHERE cve_id = ?
            """,
            (status, (summary or "")[:MAX_TRIAGE_CHARS], provider[:60], _now_utc(), cve_id),
        )
        self._db.commit()

    async def mark_scan_started(self, cve_id: str) -> bool:
        """Tarama baslamadan once kilitler: is_scanned=1, status=running.

        Soylesen:
          True  -> bu cagri kilidi ALDI, tarama senin sorumlulugun.
          False -> baska bir gorev/process zaten islemis, tekrar calistirma.

        Boylece bot coklu dongu yapsa ya da iki surec ayni DB'yi kullansa
        ayni CVE icin iki tarama calismaz (yaris kosulu onlenir).
        """
        return await self._run(self._retrying,
                               functools.partial(self._mark_scan_started_sync, cve_id),
                               f"mark_scan_started({cve_id})")

    def _mark_scan_started_sync(self, cve_id: str) -> bool:
        cur = self._db.execute(
            """
            UPDATE cves
               SET is_scanned = 1, scan_status = ?, scan_started_at = ?, updated_at = ?
             WHERE cve_id = ? AND is_scanned = 0
            """,
            (ScanStatus.RUNNING, _now_utc(), _now_utc(), cve_id),
        )
        self._db.commit()
        return cur.rowcount == 1   # True -> bu çağrı kilidi aldı, taramayı sen yap

    async def mark_scan_finished(self, cve_id: str, status: str, output: str = "") -> None:
        """Tarama bitti: sonucu yaz, is_scanned=1 kalir."""
        await self._run(
            self._retrying,
            functools.partial(self._mark_scan_finished_sync, cve_id, status, output),
            f"mark_scan_finished({cve_id})",
        )

    def _mark_scan_finished_sync(self, cve_id: str, status: str, output: str) -> None:
        self._db.execute(
            """
            UPDATE cves
               SET scan_status = ?, scan_output = ?, scan_finished_at = ?, updated_at = ?
             WHERE cve_id = ?
            """,
            (status, (output or "")[:MAX_SCAN_OUTPUT_CHARS], _now_utc(), _now_utc(), cve_id),
        )
        self._db.commit()

    async def log_scan_event(self, cve_id: str, targets: Sequence[str], template: str,
                             command: str, status: str, findings: int = 0,
                             dry_run: bool = True, duration_ms: int = 0,
                             error: str = "") -> None:
        """Denetim izi: kim/ne zaman/hangi hedefe ne komut calistirdi (Modul 3)."""
        await self._run(
            self._retrying,
            functools.partial(self._log_scan_event_sync, cve_id, targets, template,
                              command, status, findings, dry_run, duration_ms, error),
            f"log_scan_event({cve_id})",
        )

    def _log_scan_event_sync(self, cve_id, targets, template, command, status,
                             findings, dry_run, duration_ms, error) -> None:
        self._db.execute(
            """
            INSERT INTO scan_events
                (cve_id, targets, template, command, status, findings,
                 dry_run, duration_ms, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                ",".join(targets)[:2_000],
                template[:300],
                command[:2_000],
                status[:40],
                int(findings),
                1 if dry_run else 0,
                int(duration_ms),
                (error or "")[:1_000],
                _now_utc(),
            ),
        )
        self._db.commit()

    # ------------------------------------------------------------- okuma islemleri

    async def get(self, cve_id: str) -> CVE | None:
        """Tek CVE kaydini doner (yoksa None)."""
        return await self._run(self._get_sync, cve_id)

    def _get_sync(self, cve_id: str) -> CVE | None:
        row = self._db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return CVE.from_row(row) if row else None

    async def get_many(self, cve_ids: Sequence[str]) -> dict[str, CVE]:
        """Birden fazla CVE'yi tek sorguda getirir.

        N+1 sorgu tuzagindan kacinmak icin: dongude `get()` cagrisi yerine
        buradaki tek IN(...) sorgusu kullanilir. Modul 3'te hedef eslestirme
        icin gereklidir.
        """
        ids = [c for c in cve_ids if c]
        if not ids:
            return {}
        return await self._run(self._get_many_sync, ids)

    def _get_many_sync(self, ids: Sequence[str]) -> dict[str, CVE]:
        # SQLite parametre sayisi siniri (varsayilan 999) -> parcalama
        out: dict[str, CVE] = {}
        chunk = 900
        for i in range(0, len(ids), chunk):
            part = list(ids[i:i + chunk])
            placeholders = ", ".join("?" for _ in part)
            rows = self._db.execute(
                f"SELECT * FROM cves WHERE cve_id IN ({placeholders})", part
            ).fetchall()
            for row in rows:
                cve = CVE.from_row(row)
                out[cve.cve_id] = cve
        return out

    async def pending_triage(self, limit: int = 50) -> list[CVE]:
        """Triaj bekleyen CVE'ler (Modul 2 girdi kuyrugu)."""
        return await self._run(self._pending_triage_sync, limit)

    def _pending_triage_sync(self, limit: int) -> list[CVE]:
        rows = self._db.execute(
            """
            SELECT * FROM cves
             WHERE triage_status IN (?, ?)
             ORDER BY date_added DESC, first_seen_at DESC
             LIMIT ?
            """,
            (TriageStatus.PENDING, TriageStatus.FAILED, limit),
        ).fetchall()
        return [CVE.from_row(r) for r in rows]

    async def pending_scans(self, min_cvss: float = 0.0, limit: int = 100) -> list[CVE]:
        """Tarama kuyrugu: henuz is_scanned=0 OLAN ve CVSS esigini gecenler.

        Esik burada SQL icinde uygulanir; Python tarafinda filtrelemek
        gerekmez (ve daha onemlisi, dogru indeks kullanilir).
        """
        return await self._run(self._pending_scans_sync, min_cvss, limit)

    def _pending_scans_sync(self, min_cvss: float, limit: int) -> list[CVE]:
        sql = (
            "SELECT * FROM cves WHERE is_scanned = 0 "
            "  AND cvss_score IS NOT NULL AND cvss_score >= ? "
        )
        params: list[Any] = [min_cvss]
        # ONCE LLM triaji tamamlanmis olsun: butun CVE'ye ayni anda hem rapor
        # hem tarama yapmak yerine once basari durumu, sonra tarama.
        sql += " AND triage_status = ? "
        params.append(TriageStatus.DONE)
        sql += " ORDER BY cvss_score DESC, date_added DESC LIMIT ?"
        params.append(limit)

        rows = self._db.execute(sql, params).fetchall()
        return [CVE.from_row(r) for r in rows]

    async def pending_cvss_enrichment(self, limit: int = 25) -> list[CVE]:
        """CVSS bilgisi olmayan CVE'ler (NVD zenginlestirme kuyrugu).

        KEV bu alani icermedigi icin tarama kapisi acilmadan once doldurulmalidir.
        """
        return await self._run(self._pending_cvss_sync, limit)

    def _pending_cvss_sync(self, limit: int) -> list[CVE]:
        rows = self._db.execute(
            """
            SELECT * FROM cves
             WHERE cvss_score IS NULL AND triage_status = ?
             ORDER BY date_added DESC
             LIMIT ?
            """,
            (TriageStatus.PENDING, limit),
        ).fetchall()
        return [CVE.from_row(r) for r in rows]

    async def mark_triage_skipped(self, cve_ids: Sequence[str], status: str = TriageStatus.DISABLED) -> int:
        """LLM kapaliyken/erisilemiyorken kuyrugu takilmemek icin isaretler."""
        ids = [c for c in cve_ids if c]
        if not ids:
            return 0
        return await self._run(self._mark_triage_skipped_sync, ids, status)

    def _mark_triage_skipped_sync(self, ids: Sequence[str], status: str) -> int:
        placeholders = ", ".join("?" for _ in ids)
        cur = self._db.execute(
            f"UPDATE cves SET triage_status = ?, updated_at = ? WHERE cve_id IN ({placeholders})",
            [status, _now_utc(), *ids],
        )
        self._db.commit()
        return cur.rowcount

    async def stats(self) -> dict[str, Any]:
        """Ozet/rapor metrikleri."""
        return await self._run(self._stats_sync)

    def _stats_sync(self) -> dict[str, Any]:
        conn = self._db
        total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        by_scan = {
            r["scan_status"]: r["n"]
            for r in conn.execute(
                "SELECT scan_status, COUNT(*) AS n FROM cves GROUP BY scan_status"
            )
        }
        by_triage = {
            r["triage_status"]: r["n"]
            for r in conn.execute(
                "SELECT triage_status, COUNT(*) AS n FROM cves GROUP BY triage_status"
            )
        }
        critical = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE cvss_score >= ?", (CONFIG.nuclei.min_cvss,)
        ).fetchone()[0]
        scans = conn.execute("SELECT COUNT(*) FROM scan_events").fetchone()[0]
        newest = conn.execute("SELECT MAX(first_seen_at) FROM cves").fetchone()[0]
        return {
            "total_cves": total,
            "critical": critical,
            "scanned": sum(n for s, n in by_scan.items() if s != ScanStatus.PENDING),
            "scan_status": by_scan,
            "triage_status": by_triage,
            "scan_events": scans,
            "newest_seen_at": newest,
        }

    async def vacuum(self) -> None:
        """Disk alanini geri kazandir (bakim/oz bakim)."""
        await self._run(self._retrying, self._vacuum_sync, "vacuum")
        LOGGER.info("VACUUM tamamlandi.")

    def _vacuum_sync(self) -> None:
        self._db.execute("VACUUM")


# ============================================================================
#  Ornek kullanim
# ============================================================================
#
#   async def main():
#       async with Database() as db:
#           new_cves = await db.insert_many(
#               CVE.from_kev(v) for v in kev_payload["vulnerabilities"]
#           )
#           for cve in new_cves:
#               await db.save_triage(cve.cve_id, "...", "ollama")
#
#           for cve in await db.pending_scans(min_cvss=8.0):
#               print(cve.cve_id, cve.cvss_score, cve.scan_status)