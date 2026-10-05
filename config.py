"""
Ortak Yapılandırma Katmanı
-------------------------
Tüm sırlar (secret) ortam değişkenlerinden okunur; kod içine sabit yazılmaz.
`..py` içindeki gibi token'ı kaynak koda yazmak, botu GitHub'a koyduğunuz anda
sızıntıya dönüşür. Burada tek bir doğrulama noktası (validation) vardır.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOGGER = logging.getLogger("cyber.config")

# ---------------------------------------------------------------- yardımcılar


def _str(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def _int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("%s='%s' tamsayıya çevrilemedi, varsayılan kullanılıyor: %s", key, raw, default)
        return default


def _float(key: str, default: float) -> float:
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        LOGGER.warning("%s='%s' float'a çevrilemedi, varsayılan kullanılıyor: %s", key, raw, default)
        return default


def _flag(key: str, default: bool = False) -> bool:
    """'true/1/yes/on' -> True. Env string'lerinde 'False' de truthy olduğu için
    küçük-büyük harf duyarlı ayrım şart."""
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _path(key: str, default: Path) -> Path:
    raw = os.getenv(key)
    return Path(raw).expanduser().resolve() if raw else default


# ------------------------------------------------------------- varsayilanlar
#
# DIKKAT: `@dataclass(slots=True)` kullanildiginda sinif ozellikleri
# `member_descriptor` nesnesine donusur. Bu yuzden varsayilan degerlere
# `FeedConfig.kev_url` gibi SINIF UZERINDEN erisilemez; modül seviyesinde
# sabitler tutuyoruz.

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_LLM_MODEL = "qwen2.5:14b-instruct"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_LLM_TIMEOUT = 180
DEFAULT_LLM_MAX_RETRIES = 2
DEFAULT_DB_NAME = "cyber_intel.db"
DEFAULT_LOG_NAME = "cyber_bot.log"
DEFAULT_ASSETS_FILE = BASE_DIR / "assets.txt"
DEFAULT_ASSET_MAP_FILE = BASE_DIR / "cve_asset_map.json"
DEFAULT_TEMPLATE_DIR = BASE_DIR / "nuclei-templates"

# ------------------------------------------------------------- veri dizinleri

DATA_DIR = _path("CYBER_DATA_DIR", BASE_DIR / "data")
SCAN_OUTPUT_DIR = DATA_DIR / "scans"
TEMPLATE_DIR = _path("NUCLEI_TEMPLATES", DEFAULT_TEMPLATE_DIR)

for _d in (DATA_DIR, SCAN_OUTPUT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------- veri tabanı


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """SQLite bağlantı ayarları."""

    path: Path = DATA_DIR / "cyber_intel.db"
    timeout: float = 10.0        # 'busy_timeout' saniyesi -> başka yazma varsa bekle
    retry_attempts: int = 3      # 'database is locked' hatasında yeniden deneme
    busy_timeout_ms: int = 10_000


# ------------------------------------------------------------------- istihbarat


@dataclass(frozen=True, slots=True)
class FeedConfig:
    """CISA KEV + NVD zenginleştirme."""

    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""            # bos ise anonim kota (5 istek/30sn)
    check_interval: int = 1_800       # ana dongu bekleme suresi (sn)
    request_timeout: int = 30
    max_concurrent_fetches: int = 3

    # NVD rate limit (RFC/dokumana gore)
    nvd_rate_limit: int = field(default=5)
    nvd_rate_window: int = 30        # saniye


# ------------------------------------------------------------------ LLM triage


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """OpenAI veya Ollama saglayicisi icin ortak ayarlar.

    provider: "openai" | "ollama"
    Ollama icin api_key gerekmez; OpenAI uyumlu yerel sunucular da
    provider="openai" + base_url ile baglanabilir (vLLM, LM Studio, llama.cpp).
    """

    provider: str = "ollama"
    model: str = "qwen2.5:14b-instruct"        # openai icin: "gpt-4o-mini"
    api_key: str = ""
    base_url: str = ""                          # openai: https://api.openai.com/v1
    ollama_host: str = "http://127.0.0.1:11434"

    # YEREL MODELLER YAVAS OLABILIR. Olculmus deger: Ollama'da 5GB llama modeli,
    # CPU-only, 3 maddelik cikti icin ~125 sn surdu. 45 sn'lik zaman asimi
    # modele zaman asimina ugratir, sonra 3 kez yeniden deneyerek cagriyi 6
    # dakikaya uzatir. Bu yuzden varsayilan 180 sn; OpenAI gibi uzak API'ler
    # icin LLM_TIMEOUT=60 yapabilirsiniz.
    timeout: int = 180               # tek istek zaman asimi
    max_retries: int = 2             # 429/5xx icin geri cekilerek yeniden deneme
    backoff_base: float = 1.5        # ustel geri cekilme tabani (saniye)
    backoff_max: float = 30.0
    max_concurrency: int = 2         # ayni anda gidecek LLM cagrisi
    max_input_chars: int = 3_500     # istifteki aciklamayi kirp -> token/maliyet korumasi
    temperature: float = 0.1
    enabled: bool = True

    def validate(self) -> None:
        if self.provider not in {"openai", "ollama"}:
            LOGGER.warning(
                "Bilinmeyen LLM provider '%s'. Gecerli degerler: 'openai' veya 'ollama'. "
                "Triaj kural tabanli ozete duserek calismaya devam edecek.", self.provider
            )
        if self.provider == "openai" and not self.api_key and not self.base_url:
            LOGGER.warning(
                "LLM provider 'openai' secildi ama OPENAI_API_KEY bos. "
                "Triaj adimi atlanacak ya da yerel OpenAI-uyumlu sunucu icin LLM_BASE_URL verin."
            )


# --------------------------------------------------------------------- nuclei


@dataclass(frozen=True, slots=True)
class NucleiConfig:
    """Modul 3: otomatik kesif (recon) ayarlari.

    guvenlik seridi: `dry_run` varsayilan True'dur. Gercek komut calistirmak icin
    CYBER_DRY_RUN=false VE CYBER_CONFIRM_SCAN=true ikisinin de verilmesi gerekir.
    Boylece yeni bir ortama ilk deploy edildiginde kazara tarama yapilmaz.
    """

    binary: str = "nuclei"
    template_dir: Path = TEMPLATE_DIR
    rate_limit: int = 50              # saniyedeki istek -> kendi altyapini korur
    concurrency: int = 10             # -c
    timeout: int = 10                 # -timeout (saniye, template basina)
    retries: int = 1                  # -retries
    scan_timeout: int = 600           # tum alt-surec icin ust sinir (saniye)
    max_targets_per_scan: int = 50    # tek taramada hedef siniri
    max_scans_per_cycle: int = 5      # dongu basina tetiklenecek azami tarama
    max_scans_per_cve: int = 1        # ayni CVE icin tekrar tarama yapma

    # varlik (asset) eslesmesi
    assets_file: Path = BASE_DIR / "assets.txt"
    cve_asset_map: Path = BASE_DIR / "cve_asset_map.json"

    # zafiyet kapisi
    min_cvss: float = 8.0             # esik deger: sadece kritik/acil
    require_kev: bool = True          # yalnizca CISA KEV listesindekiler taranir mi

    dry_run: bool = True
    confirm_scan: bool = False


# ------------------------------------------------------------------ telegram


@dataclass(frozen=True, slots=True)
class TelegramConfig:
    token: str = ""
    chat_id: str = ""
    api_base: str = "https://api.telegram.org"
    parse_mode: str = "HTML"   # HTML daha guvenli: CVE metni icinde '_' '*' '`' patlar
    max_chars: int = 4_000     # Telegram tek mesaj limiti 4096


# -------------------------------------------------------------------- ana obje


@dataclass(frozen=True, slots=True)
class AppConfig:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    feeds: FeedConfig = field(default_factory=FeedConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    log_level: str = "INFO"
    log_file: Path = DATA_DIR / "cyber_bot.log"


def load_config() -> AppConfig:
    """Ortam degiskenlerini tek seferde okuyup dogrulanmis yapilandirma uretir."""
    cfg = AppConfig(
        database=DatabaseConfig(
            path=_path("CYBER_DB_PATH", DATA_DIR / DEFAULT_DB_NAME),
            timeout=_float("CYBER_DB_TIMEOUT", 10.0),
            retry_attempts=_int("CYBER_DB_RETRIES", 3),
        ),
        feeds=FeedConfig(
            kev_url=_str("CISA_KEV_URL", DEFAULT_KEV_URL),
            nvd_api_key=_str("NVD_API_KEY"),
            check_interval=_int("CHECK_INTERVAL", 1_800),
            request_timeout=_int("REQUEST_TIMEOUT", 30),
            nvd_rate_limit=_int("NVD_RATE_LIMIT", 50 if _str("NVD_API_KEY") else 5),
        ),
        llm=LLMConfig(
            provider=_str("LLM_PROVIDER", "ollama").lower(),
            model=_str("LLM_MODEL", DEFAULT_LLM_MODEL),
            api_key=_str("OPENAI_API_KEY"),
            base_url=_str("LLM_BASE_URL"),
            ollama_host=_str("OLLAMA_HOST", DEFAULT_OLLAMA_HOST),
            max_concurrency=_int("LLM_MAX_CONCURRENCY", 2),
            timeout=_int("LLM_TIMEOUT", DEFAULT_LLM_TIMEOUT),
            max_retries=_int("LLM_MAX_RETRIES", DEFAULT_LLM_MAX_RETRIES),
            enabled=_flag("LLM_ENABLED", True),
        ),
        nuclei=NucleiConfig(
            binary=_str("NUCLEI_BINARY", "nuclei"),
            template_dir=_path("NUCLEI_TEMPLATES", TEMPLATE_DIR),
            assets_file=_path("CYBER_ASSETS_FILE", DEFAULT_ASSETS_FILE),
            cve_asset_map=_path("CYBER_CVE_ASSET_MAP", DEFAULT_ASSET_MAP_FILE),
            min_cvss=_float("SCAN_MIN_CVSS", 8.0),
            dry_run=_flag("CYBER_DRY_RUN", True),
            confirm_scan=_flag("CYBER_CONFIRM_SCAN", False),
            rate_limit=_int("NUCLEI_RATE_LIMIT", 50),
        ),
        telegram=TelegramConfig(
            token=_str("TELEGRAM_BOT_TOKEN"),
            chat_id=_str("TELEGRAM_CHAT_ID"),
        ),
        log_level=_str("LOG_LEVEL", "INFO").upper(),
        log_file=_path("CYBER_LOG_FILE", DATA_DIR / DEFAULT_LOG_NAME),
    )

    cfg.llm.validate()

    if not cfg.telegram.token or not cfg.telegram.chat_id:
        LOGGER.warning("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID tanimli degil; bildirimler devre disi.")
    if cfg.nuclei.dry_run:
        LOGGER.warning(
            "Nuclei DRY-RUN modunda (CYBER_DRY_RUN). Gercek tarama icin "
            "CYBER_DRY_RUN=false ve CYBER_CONFIRM_SCAN=true ayarla."
        )
    return cfg


CONFIG = load_config()