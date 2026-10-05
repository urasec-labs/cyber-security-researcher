"""
ISTIHBARAT KAYNAKLARI
=====================
1. CISA KEV  -> ham zafiyet listesi (ana kaynak)
2. NVD API 2.0 -> CVSS skoru + zenginleştirme (Modul 3'ün kapisi bunu gerektirir)

>>> KRITIK BULGU <<<
Dogrulanmis gercek: CISA KEV JSON icinde **CVSS skoru YOKTUR**. 1734 kaydin
tamami test edildi (`hasAnyCvss: false`). KEV yalnizca `dateAdded` / `dueDate`
(BOD yonlendirmesi) ve `knownRansomwareCampaignUse` bilgisi verir.

Bu yuzden "CVSS > 8.0" kapisi KEV'den TEK BASINA kurulamaz. Akis:
    KEV -> DB (cvss_score = NULL)
       -> NVD ile zenginlestir (cvss_score dolar)
       -> ancak O ZAMAN tarama kapisi degerlendirilir
NVD zenginlestirmesi ertelenirse `pending_scans` sorgusu bu CVE'leri zaten
eleyer (SQL'de `cvss_score IS NOT NULL`), yani sessizce yanlis taranmaz.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

from config import CONFIG, FeedConfig
from db import CVE

LOGGER = logging.getLogger("cyber.feeds")


# ------------------------------------------------------------------ KEV


async def fetch_cisa_kev(session: aiohttp.ClientSession,
                        config: FeedConfig | None = None) -> list[CVE]:
    """CISA KEV listesinin TAMAMINI cekip CVE nesnelerine cevirir.

    `$..py` icindeki `vulnerabilities[-3:]` dilimi bir hatadir:
    KEV listesi YENIDEN ESKIYE siralidir, dolayisiyla `[-3:]` listenin EN ESKI
    uc zafiyetini verir - yani botunuz her turda 2020-2021 zafiyetlerini
    "yeni" diye bildirir. Burada tum liste islenir, tarihe gore siralanir ve
    filtre uygulanir.
    """
    cfg = config or CONFIG.feeds
    LOGGER.info("CISA KEV cekiliyor: %s", cfg.kev_url)

    timeout = aiohttp.ClientTimeout(total=cfg.request_timeout)
    try:
        async with session.get(
            cfg.kev_url,
            timeout=timeout,
            headers={"User-Agent": "cyber-research-bot/1.0 (+internal threat intel)"},
        ) as resp:
            if resp.status != 200:
                LOGGER.error("CISA KEV HTTP %s", resp.status)
                return []

            data = await resp.json(content_type=None)   # CORS/Content-Type takilmasin

    except asyncio.TimeoutError:
        LOGGER.error("CISA KEV zaman asimi (%ss)", cfg.request_timeout)
        return []
    except aiohttp.ClientError as exc:
        LOGGER.error("CISA KEV baglanti hatasi: %s", exc)
        return []
    except Exception:                                # noqa: BLE001
        LOGGER.exception("CISA KEV cozumlenemedi (beklenmeyen yapı)")
        return []

    raw: list[dict[str, Any]] = data.get("vulnerabilities") or []
    if not raw:
        LOGGER.warning("CISA KEV bos geldi (beklenmeyen durum).")
        return []

    LOGGER.info("KEV kayit sayisi: %d (surum %s, yayin %s)",
                len(raw), data.get("catalogVersion"), data.get("dateReleased"))

    cves = [CVE.from_kev(v) for v in raw]
    cves = [c for c in cves if c.cve_id]              # kimliksiz kayitlari ele

    # Yeni -> eski sirala
    cves.sort(key=lambda c: c.date_added, reverse=True)
    LOGGER.info("En yeni 3: %s", ", ".join(c.cve_id for c in cves[:3]))
    return cves


# ------------------------------------------------------------------ NVD


@dataclass(slots=True)
class CVSSInfo:
    """NVD'den gelen zenginlestirme."""

    score: float | None
    vector: str
    severity: str


class NVDClient:
    """NVD API 2.0 istemcisi.

    DIKKAT - RATE LIMIT: NVD anonim erisimde **5 istek / 30 saniye**,
    API anahtari ile **50 istek / 30 saniye** izni verir. Limit asilirsa
    HTTP 403 alirsin. Bu yuzden asagida basit bir kayan pencere (sliding
    window) hiz limiter var.
    """

    def __init__(self, session: aiohttp.ClientSession,
                 config: FeedConfig | None = None) -> None:
        self._session = session
        self._cfg = config or CONFIG.feeds
        self._sem = asyncio.Semaphore(max(1, self._cfg.max_concurrent_fetches))
        self._request_times: list[float] = []

    async def _rate_limit(self) -> None:
        """Sliding window: son N saniyede `limit` istek gondermemizi garanti eder."""
        window = self._cfg.nvd_rate_window
        limit = self._cfg.nvd_rate_limit
        while True:
            now = time.monotonic()
            self._request_times = [t for t in self._request_times if now - t < window]
            if len(self._request_times) < limit:
                self._request_times.append(now)
                return
            sleep_for = window - (now - self._request_times[0]) + 0.1
            LOGGER.info("NVD kota beklemesi: %.1fs", sleep_for)
            await asyncio.sleep(sleep_for)

    async def fetch_cvss(self, cve_id: str) -> CVSSInfo | None:
        """Tek CVE icin CVSS skoru vektoru getirir. Hata halinde None."""
        headers = {"User-Agent": "cyber-research-bot/1.0 (+internal threat intel)"}
        if self._cfg.nvd_api_key:
            headers["apiKey"] = self._cfg.nvd_api_key

        timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout)
        try:
            async with self._sem:
                await self._rate_limit()
                async with self._session.get(
                    self._cfg.nvd_url,
                    params={"cveId": cve_id},
                    headers=headers,
                    timeout=timeout,
                ) as resp:
                    if resp.status == 404:
                        LOGGER.debug("NVD kayit yok: %s", cve_id)
                        return None
                    if resp.status == 403:
                        LOGGER.warning("NVD kota asildi (403) - API anahtari gerekli olabilir.")
                        return None
                    if resp.status != 200:
                        LOGGER.error("NVD HTTP %s (%s)", resp.status, cve_id)
                        return None
                    payload = await resp.json(content_type=None)

            return self._parse_cvss(payload)

        except asyncio.TimeoutError:
            LOGGER.warning("NVD zaman asimi: %s", cve_id)
            return None
        except aiohttp.ClientError as exc:
            LOGGER.warning("NVD baglanti hatasi (%s): %s", cve_id, exc)
            return None
        except Exception:                              # noqa: BLE001
            LOGGER.exception("NVD cozumlenemedi: %s", cve_id)
            return None

    @staticmethod
    def _parse_cvss(payload: dict[str, Any]) -> CVSSInfo | None:
        """NVD yanitindan en uygun CVSS metrigini sec.

        Oncelik sirasi: v4.0 -> v3.1 -> v3.0 -> v2.0. NVD bazen birden fazla
        metrik dondurur (biri CPE'ye ozel olabilir); ilkini aliyoruz.
        """
        try:
            items = payload.get("vulnerabilities") or []
            if not items:
                return None
            metrics = (items[0].get("cve") or {}).get("metrics") or {}
        except (AttributeError, IndexError, TypeError):
            LOGGER.error("NVD yanit yapisi beklenmeyin.")
            return None

        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if not entries:
                continue
            data = entries[0].get("cvssData") or {}
            raw_score = data.get("baseScore")
            if raw_score is None:
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            severity = data.get("baseSeverity") or ""
            if not severity:      # CVSS v2'de baseSeverity yok
                severity = {"10": "CRITICAL", "7": "HIGH"}.get(str(int(score)), "")
            return CVSSInfo(
                score=score,
                vector=str(data.get("vectorString", "")),
                severity=str(severity),
            )

        LOGGER.debug("NVD yanitinda CVSS metrigi bulunamadi (beklenir: yeni/yenilenmis CVE).")
        return None

    async def enrich_many(self, cve_ids: list[str],
                          on_result: Any = None) -> dict[str, CVSSInfo]:
        """Birden fazla CVE'yi zenginlestirir (rate limit'li, es zamanli).

        `on_result` opsiyonel bir async geri cagirma: her CVE islenince
        veritabanina yazilir. Boylece program cok uzun surse bile ilerleme
        kalici olur.
        """
        if not cve_ids:
            return {}

        LOGGER.info("NVD zenginlestirme: %d CVE (limit %d/%ds)",
                    len(cve_ids), self._cfg.nvd_rate_limit, self._cfg.nvd_rate_window)

        async def one(cve_id: str) -> tuple[str, CVSSInfo | None]:
            return cve_id, await self.fetch_cvss(cve_id)

        pairs = await asyncio.gather(*(one(c) for c in cve_ids), return_exceptions=True)

        out: dict[str, CVSSInfo] = {}
        for pair in pairs:
            if isinstance(pair, BaseException):
                LOGGER.error("NVD toplu hatasi: %s", pair)
                continue
            cve_id, info = pair
            if info is None:
                continue
            out[cve_id] = info
            if on_result is not None:
                try:
                    res = on_result(cve_id, info)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:                      # noqa: BLE001
                    LOGGER.exception("on_result hatasi: %s", cve_id)

        LOGGER.info("NVD zenginlestirme bitti: %d/%d CVE skorlandi", len(out), len(cve_ids))
        return out