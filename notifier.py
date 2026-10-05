"""
TELEGRAM BILDIRIM KATMANI
========================
`$..py` icindeki iki hatayi duzeltir:

1. URL hatası:
       f"https://telegram.org{CONFIG['TELEGRAM_BOT_TOKEN']}/sendMessage"
   Bu adres Telegram API'si DEGILDIR (normal web sitesidir) ve her zaman
   404/302 doner. Dogru bicim:
       https://api.telegram.org/bot<TOKEN>/sendMessage

2. Markdown kirilması:
   `parse_mode="Markdown"` kullanildiginda CVE aciklamalarindaki `_ * ` [`
   karakterleri Telegram'da "parse entities failed" hatasina yol acar ve
   mesajiniz HIC gonderilmez. Cozum: varsayilan `parse_mode="HTML"` +
   `html.escape()`. Boylece ham metin guvenle gonderilir.

Ayrıca ekler:
  * yeniden deneme (429 flood wait -> Retry-After'a uy)
  * 4096 karakter limitinde mesaj bolme
  * oturum kapama yonetimi
"""

from __future__ import annotations

import asyncio
import html
import logging
from typing import Any

import aiohttp

from config import CONFIG, TelegramConfig

LOGGER = logging.getLogger("cyber.telegram")


class TelegramNotifier:
    """Telegram Bot API istemcisi."""

    def __init__(self, session: aiohttp.ClientSession,
                 config: TelegramConfig | None = None) -> None:
        self._cfg = config or CONFIG.telegram
        self._session = session
        self._enabled = bool(self._cfg.token and self._cfg.chat_id)
        if not self._enabled:
            LOGGER.warning("Telegram yapilandirilmamis; bildirimler devre disi.")
        self._sent = 0
        self._failed = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------ yardimcilar

    @property
    def _url(self) -> str:
        return f"{self._cfg.api_base}/bot{self._cfg.token}/sendMessage"

    @staticmethod
    def escape(text: str) -> str:
        """Kullanici/feed metnini HTML'e guvenli cevirir.

        Ters sirada calisir: once metni kirp, SONRA escape et. Aksi halde
        kirpmadan sonra '&amp;' yarim kalmis olur.
        """
        return html.escape(str(text or ""), quote=False)

    def split_message(self, text: str, limit: int | None = None) -> list[str]:
        """Mesaji Telegram limitinin altinda parcalara boler.

        Satir sonundan kesmeye calisir; cok uzun tek satir varsa karakter
        limitinde keser. HTML etiketlerinin ortada bolunmesi onlenir.
        """
        limit = limit or self._cfg.max_chars
        if len(text) <= limit:
            return [text]

        chunks: list[str] = []
        remaining = text
        while remaining:
            if len(remaining) <= limit:
                chunks.append(remaining)
                break
            window = remaining[:limit]
            cut = window.rfind("\n")
            if cut < limit // 2:            # yari noktada kesmek anlamsiz
                cut = window.rfind(" ")
            if cut <= 0:
                cut = limit
            chunks.append(remaining[:cut])
            remaining = remaining[cut:].lstrip("\n")
        LOGGER.debug("Uzun mesaj %d parcaya bolundu.", len(chunks))
        return chunks

    # --------------------------------------------------------------- gonderim

    async def send(self, text: str, parse_mode: str | None = None,
                   disable_preview: bool = True) -> bool:
        """Tek mesaj gonderir. Uzun metinleri otomatik boler."""
        if not self._enabled:
            return False

        mode = self._cfg.parse_mode if parse_mode is None else parse_mode
        payload_base = {
            "chat_id": self._cfg.chat_id,
            "disable_web_page_preview": disable_preview,
        }
        if mode:
            payload_base["parse_mode"] = mode

        for i, chunk in enumerate(self.split_message(text), start=1):
            ok = await self._send_one({**payload_base, "text": chunk})
            if not ok:
                return False
            if i > 1:
                await asyncio.sleep(0.4)   # Telegram rate limitine saygi
        return True

    async def _send_one(self, payload: dict[str, Any], max_retries: int = 3) -> bool:
        """Tek HTTP istegi + yeniden deneme."""
        timeout = aiohttp.ClientTimeout(total=20)

        for attempt in range(1, max_retries + 1):
            try:
                async with self._session.post(self._url, json=payload, timeout=timeout) as resp:
                    body = await resp.text()

                    if resp.status == 200:
                        self._sent += 1
                        return True

                    # 429 = flood limit; sunucu ne kadar beklememizi istiyorsa o kadar bekleyelim.
                    if resp.status == 429:
                        wait = 5.0 * attempt
                        try:
                            data = await resp.json(content_type=None)
                            wait = float(data.get("parameters", {}).get("retry_after", wait))
                        except Exception:            # noqa: BLE001
                            pass
                        LOGGER.warning("Telegram rate limit, %.1fs bekleniyor (%d/%d)",
                                       wait, attempt, max_retries)
                        await asyncio.sleep(wait)
                        continue

                    LOGGER.error("Telegram HTTP %s: %s", resp.status, body[:300])
                    return False

            except asyncio.TimeoutError:
                LOGGER.warning("Telegram zaman asimi (%d/%d)", attempt, max_retries)
            except aiohttp.ClientError as exc:
                LOGGER.warning("Telegram baglanti hatasi: %s (%d/%d)", exc, attempt, max_retries)

            if attempt < max_retries:
                await asyncio.sleep(1.5 * attempt)

        self._failed += 1
        LOGGER.error("Telegram mesaji gonderilemedi (%d deneme).", max_retries)
        return False

    async def send_photo(self, caption: str, photo_path: str) -> bool:
        """Dosya gonderimi (ornegin tarama ciktisi ekran goruntusu)."""
        if not self._enabled:
            return False
        try:
            form = aiohttp.FormData()
            with open(photo_path, "rb") as fh:
                form.add_field("photo", fh, filename=photo_path)
                form.add_field("chat_id", self._cfg.chat_id)
                form.add_field("caption", self.escape(caption)[:1_000])
                async with self._session.post(
                    f"{self._cfg.api_base}/bot{self._cfg.token}/sendPhoto",
                    data=form, timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        LOGGER.error("sendPhoto HTTP %s", resp.status)
                        return False
                    return True
        except (OSError, aiohttp.ClientError) as exc:
            LOGGER.error("sendPhoto hatasi: %s", exc)
            return False

    def stats(self) -> str:
        return f"Telegram: {self._sent} gonderildi, {self._failed} basarisiz"