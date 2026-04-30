"""Telegram Bot alert sender for detection notifications."""

from __future__ import annotations

import logging
import threading
import time
from typing import Union

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"


def _has_unsubstituted_placeholder(value: Union[str, None]) -> bool:
    """True if ``value`` still contains a ``${...}`` token.

    The Config loader interpolates env vars but leaves the literal
    ``${NAME}`` token in place when the env var is missing.  Treat that
    as "not configured" so we don't POST garbage tokens to Telegram and
    rack up 404s.
    """
    return bool(value) and "${" in str(value)


class TelegramAlert:
    """Sends detection alerts to a Telegram chat via Bot API.

    Uses requests library (no python-telegram-bot dependency needed).
    Gracefully degrades if token/chat_id not configured.
    """

    def __init__(self, bot_token: str = "", chat_id: str = "",
                 enabled: bool = True) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id

        # Detect unsubstituted ${TELEGRAM_BOT_TOKEN} / ${TELEGRAM_CHAT_ID}
        # tokens — the literal string is truthy so the bool() guard
        # below is not enough on its own.
        placeholder_token = _has_unsubstituted_placeholder(bot_token)
        placeholder_chat = _has_unsubstituted_placeholder(chat_id)

        self.enabled = (
            enabled
            and bool(bot_token)
            and bool(chat_id)
            and not placeholder_token
            and not placeholder_chat
        )
        self._last_send = 0
        self._min_interval = 2.0  # rate limit: 1 msg per 2 seconds

        if self.enabled:
            logger.info("Telegram alerts enabled (chat_id=%s)", chat_id)
        elif placeholder_token or placeholder_chat:
            logger.info(
                "Telegram disabled — bot_token/chat_id contains "
                "unsubstituted ${...} placeholder (run "
                "scripts/setup_telegram.py or export the env vars)"
            )
        else:
            logger.info("Telegram alerts disabled (no token/chat_id)")

    def _api_url(self, method):
        return TELEGRAM_API.format(token=self.bot_token, method=method)

    def send_text(self, message):
        """Send a text message to the configured chat."""
        if not self.enabled:
            logger.info("[Telegram disabled] %s", message[:100])
            return False

        now = time.time()
        if now - self._last_send < self._min_interval:
            time.sleep(self._min_interval - (now - self._last_send))

        try:
            import requests
            resp = requests.post(
                self._api_url("sendMessage"),
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            self._last_send = time.time()
            if resp.status_code == 200:
                logger.info("Telegram message sent")
                return True
            else:
                logger.warning("Telegram API error: %d %s",
                               resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
            return False

    def send_photo(self, jpeg_bytes, caption=""):
        """Send a photo (JPEG bytes) with optional caption."""
        if not self.enabled:
            logger.info("[Telegram disabled] Photo: %s", caption[:50])
            return False

        now = time.time()
        if now - self._last_send < self._min_interval:
            time.sleep(self._min_interval - (now - self._last_send))

        try:
            import requests
            resp = requests.post(
                self._api_url("sendPhoto"),
                data={
                    "chat_id": self.chat_id,
                    "caption": caption,
                    "parse_mode": "Markdown",
                },
                files={"photo": ("evidence.jpg", jpeg_bytes, "image/jpeg")},
                timeout=30,
            )
            self._last_send = time.time()
            if resp.status_code == 200:
                logger.info("Telegram photo sent")
                return True
            else:
                logger.warning("Telegram photo error: %d", resp.status_code)
                return False
        except Exception as e:
            logger.error("Telegram photo send failed: %s", e)
            return False

    def send_document(self, file_bytes, filename, caption=""):
        """Send an arbitrary document (e.g. forensic PDF) with optional caption.

        Mirrors send_photo's structure: rate-limit/cooldown, disabled-fallback,
        and a try/except around the requests POST. The multipart field name
        for sendDocument is ``document`` (not ``photo``) and we declare the
        MIME as ``application/pdf``.

        Notes:
        - Telegram's sendDocument file-size limit is 50 MB. Forensic PDFs in
          this project are typically 50-500 KB so no size guard is needed.
        - 60 s timeout because PDFs are larger than photos and the bus's
          uplink (LTE / Cloudflare tunnel) can be slow.
        """
        if not self.enabled:
            logger.info("[Telegram disabled] Document: %s", filename)
            return False

        now = time.time()
        if now - self._last_send < self._min_interval:
            time.sleep(self._min_interval - (now - self._last_send))

        try:
            import requests
            resp = requests.post(
                self._api_url("sendDocument"),
                data={
                    "chat_id": self.chat_id,
                    "caption": caption,
                    "parse_mode": "Markdown",
                },
                files={"document": (filename, file_bytes, "application/pdf")},
                timeout=60,
            )
            self._last_send = time.time()
            if resp.status_code == 200:
                logger.info("Telegram document sent (%s, %d bytes)",
                            filename, len(file_bytes))
                return True
            else:
                logger.warning("Telegram document error: %d %s",
                               resp.status_code, resp.text[:200])
                return False
        except Exception as e:
            logger.error("Telegram document send failed: %s", e)
            return False

    def send_ddos_alert(self, details):
        """Send a formatted DDoS detection alert."""
        msg = (
            "*DDoS DETECTED on Bus {bus_id}*\n"
            "Time: `{timestamp}`\n\n"
            "Rate: `{rate_mbps:.1f} Mbps` (threshold: 15 Mbps)\n"
            "Loss: `{loss_pct:.1f}%` (threshold: 5%)\n"
            "RTT: `{rtt_ms:.1f} ms` (threshold: 100 ms)\n\n"
            "Forensic evidence upload initiated."
        ).format(
            bus_id=details.get('bus_id', 0),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            rate_mbps=details.get('rate_bps', 0) / 1e6,
            loss_pct=details.get('loss_pct', 0) * 100,
            rtt_ms=details.get('rtt_ms', 0),
        )
        return self.send_text(msg)

    def send_gps_alert(self, details, jpeg_bytes=None):
        """Send a formatted GPS spoofing alert, optionally with photo."""
        msg = (
            "*GPS SPOOFING DETECTED on Bus {bus_id}*\n"
            "Time: `{timestamp}`\n\n"
            "Speed: `{speed:.1f} m/s` (threshold: 22.2 m/s)\n"
            "Jump: `{distance:.0f} m` (threshold: 1000 m)\n"
            "Corridor: `{corridor:.0f} m` (threshold: 1500 m)\n"
            "Source IP: `{src_ip}`\n\n"
            "Forensic evidence upload initiated."
        ).format(
            bus_id=details.get('bus_id', 0),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            speed=details.get('speed', 0),
            distance=details.get('distance', 0),
            corridor=details.get('corridor_dist', 0),
            src_ip=details.get('src_ip', 'unknown'),
        )
        if jpeg_bytes:
            return self.send_photo(jpeg_bytes, caption=msg[:1024])
        return self.send_text(msg)
