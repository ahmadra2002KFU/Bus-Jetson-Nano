"""Server-side Telegram bot client.

Sends a text alert and the forensic PDF to a configured chat when
detection fires. Reads ``TELEGRAM_BOT_TOKEN`` and ``TELEGRAM_CHAT_ID``
from the environment at construction time. If either is missing or
contains an unsubstituted ``${...}`` placeholder, the client logs a
single info line and disables itself; subsequent calls become no-ops
that log at debug level. This keeps dev runs (no token configured)
and prod runs (token configured) on the same code path.

Mirrors the Jetson-side ``jetson/alerting/telegram_bot.py`` in shape
but is async and uses ``httpx.AsyncClient`` so it integrates with the
FastAPI event loop without thread hops.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional, Union

import httpx

logger = logging.getLogger(__name__)

_TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"


def _has_unsubstituted_placeholder(value: Union[str, None]) -> bool:
    return bool(value) and "${" in str(value)


class TelegramAlerter:
    """Async Telegram client for server-side detection alerts.

    A single instance is constructed at FastAPI startup (lifespan) and
    reused across all detection paths. The 2 s send cooldown is enforced
    by an asyncio Lock so concurrent detections do not violate
    Telegram's per-chat rate limit.
    """

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        min_interval: float = 2.0,
        text_timeout: float = 10.0,
        document_timeout: float = 60.0,
    ) -> None:
        token = bot_token if bot_token is not None else os.environ.get(
            "TELEGRAM_BOT_TOKEN", ""
        )
        chat = chat_id if chat_id is not None else os.environ.get(
            "TELEGRAM_CHAT_ID", ""
        )

        placeholder_token = _has_unsubstituted_placeholder(token)
        placeholder_chat = _has_unsubstituted_placeholder(chat)

        self._token = token
        self._chat_id = chat
        self.enabled = (
            bool(token)
            and bool(chat)
            and not placeholder_token
            and not placeholder_chat
        )
        self._min_interval = min_interval
        self._text_timeout = text_timeout
        self._document_timeout = document_timeout
        self._last_send = 0.0
        self._lock = asyncio.Lock()
        self._client: Optional[httpx.AsyncClient] = None

        if self.enabled:
            logger.info(
                "Telegram alerter enabled (chat_id=%s)", self._chat_id
            )
        elif placeholder_token or placeholder_chat:
            logger.info(
                "Telegram alerter disabled: TELEGRAM_BOT_TOKEN/CHAT_ID "
                "contains an unsubstituted ${...} placeholder."
            )
        else:
            logger.info(
                "Telegram alerter disabled: TELEGRAM_BOT_TOKEN or "
                "TELEGRAM_CHAT_ID not set."
            )

    async def start(self) -> None:
        if self.enabled and self._client is None:
            self._client = httpx.AsyncClient()

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                logger.debug("Telegram client close failed", exc_info=True)
            self._client = None

    def _api_url(self, method: str) -> str:
        return _TELEGRAM_API.format(token=self._token, method=method)

    async def _wait_cooldown(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_send
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)

    async def send_text(self, message: str) -> bool:
        """Send a Markdown text message to the configured chat."""
        if not self.enabled or self._client is None:
            logger.debug("[Telegram disabled] %s", message[:120])
            return False
        async with self._lock:
            await self._wait_cooldown()
            try:
                resp = await self._client.post(
                    self._api_url("sendMessage"),
                    json={
                        "chat_id": self._chat_id,
                        "text": message,
                        "parse_mode": "Markdown",
                    },
                    timeout=self._text_timeout,
                )
                self._last_send = time.monotonic()
                if resp.status_code == 200:
                    logger.info("Telegram text alert sent")
                    return True
                logger.warning(
                    "Telegram sendMessage error: %d %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
            except Exception:
                logger.exception("Telegram sendMessage failed")
                return False

    async def send_document(
        self,
        pdf_path: Union[str, Path],
        caption: str = "",
        filename: Optional[str] = None,
    ) -> bool:
        """Send a PDF (forensic report) as a Telegram document."""
        if not self.enabled or self._client is None:
            logger.debug(
                "[Telegram disabled] document: %s", str(pdf_path)
            )
            return False

        path = Path(pdf_path)
        try:
            pdf_bytes = await asyncio.get_running_loop().run_in_executor(
                None, path.read_bytes
            )
        except FileNotFoundError:
            logger.warning("Telegram: PDF not found: %s", path)
            return False
        except Exception:
            logger.exception("Telegram: PDF read failed: %s", path)
            return False

        async with self._lock:
            await self._wait_cooldown()
            try:
                resp = await self._client.post(
                    self._api_url("sendDocument"),
                    data={
                        "chat_id": self._chat_id,
                        "caption": caption,
                        "parse_mode": "Markdown",
                    },
                    files={
                        "document": (
                            filename or path.name,
                            pdf_bytes,
                            "application/pdf",
                        )
                    },
                    timeout=self._document_timeout,
                )
                self._last_send = time.monotonic()
                if resp.status_code == 200:
                    logger.info(
                        "Telegram document sent (%s, %d bytes)",
                        path.name,
                        len(pdf_bytes),
                    )
                    return True
                logger.warning(
                    "Telegram sendDocument error: %d %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
            except Exception:
                logger.exception("Telegram sendDocument failed")
                return False

    @staticmethod
    def format_gps_spoof(bus_id: int, details: dict) -> str:
        return (
            "*GPS SPOOFING DETECTED on Bus {bus_id}*\n"
            "Time: `{ts}`\n\n"
            "Speed: `{speed:.1f} m/s`\n"
            "Corridor: `{corridor:.0f} m`\n"
            "Source IP: `{src_ip}`\n\n"
            "Forensic PDF attached."
        ).format(
            bus_id=bus_id,
            ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            speed=float(details.get("speed") or 0.0),
            corridor=float(details.get("corridor_dist") or 0.0),
            src_ip=details.get("src_ip", "unknown"),
        )

    @staticmethod
    def format_ddos(bus_id: int, details: dict) -> str:
        return (
            "*DDoS DETECTED on Bus {bus_id}*\n"
            "Time: `{ts}`\n\n"
            "Rate: `{rate:.1f} Mbps`\n"
            "Loss: `{loss:.1f} %`\n"
            "Source IP: `{src_ip}`\n"
        ).format(
            bus_id=bus_id,
            ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            rate=float(details.get("rate_mbps") or 0.0),
            loss=float(details.get("loss_pct") or 0.0),
            src_ip=details.get("src_ip", "unknown"),
        )

    @staticmethod
    def format_forensic_upload(
        bus_id: int, attack_type: str, size_bytes: int
    ) -> str:
        return (
            "*Forensic Evidence Received*\n"
            "Bus: `{bus_id}`\n"
            "Attack: `{attack_type}`\n"
            "Time: `{ts}`\n"
            "Size: `{size_kb:.1f} KB`\n\n"
            "PDF attached."
        ).format(
            bus_id=bus_id,
            attack_type=attack_type,
            ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            size_kb=size_bytes / 1024.0,
        )
