"""Ticketing — HTTPS POST bursts.

Posts JSON ticket transactions to ``{server_url}/ingest/ticket``. Burst
intervals and sizes match the ns-3 simulation (6-20 s apart, 1-3
transactions per burst).
"""

from __future__ import annotations

import logging
import random
import threading
import time
import uuid

import requests

from jetson.constants import (
    TICKET_MAX_BURST,
    TICKET_MAX_INTERVAL,
    TICKET_MIN_BURST,
    TICKET_MIN_INTERVAL,
    TICKET_PACKET_SIZE,
)

logger = logging.getLogger(__name__)


class TicketingClient(threading.Thread):
    """Sends ticket transaction POSTs at random burst intervals."""

    def __init__(
        self,
        *,
        server_url: str,
        bus_id: int,
        session: "requests.Session | None" = None,
    ):
        super().__init__(daemon=True, name=f"Ticketing-bus{bus_id}")
        self._url = server_url.rstrip("/") + "/ingest/ticket"
        self._bus_id = bus_id
        self._stop_event = threading.Event()
        self._session = session or requests.Session()

    def run(self) -> None:
        logger.info("Ticketing start bus=%d url=%s", self._bus_id, self._url)
        while not self._stop_event.is_set():
            interval = random.uniform(TICKET_MIN_INTERVAL, TICKET_MAX_INTERVAL)
            if self._stop_event.wait(timeout=interval):
                break
            self._send_burst()
        logger.info("Ticketing stop bus=%d", self._bus_id)

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=5.0)

    # ------------------------------------------------------------------

    def _send_burst(self) -> None:
        n = random.randint(TICKET_MIN_BURST, TICKET_MAX_BURST)
        for i in range(n):
            payload = {
                "bus_id": self._bus_id,
                "ts": time.time(),
                "txn_id": uuid.uuid4().hex,
                "size_bytes": TICKET_PACKET_SIZE,
            }
            try:
                resp = self._session.post(self._url, json=payload, timeout=10)
                if resp.status_code >= 400:
                    logger.warning(
                        "ticket post bus=%d status=%d", self._bus_id, resp.status_code,
                    )
            except requests.RequestException as exc:
                logger.warning("ticket post bus=%d failed: %s", self._bus_id, exc)
                return  # drop the rest of this burst; next interval will retry
