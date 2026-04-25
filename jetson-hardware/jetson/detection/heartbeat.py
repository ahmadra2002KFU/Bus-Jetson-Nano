"""Heartbeat probe — HTTPS GET to {server_url}/health/heartbeat.

Replaces the old UDP echo with an HTTPS probe every 1 s. Treats any
non-2xx response or timeout as a lost probe. Keeps the public API
(``get_interval_loss`` / ``get_avg_rtt``) unchanged so the DDoS
detector can keep querying it.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

_SEND_INTERVAL = 1.0
_REQUEST_TIMEOUT = 3.0


class HeartbeatProbe:
    """HTTPS-based heartbeat loss / RTT tracker."""

    def __init__(
        self,
        *,
        server_url: str,
        bus_id: int,
        session: "requests.Session | None" = None,
    ):
        self._url = server_url.rstrip("/") + "/health/heartbeat"
        self._bus_id = bus_id
        self._session = session or requests.Session()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sent = 0
        self._acked = 0
        self._rtts: List[float] = []
        self._seq = 0
        self._thread: Optional[threading.Thread] = None

    # Public -----------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="heartbeat"
        )
        self._thread.start()
        logger.info("Heartbeat start bus=%d url=%s", self._bus_id, self._url)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Heartbeat stop bus=%d", self._bus_id)

    def get_interval_loss(self) -> float:
        """Loss ratio in [0, 1] over the last window, resets counters."""
        with self._lock:
            sent, acked = self._sent, self._acked
            self._sent = 0
            self._acked = 0
            self._rtts.clear()
        if sent == 0:
            return 0.0
        lost = sent - acked
        return max(0.0, min(1.0, lost / sent))

    def get_avg_rtt(self) -> float:
        """Average RTT in seconds over the current window (no reset)."""
        with self._lock:
            samples = list(self._rtts)
        if not samples:
            return 0.0
        return sum(samples) / len(samples)

    # Internal ---------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self._probe_once()
            self._stop_event.wait(timeout=_SEND_INTERVAL)

    def _probe_once(self) -> None:
        self._seq += 1
        params = {"bus_id": self._bus_id, "seq": self._seq, "ts": time.time()}
        t0 = time.monotonic()
        with self._lock:
            self._sent += 1
        try:
            resp = self._session.get(
                self._url, params=params, timeout=_REQUEST_TIMEOUT
            )
            if resp.status_code < 400:
                rtt = time.monotonic() - t0
                with self._lock:
                    self._acked += 1
                    self._rtts.append(rtt)
                logger.debug("heartbeat ok seq=%d rtt=%.3fs", self._seq, rtt)
            else:
                logger.debug("heartbeat status=%d seq=%d", resp.status_code, self._seq)
        except requests.RequestException as exc:
            logger.debug("heartbeat fail seq=%d: %s", self._seq, exc)
