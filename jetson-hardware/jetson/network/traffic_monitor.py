"""
Al-Ahsa Smart Bus — Network traffic rate monitor.

Measures incoming traffic (rx_bytes) on the specified network interface
over 10-second windows.  The DDoS detector queries this to check whether
the inbound rate exceeds the 15 Mbps threshold.

Platform strategy:
  - Linux (Jetson Nano):  reads /sys/class/net/{iface}/statistics/rx_bytes
    every second — zero dependencies, no root required.
  - Windows / fallback:  uses psutil.net_io_counters() for the given
    interface (or system-wide if the interface is not found).
"""

import logging
import os
import platform
import threading
import time

logger = logging.getLogger(__name__)

_SAMPLE_INTERVAL = 1.0      # seconds between counter reads
_WINDOW_DURATION = 10.0      # seconds per measurement window


class TrafficMonitor:
    """Thread that tracks incoming network bytes."""

    def __init__(self, interface: str = "wwan0"):
        self._interface = interface
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Per-window state (protected by _lock)
        self._lock = threading.Lock()
        self._window_start_bytes: int = 0
        self._window_current_bytes: int = 0
        self._window_start_time: float = 0.0
        self._window_end_time: float = 0.0

        # Pick platform reader
        self._is_linux = platform.system() == "Linux"
        self._sysfs_path = (
            f"/sys/class/net/{self._interface}/statistics/rx_bytes"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        initial = self._read_rx_bytes()
        now = time.monotonic()
        with self._lock:
            self._window_start_bytes = initial
            self._window_current_bytes = initial
            self._window_start_time = now
            self._window_end_time = now

        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="traffic-monitor"
        )
        self._thread.start()
        logger.info(
            "TrafficMonitor started on %s (linux=%s)",
            self._interface,
            self._is_linux,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("TrafficMonitor stopped")

    def get_interval_rate(self) -> float:
        """Return average inbound rate in bits per second for the last window.

        Resets the window for the next measurement.
        """
        now = time.monotonic()
        current = self._read_rx_bytes()

        with self._lock:
            delta_bytes = current - self._window_start_bytes
            delta_time = now - self._window_start_time
            # Reset window
            self._window_start_bytes = current
            self._window_current_bytes = current
            self._window_start_time = now
            self._window_end_time = now

        if delta_time <= 0:
            return 0.0
        return (delta_bytes * 8.0) / delta_time

    def get_interval_bytes(self) -> int:
        """Return total bytes received in the current window (non-resetting)."""
        current = self._read_rx_bytes()
        with self._lock:
            return current - self._window_start_bytes

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Continuously sample rx_bytes so the counter stays fresh."""
        while not self._stop_event.is_set():
            try:
                current = self._read_rx_bytes()
                with self._lock:
                    self._window_current_bytes = current
                    self._window_end_time = time.monotonic()
            except Exception as exc:
                logger.warning("TrafficMonitor poll error: %s", exc)
            self._stop_event.wait(timeout=_SAMPLE_INTERVAL)

    def _read_rx_bytes(self) -> int:
        """Read cumulative received bytes from the OS."""
        if self._is_linux:
            return self._read_sysfs()
        return self._read_psutil()

    def _read_sysfs(self) -> int:
        """Linux: read /sys/class/net/<iface>/statistics/rx_bytes."""
        try:
            with open(self._sysfs_path, "r") as fh:
                return int(fh.read().strip())
        except FileNotFoundError:
            logger.warning(
                "sysfs path %s not found, falling back to psutil",
                self._sysfs_path,
            )
            self._is_linux = False
            return self._read_psutil()
        except (ValueError, OSError) as exc:
            logger.warning("sysfs read error: %s", exc)
            return 0

    def _read_psutil(self) -> int:
        """Fallback: use psutil for any platform."""
        try:
            import psutil
        except ImportError:
            logger.error(
                "psutil not installed — cannot monitor traffic on this platform"
            )
            return 0

        try:
            counters = psutil.net_io_counters(pernic=True)
            if self._interface in counters:
                return counters[self._interface].bytes_recv
            # Fallback to system-wide counters
            total = psutil.net_io_counters(pernic=False)
            return total.bytes_recv
        except Exception as exc:
            logger.warning("psutil read error: %s", exc)
            return 0
