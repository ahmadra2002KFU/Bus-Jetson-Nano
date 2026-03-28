"""
Al-Ahsa Smart Bus — DDoS detection engine.

Runs a check every 10 seconds.  Uses the TrafficMonitor (rate) and
HeartbeatProbe (loss, RTT) to decide whether a DDoS attack is in
progress.

Detection logic mirrors CheckDDoS() in smart-bus.cc (lines 1058-1211):
  - Warmup: ignore the first 90 seconds after start.
  - Trigger on ANY of:
      rate  > 15 Mbps   (DDOS_RATE_THRESHOLD)
      loss  > 5%        (DDOS_LOSS_THRESHOLD)
      RTT   > 100 ms    (DDOS_DELAY_THRESHOLD)
  - One-shot: once triggered, the event is set and the detector never
    re-triggers (matches g_ddosDetected semantics in ns-3).
"""

import logging
import threading
import time
from typing import Callable, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Thresholds — smart-bus.cc lines 58-60
DDOS_RATE_THRESHOLD = 15_000_000.0   # 15 Mbps in bps
DDOS_LOSS_THRESHOLD = 0.05            # 5 %
DDOS_DELAY_THRESHOLD = 0.1            # 100 ms

# Timing
CHECK_INTERVAL = 10.0                 # seconds (smart-bus.cc line 1720)
WARMUP_TIME = 90.0                    # seconds (smart-bus.cc line 64)


class DDoSDetector:
    """Periodic thread that checks for DDoS conditions."""

    def __init__(
        self,
        traffic_monitor,          # TrafficMonitor instance
        heartbeat: object,        # HeartbeatProbe instance
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        warmup: float = WARMUP_TIME,
        check_interval: float = CHECK_INTERVAL,
        rate_threshold: float = DDOS_RATE_THRESHOLD,
        loss_threshold: float = DDOS_LOSS_THRESHOLD,
        delay_threshold: float = DDOS_DELAY_THRESHOLD,
    ):
        self._traffic_monitor = traffic_monitor
        self._heartbeat = heartbeat
        self._callback = callback

        self._warmup = warmup
        self._check_interval = check_interval
        self._rate_threshold = rate_threshold
        self._loss_threshold = loss_threshold
        self._delay_threshold = delay_threshold

        # One-shot detection flag
        self.detected = threading.Event()

        # Internal
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self.detected.clear()
        self._start_time = time.monotonic()

        self._thread = threading.Thread(
            target=self._check_loop, daemon=True, name="ddos-detector"
        )
        self._thread.start()
        logger.info(
            "DDoSDetector started (warmup=%.0fs, interval=%.0fs)",
            self._warmup,
            self._check_interval,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self._check_interval + 2.0)
        logger.info("DDoSDetector stopped")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._check_interval)
            if self._stop_event.is_set():
                break

            elapsed = time.monotonic() - self._start_time

            # Warmup — skip detection but still read counters to
            # keep the window baseline fresh (mirrors ns-3 warmup
            # accumulation at lines 1072-1108).
            if elapsed < self._warmup:
                # Drain the window so the first real check is clean
                _ = self._traffic_monitor.get_interval_rate()
                _ = self._heartbeat.get_interval_loss()
                logger.debug(
                    "DDoS warmup: %.1f / %.1f s elapsed", elapsed, self._warmup
                )
                continue

            # Collect metrics
            rate_bps = self._traffic_monitor.get_interval_rate()
            loss = self._heartbeat.get_interval_loss()
            avg_rtt = self._heartbeat.get_avg_rtt()

            rate_exceeded = rate_bps > self._rate_threshold
            loss_exceeded = loss > self._loss_threshold
            delay_exceeded = avg_rtt > self._delay_threshold

            logger.info(
                "DDoS check: rate=%.2f Mbps (>%.1f? %s)  "
                "loss=%.2f%% (>%.1f%%? %s)  "
                "rtt=%.1f ms (>%.0f ms? %s)",
                rate_bps / 1e6,
                self._rate_threshold / 1e6,
                rate_exceeded,
                loss * 100,
                self._loss_threshold * 100,
                loss_exceeded,
                avg_rtt * 1000,
                self._delay_threshold * 1000,
                delay_exceeded,
            )

            # Already triggered — log but do not fire again
            if self.detected.is_set():
                continue

            # ANY mode: one condition is enough (smart-bus.cc line 1187)
            if rate_exceeded or loss_exceeded or delay_exceeded:
                self.detected.set()
                details = {
                    "type": "ddos",
                    "timestamp": time.time(),
                    "rate_bps": rate_bps,
                    "loss_pct": loss,
                    "rtt_ms": avg_rtt * 1000,
                    "trigger_rate": rate_exceeded,
                    "trigger_loss": loss_exceeded,
                    "trigger_delay": delay_exceeded,
                }
                logger.warning(
                    "[DDoS DETECTED] rate=%.2f Mbps  loss=%.2f%%  rtt=%.1f ms",
                    rate_bps / 1e6,
                    loss * 100,
                    avg_rtt * 1000,
                )
                if self._callback:
                    try:
                        self._callback(details)
                    except Exception:
                        logger.exception("DDoS callback error")
