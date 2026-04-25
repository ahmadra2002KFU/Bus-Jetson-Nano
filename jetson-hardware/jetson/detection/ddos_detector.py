"""
Al-Ahsa Smart Bus — DDoS detection engine.

Runs a check every 10 seconds.  Uses the TrafficMonitor (rate) and
HeartbeatProbe (loss, RTT) to decide whether a DDoS attack is in
progress.

Detection logic mirrors CheckDDoS() in smart-bus.cc (lines 1058-1211):
  - Warmup: ignore the first 90 seconds after start.
  - A "bad" window is one where ANY of:
      rate  > 15 Mbps   (DDOS_RATE_THRESHOLD)
      loss  > 5%        (DDOS_LOSS_THRESHOLD)
      RTT   > 100 ms    (DDOS_DELAY_THRESHOLD)
  - Trigger only after ``loss_streak_required`` consecutive bad windows
    (defends against transient WebSocket reconnect blips that otherwise
    look like a single 12.5% loss window).
  - Clear path: after ``clear_streak_required`` consecutive clean
    windows the ``detected`` event is cleared and the optional
    ``cleared`` callback is fired so the rest of the agent (e.g. the
    forensic re-arm latch in main.py) can react.
  - One-shot per detection event: ``callback(details)`` still fires
    exactly once when ``detected`` transitions from clear to set, so
    each genuine attack produces one alert + one PDF.
"""

from __future__ import annotations

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
        loss_streak_required: int = 2,
        clear_streak_required: int = 3,
        cleared: Optional[Callable[[], None]] = None,
    ):
        self._traffic_monitor = traffic_monitor
        self._heartbeat = heartbeat
        self._callback = callback
        self._cleared_callback = cleared

        self._warmup = warmup
        self._check_interval = check_interval
        self._rate_threshold = rate_threshold
        self._loss_threshold = loss_threshold
        self._delay_threshold = delay_threshold

        # Streak gating — values <1 are coerced to 1 so the detector
        # always requires at least one bad window to fire and one good
        # window to clear (matches the pre-streak behaviour).
        self._loss_streak_required = max(1, int(loss_streak_required))
        self._clear_streak_required = max(1, int(clear_streak_required))

        # Detection flag — set on transition to "attack", cleared on a
        # run of clean windows so a subsequent attack can re-fire.
        self.detected = threading.Event()

        # Streak counters (reset on every set/clear transition).
        self._consecutive_bad: int = 0
        self._consecutive_good: int = 0

        # Internal
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self.detected.clear()
        self._consecutive_bad = 0
        self._consecutive_good = 0
        self._start_time = time.monotonic()

        self._thread = threading.Thread(
            target=self._check_loop, daemon=True, name="ddos-detector"
        )
        self._thread.start()
        logger.info(
            "DDoSDetector started (warmup=%.0fs, interval=%.0fs, "
            "loss_streak=%d, clear_streak=%d)",
            self._warmup,
            self._check_interval,
            self._loss_streak_required,
            self._clear_streak_required,
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

            window_bad = rate_exceeded or loss_exceeded or delay_exceeded

            logger.info(
                "DDoS check: rate=%.2f Mbps (>%.1f? %s)  "
                "loss=%.2f%% (>%.1f%%? %s)  "
                "rtt=%.1f ms (>%.0f ms? %s)  "
                "[bad=%d/%d, good=%d/%d, detected=%s]",
                rate_bps / 1e6,
                self._rate_threshold / 1e6,
                rate_exceeded,
                loss * 100,
                self._loss_threshold * 100,
                loss_exceeded,
                avg_rtt * 1000,
                self._delay_threshold * 1000,
                delay_exceeded,
                # streak counters reflect the state BEFORE this window;
                # show the "would-be" target streak each time so the
                # operator can see how close we are to fire/clear.
                self._consecutive_bad,
                self._loss_streak_required,
                self._consecutive_good,
                self._clear_streak_required,
                self.detected.is_set(),
            )

            # ----------------------------------------------------------
            # Update streak counters.  We track both regardless of which
            # state we are in so the transition logic below is simple.
            # ----------------------------------------------------------
            if window_bad:
                self._consecutive_bad += 1
                self._consecutive_good = 0
            else:
                self._consecutive_good += 1
                self._consecutive_bad = 0

            # ----------------------------------------------------------
            # CLEAR PATH — already detected, watching for clean windows.
            # ----------------------------------------------------------
            if self.detected.is_set():
                if self._consecutive_good >= self._clear_streak_required:
                    self.detected.clear()
                    # Reset bad streak too so the next bad window starts
                    # fresh — otherwise a transient blip during recovery
                    # would carry over.
                    self._consecutive_bad = 0
                    self._consecutive_good = 0
                    logger.info(
                        "DDoS state CLEARED after %d clean windows",
                        self._clear_streak_required,
                    )
                    if self._cleared_callback:
                        try:
                            self._cleared_callback()
                        except Exception:
                            logger.exception("DDoS cleared callback error")
                continue

            # ----------------------------------------------------------
            # DETECT PATH — not yet detected, watching for bad streak.
            # ANY mode (smart-bus.cc line 1187) but gated by streak.
            # ----------------------------------------------------------
            if window_bad and self._consecutive_bad >= self._loss_streak_required:
                self.detected.set()
                # Reset good streak so the clear path waits for a fresh
                # run of clean windows.
                self._consecutive_good = 0
                details: Dict[str, Any] = {
                    "type": "ddos",
                    "timestamp": time.time(),
                    "rate_bps": rate_bps,
                    "loss_pct": loss,
                    "rtt_ms": avg_rtt * 1000,
                    "trigger_rate": rate_exceeded,
                    "trigger_loss": loss_exceeded,
                    "trigger_delay": delay_exceeded,
                    "bad_streak": self._consecutive_bad,
                }
                logger.warning(
                    "[DDoS DETECTED] rate=%.2f Mbps  loss=%.2f%%  "
                    "rtt=%.1f ms  (after %d consecutive bad windows)",
                    rate_bps / 1e6,
                    loss * 100,
                    avg_rtt * 1000,
                    self._consecutive_bad,
                )
                if self._callback:
                    try:
                        self._callback(details)
                    except Exception:
                        logger.exception("DDoS callback error")
