#!/usr/bin/env python3
"""BusAgent — Jetson edge device orchestrator (internet-facing build).

Starts WebSocket/HTTPS telemetry, local DDoS detection, heartbeat probe,
forensic PDF capture + HTTPS upload, Telegram alerts, and CSV logging.
GPS spoof detection has moved to the server (public ingestion endpoint),
so the Jetson no longer runs a local GPS detector.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jetson.alerting.csv_logger import CSVLogger
from jetson.alerting.telegram_bot import TelegramAlert
from jetson.camera.camera_factory import create_camera
from jetson.config_loader import Config
from jetson.detection.ddos_detector import DDoSDetector
from jetson.detection.heartbeat import HeartbeatProbe
from jetson.forensic.evidence_capture import capture_evidence
from jetson.forensic.evidence_upload import upload_evidence
from jetson.network.offline_queue import OfflineQueue
from jetson.network.traffic_monitor import TrafficMonitor
from jetson.routes import create_routes, get_bus_route_assignment
from jetson.traffic.cctv_stream import CCTVStream
from jetson.traffic.gps_telemetry import GpsTelemetry
from jetson.traffic.ticketing import TicketingClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-22s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("jetson.main")

BANNER = r"""
======================================================
  Al-Ahsa Smart Bus System — Jetson Edge Device
  Bus Node: Real-time detection & forensic response
  Internet build: Cloudflare tunnel transport
======================================================
"""


class BusAgent:
    """Orchestrates all subsystems on a bus."""

    def __init__(self, config_path: str = "config.ini") -> None:
        self.config = Config(config_path)
        self.stop_event = threading.Event()
        self.ddos_detected = threading.Event()
        self.forensic_triggered = threading.Event()
        self._detection_details: Dict[str, Any] = {}
        self._components = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        print(BANNER)
        cfg = self.config

        logger.info("bus_id=%d server=%s interface=%s",
                    cfg.bus_id, cfg.server_url, cfg.interface)

        self.csv_logger = CSVLogger(log_dir=cfg.log_dir)

        self.telegram = TelegramAlert(
            bot_token=cfg.telegram_bot_token,
            chat_id=cfg.telegram_chat_id,
            enabled=cfg.telegram_enabled,
        )

        self.camera = create_camera(
            use_real_camera=cfg.use_real_camera,
            width=cfg.camera_width,
            height=cfg.camera_height,
        )

        self.offline_queue = OfflineQueue(cfg.offline_db_path)

        # Mobility route for this bus.
        assignment = get_bus_route_assignment()
        route_idx = assignment[cfg.bus_id] if cfg.bus_id < len(assignment) else 0
        routes = create_routes()
        self._route_polyline = routes[route_idx]

        # Traffic generators
        self.gps = GpsTelemetry(
            server_url=cfg.server_url,
            bus_id=cfg.bus_id,
            route_waypoints=self._route_polyline,
            send_interval=cfg.gps_interval_s,
        )
        self.gps.start()

        self.cctv = CCTVStream(
            server_url=cfg.server_url,
            bus_id=cfg.bus_id,
            camera_device=None,  # Real frames come through self.camera/PDF
        )
        self.cctv.start()

        self.ticketing = TicketingClient(
            server_url=cfg.server_url,
            bus_id=cfg.bus_id,
        )
        self.ticketing.start()

        # Heartbeat (HTTPS)
        self.heartbeat = HeartbeatProbe(
            server_url=cfg.server_url,
            bus_id=cfg.bus_id,
        )
        self.heartbeat.start()

        # Local DDoS detection uses interface rx_bytes + heartbeat loss/RTT
        self.traffic_monitor = TrafficMonitor(interface=cfg.interface)
        self.traffic_monitor.start()

        # Streak gating — read directly via the raw getint accessor so
        # we don't have to add a typed property for two rarely-tuned
        # knobs.  Defaults match DDoSDetector's own.
        loss_streak = cfg.getint(
            "thresholds", "ddos_loss_streak", fallback=2
        )
        clear_streak = cfg.getint(
            "thresholds", "ddos_clear_streak", fallback=3
        )

        self.ddos_detector = DDoSDetector(
            traffic_monitor=self.traffic_monitor,
            heartbeat=self.heartbeat,
            callback=self._on_ddos_detected,
            rate_threshold=cfg.ddos_rate_bps,
            loss_threshold=cfg.ddos_loss_pct,
            delay_threshold=cfg.ddos_delay_s,
            check_interval=cfg.ddos_check_interval_s,
            warmup=cfg.warmup_time_s,
            loss_streak_required=loss_streak,
            clear_streak_required=clear_streak,
            cleared=self._on_ddos_cleared,
        )
        self.ddos_detector.start()
        # Mirror the detector's own `detected` Event into ours for the
        # forensic-trigger loop.
        self.ddos_detected = self.ddos_detector.detected

        # Forensic trigger + offline flusher
        threading.Thread(
            target=self._forensic_trigger_loop,
            name="Forensic-Trigger",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._offline_flusher_loop,
            name="Offline-Flusher",
            daemon=True,
        ).start()

        logger.info("all subsystems started; warmup=%ds", int(cfg.warmup_time_s))
        logger.info("press Ctrl+C to stop.")

    def shutdown(self) -> None:
        logger.info("shutting down...")
        self.stop_event.set()
        for name in ("gps", "cctv", "ticketing", "heartbeat", "traffic_monitor",
                     "ddos_detector"):
            comp = getattr(self, name, None)
            if comp is not None and hasattr(comp, "stop"):
                try:
                    comp.stop()
                except Exception:
                    logger.exception("error stopping %s", name)
        try:
            self.offline_queue.close()
        except Exception:
            pass
        logger.info("shutdown complete")

    def run_forever(self) -> None:
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(timeout=5.0)
                if self.stop_event.is_set():
                    break
                status = "IDLE"
                if self.ddos_detected.is_set():
                    status = "DDoS DETECTED"
                queued = self.offline_queue.size()
                logger.info(
                    "status=%s | queue events=%d forensics=%d",
                    status, queued["events"], queued["forensics"],
                )
        except KeyboardInterrupt:
            pass

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_ddos_detected(self, details: Dict[str, Any]) -> None:
        self._detection_details["ddos"] = details
        bus_id = self.config.bus_id
        logger.warning("*** DDoS DETECTED ***")
        logger.warning("  rate=%.1f Mbps loss=%.1f%% rtt=%.1f ms",
                       details.get("rate_bps", 0) / 1e6,
                       details.get("loss_pct", 0) * 100,
                       details.get("rtt_ms", 0))
        self.csv_logger.log_event(
            bus_id, "ddos_detect",
            value1=details.get("rate_bps", 0) / 1e6,
            value2=details.get("loss_pct", 0) * 100,
            detail=f"rtt={details.get('rtt_ms', 0):.1f}ms",
        )
        try:
            self.telegram.send_ddos_alert({**details, "bus_id": bus_id})
        except Exception:
            logger.exception("telegram ddos alert failed")

    def _on_ddos_cleared(self) -> None:
        """Re-arm the forensic latch after the DDoS state clears.

        Fired by DDoSDetector once it has seen ``clear_streak_required``
        consecutive clean windows.  Without this, ``forensic_triggered``
        would stay set forever and a future genuine attack would never
        produce a new PDF.
        """
        self.forensic_triggered.clear()
        # Also drop the cached detection details so the next PDF reflects
        # the new attack, not the old one.
        self._detection_details.pop("ddos", None)
        logger.info("Forensic re-armed")

    # ------------------------------------------------------------------
    # Forensic and offline-queue loops
    # ------------------------------------------------------------------

    def _forensic_trigger_loop(self) -> None:
        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=2.0)
            if self.forensic_triggered.is_set():
                continue
            if not self.ddos_detected.is_set():
                continue

            self.forensic_triggered.set()
            attack_type = "ddos"
            logger.info("forensic trigger: %s — capturing evidence", attack_type)
            trigger_time = time.time()

            try:
                pdf_bytes, metadata = capture_evidence(
                    self.camera, self.csv_logger,
                    bus_id=self.config.bus_id,
                    attack_type=attack_type,
                    detection_details=self._detection_details.get(attack_type),
                    gps_trace=self.gps.get_recent_trace(),
                    route_polyline=list(self._route_polyline),
                )
            except Exception:
                logger.exception("capture_evidence failed")
                continue

            result = upload_evidence(
                pdf_bytes, metadata, server_url=self.config.server_url
            )

            if result["completed"]:
                logger.info(
                    "forensic upload complete: %d bytes in %.2fs",
                    result["bytes_sent"],
                    result["upload_finish"] - result["upload_start"],
                )
            else:
                logger.error("forensic upload failed; queueing for retry")
                try:
                    self.offline_queue.enqueue_forensic(metadata, pdf_bytes)
                except Exception:
                    logger.exception("failed to enqueue forensic")

            self.csv_logger.log_forensic(
                trigger_time=trigger_time,
                bus_id=self.config.bus_id,
                attack_type=attack_type,
                upload_start=result["upload_start"],
                upload_finish=result["upload_finish"],
                completed=result["completed"],
                bytes_received=result["bytes_sent"],
            )

    def _offline_flusher_loop(self) -> None:
        """Periodically flush queued forensics after a prior upload failure."""
        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=30.0)
            if self.stop_event.is_set():
                break
            batch = self.offline_queue.peek_batch("forensic", limit=5)
            for row in batch:
                try:
                    with open(row["pdf_path"], "rb") as f:
                        pdf_bytes = f.read()
                except OSError:
                    logger.warning("queued pdf missing: %s", row["pdf_path"])
                    self.offline_queue.ack("forensic", row["id"])
                    continue
                res = upload_evidence(
                    pdf_bytes, row["metadata"], server_url=self.config.server_url
                )
                if res["completed"]:
                    self.offline_queue.ack("forensic", row["id"])
                    logger.info("flushed queued forensic id=%d", row["id"])
                else:
                    logger.info("flush failed id=%d; will retry later", row["id"])
                    break  # don't hammer on outage; try again next tick


def main() -> None:
    parser = argparse.ArgumentParser(description="Smart Bus Jetson Agent")
    parser.add_argument("--config", default="config.ini")
    args = parser.parse_args()

    agent = BusAgent(config_path=args.config)

    def _handle(_signum, _frame):
        agent.shutdown()

    signal.signal(signal.SIGINT, _handle)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle)

    agent.start()
    agent.run_forever()
    agent.shutdown()


if __name__ == "__main__":
    main()
