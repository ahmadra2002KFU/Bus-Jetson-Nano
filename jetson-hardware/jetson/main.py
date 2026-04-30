#!/usr/bin/env python3
"""BusAgent — Jetson edge device orchestrator (internet-facing build).

Starts WebSocket/HTTPS telemetry, local DDoS detection, edge-side GPS
spoof detection (against the bus's own outgoing positions), heartbeat
probe, forensic PDF capture + HTTPS upload, Telegram alerts, and CSV
logging.

Edge-side spoof detection complements the server's. If an RF spoofer
near the bus hijacks the GPS receiver, the bus reports a fake position;
the server eventually catches that, but the edge detector catches it
first and ships a forensic PDF with a real camera frame attached. The
on-bus spoof can be exercised via ``python -m jetson.spoof_local``.
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
from jetson.config_loader import Config
from jetson.detection.ddos_detector import DDoSDetector
from jetson.detection.edge_gps_detector import EdgeGpsDetector
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
        self.gps_detected = threading.Event()
        # Per-attack-type latches so a DDoS PDF doesn't block a later GPS
        # spoof PDF (and vice versa).
        self._latch_lock = threading.Lock()
        self._latched: Dict[str, bool] = {"ddos": False, "gps_spoof": False}
        self._detection_details: Dict[str, Any] = {}

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

        self.offline_queue = OfflineQueue(cfg.offline_db_path)

        # Mobility route for this bus.
        assignment = get_bus_route_assignment()
        route_idx = assignment[cfg.bus_id] if cfg.bus_id < len(assignment) else 0
        routes = create_routes()
        self._route_polyline = routes[route_idx]

        # Edge GPS detector (set up before GPS telemetry so we can hand
        # it the outgoing-position callback).
        spoof_file = cfg.get("edge_gps", "spoof_file",
                             fallback="/tmp/smartbus-spoof.json")
        self.gps_detector = EdgeGpsDetector(
            bus_id=cfg.bus_id,
            route_polyline=self._route_polyline,
            callback=self._on_gps_spoof_detected,
            cleared=self._on_gps_spoof_cleared,
            speed_threshold=cfg.gps_speed_ms,
            jump_threshold=cfg.gps_jump_m,
            corridor_threshold=cfg.gps_corridor_m,
            streak_required=cfg.gps_streak_required,
        )
        self.gps_detected = self.gps_detector.detected

        # Traffic generators
        self.gps = GpsTelemetry(
            server_url=cfg.server_url,
            bus_id=cfg.bus_id,
            route_waypoints=self._route_polyline,
            send_interval=cfg.gps_interval_s,
            on_send_position=self._on_gps_position_sent,
            spoof_file=spoof_file,
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

        loss_streak = cfg.getint("thresholds", "ddos_loss_streak", fallback=2)
        clear_streak = cfg.getint("thresholds", "ddos_clear_streak", fallback=3)

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
        self.ddos_detected = self.ddos_detector.detected

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
                flags = []
                if self.ddos_detected.is_set(): flags.append("DDoS")
                if self.gps_detected.is_set():  flags.append("GPS-SPOOF")
                status = " + ".join(flags) if flags else "IDLE"
                queued = self.offline_queue.size()
                logger.info(
                    "status=%s | queue events=%d forensics=%d",
                    status, queued["events"], queued["forensics"],
                )
        except KeyboardInterrupt:
            pass

    # ------------------------------------------------------------------
    # Detection callbacks
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
        with self._latch_lock:
            self._latched["ddos"] = False
        self._detection_details.pop("ddos", None)
        logger.info("Forensic re-armed (ddos)")

    def _on_gps_spoof_detected(self, details: Dict[str, Any]) -> None:
        self._detection_details["gps_spoof"] = details
        bus_id = self.config.bus_id
        logger.warning("*** EDGE GPS SPOOF DETECTED ***")
        logger.warning("  speed=%.1f m/s  corridor=%.0f m  streak=%d",
                       details.get("speed", 0),
                       details.get("corridor_dist", 0),
                       details.get("streak", 0))
        self.csv_logger.log_event(
            bus_id, "gps_spoof_detect",
            value1=details.get("speed", 0),
            value2=details.get("corridor_dist", 0),
            detail=f"streak={details.get('streak', 0)}",
        )
        try:
            self.telegram.send_gps_alert({**details, "bus_id": bus_id})
        except Exception:
            logger.exception("telegram gps alert failed")

    def _on_gps_spoof_cleared(self) -> None:
        with self._latch_lock:
            self._latched["gps_spoof"] = False
        self._detection_details.pop("gps_spoof", None)
        # Drop the detector's last position so the next legit reading
        # initialises cleanly (avoids a transient speed_anom on resume).
        try:
            self.gps_detector.reset()
        except Exception:
            pass
        logger.info("Forensic re-armed (gps_spoof)")

    def _on_gps_position_sent(self, pos_x: float, pos_y: float, is_spoofed: bool) -> None:
        """Hook GpsTelemetry calls after each outbound packet so the
        edge detector sees the same positions the server sees."""
        try:
            self.gps_detector.feed(pos_x, pos_y)
        except Exception:
            logger.exception("edge GPS detector feed failed")

    # ------------------------------------------------------------------
    # Forensic and offline-queue loops
    # ------------------------------------------------------------------

    def _forensic_trigger_loop(self) -> None:
        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=2.0)
            if self.stop_event.is_set():
                break
            # Fire DDoS path
            if self.ddos_detected.is_set() and not self._is_latched("ddos"):
                self._set_latched("ddos")
                self._fire_forensic("ddos")
            # Fire GPS-spoof path
            if self.gps_detected.is_set() and not self._is_latched("gps_spoof"):
                self._set_latched("gps_spoof")
                self._fire_forensic("gps_spoof")

    def _is_latched(self, kind: str) -> bool:
        with self._latch_lock:
            return self._latched.get(kind, False)

    def _set_latched(self, kind: str) -> None:
        with self._latch_lock:
            self._latched[kind] = True

    def _fire_forensic(self, attack_type: str) -> None:
        logger.info("forensic trigger: %s — capturing evidence", attack_type)
        trigger_time = time.time()
        try:
            pdf_bytes, metadata = capture_evidence(
                None, self.csv_logger,
                bus_id=self.config.bus_id,
                attack_type=attack_type,
                detection_details=self._detection_details.get(attack_type),
                gps_trace=self.gps.get_recent_trace(),
                route_polyline=list(self._route_polyline),
            )
        except Exception:
            logger.exception("capture_evidence failed (%s)", attack_type)
            return

        # Two-stage Telegram flow:
        #   Stage 1 (already happened ~2 s ago): _on_ddos_detected /
        #     _on_gps_spoof_detected fired the moment the detector latched
        #     and pushed a text-only alert via send_ddos_alert /
        #     send_gps_alert. That gives the operator immediate awareness.
        #   Stage 2 (here): now that capture_evidence has produced the PDF,
        #     ship it as a follow-up document so the operator has the full
        #     forensic report in-chat without waiting for the server.
        # Telegram failures must NOT block the server upload below, so this
        # is wrapped in its own try/except.
        bus_id = self.config.bus_id
        pdf_filename = f"incident_bus{bus_id}_{attack_type}_{int(trigger_time)}.pdf"
        pdf_caption = (
            f"*Forensic Report*\n"
            f"Attack: `{attack_type}`\n"
            f"Bus: `{bus_id}`\n"
            f"Trigger: `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(trigger_time))}`"
        )
        try:
            tg_ok = self.telegram.send_document(
                pdf_bytes, filename=pdf_filename, caption=pdf_caption,
            )
            if tg_ok:
                logger.info("forensic PDF pushed to Telegram (%s, %d bytes)",
                            pdf_filename, len(pdf_bytes))
            else:
                logger.warning("forensic PDF Telegram send returned False (%s)",
                               attack_type)
        except Exception:
            logger.exception("telegram send_document failed (%s) — continuing to server upload",
                             attack_type)

        result = upload_evidence(
            pdf_bytes, metadata, server_url=self.config.server_url,
        )
        if result["completed"]:
            logger.info(
                "forensic upload complete (%s): %d bytes in %.2fs",
                attack_type, result["bytes_sent"],
                result["upload_finish"] - result["upload_start"],
            )
        else:
            logger.error("forensic upload failed (%s); queueing for retry", attack_type)
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
                    pdf_bytes, row["metadata"], server_url=self.config.server_url,
                )
                if res["completed"]:
                    self.offline_queue.ack("forensic", row["id"])
                    logger.info("flushed queued forensic id=%d", row["id"])
                else:
                    logger.info("flush failed id=%d; will retry later", row["id"])
                    break


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
