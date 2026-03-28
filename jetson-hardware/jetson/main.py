#!/usr/bin/env python3
"""Jetson main — orchestrates all bus subsystems.

Starts traffic generators, detection engines, and forensic response.
This is the entry point for the Jetson Orin Nano edge device.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from jetson.config_loader import Config
from jetson.camera.camera_factory import create_camera
from jetson.alerting.csv_logger import CSVLogger
from jetson.alerting.telegram_bot import TelegramAlert
from jetson.traffic.gps_telemetry import GpsTelemetryGenerator
from jetson.traffic.cctv_stream import CctvStreamGenerator
from jetson.traffic.ticketing import TicketingGenerator
from jetson.detection.heartbeat import HeartbeatProbe
from jetson.detection.ddos_detector import DDoSDetector
from jetson.detection.gps_detector import GpsDetector
from jetson.network.traffic_monitor import TrafficMonitor
from jetson.forensic.evidence_capture import capture_evidence
from jetson.forensic.evidence_upload import upload_evidence
from jetson.routes import create_routes, get_route_for_bus

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)-20s] %(levelname)s  %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('jetson.main')

BANNER = r"""
======================================================
  Al-Ahsa Smart Bus System — Jetson Edge Device
  Bus Node: Real-time detection & forensic response
======================================================
"""


class BusAgent:
    """Main orchestrator for the Jetson bus edge device."""

    def __init__(self, config_path='config.ini'):
        self.config = Config(config_path)
        self.stop_event = threading.Event()
        self.ddos_detected = threading.Event()
        self.gps_detected = threading.Event()
        self.forensic_triggered = threading.Event()
        self._detection_details = {}
        self._threads = []
        self._components = []

    def start(self):
        print(BANNER)
        cfg = self.config

        logger.info("Bus ID: %d", cfg.bus_id)
        logger.info("Server: %s", cfg.server_ip)
        logger.info("Interface: %s", cfg.lte_interface)

        # CSV Logger
        self.csv_logger = CSVLogger(log_dir="logs")
        self._components.append(('CSVLogger', self.csv_logger))

        # Telegram
        self.telegram = TelegramAlert(
            bot_token=cfg.telegram_bot_token,
            chat_id=cfg.telegram_chat_id,
        )

        # Camera
        self.camera = create_camera(
            use_real_camera=False,
            width=cfg.camera_frame_width,
            height=cfg.camera_frame_height,
            fps=cfg.camera_fps,
        )
        self._components.append(('Camera', self.camera))

        # Route waypoints for this bus
        routes = create_routes()
        route_index = get_route_for_bus(cfg.bus_id)
        waypoints = routes[route_index]

        # Traffic generators (Thread subclasses — use .start())
        self.gps = GpsTelemetryGenerator(
            server_ip=cfg.server_ip,
            bus_id=cfg.bus_id,
            route_waypoints=waypoints,
            server_port=cfg.telemetry_port,
            send_interval=cfg.gps_interval_s,
        )
        self.gps.start()
        logger.info("Started GPS-Telemetry")

        self.cctv = CctvStreamGenerator(
            server_ip=cfg.server_ip,
            bus_id=cfg.bus_id,
            server_port=cfg.cctv_port,
        )
        self.cctv.start()
        logger.info("Started CCTV-Stream")

        self.ticketing = TicketingGenerator(
            server_ip=cfg.server_ip,
            bus_id=cfg.bus_id,
            server_port=cfg.ticket_port,
        )
        self.ticketing.start()
        logger.info("Started Ticketing")

        # Monitoring (plain classes with .start() that spawn internal threads)
        self.traffic_monitor = TrafficMonitor(
            interface=cfg.lte_interface,
        )
        self.traffic_monitor.start()
        logger.info("Started Traffic-Monitor")

        self.heartbeat = HeartbeatProbe(
            server_ip=cfg.server_ip,
            server_port=5001,
        )
        self.heartbeat.start()
        logger.info("Started Heartbeat")

        # Detection engines
        self.ddos_detector = DDoSDetector(
            traffic_monitor=self.traffic_monitor,
            heartbeat=self.heartbeat,
            callback=self._on_ddos_detected,
            warmup=cfg.warmup_time_s,
            check_interval=cfg.ddos_check_interval_s,
            rate_threshold=cfg.ddos_rate_bps,
            loss_threshold=cfg.ddos_loss_pct,
            delay_threshold=cfg.ddos_delay_s,
        )
        self.ddos_detector.start()
        logger.info("Started DDoS-Detector")

        self.gps_detector = GpsDetector(
            listen_port=cfg.telemetry_port,
            callback=self._on_gps_detected,
            detection_mode=cfg.detection_mode,
            speed_threshold=cfg.gps_speed_ms,
            jump_threshold=cfg.gps_jump_m,
            corridor_threshold=cfg.gps_corridor_m,
            streak_required=cfg.gps_streak_required,
        )
        self.gps_detector.start()
        logger.info("Started GPS-Detector")

        # Forensic trigger poller
        t = threading.Thread(target=self._forensic_trigger_loop,
                             name='Forensic-Trigger', daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("Started Forensic-Trigger")

        logger.info("All subsystems started. Warmup: %ds", int(cfg.warmup_time_s))
        logger.info("Press Ctrl+C to stop.")
        print()

    def _on_ddos_detected(self, details):
        """Callback when DDoS is detected."""
        self.ddos_detected.set()
        self._detection_details['ddos'] = details
        bus_id = self.config.bus_id

        logger.warning("*** DDoS DETECTED ***")
        logger.warning("  Rate: %.1f Mbps", details.get('rate_bps', 0) / 1e6)
        logger.warning("  Loss: %.1f%%", details.get('loss_pct', 0) * 100)
        logger.warning("  RTT:  %.1f ms", details.get('rtt_ms', 0))

        self.csv_logger.log_event(
            bus_id, 'ddos_detect',
            value1=details.get('rate_bps', 0) / 1e6,
            value2=details.get('loss_pct', 0) * 100,
            detail=f"rtt={details.get('rtt_ms', 0):.1f}ms",
        )

        self.telegram.send_ddos_alert({**details, 'bus_id': bus_id})

    def _on_gps_detected(self, details):
        """Callback when GPS spoofing is detected."""
        self.gps_detected.set()
        self._detection_details['gps'] = details
        bus_id = details.get('bus_id', self.config.bus_id)

        logger.warning("*** GPS SPOOFING DETECTED ***")
        logger.warning("  Speed:    %.1f m/s", details.get('speed', 0))
        logger.warning("  Jump:     %.0f m", details.get('distance', 0))
        logger.warning("  Corridor: %.0f m", details.get('corridor_dist', 0))
        logger.warning("  Src IP:   %s", details.get('src_ip', 'unknown'))

        self.csv_logger.log_event(
            bus_id, 'gps_spoof_detect',
            value1=details.get('speed', 0),
            value2=details.get('corridor_dist', 0),
            detail=f"src={details.get('src_ip', '')}",
        )

        jpeg = self.camera.grab_jpeg() if self.camera else None
        self.telegram.send_gps_alert({**details, 'bus_id': bus_id}, jpeg)

    def _forensic_trigger_loop(self):
        """Polls detection flags every 2s and triggers forensic upload once."""
        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=2.0)

            if self.forensic_triggered.is_set():
                continue

            if self.ddos_detected.is_set() or self.gps_detected.is_set():
                self.forensic_triggered.set()
                attack_type = 'ddos' if self.ddos_detected.is_set() else 'gps_spoof'
                logger.info("Forensic trigger: %s — capturing evidence...",
                            attack_type)

                trigger_time = time.time()

                # Capture evidence
                evidence, _ = capture_evidence(
                    self.camera, self.csv_logger,
                    bus_id=self.config.bus_id,
                    attack_type=attack_type,
                )

                # Upload
                result = upload_evidence(
                    evidence, self.config.server_ip,
                    port=self.config.forensic_port,
                )

                # Log forensic event
                self.csv_logger.log_forensic(
                    trigger_time=trigger_time,
                    bus_id=self.config.bus_id,
                    attack_type=attack_type,
                    upload_start=result['upload_start'],
                    upload_finish=result['upload_finish'],
                    completed=result['completed'],
                    bytes_received=result['bytes_sent'],
                )

                if result['completed']:
                    logger.info("Forensic upload complete: %d bytes in %.1fs",
                                result['bytes_sent'],
                                result['upload_finish'] - result['upload_start'])
                else:
                    logger.error("Forensic upload failed")

    def run_forever(self):
        """Block until Ctrl+C."""
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(timeout=5.0)
                if not self.stop_event.is_set():
                    status = "IDLE"
                    if self.ddos_detected.is_set():
                        status = "DDoS DETECTED"
                    elif self.gps_detected.is_set():
                        status = "GPS SPOOF DETECTED"
                    logger.info("Status: %s | GPS sending | CCTV streaming",
                                status)
        except KeyboardInterrupt:
            pass

    def shutdown(self):
        logger.info("Shutting down...")
        self.stop_event.set()

        for _, comp in self._components:
            try:
                if hasattr(comp, 'stop'):
                    comp.stop()
            except Exception:
                pass

        for attr_name in ('gps', 'cctv', 'ticketing', 'traffic_monitor',
                          'heartbeat', 'ddos_detector', 'gps_detector'):
            comp = getattr(self, attr_name, None)
            if comp and hasattr(comp, 'stop'):
                try:
                    comp.stop()
                except Exception:
                    pass

        logger.info("All subsystems stopped.")


def main():
    parser = argparse.ArgumentParser(description='Smart Bus Jetson Agent')
    parser.add_argument('--config', default='config.ini',
                        help='Path to config.ini')
    args = parser.parse_args()

    agent = BusAgent(config_path=args.config)

    def handle_signal(signum, frame):
        agent.shutdown()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    agent.start()
    agent.run_forever()
    agent.shutdown()


if __name__ == '__main__':
    main()
