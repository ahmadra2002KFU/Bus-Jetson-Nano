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
from jetson.traffic.gps_telemetry import GPSTelemetry
from jetson.traffic.cctv_stream import CCTVStream
from jetson.traffic.ticketing import TicketingClient
from jetson.detection.heartbeat import HeartbeatProbe
from jetson.detection.ddos_detector import DDoSDetector
from jetson.detection.gps_detector import GpsDetector
from jetson.network.traffic_monitor import TrafficMonitor
from jetson.forensic.evidence_capture import capture_evidence
from jetson.forensic.evidence_upload import upload_evidence

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
        logger.info("Interface: %s", cfg.interface)

        # CSV Logger
        self.csv_logger = CSVLogger(log_dir="logs")
        self._components.append(('CSVLogger', self.csv_logger))

        # Telegram
        self.telegram = TelegramAlert(
            bot_token=cfg.telegram_token,
            chat_id=cfg.telegram_chat_id,
            enabled=cfg.telegram_enabled,
        )

        # Camera
        self.camera = create_camera(
            use_real_camera=cfg.use_real_camera,
            width=cfg.camera_width,
            height=cfg.camera_height,
        )
        self._components.append(('Camera', self.camera))

        # Traffic generators
        self.gps = GPSTelemetry(
            server_ip=cfg.server_ip, port=cfg.telemetry_port,
            bus_id=cfg.bus_id, route_index=cfg.bus_route_index,
            interval=cfg.gps_interval,
        )
        self._start_thread('GPS-Telemetry', self.gps.run)

        self.cctv = CCTVStream(
            server_ip=cfg.server_ip, port=cfg.cctv_port,
            rate_kbps=cfg.cctv_rate_kbps, packet_size=cfg.cctv_packet_size,
        )
        self._start_thread('CCTV-Stream', self.cctv.run)

        self.ticketing = TicketingClient(
            server_ip=cfg.server_ip, port=cfg.ticketing_port,
            min_interval=cfg.ticket_min_interval,
            max_interval=cfg.ticket_max_interval,
            packet_size=cfg.ticket_packet_size,
            min_burst=cfg.ticket_min_burst,
            max_burst=cfg.ticket_max_burst,
        )
        self._start_thread('Ticketing', self.ticketing.run)

        # Monitoring
        self.traffic_monitor = TrafficMonitor(
            interface=cfg.interface,
            window_seconds=cfg.ddos_check_interval,
        )
        self._start_thread('Traffic-Monitor', self.traffic_monitor.run)

        self.heartbeat = HeartbeatProbe(
            server_ip=cfg.server_ip, port=cfg.heartbeat_port,
        )
        self._start_thread('Heartbeat', self.heartbeat.run)

        # Detection engines
        self.ddos_detector = DDoSDetector(
            traffic_monitor=self.traffic_monitor,
            heartbeat=self.heartbeat,
            detection_event=self.ddos_detected,
            callback=self._on_ddos_detected,
            rate_threshold=cfg.ddos_rate_bps,
            loss_threshold=cfg.ddos_loss_pct / 100.0,
            delay_threshold=cfg.ddos_delay_ms / 1000.0,
            check_interval=cfg.ddos_check_interval,
            warmup=cfg.ddos_warmup,
        )
        self._start_thread('DDoS-Detector', self.ddos_detector.run)

        self.gps_detector = GpsDetector(
            port=cfg.telemetry_port,
            bus_id=cfg.bus_id,
            route_index=cfg.bus_route_index,
            detection_event=self.gps_detected,
            callback=self._on_gps_detected,
        )
        self._start_thread('GPS-Detector', self.gps_detector.run)

        # Forensic trigger poller
        self._start_thread('Forensic-Trigger', self._forensic_trigger_loop)

        logger.info("All subsystems started. Warmup: %ds", int(cfg.ddos_warmup))
        logger.info("Press Ctrl+C to stop.")
        print()

    def _start_thread(self, name, target):
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("Started %s", name)

    def _on_ddos_detected(self, details):
        """Callback when DDoS is detected."""
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
