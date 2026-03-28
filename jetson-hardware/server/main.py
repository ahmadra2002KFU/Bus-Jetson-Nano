#!/usr/bin/env python3
"""Server main — starts all receiver services for the Smart Bus system."""

import argparse
import logging
import os
import signal
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server.gps_receiver import GpsReceiver
from server.cctv_receiver import CctvReceiver
from server.ticketing_receiver import TicketingReceiver
from server.forensic_receiver import ForensicReceiver
from server.heartbeat_server import HeartbeatServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)-20s] %(levelname)s  %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('server.main')

BANNER = r"""
======================================================
  Al-Ahsa Smart Bus System — Server
  Listening for bus traffic on all ports
======================================================
"""


def main():
    parser = argparse.ArgumentParser(description='Smart Bus Server')
    parser.add_argument('--bind', default='0.0.0.0', help='Bind address')
    parser.add_argument('--evidence-dir', default='evidence',
                        help='Directory for forensic evidence files')
    parser.add_argument('--log-dir', default='server_logs',
                        help='Directory for server logs')
    args = parser.parse_args()

    print(BANNER)

    os.makedirs(args.evidence_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)

    stop_event = threading.Event()

    # Create all receivers
    services = []

    gps = GpsReceiver(bind_ip=args.bind, bind_port=5000)
    services.append(('GPS Receiver :5000', gps))

    cctv = CctvReceiver(bind_ip=args.bind, bind_port=6000)
    services.append(('CCTV Receiver :6000', cctv))

    ticketing = TicketingReceiver(bind_ip=args.bind, bind_port=7000)
    services.append(('Ticketing Receiver :7000', ticketing))

    forensic = ForensicReceiver(bind_ip=args.bind, bind_port=8000,
                                output_dir=args.evidence_dir)
    services.append(('Forensic Receiver :8000', forensic))

    heartbeat = HeartbeatServer(bind_ip=args.bind, bind_port=5001)
    services.append(('Heartbeat Echo :5001', heartbeat))

    # Start all services
    threads = []
    for name, service in services:
        t = threading.Thread(target=service.run, name=name, daemon=True)
        t.start()
        threads.append(t)
        logger.info("Started %s", name)

    # Handle Ctrl+C
    def shutdown(signum, frame):
        logger.info("Shutting down...")
        stop_event.set()
        for _, service in services:
            try:
                service.stop()
            except Exception:
                pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Server ready. Press Ctrl+C to stop.")
    print()

    # Status loop
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=10)
            if not stop_event.is_set():
                # Print status summary
                stats = []
                if hasattr(gps, 'packet_count'):
                    stats.append(f"GPS: {gps.packet_count} pkts")
                if hasattr(cctv, 'total_bytes'):
                    mbps = cctv.total_bytes * 8 / max(1, cctv.elapsed()) / 1e6
                    stats.append(f"CCTV: {mbps:.1f} Mbps")
                if hasattr(heartbeat, 'echo_count'):
                    stats.append(f"HB: {heartbeat.echo_count} echoes")
                if stats:
                    logger.info("Status: %s", " | ".join(stats))
    except KeyboardInterrupt:
        shutdown(None, None)

    logger.info("Server stopped.")


if __name__ == '__main__':
    main()
