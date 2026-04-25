#!/usr/bin/env python3
"""Local GPS spoof injector — simulates an on-bus RF spoofer.

Writes a JSON file the running BusAgent's ``GpsTelemetry`` watches.
While the file is present and unexpired the GPS generator overrides
its WaypointMobilityModel position with the fake one for every
outgoing packet, so the edge detector (and the server) see the bus
reporting an impossible location.

Usage:
    # 12-second spoof at fake position (14000, 1000) — ~6.5 km off route 0
    python -m jetson.spoof_local --duration 12

    # Custom coords + duration
    python -m jetson.spoof_local --x 0 --y 0 --duration 8

    # Cancel an active spoof immediately
    python -m jetson.spoof_local --clear
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

DEFAULT_FILE = "/tmp/smartbus-spoof.json"

logger = logging.getLogger("jetson.spoof_local")


def write_spoof(path: str, pos_x: float, pos_y: float, duration: float) -> float:
    expires_at = time.time() + duration
    payload = {"pos_x": float(pos_x), "pos_y": float(pos_y), "expires_at": expires_at}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(payload, f)
    os.replace(tmp, path)
    return expires_at


def clear_spoof(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--x", type=float, default=14000.0, help="Fake X (m). Default 14000.")
    p.add_argument("--y", type=float, default=1000.0, help="Fake Y (m). Default 1000.")
    p.add_argument("--duration", type=float, default=12.0,
                   help="Seconds to inject. Default 12.")
    p.add_argument("--file", default=DEFAULT_FILE,
                   help=f"Spoof state file (default {DEFAULT_FILE}).")
    p.add_argument("--clear", action="store_true",
                   help="Cancel any active spoof and exit.")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.clear:
        removed = clear_spoof(args.file)
        print("Cleared." if removed else "No active spoof.")
        return

    expires_at = write_spoof(args.file, args.x, args.y, args.duration)
    print(f"Spoof active: pos=({args.x:g}, {args.y:g})  for {args.duration:.1f}s "
          f"(expires at {time.strftime('%H:%M:%S', time.localtime(expires_at))})")
    print(f"State file: {args.file}")
    print("Waiting for spoof to expire (Ctrl+C to leave it active and exit)...")

    try:
        while time.time() < expires_at:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nLeaving spoof file in place; expires on its own.")
        return

    # Cleanup the file even though it's expired — the GPS generator
    # already ignores expired entries, but a stale file is noise.
    if clear_spoof(args.file):
        print("Spoof window ended; state file removed.")
    else:
        print("Spoof window ended; state file already gone.")


if __name__ == "__main__":
    main()
