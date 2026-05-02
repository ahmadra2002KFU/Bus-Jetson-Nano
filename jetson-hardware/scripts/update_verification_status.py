#!/usr/bin/env python3
"""Update PENDING rows in forensics_metrics.csv with the live /verify result.

For each row whose ``integrity_verification`` is "PENDING", hit
``GET <server>/verify/<incident_id>`` and rewrite the row in place with
"PASS" or "FAIL" based on the JSON ``verified`` field.

Usage:
    python scripts/update_verification_status.py [csv_path] [--server URL]

Defaults:
    csv_path = ./logs/forensics_metrics.csv
    server   = value of $SERVER_URL or https://jetson.testingdomainzforprototypes.website
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_CSV = os.path.join("logs", "forensics_metrics.csv")
DEFAULT_SERVER = os.environ.get(
    "SERVER_URL", "https://jetson.testingdomainzforprototypes.website"
)


def query_verify(server: str, incident_id: str, timeout: float = 10.0) -> str:
    """Return 'PASS', 'FAIL', or 'ERROR' for one incident."""
    url = f"{server.rstrip('/')}/verify/{incident_id}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = json.loads(resp.read())
        return "PASS" if body.get("verified") else "FAIL"
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        print(f"  WARN: verify failed for {incident_id}: {exc}", file=sys.stderr)
        return "ERROR"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv_path", nargs="?", default=DEFAULT_CSV)
    ap.add_argument("--server", default=DEFAULT_SERVER)
    args = ap.parse_args()

    if not os.path.isfile(args.csv_path):
        print(f"ERROR: not found: {args.csv_path}", file=sys.stderr)
        return 2

    with open(args.csv_path, "r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("forensics_metrics.csv is empty; nothing to update.")
        return 0

    fieldnames = list(rows[0].keys())
    pending = [r for r in rows if r.get("integrity_verification") == "PENDING"]
    print(f"Found {len(pending)} PENDING row(s) of {len(rows)} total.")

    updated = 0
    for r in pending:
        incident_id = r.get("incident_id", "").strip()
        if not incident_id:
            continue
        print(f"  -> verifying {incident_id} ...", end=" ", flush=True)
        verdict = query_verify(args.server, incident_id)
        r["integrity_verification"] = verdict
        print(verdict)
        if verdict in ("PASS", "FAIL"):
            updated += 1

    with open(args.csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Updated {updated} row(s) in {args.csv_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
