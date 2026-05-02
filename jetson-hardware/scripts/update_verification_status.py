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


# Cloudflare's WAF (rule 1010) returns 403 for the default Python-urllib UA;
# we send a normal browser-like UA so the call reaches the FastAPI origin.
USER_AGENT = "Mozilla/5.0 (compatible; jetson-m4-verify/1.0)"


def _http_get(url: str, timeout: float = 10.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


_forensic_index_cache = None  # type: ignore[var-annotated]

# Tolerance for matching CSV trigger_ts to server ts. The agent captures
# trigger_ts and the upload-side ts at slightly different moments, so they
# can drift by under a millisecond. 1 second is generous yet still well
# below the inter-incident gap (≥45s) so the nearest match is unambiguous.
TS_TOLERANCE_S = 1.0


def _load_forensic_index(server: str, timeout: float = 10.0):
    """Fetch /api/forensics and cache it as a list of (bus_id, ts, id)."""
    global _forensic_index_cache
    if _forensic_index_cache is not None:
        return _forensic_index_cache
    url = f"{server.rstrip('/')}/api/forensics"
    rows = json.loads(_http_get(url, timeout))
    _forensic_index_cache = [
        (int(r["bus_id"]), float(r["ts"]), int(r["id"])) for r in rows
    ]
    return _forensic_index_cache


def _resolve_forensic_id(index, bus_id: int, trigger_ts: float):
    """Return the forensic_id whose (bus_id, ts) is closest to the trigger,
    within TS_TOLERANCE_S, or None."""
    best = None  # (abs_dt, fid)
    for srv_bus, srv_ts, fid in index:
        if srv_bus != bus_id:
            continue
        dt = abs(srv_ts - trigger_ts)
        if dt <= TS_TOLERANCE_S and (best is None or dt < best[0]):
            best = (dt, fid)
    return None if best is None else best[1]


def query_verify(
    server: str,
    incident_id: str,
    *,
    bus_id: int,
    trigger_ts: float,
    timeout: float = 10.0,
) -> str:
    """Return 'PASS', 'FAIL', or 'ERROR' for one incident.

    The server's /verify endpoint is keyed by integer forensic_id (DB PK),
    not by the textual incident_id. We resolve forensic_id by matching
    (bus_id, trigger_ts) against /api/forensics.
    """
    try:
        index = _load_forensic_index(server, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        print(f"  WARN: /api/forensics lookup failed: {exc}", file=sys.stderr)
        return "ERROR"

    forensic_id = _resolve_forensic_id(index, int(bus_id), float(trigger_ts))
    if forensic_id is None:
        print(
            f"  WARN: no forensic_id for {incident_id} "
            f"(bus={bus_id} ts={trigger_ts:.3f})",
            file=sys.stderr,
        )
        return "ERROR"

    url = f"{server.rstrip('/')}/verify/{forensic_id}"
    try:
        body = json.loads(_http_get(url, timeout))
        return "PASS" if body.get("verified") else "FAIL"
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        print(
            f"  WARN: verify failed for {incident_id} "
            f"(forensic_id={forensic_id}): {exc}",
            file=sys.stderr,
        )
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
        try:
            bus_id = int(r.get("bus_id", "0"))
            trigger_ts = float(r.get("trigger_ts", "0"))
        except ValueError:
            print("ERROR (bad CSV row)")
            r["integrity_verification"] = "ERROR"
            continue
        verdict = query_verify(
            args.server, incident_id, bus_id=bus_id, trigger_ts=trigger_ts
        )
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
