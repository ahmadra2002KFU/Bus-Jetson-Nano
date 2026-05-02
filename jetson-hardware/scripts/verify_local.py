#!/usr/bin/env python3
"""verify_local.py — pure-Python `sha256sum -c hash_manifest.txt` for INC_*/.

Usage:
    python verify_local.py <INC_folder>

Exit code: 0 if every file's sha256 matches the manifest, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import os
import sys


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_manifest(manifest_path: str) -> list[tuple[str, str]]:
    """Return list of (expected_sha256, filename) parsed from sha256sum format.

    Each line: `<64-hex>  <filename>` (two spaces in binary mode; one space +
    `*` prefix in some variants). We accept either.
    """
    entries: list[tuple[str, str]] = []
    with open(manifest_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            # split on first run of whitespace
            parts = line.split(None, 1)
            if len(parts) != 2 or len(parts[0]) != 64:
                print(f"FAIL  manifest parse error: {raw!r}")
                continue
            digest = parts[0].lower()
            name = parts[1].lstrip("*").strip()
            entries.append((digest, name))
    return entries


def verify_folder(folder: str) -> bool:
    manifest = os.path.join(folder, "hash_manifest.txt")
    if not os.path.isfile(manifest):
        print(f"FAIL  hash_manifest.txt not found in {folder}")
        return False

    entries = _parse_manifest(manifest)
    if not entries:
        print("FAIL  manifest is empty")
        return False

    all_ok = True
    for expected, name in entries:
        target = os.path.join(folder, name)
        if not os.path.isfile(target):
            print(f"FAIL  {name}: missing")
            all_ok = False
            continue
        actual = _sha256_file(target)
        if actual == expected:
            print(f"OK    {name}")
        else:
            print(f"FAIL  {name}: expected {expected} got {actual}")
            all_ok = False
    return all_ok


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_local.py <INC_folder>", file=sys.stderr)
        return 2
    ok = verify_folder(sys.argv[1])
    print("---")
    print("RESULT: OK" if ok else "RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
