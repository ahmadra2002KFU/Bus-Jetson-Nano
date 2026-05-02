#!/usr/bin/env python3
"""tamper_test.py — supervisor TC6 tamper-detection test.

Steps:
    1. Copy a real INC_*/ folder to a temp dir.
    2. Flip one byte in edge_forensic_report.pdf.
    3. Run verify_local.py against the tampered copy.
    4. Assert verification fails AND the only failing file is the PDF.

Exit code 0 = PASS (tamper was detected, only on the PDF), 1 = FAIL.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: tamper_test.py <INC_folder>", file=sys.stderr)
        return 2

    src = os.path.abspath(sys.argv[1])
    if not os.path.isdir(src):
        print(f"FAIL  not a directory: {src}", file=sys.stderr)
        return 1

    here = os.path.dirname(os.path.abspath(__file__))
    verify_script = os.path.join(here, "verify_local.py")

    with tempfile.TemporaryDirectory(prefix="tamper_test_") as tmp:
        dst = os.path.join(tmp, os.path.basename(src))
        shutil.copytree(src, dst)
        target_file = "edge_forensic_report.pdf"
        target_path = os.path.join(dst, target_file)
        if not os.path.isfile(target_path):
            print(f"FAIL  no {target_file} in copy")
            return 1

        # Baseline: verify the copy passes before tampering.
        print("--- baseline verify (untampered copy) ---")
        baseline = subprocess.run(
            [sys.executable, verify_script, dst],
            capture_output=True, text=True,
        )
        sys.stdout.write(baseline.stdout)
        if baseline.returncode != 0:
            print("FAIL  baseline verification of untampered copy failed")
            return 1

        # Tamper: flip the last byte of the PDF (PDF readers tolerate trailing
        # garbage so the file remains "openable" but its sha256 is now wrong).
        with open(target_path, "rb") as f:
            data = bytearray(f.read())
        if not data:
            print("FAIL  PDF is empty")
            return 1
        data[-1] ^= 0xFF
        with open(target_path, "wb") as f:
            f.write(bytes(data))

        print(f"--- tampered byte -1 of {target_file}; re-verifying ---")
        result = subprocess.run(
            [sys.executable, verify_script, dst],
            capture_output=True, text=True,
        )
        out = result.stdout
        sys.stdout.write(out)

        if result.returncode == 0:
            print("FAIL  verification still passed after tampering — TC6 FAIL")
            return 1

        # Check that *only* the PDF line says FAIL, every other line is OK.
        bad_lines: list[str] = []
        for line in out.splitlines():
            if line.startswith("FAIL  ") and not line.startswith("FAIL  RESULT"):
                bad_lines.append(line)

        if len(bad_lines) != 1:
            print(f"FAIL  expected exactly 1 failing file, got {len(bad_lines)}: {bad_lines}")
            return 1
        if target_file not in bad_lines[0]:
            print(f"FAIL  failure was on wrong file: {bad_lines[0]}")
            return 1

        print("---")
        print(f"PASS  TC6 tamper test: detected tampering on {target_file} only")
        return 0


if __name__ == "__main__":
    sys.exit(main())
