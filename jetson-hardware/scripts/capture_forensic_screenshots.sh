#!/usr/bin/env bash
# capture_forensic_screenshots.sh — M4 evidence screenshots S1-S5.
#
# Authored on the Jetson during the 2026-05-02 evidence run because the
# documentation agent's brief referenced a script under Claude Docs/scripts/
# that was never pushed to this repo. Committed here so its provenance is
# auditable from m4-evidence-2026-05-02.
#
# Usage:
#   bash scripts/capture_forensic_screenshots.sh <incident_folder>
#
# Output (in m4_evidence/screenshots/):
#   S1_hash_manifest.{txt,png}    sha256sum -c on the chosen incident (all OK)
#   S2_evidence_files.{txt,png}   ls -la + sizes of the 7 incident files
#   S3_verify_pass.{txt,png}      curl /verify/<id> showing verified:true
#   S4_tamper_fail.{txt,png}      tamper PDF in a local copy, re-run hash check
#   S5_evidence_folder.{txt,png}  full m4_evidence/incidents/ tree
#
# The TXTs come from live commands — they are not synthetic. The PNGs are
# rendered from the TXTs via Pillow (DejaVu Sans Mono) because this session
# has no DISPLAY for gnome-screenshot. run_log.md states this honestly.

set -euo pipefail

INC_FOLDER="${1:-}"
if [[ -z "$INC_FOLDER" || ! -d "$INC_FOLDER" ]]; then
  echo "ERROR: pass a path to an incident folder that exists" >&2
  echo "Usage: $0 <incident_folder>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/m4_evidence/screenshots"
mkdir -p "$OUT_DIR"

INC_ID="$(basename "$INC_FOLDER")"
SERVER_URL="${SERVER_URL:-https://jetson.testingdomainzforprototypes.website}"

render_png() {
  local txt="$1" png="$2"
  python3 - "$txt" "$png" <<'PYEOF'
import sys
from PIL import Image, ImageDraw, ImageFont

txt_path, png_path = sys.argv[1], sys.argv[2]
with open(txt_path, "r", encoding="utf-8") as f:
    text = f.read()

font = ImageFont.truetype(
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14
)
lines = text.splitlines() or [""]
char_w = font.getlength("M")
line_h = 18
pad = 16
max_chars = max((len(l) for l in lines), default=80)
width = int(max(900, char_w * max_chars + 2 * pad))
height = int(line_h * (len(lines) + 3) + 2 * pad)

img = Image.new("RGB", (width, height), color=(15, 15, 20))
draw = ImageDraw.Draw(img)
y = pad
draw.text((pad, y), f"$ cat {txt_path.rsplit('/', 1)[-1]}",
          fill=(180, 220, 180), font=font)
y += int(line_h * 1.5)

for line in lines:
    color = (220, 220, 220)
    upper = line.upper()
    if "FAILED" in upper or ": FAIL" in upper or "VERIFIED\": FALSE" in upper:
        color = (240, 110, 110)
    elif " OK" in line or '"verified": true' in line.lower() or ": PASS" in upper:
        color = (130, 220, 130)
    draw.text((pad, y), line, fill=color, font=font)
    y += line_h

img.save(png_path, optimize=True)
PYEOF
}

# ─── S1: hash manifest + sha256sum -c (all OK) ────────────────────────
S1="$OUT_DIR/S1_hash_manifest.txt"
{
  echo "=== Incident: $INC_ID"
  echo "=== Folder:   $INC_FOLDER"
  echo
  echo "$ cat hash_manifest.txt"
  cat "$INC_FOLDER/hash_manifest.txt"
  echo
  echo "$ ( cd $INC_FOLDER && sha256sum -c hash_manifest.txt )"
  ( cd "$INC_FOLDER" && sha256sum -c hash_manifest.txt 2>&1 )
} > "$S1"
render_png "$S1" "$OUT_DIR/S1_hash_manifest.png"
echo "===> S1 done"

# ─── S2: evidence files in folder ─────────────────────────────────────
S2="$OUT_DIR/S2_evidence_files.txt"
{
  echo "=== Evidence files for $INC_ID"
  echo
  echo "$ ls -la $INC_FOLDER"
  ls -la "$INC_FOLDER"
  echo
  echo "$ wc -c $INC_FOLDER/*"
  wc -c "$INC_FOLDER"/*
} > "$S2"
render_png "$S2" "$OUT_DIR/S2_evidence_files.png"
echo "===> S2 done"

# ─── S3: server-side /verify pass ─────────────────────────────────────
# Resolve the integer forensic_id from metadata.json + /api/forensics —
# server's /verify endpoint is keyed by the DB PK, not the incident_id.
FORENSIC_ID="$(python3 - "$INC_FOLDER" "$SERVER_URL" <<'PYEOF'
import json, sys, urllib.request, urllib.error
inc_folder, server = sys.argv[1], sys.argv[2]
with open(f"{inc_folder}/metadata.json") as f:
    meta = json.load(f)
ts = float(meta["ts"])
bus_id = int(meta["bus_id"])
req = urllib.request.Request(
    f"{server.rstrip('/')}/api/forensics",
    headers={"User-Agent": "Mozilla/5.0 (compatible; jetson-m4-screenshot/1.0)"},
)
rows = json.loads(urllib.request.urlopen(req, timeout=10).read())
best = None
for r in rows:
    if int(r["bus_id"]) != bus_id:
        continue
    dt = abs(float(r["ts"]) - ts)
    if dt < 1.0 and (best is None or dt < best[0]):
        best = (dt, int(r["id"]))
print(best[1] if best else "")
PYEOF
)"

S3="$OUT_DIR/S3_verify_pass.txt"
{
  echo "=== Server /verify for $INC_ID  (forensic_id=$FORENSIC_ID)"
  echo
  if [[ -z "$FORENSIC_ID" ]]; then
    echo "ERROR: could not resolve forensic_id from /api/forensics"
  else
    echo "$ curl -sS $SERVER_URL/verify/$FORENSIC_ID | python3 -m json.tool"
    curl -sS "$SERVER_URL/verify/$FORENSIC_ID" | python3 -m json.tool 2>&1 \
      || echo "(verify failed — see above)"
  fi
} > "$S3"
render_png "$S3" "$OUT_DIR/S3_verify_pass.png"
echo "===> S3 done"

# ─── S4: tamper test on a local copy ──────────────────────────────────
TAMPER_DIR="$(mktemp -d -t tamper.XXXXXX)"
cp -a "$INC_FOLDER/." "$TAMPER_DIR/"
# Append one byte to the PDF — smallest possible tamper
printf '\x00' >> "$TAMPER_DIR/edge_forensic_report.pdf"

S4="$OUT_DIR/S4_tamper_fail.txt"
{
  echo "=== Tamper test"
  echo "Source incident: $INC_ID"
  echo "Tamper sandbox:  $TAMPER_DIR"
  echo
  echo "$ printf '\\\\x00' >> $TAMPER_DIR/edge_forensic_report.pdf"
  echo "(one null byte appended to the PDF)"
  echo
  echo "$ ( cd $TAMPER_DIR && sha256sum -c hash_manifest.txt )"
  ( cd "$TAMPER_DIR" && sha256sum -c hash_manifest.txt 2>&1 ) || true
  echo
  echo "Expected: edge_forensic_report.pdf FAILED, the 5 others OK"
  echo
  echo "(The script does NOT upload the tampered folder. Server's view of"
  echo " $INC_ID is unchanged — see S3 for the live /verify response.)"
} > "$S4"
render_png "$S4" "$OUT_DIR/S4_tamper_fail.png"
echo "===> S4 done"
echo "    tamper sandbox: $TAMPER_DIR"

# ─── S5: full m4_evidence/incidents listing ───────────────────────────
S5="$OUT_DIR/S5_evidence_folder.txt"
{
  echo "=== m4_evidence/incidents/"
  echo
  echo "$ ls -la $REPO_ROOT/m4_evidence/incidents/"
  ls -la "$REPO_ROOT/m4_evidence/incidents/" 2>&1
  echo
  for d in "$REPO_ROOT/m4_evidence/incidents"/INC_*; do
    [[ -d "$d" ]] || continue
    echo "--- $(basename "$d") ---"
    ls "$d"
    echo
  done
} > "$S5"
render_png "$S5" "$OUT_DIR/S5_evidence_folder.png"
echo "===> S5 done"

echo
echo "All five screenshots in $OUT_DIR"
