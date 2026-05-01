#!/bin/bash
# setup_ca_variants.sh - Stage CA variant .cc files into sibling scratch
# directories so ns-3 builds them as separate executables.
#
# Why this exists: ns-3 scratch builds combine every .cc file in a single
# scratch subdirectory into one program. Putting smart-bus.cc,
# smart-bus-ca.cc, and smart-bus-ca-config.cc all in scratch/smart-bus/
# makes the linker emit "multiple definition of main" errors. The fix is
# to give each variant its own scratch subdirectory. This script copies
# the versioned .cc files from variants/ into sibling scratch dirs.
#
# Throwaway. Delete along with variants/ once the bandwidth path lands.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMART_BUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH_DIR="$(cd "$SMART_BUS_DIR/.." && pwd)"

echo "Staging CA variants into sibling scratch directories..."
echo "  smart-bus repo: $SMART_BUS_DIR"
echo "  scratch root:   $SCRATCH_DIR"
echo

# Variant 1: CA via LteHelper SetAttribute
SRC_A="$SMART_BUS_DIR/variants/smart-bus-ca/smart-bus-ca.cc"
DST_A_DIR="$SCRATCH_DIR/smart-bus-ca"
if [[ ! -f "$SRC_A" ]]; then
  echo "ERROR: missing source $SRC_A" >&2
  exit 1
fi
mkdir -p "$DST_A_DIR"
cp "$SRC_A" "$DST_A_DIR/smart-bus-ca.cc"
echo "  staged -> $DST_A_DIR/smart-bus-ca.cc"

# Variant 2: CA via Config::SetDefault
SRC_B="$SMART_BUS_DIR/variants/smart-bus-ca-config/smart-bus-ca-config.cc"
DST_B_DIR="$SCRATCH_DIR/smart-bus-ca-config"
if [[ ! -f "$SRC_B" ]]; then
  echo "ERROR: missing source $SRC_B" >&2
  exit 1
fi
mkdir -p "$DST_B_DIR"
cp "$SRC_B" "$DST_B_DIR/smart-bus-ca-config.cc"
echo "  staged -> $DST_B_DIR/smart-bus-ca-config.cc"

echo
echo "Done. Run ./ns3 build to compile all three executables."
echo "Expected binaries:"
echo "  build/scratch/smart-bus/ns3.40-smart-bus-default"
echo "  build/scratch/smart-bus-ca/ns3.40-smart-bus-ca-default"
echo "  build/scratch/smart-bus-ca-config/ns3.40-smart-bus-ca-config-default"
