#!/bin/bash
# teardown_ca_variants.sh - Remove the sibling CA scratch directories
# created by setup_ca_variants.sh. Run after the bandwidth path is
# decided and we no longer need the throwaway CA variants compiled.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMART_BUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH_DIR="$(cd "$SMART_BUS_DIR/.." && pwd)"

for d in smart-bus-ca smart-bus-ca-config; do
  if [[ -d "$SCRATCH_DIR/$d" ]]; then
    rm -rf "$SCRATCH_DIR/$d"
    echo "removed: $SCRATCH_DIR/$d"
  else
    echo "skip (not present): $SCRATCH_DIR/$d"
  fi
done
echo "Teardown complete."
