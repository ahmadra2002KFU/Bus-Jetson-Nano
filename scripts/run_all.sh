#!/bin/bash
# run_all.sh — Run all 9 scenarios × 5 seeds = 45 simulation runs
# Usage: cd ns-3.40 directory, then: bash scratch/smart-bus/scripts/run_all.sh

set -e

RESULTS_DIR="results/"
mkdir -p "$RESULTS_DIR"

TOTAL=0
FAILED=0

for buses in 1 10 41; do
  for scenario in baseline ddos ddos_gps; do
    for seed in 1 2 3 4 5; do

      flags="--numBuses=$buses --scenario=$scenario --RngRun=$seed --resultsDir=$RESULTS_DIR"

      if [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]]; then
        flags="$flags --enableDDoS=true"
      fi

      if [[ "$scenario" == "ddos_gps" ]]; then
        flags="$flags --enableGpsSpoofing=true"
      fi

      echo "========================================"
      echo "Running: buses=$buses scenario=$scenario seed=$seed"
      echo "========================================"

      if ./ns3 run "smart-bus $flags"; then
        echo "[OK] buses=$buses scenario=$scenario seed=$seed"
      else
        echo "[FAIL] buses=$buses scenario=$scenario seed=$seed"
        FAILED=$((FAILED + 1))
      fi

      TOTAL=$((TOTAL + 1))
    done
  done
done

echo ""
echo "========================================"
echo "COMPLETE: $TOTAL runs, $FAILED failures"
echo "========================================"
