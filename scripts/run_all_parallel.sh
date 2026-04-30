#!/bin/bash
# run_all_parallel.sh - Runs the simulations much faster by using background processes
set -euo pipefail

# This script is expected to be run from $NS3_ROOT/scratch/smart-bus.
# Resolve the ns-3 root robustly instead of assuming ../../../.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMART_BUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NS3_ROOT="$(cd "$SMART_BUS_DIR/../.." && pwd)"
RESULTS_DIR="$SMART_BUS_DIR/results"
mkdir -p "$RESULTS_DIR"

echo "Starting Parallel Runs..."
echo "ns-3 root: $NS3_ROOT"
echo "results: $RESULTS_DIR"

cd "$NS3_ROOT"

declare -a pids

echo "Clearing old 1/10/41 bus XML/CSV outputs..."
rm -f "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}.xml \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_events.csv \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_forensics.csv

# One run per configuration: 3 bus sizes × 3 scenarios × seed 1 = 9 runs.
for buses in 1 10 41; do
  for scenario in baseline ddos ddos_gps; do
    for seed in 1; do
      flags=""
      [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]] && flags="$flags --enableDDoS=true"
      [[ "$scenario" == "ddos_gps" ]] && flags="$flags --enableGpsSpoofing=true"

      echo "Starting: $scenario | Buses: $buses | Seed: $seed"
      ./ns3 run --no-build "smart-bus --numBuses=$buses --scenario=$scenario $flags --RngRun=$seed --resultsDir=scratch/smart-bus/results/" \
        > "$RESULTS_DIR/${scenario}_${buses}buses_any_${seed}.log" 2>&1 &
      pids+=("$!")

      # Limit concurrency to 8 jobs so we don't crash the server
      if (( ${#pids[@]} >= 8 )); then
        wait -n
        # Clean up finished PIDs
        new_pids=()
        for pid in "${pids[@]}"; do
          if kill -0 "$pid" 2>/dev/null; then
            new_pids+=("$pid")
          fi
        done
        pids=("${new_pids[@]}")
      fi
    done
  done
done

# Wait for remaining jobs
wait
echo "All runs completed!"
