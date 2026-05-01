#!/bin/bash
# run_all_parallel_ca.sh - Runs the CA variant (LteHelper SetAttribute form).
# Throwaway script; delete after the bandwidth strategy is decided.
set -euo pipefail

# Expected layout: $NS3_ROOT/scratch/smart-bus/scripts/run_all_parallel_ca.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMART_BUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NS3_ROOT="$(cd "$SMART_BUS_DIR/../.." && pwd)"
RESULTS_DIR="$SMART_BUS_DIR/results_ca"
mkdir -p "$RESULTS_DIR"

echo "Starting CA-variant Parallel Runs (binary: smart-bus-ca)..."
echo "ns-3 root: $NS3_ROOT"
echo "results: $RESULTS_DIR"

cd "$NS3_ROOT"

declare -a pids

echo "Clearing old CA-variant 1/10/41 bus XML/CSV outputs..."
rm -f "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}.xml \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_events.csv \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_forensics.csv

# One run per configuration: 3 bus sizes x 3 scenarios x seed 1 = 9 runs.
for buses in 1 10 41; do
  for scenario in baseline ddos ddos_gps; do
    for seed in 1; do
      flags=""
      [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]] && flags="$flags --enableDDoS=true"
      [[ "$scenario" == "ddos_gps" ]] && flags="$flags --enableGpsSpoofing=true"

      echo "Starting: $scenario | Buses: $buses | Seed: $seed"
      ./ns3 run --no-build "smart-bus-ca --numBuses=$buses --scenario=$scenario $flags --RngRun=$seed --resultsDir=scratch/smart-bus/results_ca/" \
        > "$RESULTS_DIR/${scenario}_${buses}buses_any_${seed}.log" 2>&1 &
      pids+=("$!")

      # Limit concurrency to 8 jobs so we don't crash the server
      if (( ${#pids[@]} >= 8 )); then
        wait -n
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

wait
echo "All CA-variant runs completed!"
