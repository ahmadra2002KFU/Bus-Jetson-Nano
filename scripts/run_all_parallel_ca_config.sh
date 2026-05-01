#!/bin/bash
# run_all_parallel_ca_config.sh - Runs the CA variant (Config::SetDefault form).
# Safety-net build in case smart-bus-ca rejects the LteHelper SetAttribute API.
# Throwaway script; delete after the bandwidth strategy is decided.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMART_BUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NS3_ROOT="$(cd "$SMART_BUS_DIR/../.." && pwd)"
RESULTS_DIR="$SMART_BUS_DIR/results_ca_config"
mkdir -p "$RESULTS_DIR"

echo "Starting CA-config-variant Parallel Runs (binary: smart-bus-ca-config)..."
echo "ns-3 root: $NS3_ROOT"
echo "results: $RESULTS_DIR"

cd "$NS3_ROOT"

declare -a pids

echo "Clearing old CA-config-variant 1/10/41 bus XML/CSV outputs..."
rm -f "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}.xml \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_events.csv \
      "$RESULTS_DIR"/{baseline,ddos,ddos_gps}_{1,10,41}buses_any_{1,2,3,4,5}_forensics.csv

for buses in 1 10 41; do
  for scenario in baseline ddos ddos_gps; do
    for seed in 1; do
      flags=""
      [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]] && flags="$flags --enableDDoS=true"
      [[ "$scenario" == "ddos_gps" ]] && flags="$flags --enableGpsSpoofing=true"

      echo "Starting: $scenario | Buses: $buses | Seed: $seed"
      ./ns3 run --no-build "smart-bus-ca-config --numBuses=$buses --scenario=$scenario $flags --RngRun=$seed --resultsDir=scratch/smart-bus/results_ca_config/" \
        > "$RESULTS_DIR/${scenario}_${buses}buses_any_${seed}.log" 2>&1 &
      pids+=("$!")

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
echo "All CA-config-variant runs completed!"
