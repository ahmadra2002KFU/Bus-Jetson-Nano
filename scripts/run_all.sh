#!/bin/bash
# run_all.sh
#
# Multi-seed batch runner for the Al-Ahsa Smart Bus simulation.
#
# Behaviour:
#   - SEEDS env var overrides the default seed list. e.g.
#       SEEDS="1 2 3 4 5" bash run_all.sh
#   - When more than one seed is requested, results are written into
#     ../../../results_combined_multiseed/<scenario>_<fleet>_seed<N>/ and
#     filenames keep the legacy <scenario>_<buses>buses_<mode>_<seed>.xml form
#     so analyze.py can find them.
#   - When SEEDS resolves to a single value (default backward-compatible
#     mode), output goes to ../../../results/ exactly as before.

mkdir -p ../../../results

echo "Starting Al-Ahsa Smart Bus Network Simulation Runs..."

# Arrays
BUS_COUNTS=(1 10 41)
SCENARIOS=("baseline" "ddos" "ddos_gps")
DETECTION_MODES=("any")

# Default to 5 seeds for the multi-seed campaign. Override with:
#   SEEDS="1" bash run_all.sh        # legacy single-seed mode
#   SEEDS="1 2 3" bash run_all.sh    # custom subset
DEFAULT_SEEDS=(1 2 3 4 5)
if [ -n "${SEEDS:-}" ]; then
    # shellcheck disable=SC2206
    SEED_LIST=(${SEEDS})
else
    SEED_LIST=("${DEFAULT_SEEDS[@]}")
fi

MULTISEED=0
if [ "${#SEED_LIST[@]}" -gt 1 ]; then
    MULTISEED=1
    mkdir -p ../../../results_combined_multiseed
fi

TOTAL_RUNS=$(( ${#BUS_COUNTS[@]} * ${#SCENARIOS[@]} * ${#DETECTION_MODES[@]} * ${#SEED_LIST[@]} ))
CURRENT_RUN=1

# Execute from ns-3 root
cd ../../../

for mode in "${DETECTION_MODES[@]}"; do
  for buses in "${BUS_COUNTS[@]}"; do
    for scenario in "${SCENARIOS[@]}"; do
      for seed in "${SEED_LIST[@]}"; do
        if [ "$MULTISEED" -eq 1 ]; then
            outdir="results_combined_multiseed/${scenario}_${buses}buses_seed${seed}"
            mkdir -p "$outdir"
        else
            outdir="results"
        fi

        echo "[$CURRENT_RUN/$TOTAL_RUNS] Mode: $mode | Scenario: $scenario | Buses: $buses | Seed: $seed | Out: $outdir"

        flags=""
        if [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]]; then
          flags="$flags --enableDDoS=true"
        fi
        if [[ "$scenario" == "ddos_gps" ]]; then
          flags="$flags --enableGpsSpoofing=true"
        fi

        # Pass --seed and --run so RngSeedManager::SetSeed/SetRun are
        # called explicitly inside main(). Keep --RngRun for ns-3 native
        # consistency in case anything else queries the run number.
        ./ns3 run "smart-bus --numBuses=$buses --scenario=$scenario --detectionMode=$mode $flags --seed=$seed --run=$seed --RngRun=$seed --resultsDir=${outdir}/" > /dev/null 2>&1

        xml_file="${outdir}/${scenario}_${buses}buses_${mode}_${seed}.xml"
        if [ ! -f "$xml_file" ]; then
          echo "  [ERROR] $xml_file was not created!"
        fi

        ((CURRENT_RUN++))
      done
    done
  done
done

echo "All $TOTAL_RUNS simulation runs completed."
if [ "$MULTISEED" -eq 1 ]; then
    echo "Multi-seed results in: results_combined_multiseed/"
    echo "Run analyze.py with RESULTS_DIR=results_combined_multiseed MULTISEED=1 to aggregate."
fi
