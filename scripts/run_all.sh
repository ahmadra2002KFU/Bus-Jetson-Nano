#!/bin/bash
# run_all.sh

# Ensure results directory exists
mkdir -p ../../../results

echo "Starting Al-Ahsa Smart Bus Network Simulation Runs..."

# Arrays
BUS_COUNTS=(1 10 41)
SCENARIOS=("baseline" "ddos" "ddos_gps")
SEEDS=(1 2 3 4 5)

TOTAL_RUNS=$(( ${#BUS_COUNTS[@]} * ${#SCENARIOS[@]} * ${#SEEDS[@]} ))
CURRENT_RUN=1

# Execute from ns-3 root
cd ../../../

for buses in "${BUS_COUNTS[@]}"; do
  for scenario in "${SCENARIOS[@]}"; do
    for seed in "${SEEDS[@]}"; do
      echo "[$CURRENT_RUN/$TOTAL_RUNS] Running Scenario: $scenario | Buses: $buses | Seed: $seed"
      
      flags=""
      if [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]]; then
        flags="$flags --enableDDoS=true"
      fi
      if [[ "$scenario" == "ddos_gps" ]]; then
        flags="$flags --enableGpsSpoofing=true"
      fi
      
      ./ns3 run "smart-bus --numBuses=$buses --scenario=$scenario $flags --RngRun=$seed --resultsDir=results/" > /dev/null 2>&1
      
      # Optional: check if the XML was actually generated
      xml_file="results/${scenario}_${buses}buses_${seed}.xml"
      if [ ! -f "$xml_file" ]; then
        echo "  [ERROR] $xml_file was not created!"
      fi
      
      ((CURRENT_RUN++))
    done
  done
done

echo "All $TOTAL_RUNS simulation runs completed successfully!"
