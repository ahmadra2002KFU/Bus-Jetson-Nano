#!/bin/bash
# run_all_parallel.sh - Runs the simulations much faster by using background processes

mkdir -p ../../../results
cd ../../../
echo "Starting Parallel Runs..."

declare -a pids

for buses in 1 10 41; do
  for scenario in baseline ddos ddos_gps; do
    for seed in 1 2 3 4 5; do
      flags=""
      [[ "$scenario" == "ddos" || "$scenario" == "ddos_gps" ]] && flags="$flags --enableDDoS=true"
      [[ "$scenario" == "ddos_gps" ]] && flags="$flags --enableGpsSpoofing=true"
      
      echo "Starting: $scenario | Buses: $buses | Seed: $seed"
      ./ns3 run "smart-bus --numBuses=$buses --scenario=$scenario $flags --RngRun=$seed --resultsDir=results/" > /dev/null 2>&1 &
      pids+=($!)
      
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
