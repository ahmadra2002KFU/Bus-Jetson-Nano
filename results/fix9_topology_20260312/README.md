# Fix9 Topology Rerun

Date: 2026-03-12

This directory contains the latest `41`-bus rerun artifacts after replacing the
original diagonal 3-eNB placement with a route-weighted layout:

- `(4500, 6000, 30)`
- `(12000, 6500, 30)`
- `(8000, 16000, 30)`

## Included Scenarios

- `baseline_41buses_any_1_*`
- `ddos_41buses_any_1_*`
- `ddos_gps_41buses_any_1_*`

## Observed Outcomes

- `baseline / 41 buses`: still shows a marginal false `ddos_detect` at `170 s`
  with `deltaLoss=0.0512195`
- `ddos / 41 buses`: DDoS detection fires at `110 s`; forensic upload improves
  to `4561360` bytes but does not finish `10 MB`
- `ddos_gps / 41 buses`: DDoS detection fires at `110 s`, GPS spoof detection
  fires at `152.015 s`; forensic upload improves to `4561360` bytes but does
  not finish `10 MB`

## Why This Matters

The tower relocation improved `41`-bus attack-run upload progress and kept both
attack detectors stable, but it did not clear the last baseline false positive.
This makes the directory a useful handoff point for the next debugging pass.
