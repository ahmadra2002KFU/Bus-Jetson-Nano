# Router Power Validation Summary

Date: 2026-03-12

This directory records the current validation state after moving the LTE UE
model from a handset-style cap to a bus-router proxy (`33 dBm` UE transmit
power and `33 dBm` uplink `Pcmax`).

## Source Run Directories

- `/home/ahmed/ns-3/results_fix4_20260312/`
- `/home/ahmed/ns-3/results_fix8_router33pcmax_det10_20260312/`
- `/home/ahmed/ns-3/results_parallel_attack_20260312/`

## Scenario Matrix

Note: `baseline / 1 bus` and `baseline / 10 buses` are carried from the last
clean baseline check in `results_fix4_20260312`. This update reran the `41`-bus
baseline and all `6` attack scenarios.

| Scenario | Expected | Observed | Status |
| --- | --- | --- | --- |
| baseline / 1 bus | no detections | clean baseline from `results_fix4_20260312` | pass |
| baseline / 10 buses | no detections | clean baseline from `results_fix4_20260312` | pass |
| baseline / 41 buses | no detections | false `ddos_detect` at `190 s` | fail |
| ddos / 1 bus | DDoS detect + forensic upload | detected at `110 s`, upload complete | pass |
| ddos / 10 buses | DDoS detect + forensic upload | detected at `110 s`, upload complete | pass |
| ddos / 41 buses | DDoS detect + forensic upload | detected at `110 s`, upload incomplete | partial |
| ddos_gps / 1 bus | DDoS + GPS detect + forensic upload | both detects fired, upload complete | pass |
| ddos_gps / 10 buses | DDoS + GPS detect + forensic upload | both detects fired, upload complete | pass |
| ddos_gps / 41 buses | DDoS + GPS detect + forensic upload | both detects fired, upload incomplete | partial |

## Key Numbers

- Remaining `41`-bus baseline false positive: `deltaLoss=0.0512821`,
  `avgDelay=0.025377 s`, `telemetryRate=67488 bps`
- `41`-bus forensic upload progress under attack: `1269248` bytes received
- Successful forensic upload size in `1`- and `10`-bus attack runs:
  `10485760` bytes
