# Router Power Validation Report

Date: 2026-03-12
Branch: `main-dev`

## Goal

Stabilize the requirements-aligned LTE smart bus simulation after the `41`-bus
baseline showed false DDoS and GPS spoof detections, and document the current
validation state before the next retest cycle.

## Code Changes Included In This Update

### 1. Model buses as vehicle routers instead of handset UEs

- Set `ns3::LteUePhy::TxPower` to `33 dBm`.
- Set `ns3::LteUePowerControl::Pcmax` to `33 dBm`.
- Keep `ns3::LteEnbPhy::TxPower` at `46 dBm`.

Reason: the requirements describe a `4G/5G router` on each bus, so the uplink
budget should be closer to a roof-mounted vehicular router than a handset-class
UE capped at `23 dBm`.

### 2. Keep the LTE stack aligned with the requirement architecture

- Retain `20 MHz` LTE bandwidth (`100` RBs).
- Use `PssFfMacScheduler` with `SRS_UL_CQI`.
- Enable `A3RsrpHandoverAlgorithm` with `Hysteresis=3.0` and
  `TimeToTrigger=256 ms`.
- Keep Friis propagation for the required `3`-tower, `15 km x 20 km` topology.

Reason: realistic urban pathloss models were tested, but with exactly `3` eNBs
they caused catastrophic disconnection and prevented meaningful attack
comparison.

### 3. Harden GPS spoof detection against LTE delivery jitter

- Add a `dt < 0.5 s` filter so queued telemetry packets do not create false
  speed spikes.
- Add a `3`-reading anomaly streak requirement before triggering
  `gps_spoof_detect`.

Reason: `41`-bus baseline traffic can bunch delayed packets together and make a
normal bus look like it exceeded the speed threshold.

### 4. Harden DDoS detection against baseline congestion noise

- Raise warmup from `60 s` to `90 s`.
- Use interval-delta loss instead of cumulative loss.
- Skip zero-receive telemetry flows when computing DDoS loss.
- Use weighted average delay instead of worst-flow delay.
- Require at least `10` packets before evaluating interval loss.
- Schedule the DDoS detector every `10 s` instead of `5 s`.

Reason: the detector should react to sustained attack symptoms, not startup
transients, in-flight FlowMonitor counters, or one bad cell-edge flow.

### 5. Improve traffic and topology fidelity

- Add per-port dedicated EPS bearers for telemetry, CCTV, ticketing, and
  forensic upload.
- Distribute buses spatially along their route loop at `t=0` instead of leaving
  many buses parked at the first station.
- Keep bus waypoint height at `1.5 m`.
- Delay normal app start times to reduce startup-only congestion.
- Use one attacker node for both DDoS and GPS spoofing, matching the current
  project plan.

## Validation Snapshot

Source run directories on the ns-3 workspace:

- `/home/ahmed/ns-3/results_fix4_20260312/`
- `/home/ahmed/ns-3/results_fix6_router30pcmax_20260312/`
- `/home/ahmed/ns-3/results_fix7_router33pcmax_20260312/`
- `/home/ahmed/ns-3/results_fix8_router33pcmax_det10_20260312/`
- `/home/ahmed/ns-3/results_parallel_attack_20260312/`

### Current nine-scenario status

`baseline / 1 bus` and `baseline / 10 buses` are carried forward from the last
clean baseline validation set in `results_fix4_20260312`. The latest reruns in
this update focused on the `41`-bus baseline and the `6` attack scenarios.

| Scenario | Result | Notes |
| --- | --- | --- |
| baseline / 1 bus | pass | Clean baseline from `results_fix4_20260312` |
| baseline / 10 buses | pass | Clean baseline from `results_fix4_20260312` |
| baseline / 41 buses | fail | Marginal false `ddos_detect` at `190 s`, `deltaLoss=0.0512821` |
| ddos / 1 bus | pass | DDoS detected at `110 s`, forensic upload completed |
| ddos / 10 buses | pass | DDoS detected at `110 s`, forensic upload completed |
| ddos / 41 buses | partial | DDoS detected at `110 s`, forensic upload stalled at `1269248` bytes |
| ddos_gps / 1 bus | pass | DDoS at `110 s`, GPS spoof at `152.015 s`, forensic upload completed |
| ddos_gps / 10 buses | pass | DDoS at `110 s`, GPS spoof at `152.015 s`, forensic upload completed |
| ddos_gps / 41 buses | partial | Both detections fire, forensic upload stalls at `1269248` bytes |

### What improved

- The earlier `41`-bus GPS baseline false positive disappeared after the router
  power-control fix and GPS detector hardening.
- DDoS attack detection is stable across `1`, `10`, and `41` buses.
- DDoS+GPS combined attack detection is stable across `1`, `10`, and `41`
  buses.

### What is still open

- The `41`-bus baseline remains slightly above the `5%` loss threshold, so the
  detector still raises one false DDoS event.
- `41`-bus forensic uploads do not finish within the current simulation window
  once the network is under attack.
- `queue_delay` is still measured on the wrong link and remains effectively
  zero.

## Next Steps

1. Inspect which telemetry flows create the remaining `~5.13%` baseline loss in
   the `41`-bus run.
2. Fix forensic upload completion for `41`-bus attack scenarios.
3. Correct queue delay measurement.
4. Rerun the `41`-bus trio and then rerun the full `9`-scenario matrix.
