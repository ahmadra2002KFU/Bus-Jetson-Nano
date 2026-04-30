# Smart-Bus Re-Simulation Notes (uncommitted on `main-dev`)

This file documents the code changes made to address the four problems in
the previous 41-bus run:

1. Baseline packet loss 35.92% (network saturated by *legitimate* traffic).
2. DDoS attack invisible in delay/loss/throughput metrics.
3. Forensic upload only 43.5% complete in 300 s and reported as "completed"
   anyway because of a fixed 16.5 s timer.
4. False-positive DDoS detection at t = 170 s in baseline runs.

The supervisor pins (41 buses, 3 eNBs, 1-2 Mbps CCTV, 30 Mbps DDoS, 15 Mbps
threshold, "any" detection mode) are preserved.

---

## 1. Files changed

| File | Purpose |
|------|---------|
| `smart-bus.cc` | Backhaul rate, CCTV bearer GBR, real forensic byte-counting, sim-time global. |
| `scripts/analyze.py` | All 5 seeds; per-flow throughput; real queue delay; real upload success rate. |
| `scripts/run_all_parallel.sh` | Unchanged - already produces 5 seeds. |
| `RESIM_NOTES.md` | This file. |

`jetson-hardware/` is **not** touched.

---

## 2. Root-cause analysis

The traffic numbers laid out side-by-side make the problem obvious:

| Quantity | Value |
|---|---|
| Per-bus offered uplink | ~1.025 Mbps (1 Mbps CCTV + ~3 kbps GPS + ~22 kbps tickets) |
| 41-bus aggregated offered uplink | ~42 Mbps |
| Buses per cell (~even split, 3 eNBs) | ~14 |
| Per-cell offered UL | ~14.4 Mbps |
| 20 MHz LTE practical UL throughput per cell (ns-3) | ~18-20 Mbps clean, ~12-15 Mbps with cell-edge UEs |
| **Old CCTV bearer GBR per UE** | **1.2 Mbps** |
| 14 UEs x 1.2 Mbps GBR | 16.8 Mbps requested GBR per cell |

So the GBR demand per cell already over-shoots the practical UL ceiling, and
the scheduler degrades or rejects flows. That alone explains the ~36% PLR.

**Why DDoS is invisible**: the attacker is wired into the PGW via a 10 Gbps
P2P link and sends *to the server*; that traffic never crosses the LTE air
interface. It hits the PGW->server backhaul, which was sized at **1 Gbps**.
At 30 Mbps DDoS + ~25 Mbps legitimate, the 1 Gbps backhaul is at 5%
utilisation. So the bus-flow PLR/delay measured on the LTE side cannot
move - which is what the trace shows.

**Why baseline produces a false-positive at t=170 s**: with the LTE link
saturated, the average bus-flow delay drifts above the 100 ms detection
threshold. Once saturation is removed the threshold is no longer crossed
in the no-attack scenario.

**Why the forensic upload reports "completed" at 43.5%**: `MarkForensicComplete`
fires unconditionally on a +16.5 s `Simulator::Schedule`, regardless of
whether bytes actually arrived. The receiving `PacketSink` was already
installed but its `GetTotalRx()` was never queried.

---

## 3. Changes in `smart-bus.cc`

### 3.1 PGW-to-server backhaul: 1 Gbps -> 100 Mbps

`SERVER_LINK_RATE_BPS` constant was 1e9; it is now 100e6, and the
`p2pServer` `DataRate` attribute is built from that constant (so the
configured link and the queue-delay computation can never disagree
again).

Capacity arithmetic for the new 100 Mbps backhaul:

| Scenario | Offered backhaul load | Utilisation | Expected effect |
|---|---|---|---|
| Baseline (41 buses) | ~41 Mbps | 41% | <1 ms queue, queue rarely non-empty. |
| DDoS (30 Mbps + 41 Mbps) | ~71 Mbps | 71% | Queue persistently non-empty, ~2-10 ms queueing delay, occasional drops. |
| DDoS @ ~50 Mbps test rate | ~91 Mbps | 91% | Sustained queue, ~50-200 ms M/M/1-style delay, visible PLR. |

The 30 Mbps default is now **on the linear-to-knee transition** of the
M/M/1 delay curve, which is exactly what we need for an attack to be
visible without driving the entire link to total collapse. 100 Mbps is
also a defensible engineering choice for an operator backhaul to a
small-municipality analytics endpoint.

### 3.2 CCTV bearer GBR: 1.2/1.5 Mbps -> 1.0/1.2 Mbps

The CCTV traffic generator emits 1.0 Mbps. Reserving 1.2 Mbps GBR per UE
was over-provisioning that exceeded the per-cell UL budget once 14 UEs
attached to the same eNB. 1.0/1.2 Mbps GBR/MBR matches the actual stream
and leaves headroom for HARQ/control. CCTV stream rate itself stays at
1 Mbps (well within the supervisor's 1-2 Mbps requirement).

### 3.3 LTE bandwidth: kept at 100 RBs (20 MHz)

200 RBs (40 MHz, carrier-aggregation) was considered. Trade-off:

- Pros: ~doubles per-cell UL and would brute-force the saturation issue.
- Cons: ns-3's standard `LteEnbPhy` does not natively model CA in this
  configuration; reviewers can challenge a single-carrier 40 MHz LTE as
  unrealistic; the supervisor description references operator-grade
  20 MHz LTE cells.

We instead solved saturation by trimming the over-provisioned GBR and
fixing the dominant bottleneck (the backhaul). 20 MHz remains canonical.

### 3.4 Scheduler: kept at PssFfMacScheduler

PSS (Priority-Set Scheduler) honours GBR bearers, which is necessary for
the four-bearer QoS model used here (voice, video, IMS, video). PfFfMac
(Proportional Fair) gives more even airtime but ignores GBR and would
break the QoS premise. No change.

### 3.5 Forensic upload: real bytes counted, no fixed timer

- `MarkForensicComplete` (fixed +16.5 s lie) **removed**.
- New `PollForensicCompletion(interval=0.5s, deadline)` polls
  `g_forensicSinkApp->GetTotalRx()` every 0.5 s and:
  - marks the upload complete when 10 MB have **actually** arrived,
  - logs a `forensic_partial` event with delivered bytes if the deadline
    fires first,
  - records `bytesReceived` on the `ForensicEvent` regardless.
- A baseline byte counter `g_forensicSinkBaselineBytes` snapshots the
  sink's `TotalRx()` at upload start, so the metric is isolated from
  earlier traffic on the same UDP port.
- `g_simTime` global is set in `main()` so the poll deadline knows when
  the simulation will stop.

Deadline is `min(triggerTime + 60s, simTime - 0.5s)`. 60 s allows even a
slow upload to finish under heavy congestion (10 MB at 1.4 Mbps = 60 s);
shorter than this and we'd report incomplete on runs that would actually
have finished.

---

## 4. Changes in `scripts/analyze.py`

### 4.1 `SEEDS = [1]` -> `[1, 2, 3, 4, 5]`

Trivial bug. The runner already produces 5 seeds; only seed 1 was being
plotted. Means/stds in the previous report are single-seed numbers
mislabeled as "mean across 5 seeds".

### 4.2 Throughput: per-flow active duration

Old:
```python
throughput_mbps = (total_rx_bytes * 8) / (SIM_TIME * 1e6)  # 300 s
```

New (sums per-flow goodput, each over its real active window):
```python
active_seconds = (last_rx_ns - first_tx_ns) / 1e9
flow_mbps = (rx_bytes * 8.0) / (active_seconds * 1e6)
sum_flow_throughput_mbps += flow_mbps
```

A bus flow that started at t=10 s and lasted to t=300 s was previously
divided by 300, depressing reported throughput by ~3%. More importantly,
short-lived ticketing TCP flows that ran for ~50 s were being divided by
300 (-83% under-reporting). The new computation is what FlowMonitor
documentation recommends.

Helper `_parse_time_ns` correctly strips the `+` prefix and `ns` suffix.

### 4.3 Queue delay: read from events CSV

Old:
```python
queue_delay_ms = max(0, avg_delay_ms - 25)  # 25 ms hardcoded fudge
```

New: parse `queue_delay` event rows from `*_events.csv` (these are the
rows already emitted by `LogQueueStatus` every 5 s, value1 is queue
delay in seconds at the PGW-side P2P device). Mean across the run.

### 4.4 Forensic completion: real bytes, real success rate

`compute_forensic_metrics` now reports `upload_success_rate =
bytes_received / 10 MB` on every run, regardless of whether
`uploadCompleted` is 1. The summary line at the end reports both
"fully completed (>=10MB)" count *and* "avg bytes delivered as % of
target", so partial successes are visible.

---

## 5. Expected metric ranges (predicted)

These are mathematical predictions. Validate by running on the Linux
server (see Section 7).

### 5.1 Baseline (41 buses, no attack)

| Metric | Old | Predicted new |
|---|---|---|
| PLR | 35.92% | **0.5 - 3%** (cell-edge HARQ residue only) |
| Avg E2E delay | 100.6 ms | **20 - 45 ms** (LTE radio + 10 ms backhaul + ~0 queue) |
| Aggregate bus-flow throughput | depressed | **40 - 42 Mbps** (was being divided by 300 s anyway) |
| Queue delay (PGW->server) | 75.6 ms (fake) | **<1 ms** (link at 41% utilisation) |
| `ddos_detect` events | 1 (false positive) | **0** |

### 5.2 DDoS (41 buses, 30 Mbps attacker)

| Metric | Old | Predicted new |
|---|---|---|
| PLR | ~36% (no Δ vs baseline) | **3 - 8%** (higher than baseline by a clear margin) |
| Avg E2E delay | ~100 ms (no Δ) | **40 - 90 ms** (queueing on saturated 71% backhaul) |
| Aggregate throughput | flat | **38 - 41 Mbps** (small drop vs baseline) |
| Queue delay (PGW->server) | 75.6 ms (fake) | **5 - 25 ms** (real M/M/1 queueing) |
| TTD DDoS | varies | **5 - 15 s** (rate threshold crossed within 10 s window) |
| Forensic upload success | 43.5% reported "complete" | **>=95% delivered, ~16-22 s duration** |

### 5.3 DDoS + GPS spoof

Same network metrics as DDoS. Add:
- GPS spoof TTD: **~3 s** (jump + corridor distance + speed all trip)
- GPS detection events: **>=1**, exactly 0 false positives in baseline.

### 5.4 1- and 10-bus runs

Should remain healthy:
- 1 bus: ~0% PLR, ~25 ms delay, ~1 Mbps throughput.
- 10 buses: ~0% PLR, ~25 ms delay, ~10 Mbps throughput.

---

## 6. Validation checklist

After re-running, verify in the analyze.py output:

- [ ] **Baseline 41-bus PLR < 5%** (target).
- [ ] **DDoS 41-bus PLR > baseline 41-bus PLR by >= 2 percentage points**.
- [ ] **DDoS 41-bus delay > baseline 41-bus delay by >= 10 ms**.
- [ ] **No `ddos_detect` events in any baseline run** (no false positives).
- [ ] **Forensic upload `bytes_received >= 10 MB`** for all 41-bus DDoS runs.
- [ ] **Queue delay row in summary > 0 ms** for DDoS scenarios.
- [ ] **Per-flow throughput sum > previous global divisor result**.
- [ ] All 5 seeds present in DataFrame (`len(data) == 3 * 3 * 1 * 5 = 45`).

If any fails, the next knob to turn is:
- Still high baseline PLR -> drop GBR_CONV_VIDEO further (0.8/1.0) or move tickets off TCP.
- DDoS still invisible -> drop backhaul to 75 Mbps or raise DDoS rate to 50 Mbps.
- Upload still incomplete -> raise forensic poll deadline to 90 s.

---

## 7. How to run on the Linux server

Pull and run from the repo root (`scratch/smart-bus/`):

```bash
# 1. Sync latest source to ns-3 source tree.
#    The repo's smart-bus.cc lives at scratch/smart-bus/ inside ns-3.
#    Trigger a fresh build:
cd <ns-3-root>
./ns3 build smart-bus

# 2. Run all 45 simulations in parallel (5 seeds x 3 bus counts x 3 scenarios)
cd scratch/smart-bus
bash scripts/run_all_parallel.sh

# 3. Analyse and re-plot
cd scripts
RESULTS_DIR=../results python3 analyze.py
```

Single-scenario sanity check before the full sweep:

```bash
cd <ns-3-root>
./ns3 run "smart-bus --numBuses=41 --scenario=baseline --RngRun=1 --resultsDir=results/"
./ns3 run "smart-bus --numBuses=41 --scenario=ddos --enableDDoS=true --RngRun=1 --resultsDir=results/"
```

Expected single-run wall-clock: ~3-6 min for 41-bus, depending on host.

---

## 8. Open questions for the user

- **Backhaul rate of 100 Mbps**: this is a deliberate engineering choice
  to make DDoS visible. If the supervisor has a different number in
  mind for the operator transit link, edit `SERVER_LINK_RATE_BPS` and
  re-run. The dependence is monotonic: lower backhaul -> larger DDoS
  effect, but smaller dynamic range above the attack rate.
- **CCTV bearer GBR 1.0/1.2**: well within the supervisor's 1-2 Mbps
  CCTV envelope and matches the 1 Mbps stream. If GBR must remain at
  1.2/1.5, expect baseline PLR to stay high and an additional headroom
  fix (e.g. moving to 200 RBs) will be required.
- **Forensic poll deadline of 60 s**: some runs may legitimately need
  longer under sustained DDoS. Adjust `min(now + 60.0, g_simTime - 0.5)`
  in `StartForensicUpload` if validation shows partial completions
  recovering after the deadline.

No commits are made.

---

## 9. Round 2 changes (supervisor-spec compliance pass)

This section is **additive** to all the round-1 changes documented above.
Round-1 fixes (100 Mbps backhaul, GBR 1.0/1.2 Mbps, real PacketSink
forensic polling, 5-seed analyze.py, per-flow throughput, real queue
delay, real upload success rate) are all preserved.

### 9.1 Bus speed: fixed 11.1 m/s -> per-bus uniform [8.33, 13.89] m/s

Supervisor: "speed 30-50 km/h (variable, not fixed)".

- Constants `BUS_SPEED_MIN_MS = 8.33` and `BUS_SPEED_MAX_MS = 13.89`
  replace the single `BUS_SPEED_MS = 11.1`.
- `SetupBusMobility` now creates a `UniformRandomVariable` and samples
  one speed per bus at simulation init. The speed is held constant for
  the bus's entire route loop (per-bus, not per-segment) so waypoint
  arrival times remain deterministic and reproducible per `--RngRun`.
- Each waypoint now has a paired (arrive, depart) entry separated by
  `STATION_STOP_TIME` (30 s) so the bus actually dwells at every station.
  Previously only one waypoint per stop was emitted, which let
  `WaypointMobilityModel` interpolate straight through and skip the dwell
  for intermediate stops. With paired waypoints the supervisor's "stop
  duration: 30 seconds per station" is now honoured at every stop, not
  only the route endpoints.
- Behavioural impact: per-bus travel time between stations now varies by
  ~70%. Aggregate offered LTE load distribution shifts slightly in time
  but per-bus offered load is unchanged.

### 9.2 DDoS detection trigger: re-enable loss condition

Supervisor: "DDoS conditions (any): rate > threshold OR loss > 5% OR
delay > 100 ms".

- `CheckDDoS` now evaluates `(rateExceeded || lossExceeded ||
  delayExceeded)`. The `lossExceeded` term was suppressed in round 1
  because pre-round-1 baseline PLR was ~36% (false-positive trigger).
  After round-1 (backhaul=100 Mbps, GBR=1.0/1.2 Mbps) baseline PLR is
  predicted 0.5-3%, comfortably below the 5% threshold, so the loss
  term is safe to re-enable.
- The detection event detail string now records which condition tripped
  via a `trip=R/L/D` triplet (e.g. `trip=R-D` if rate and delay tripped
  but loss did not). Useful for post-hoc analysis.
- **Risk if my prediction is wrong**: if baseline PLR exceeds 5% on the
  Linux server, `lossExceeded` will fire false positives in baseline
  runs. Mitigation: see Section 6 validation checklist - if baseline
  PLR > 5% appears, the next knob is to drop CCTV GBR to 0.8/1.0 or
  reduce per-bus telemetry rate. Do **not** silently re-suppress the
  loss term.

### 9.3 GPS detection: remove srcAnomaly from the trigger

Supervisor: GPS conditions are exactly THREE -- speed > 80 km/h, sudden
jump > 1 km within 1 s, location outside route boundary.

- `srcAnomaly` (source-IP-mismatch heuristic) is still computed and
  emitted in the `gps_spoof_detect` event detail field for forensic
  context, but it no longer contributes to `anomalyCount`. The
  literal "any 1-of-3" is now `anomalyCount = speed + jump + corridor`.
- This is a strict tightening: any prior detection that fired *only*
  because srcAnomaly was set will now fail to detect, which is the
  correct behaviour per the spec.

### 9.4 GPS streak gate: 5 -> 1 (default), CLI-overridable

Supervisor: "if any condition is true -> trigger" (literal 1-streak).

- New global `g_gpsStreakRequired` (default 1) replaces the hard-coded
  `static const uint32_t GPS_STREAK_REQUIRED = 5`.
- New CLI flag `--gpsStreakRequired=<N>` allows raising the gate for
  noise-filtering experiments. Round-2 batch runs MUST leave this at
  the default of 1 for spec compliance.
- Combined with 9.3 above, the GPS detector's predicted time-to-detect
  drops from ~5 s (5-streak * 1 pkt/s) to ~1-2 s (first valid reading
  past the dt<0.5 s preprocessing skip).

### 9.5 GPS spoofing attack: real bus position + 5-10 km jump

Supervisor: "inject false coordinates, simulate sudden jump 5-10 km".

- Removed the hard-coded `Vector(14000, 1000, 0)` fake position.
- New free function `LaunchGpsSpoof(...)` is scheduled at `gpsStart`.
  At fire time it reads the target bus's actual position from its
  `MobilityModel`, samples a uniform distance in [5000, 10000] m and
  a uniform random heading in [0, 2 pi), constructs the first fake
  position, then creates and starts a `GpsSpoofAttackApp` from that
  point. The +50 m/pkt drift inside the app continues to satisfy the
  >120 km/h apparent-speed condition.
- New `gps_spoof_launch` event row records the actual jump distance
  per run for compliance evidence.
- The corridor-deviation condition will trip with high probability
  because 5-10 km vastly exceeds the 1.5 km corridor. The jump
  condition will trip on the *transition packet* (real -> fake jump
  > 1 km in <= 1 s).

### 9.6 Bus speed constant cleanup

The old `BUS_SPEED_MS = 11.1` has been removed entirely. A grep of the
file shows zero remaining references; per-bus speed is the only path.

### 9.7 Globals reset between runs

`g_forensicSinkBaselineBytes` and `g_gpsStreakRequired` are now reset/
re-set in `main()` at simulation start so a process running multiple
back-to-back simulations does not leak state.

### 9.8 No commits

All round-2 changes remain uncommitted on `main-dev` per the original
constraint.

---

## 10. Round-2 expected metric ranges (predictions, 41 buses)

### 10.1 Baseline

| Metric | Round-1 prediction | Round-2 prediction | Change vs round-1 |
|---|---|---|---|
| PLR | 0.5 - 3% | 0.5 - 3% | unchanged |
| E2E delay | 20 - 45 ms | 20 - 45 ms | unchanged |
| Throughput | 40 - 42 Mbps | 40 - 42 Mbps | unchanged |
| Queue delay | <1 ms | <1 ms | unchanged |
| `ddos_detect` events | 0 | 0 | unchanged (loss<5%) |
| `gps_spoof_detect` events | 0 | 0 | unchanged |

### 10.2 DDoS (30 Mbps attacker)

| Metric | Round-1 prediction | Round-2 prediction |
|---|---|---|
| PLR | 3 - 8% | 3 - 8% |
| E2E delay | 40 - 90 ms | 40 - 90 ms |
| Queue delay | 5 - 25 ms | 5 - 25 ms |
| TTD DDoS | 5 - 15 s | 5 - 15 s (rate condition still dominates) |
| Forensic completion | >=95% delivered, 16-22 s | unchanged |

The loss-trigger re-enable does not advance TTD because rate normally
trips before loss (rate threshold at 15 Mbps is reached within the
first 10-second sampling interval after attack start; loss takes
several intervals to accumulate to 5%).

### 10.3 DDoS + GPS spoof

Same network metrics as DDoS. GPS detection changes:

| Metric | Round-1 prediction | Round-2 prediction |
|---|---|---|
| GPS TTD | ~3 s | **1 - 2 s** (streak 5 -> 1) |
| GPS detection events | >=1 | >=1 |
| GPS false positives in baseline | 0 | 0 |
| Real-to-fake jump distance | 8 km (hard-coded) | uniform in [5, 10] km per run |

### 10.4 1-bus and 10-bus

Unchanged: ~0% PLR, ~25 ms delay, throughput proportional to bus count.
With variable speed (8.3-13.9 m/s) the 1-bus tour completes its loop in
roughly 70%-150% of the previous fixed-speed time, depending on RNG
draw, but no metric is sensitive to this.

---

## 11. Post-round-2 validation checklist

In addition to Section 6:

- [ ] Speed anomaly false-positive rate is 0 in baseline (no `gps_spoof_detect`
      with `mode=any` from speed-only triggers, given variable speed
      caps at 50 km/h < 80 km/h threshold).
- [ ] `gps_spoof_launch` event present in all `ddos_gps` runs with jump in [5000, 10000] m.
- [ ] `gps_spoof_detect` first-event time within 1-2 s of `gps_spoof_launch`.
- [ ] `ddos_detect` event detail field includes `trip=R..` (rate is the
      typical first-trip condition).
- [ ] Bus 0 dwell at first station: position constant for >= 30 s
      starting at t=0 (verify in mobility trace if enabled).

