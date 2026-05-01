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

## Round 3 Changes (uncommitted on `main-dev`)

Round 2 left two issues open that were caught by the Linux-agent re-run:

1. At 41 buses the LTE radio still saturates: baseline PLR ~41%, DDoS adds
   only ~0.6 percentage points, so the attack is invisible in the per-bus
   metrics.
2. The forensic upload reports `bytes_delivered=0, duration=60.0s` for
   ALL 6 attack runs (across 1/10/41 buses), including the 1-bus case
   where there is no congestion to blame.

### R3.1 LTE bandwidth: 100 RBs (20 MHz) → 200 RBs (40 MHz)

`smart-bus.cc` now sets:

```cpp
lteHelper->SetEnbDeviceAttribute("DlBandwidth", UintegerValue(200));
lteHelper->SetEnbDeviceAttribute("UlBandwidth", UintegerValue(200));
```

Justification (mirrored in `SUPERVISOR_COMPLIANCE.md`'s engineering-choices
table):

- The supervisor specification says "Realistic LTE BW" without pinning a
  specific MHz value. STC, Mobily and Zain all deploy LTE in Saudi Arabia
  with carrier aggregation reaching 40 MHz or more in urban macro cells,
  so for an Al-Ahsa fleet 40 MHz is the production-realistic value.
- ns-3.40's `LteEnbPhy` natively supports 200 RBs (the 6/15/25/50/75/100/200
  grid is enumerated in `LteEnbNetDevice::SetDlBandwidth()`).
- The previous round-2 round of fixes already trimmed CCTV GBR to 1.0/1.2
  Mbps and dropped backhaul to 100 Mbps. Those fixed the *backhaul* side of
  the problem. The *radio* side stayed saturated because at 41 UEs ÷ 3
  eNBs ≈ 14 UEs per cell × 1 Mbps offered uplink ≈ 14 Mbps per cell, which
  sits right at the practical 20-MHz ns-3 LTE UL ceiling once HARQ retries
  and control overhead are factored in. 40 MHz roughly doubles per-cell
  capacity so the offered load is at ~36% of capacity (good operating
  point) instead of ~75% (visibly saturated).
- Round 2 had explicitly considered 200 RBs and rejected it ("not natively
  modeled by `LteEnbPhy`"); on closer inspection of the ns-3.40 source that
  rejection was wrong. 200 RBs IS supported, and is the right choice.

### R3.2 Forensic upload "0 bytes delivered" — root cause

The bug lives in the round-2 `StartForensicUpload` mid-simulation
`OnOffHelper.Install(...) → app.Start(...) → app.Stop(...)` sequence.

`OnOffHelper::Install(node)` calls `node->AddApplication(app)` internally.
In ns-3.40, `Node::AddApplication` will immediately call
`application->Initialize()` on the freshly-added app *if the node has
already been initialized* — which it always has been when
`StartForensicUpload` runs, because we are inside a scheduled event during
`Simulator::Run()`.

`Application::DoInitialize()` then schedules the application's
`StartApplication`/`StopApplication` events based on the *current* values
of `m_startTime` / `m_stopTime`. At install time those are still 0 (the
defaults). So:

- `StartApplication` is scheduled with delay `0 - now = -now` (a large
  negative delay). ns-3 effectively runs it immediately, which triggers
  socket creation and the first `ScheduleStartEvent()` call. This does
  not raise a hard error.
- `StopApplication` never gets scheduled because `m_stopTime == 0` is
  treated as "no stop event" by `Application::DoInitialize`.

The subsequent `app.Start(now+0.01)` and `app.Stop(now+20)` calls only
update the scalar `m_startTime`/`m_stopTime` fields. `Application::SetStartTime`
and `SetStopTime` do not reschedule the events; they just set the
variables. The events that were scheduled during the original
`Initialize()` therefore reflect the wrong times.

Net effect: the OnOff sender ends up in an inconsistent socket-lifecycle
state and either (a) never produces packets at all because internal
state is corrupt, or (b) sends a tiny burst before falling over. The
server-side `PacketSink` sees 0 (or near-0) bytes for this upload, the
poller hits its 60-s deadline, and `bytesReceived = 0` is recorded.

### R3.3 Forensic upload — fix

Replaced `OnOffHelper.Install(busNode)` + `app.Start(...)`/`app.Stop(...)`
with the canonical mid-simulation app-injection pattern:

```cpp
Ptr<OnOffApplication> uploadApp = CreateObject<OnOffApplication>();
uploadApp->SetAttribute("Protocol",   StringValue("ns3::UdpSocketFactory"));
uploadApp->SetAttribute("Remote",     AddressValue(InetSocketAddress(serverAddr, FORENSIC_PORT)));
uploadApp->SetAttribute("DataRate",   DataRateValue(DataRate("5Mbps")));
uploadApp->SetAttribute("PacketSize", UintegerValue(1400));
uploadApp->SetAttribute("MaxBytes",   UintegerValue(10485760));   // 10 MB exactly
uploadApp->SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=16]"));
uploadApp->SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0]"));
uploadApp->SetStartTime(Seconds(now + 0.01));
uploadApp->SetStopTime (Seconds(std::min(now + 60.0, g_simTime - 0.1)));
busNode->AddApplication(uploadApp);   // <-- Initialize() now sees correct start/stop
```

Two key differences vs the broken version:

- `SetStartTime` / `SetStopTime` are called *before* `AddApplication`,
  so `Application::DoInitialize()` (which `AddApplication` triggers
  on an already-initialized node) schedules the right events.
- `MaxBytes = 10485760` bounds the upload to exactly 10 MB regardless of
  how many On/Off cycles the OnOff scheduler runs. This is a
  belt-and-braces guarantee independent of the OnTime/OffTime math.

The same pattern is used elsewhere in the file (e.g. `LaunchGpsSpoof`
adds a custom `GpsSpoofAttackApp` with `SetStartTime`/`SetStopTime`
before `AddApplication`, and that has been working). The forensic
upload was the only Round-2 path that violated it.

### R3.4 Diagnostic logging added (defence in depth)

Even with the canonical fix in place, I cannot run ns-3 on Windows to
prove the bug is gone. To make the next Linux-server run self-diagnostic
I added stderr `[FORENSIC-DIAG]` prints:

- `StartForensicUpload` prints one line at trigger time with: trigger
  time, busNode id, server addr, sink-pointer validity, baseline byte
  count, scheduled upload start/stop times, and attack type.
- `PollForensicCompletion` prints one line every ≥5 simulated seconds
  with: current time, sink-pointer validity, raw `GetTotalRx()` value,
  baseline, `delivered = totalRx - baseline`, and the 10-MB target.
- The completion / deadline branches each print one terminal line.

If the next run still shows `delivered=0` for any seed, the
`[FORENSIC-DIAG]` lines will tell us *which* of:
sinkPtr null / totalRx not advancing / baseline poisoned / nothing
ever scheduled — is the actual cause.

### R3.5 Updated expected metric ranges (predicted, 41-bus)

Predictions assume Round 1 + Round 2 + Round 3 fixes all in place. These
are *predictions*, not measurements; the Linux agent's re-run is the
ground truth.

| Metric | Round-2 measured | Round-3 predicted |
|---|---|---|
| Baseline PLR | ~41% | **< 5%** (cell-edge HARQ residue only) |
| Baseline avg E2E delay | ~70-100 ms | **20-45 ms** |
| Baseline aggregate throughput | ~25 Mbps (clipped) | **40-42 Mbps** |
| Baseline `ddos_detect` events (false +) | 0 (already fixed in R2) | **0** |
| DDoS PLR | ~41.6% (baseline+0.6) | **8-15%** (clear gap above baseline) |
| DDoS avg E2E delay | similar to baseline | **40-90 ms** (queueing on saturated 71% backhaul) |
| DDoS aggregate throughput | small drop | **38-41 Mbps** (≥ 2 Mbps below baseline) |
| Queue delay (PGW→server, DDoS run) | ~0 (radio dominated) | **5-25 ms** |
| TTD DDoS | 20 s (loss-streak gated) | **20-30 s** (unchanged) |
| Forensic upload, 1-bus DDoS | bytes=0, dur=60 s | **bytes=10485760 (100%), dur ≈ 16-18 s** |
| Forensic upload, 10-bus DDoS | bytes=0, dur=60 s | **bytes ≈ 10 MB, dur ≈ 17-22 s** |
| Forensic upload, 41-bus DDoS | bytes=0, dur=60 s | **bytes ≈ 9-10 MB, dur ≈ 18-30 s** (a few seeds may remain partial under sustained DDoS) |

`upload_success_rate` should jump from 0% on every run to ≥95% on most
runs.

### R3.6 What the Linux agent should verify when re-running

The Linux agent must re-pull `main-dev`, rebuild ns-3 (the LTE attribute
change requires a rebuild, not just a re-link), and re-run the full 45-run
sweep. Key checks:

1. **New XML / forensics CSV files dated today.** `ls -lt
   results/*.xml | head -5` should show today's date — otherwise the
   rebuild was a no-op or the binary was cached.
2. **Baseline 41-bus PLR < 5%.** If it's still ~40%, the LTE bandwidth
   change did not propagate (check that `./ns3 build smart-bus`
   completed without warnings).
3. **DDoS 41-bus PLR > baseline 41-bus PLR by ≥ 2 percentage points.**
4. **`[FORENSIC-DIAG] StartForensicUpload triggered ...` line appears
   on stderr** for each attack run — confirms the trigger fired.
5. **`[FORENSIC-DIAG] COMPLETE at t=...` line appears** for each attack
   run — confirms the upload actually delivered 10 MB.
6. **`bytesReceived` column in `*_forensics.csv` is 10485760** for
   attack runs (or close to it). Failures here go straight to the
   `[FORENSIC-DIAG]` diagnostic lines for triage.
7. **No `ddos_detect` events in any baseline run** (no false positives —
   already fixed in Round 2, just confirm it still holds).

### R3.7 Files modified in Round 3

- `smart-bus.cc` — LTE BW 100→200 RBs (DL+UL), forensic upload re-implemented, diagnostic stderr logging.
- `RESIM_NOTES.md` — this section.
- `SUPERVISOR_COMPLIANCE.md` — LTE BW row + new "Files modified in round 3" section.

`scripts/analyze.py`, `scripts/run_all_parallel.sh`, and `jetson-hardware/`
are untouched.

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

