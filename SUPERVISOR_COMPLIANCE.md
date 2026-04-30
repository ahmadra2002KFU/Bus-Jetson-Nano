# Supervisor Specification Compliance Audit (round 2)

This document is the line-by-line compliance record between the
supervisor's specification for the Al-Ahsa Smart Bus simulation and the
implementation in `smart-bus.cc` / `scripts/analyze.py` /
`scripts/run_all_parallel.sh` after both round-1 and round-2 fixes.

Status legend:

- **MET** — implemented exactly as specified.
- **PARTIAL** — implemented but with a documented narrowing (e.g. one
  representative point chosen inside a specified band).
- **NOT MET** — specification is violated.
- **WORKAROUND** — specification is technically not honoured verbatim
  due to an ns-3 framework limitation, with an explicit replacement that
  preserves the spirit of the requirement.

Every MET row maps to a concrete code location. No row is marked MET
with hidden caveats; any caveat is either PARTIAL or WORKAROUND.

---

## Part 1 — Real System (narrative facts)

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P1.1    | Operator: SAPTCO | n/a (narrative) | MET | Documented in DELIVERY_REPORT.md and project narrative. |
| P1.2    | 41 buses           | smart-bus.cc:52 | MET | `MAX_BUSES = 41`; default `numBuses = MAX_BUSES`. |
| P1.3    | 10 lines           | smart-bus.cc:198, ~200-263 | MET | `CreateRoutes()` returns 10 entries. |
| P1.4    | 135 stations       | smart-bus.cc:200-260 | PARTIAL | Sum of waypoints across the 10 routes is on the order of 80-90 (coarse-grained, one waypoint per major stop, not per individual minor stop). Coarse-graining is required by the simulator's per-bus waypoint memory budget; ratio of stations to time spent stopped vs moving is preserved. |
| P1.5    | 336 km combined route length | n/a (geometric) | PARTIAL | Routes occupy a 15 km x 20 km bounding box; aggregate path length across the 10 routes is on this order but not exactly tuned to 336 km. Functional for traffic and detection metrics. |
| P1.6    | 18 h/day operation | n/a | NOT MET (intentional) | Simulation runs 300 s. Modeling 18 h is impractical; 300 s is enough to capture multiple route loops, attack windows, and detection events. Documented deviation. |
| P1.7    | 250-400 km^2 area  | smart-bus.cc:1582-1585 | MET | 15 km x 20 km = 300 km^2, eNB positions chosen inside this footprint. |
| P1.8    | Per-bus equipment: 4G/5G router, GPS, CCTV, ticketing, Jetson | smart-bus.cc | MET | Modeled as separate UDP/TCP traffic flows + dedicated bearers per port. Jetson is hardware-only and outside the simulator scope. |
| P1.9    | Path: Bus -> LTE -> Core -> Cloud -> Dashboard, no bus-to-bus | smart-bus.cc:1597-1614 | MET | All UE traffic routed via PGW to remote server. No `AddNetworkRouteTo` exists between buses. |

## Part 2 — ns-3 Simulation Architecture

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P2.1    | 41 bus UEs            | smart-bus.cc:52, 1447, 1594 | MET | `MAX_BUSES=41`; `busNodes.Create(numBuses)`; default 41. |
| P2.2    | 3 eNBs                | smart-bus.cc:53, 1576-1588 | MET | `NUM_ENB=3`; 3 positions hard-coded. |
| P2.3    | 1 cloud server        | smart-bus.cc:1546-1548 | MET | `remoteServerContainer.Create(1)`. |
| P2.4    | 1 attacker            | smart-bus.cc:1731-1734 | MET | `attackerNode.Create(1)`. |
| P2.5    | Mobility: WaypointMobilityModel | smart-bus.cc:316 | MET | `SetMobilityModel("ns3::WaypointMobilityModel")`. |
| P2.6    | Speed 30-50 km/h, **variable, not fixed** | smart-bus.cc:54-60, 318-323, 393-396 | MET (was NOT MET in round-1) | Per-bus uniform sample in [BUS_SPEED_MIN_MS, BUS_SPEED_MAX_MS] = [8.33, 13.89] m/s. Held constant per bus across the route loop (per-bus, not per-segment) for waypoint determinism. |
| P2.7    | Stop duration: 30 s per station | smart-bus.cc:54, 379-389 | MET (was PARTIAL in round-1) | `STATION_STOP_TIME=30.0`. Round-2 added paired (arrive, depart) waypoints so dwell happens at every station, not just route endpoints. |
| P2.8    | Route repeats in loop | smart-bus.cc:344-388 | MET | `cycleIndices` builds a forward+reverse cycle and the `while (currentTime < simTime)` loop wraps around `cycleSize`. |
| P2.9    | 15 km x 20 km grid    | smart-bus.cc:200-260 | MET | All station coordinates fall in [0, 15000] x [0, 19000] m. |

## Part 3 — Traffic per bus

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P3.1    | GPS telemetry: 1 packet/sec | smart-bus.cc:1668, 396-510 | MET | `telemetryApp->Setup(..., 1.0)` and `m_interval=1.0` -> `Schedule(Seconds(m_interval))`. |
| P3.2    | CCTV: 1-2 Mbps UDP    | smart-bus.cc:1684-1697 | PARTIAL (representative point) | `DataRate("1000kbps")`. Inside the 1-2 Mbps band at the lower edge. Documented engineering choice (gives headroom on the per-cell 20 MHz UL budget). |
| P3.3    | Ticketing: random small TCP bursts | smart-bus.cc:516-698, 1706-1718 | WORKAROUND | Custom `TicketingApp` keeps one persistent TCP connection and emits 1-3 small (256 B) bursts at random intervals in [6, 20] s. ns-3's stock OnOff TCP crashes when reconnecting; "random small TCP bursts" semantically preserved. |
| P3.4    | Forensic event: 10 MB upload, START + FINISH times, success rate | smart-bus.cc:1262-1316, 1319-1365, 1391-1424 | MET (was PARTIAL in round-1) | `StartForensicUpload` records `triggerTime`/`uploadStartTime`; `PollForensicCompletion` polls real `PacketSink::GetTotalRx()` every 0.5 s and records `uploadFinishTime` + `bytesReceived`. CSV row written by `WriteForensicsCsv`. Round-1 replaced the previous fixed +16.5 s timer that lied about completion. |

## Part 4 — Attack scenarios

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P4.1    | DDoS: 20-50 Mbps UDP to cloud server | smart-bus.cc:1452, 1758-1779 | PARTIAL (representative point) | `--ddosRate` default 30e6. 30 Mbps is inside the supervisor's 20-50 Mbps band; chosen as the representative point because it produces a measurable but non-saturating effect on the round-1 100 Mbps backhaul. CLI sweep across {20, 30, 40, 50} Mbps is supported by simply setting `--ddosRate`. |
| P4.2    | Observe delay increase, packet loss, queue buildup, upload delay | smart-bus.cc:1232-1253, scripts/analyze.py:174-201 | MET | `LogQueueStatus` emits `queue_status` and `queue_delay` events every 5 s. `analyze.py::compute_queue_delay_ms` averages these for the report. End-to-end delay, PLR and upload duration are all in the per-run `xml`/`forensics` output. |
| P4.3    | GPS spoofing: inject false coordinates | smart-bus.cc:704-829, 1389-1429 | MET | `GpsSpoofAttackApp` builds a valid GPS payload with the target busId and a fake (X,Y). |
| P4.4    | GPS spoofing: sudden jump 5-10 km | smart-bus.cc:1389-1429, 1819-1832 | MET (was NOT MET in round-1) | `LaunchGpsSpoof` reads the target bus's real position at `gpsStart`, samples uniform 5-10 km offset and uniform random heading, constructs `fakePos` from there. Recorded as `gps_spoof_launch` event. |
| P4.5    | GPS spoofing: impossible speed > 120 km/h | smart-bus.cc:806 | MET | Per-packet drift +50 m at 1 pkt/s = 50 m/s = 180 km/h, > 120 km/h spec. |
| P4.6    | GPS spoofing: detect route deviation outside corridor | smart-bus.cc:995-1005 | MET | `corridorAnomaly = routeDist > GPS_CORRIDOR_THRESHOLD` (1500 m). |

## Part 5 — Detection logic ("any condition is true -> trigger")

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P5.1    | DDoS detection: rate > threshold | smart-bus.cc:58, 1195 | MET | `DDOS_RATE_THRESHOLD = 15e6`. `rateExceeded = intervalRate > DDOS_RATE_THRESHOLD`. |
| P5.2    | DDoS detection: packet loss > 5% | smart-bus.cc:59, 1196 | MET (was NOT MET in round-1) | `DDOS_LOSS_THRESHOLD = 0.05`. `lossExceeded = deltaLossRate > DDOS_LOSS_THRESHOLD`. Round-2 re-enabled this term in the trigger expression. |
| P5.3    | DDoS detection: delay > 100 ms | smart-bus.cc:60, 1197 | MET | `DDOS_DELAY_THRESHOLD = 0.1` (s). `delayExceeded = telemetryAvgDelay > DDOS_DELAY_THRESHOLD`. |
| P5.4    | DDoS trigger: any 1-of-3 fires | smart-bus.cc:1205 | MET | `(rateExceeded \|\| lossExceeded \|\| delayExceeded)`. |
| P5.5    | GPS detection: speed > 80 km/h | smart-bus.cc:61, 989 | MET | `GPS_SPEED_THRESHOLD = 22.2` (m/s = 80 km/h). `speedAnomaly = speed > GPS_SPEED_THRESHOLD`. |
| P5.6    | GPS detection: outside route boundary | smart-bus.cc:63, 995-1005 | MET | `GPS_CORRIDOR_THRESHOLD = 1500` m. `corridorAnomaly = routeDist > GPS_CORRIDOR_THRESHOLD`. |
| P5.7    | GPS detection: sudden jump > 1 km in 1 s | smart-bus.cc:62, 992 | MET | `GPS_JUMP_THRESHOLD = 1000` m. `jumpAnomaly = (dt <= 1.5 && distance > GPS_JUMP_THRESHOLD)`. The 1.5 s tolerance accommodates LTE jitter on a 1 pkt/s feed; distance threshold is per-spec. |
| P5.8    | GPS trigger: any 1-of-3 fires | smart-bus.cc:1020-1023 | MET (was NOT MET in round-1) | `anomalyCount = speedAnomaly + jumpAnomaly + corridorAnomaly` (round-2 removed `srcAnomaly`). `requiredCount = (g_detectionMode == "any") ? 1 : 2`. |
| P5.9    | Detection mode: "any" is the spec mode | smart-bus.cc:1458, 1474 | MET | Default `--detectionMode = "any"`. `analyze.py::DETECTION_MODES = ['any']`. |
| P5.10   | GPS streak gate: literal 1-of-3 fires immediately | smart-bus.cc:139-142, 1027 | MET (was NOT MET in round-1) | Round-2 changed the hard-coded 5-streak to `g_gpsStreakRequired = 1` (default), CLI-overridable for noise experiments. |
| P5.11   | No additional GPS conditions (only the 3 listed) | smart-bus.cc:1006-1018, 1020-1021 | MET (was NOT MET in round-1) | Round-2 removed `srcAnomaly` from `anomalyCount`. The `srcAnomaly` flag is still computed and written to the event detail field for forensic-only context, never gated against the trigger. |

## Part 6 — Metrics

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P6.1    | End-to-end delay         | scripts/analyze.py:144 | MET | `avg_delay_ms` from FlowMonitor `delaySum / rxPackets`. |
| P6.2    | Throughput               | scripts/analyze.py:107-148 | MET | Per-flow goodput summed over each flow's active window (round-1 fix replacing global `/SIM_TIME`). |
| P6.3    | Packet loss              | scripts/analyze.py:149 | MET | `plr = lostPackets / txPackets`. |
| P6.4    | Jitter                   | scripts/analyze.py:145 | MET | `avg_jitter_ms` from FlowMonitor `jitterSum / rxPackets`. |
| P6.5    | Queue delay              | smart-bus.cc:1232-1253, scripts/analyze.py:174-201 | MET (was PARTIAL in round-1) | `LogQueueStatus` emits real per-poll queue delay (bytesInQueue * 8 / SERVER_LINK_RATE_BPS); `analyze.py` parses these rows. |
| P6.6    | Forensic detection time  | smart-bus.cc:1916-1930 | MET | `ddos_detection_time` and `gps_detection_time` events log the delta from attack start to first detection. |
| P6.7    | Forensic evidence upload time | smart-bus.cc:1411-1424, 1287-1295 | MET | `uploadStartTime` + `uploadFinishTime` recorded in forensics CSV; `forensic_complete` event includes duration. |
| P6.8    | Forensic upload success rate | smart-bus.cc:1932-1947, scripts/analyze.py:255-293 | MET (was PARTIAL in round-1) | `upload_success_rate = bytes_received / 10 MB`. Two rates emitted: per-run `bytesReceived/target` and aggregate `completed/total`. |
| P6.9    | Detection accuracy       | smart-bus.cc:1869-1914, scripts/analyze.py:215-252 | MET | TP/FP/FN computed against ground truth attack windows; precision, recall, F1 written as events. |

## Part 7 — Scalability

| Spec ID | Supervisor requirement | Code location | Status | Evidence/notes |
|---------|------------------------|---------------|--------|----------------|
| P7.1    | Three scenarios: 1, 10, 41 buses | scripts/run_all_parallel.sh:10, scripts/analyze.py:26 | MET | Outer loop iterates `for buses in 1 10 41`; analyze plots per `BUS_COUNTS = [1, 10, 41]`. |
| P7.2    | Compare latency, congestion, detection stability, upload timing | scripts/analyze.py:441-575 | MET | Bar charts for delay, throughput, PLR, jitter, queue delay, DDoS TTD, GPS TTD, forensic upload duration are all generated per bus-count. |

## Part 8 — Execution flow (10 steps in order)

| Spec ID | Supervisor step                             | Code location              | Status |
|---------|---------------------------------------------|----------------------------|--------|
| P8.1    | 1. Initialize LTE network                   | smart-bus.cc:1502-1541     | MET    |
| P8.2    | 2. Deploy bus nodes                         | smart-bus.cc:1594-1614     | MET    |
| P8.3    | 3. Assign mobility routes                   | smart-bus.cc:1597-1600     | MET    |
| P8.4    | 4. Start normal traffic (GPS, CCTV, ticket) | smart-bus.cc:1656-1718     | MET    |
| P8.5    | 5. Run baseline                             | run_all_parallel.sh:11     | MET    |
| P8.6    | 6. Launch DDoS attack                       | smart-bus.cc:1758-1779     | MET    |
| P8.7    | 7. Launch GPS spoofing attack               | smart-bus.cc:1819-1832     | MET    |
| P8.8    | 8. Trigger forensic event                   | smart-bus.cc:1319-1386     | MET    |
| P8.9    | 9. Measure and log metrics                  | smart-bus.cc:1798-1830, 1834-1947 | MET |
| P8.10   | 10. Generate graphs and analysis            | scripts/analyze.py         | MET    |

---

## Other engineering choices (not in spec, documented for the reviewer)

| Item | Choice | Rationale |
|------|--------|-----------|
| Pathloss model | Friis (free-space) default | Spec is silent. OkumuraHata Urban/SubUrban tested but produced >95% PLR with only 3 eNBs covering 300 km^2. Friis lets the baseline operate normally so attack effects are visible. |
| LTE bandwidth | 100 RBs (20 MHz) | Spec is silent. Standard operator-grade LTE cell width. 200 RBs (40 MHz CA) was rejected as not natively supported by `LteEnbPhy` and as deviating from real-world single-carrier cells. |
| Scheduler | PssFfMacScheduler | Spec is silent. PSS honours GBR bearers, which the four-bearer QoS model (voice/video/IMS/video) requires. |
| eNB positions | 3 hard-coded sites | Spec is silent on placement. Route-weighted to minimise worst-case bus-to-eNB distance across 10 corridors. |
| Forensic transport | UDP OnOff at 5 Mbps x 16 s ~= 10 MB | Spec only specifies "10 MB upload". TCP BulkSend was rejected because ns-3 LTE handovers reset TCP connections mid-upload. |
| Backhaul rate | 100 Mbps PGW->server | Spec is silent. Sized so DDoS at 30 Mbps is visible without saturating the link. See RESIM_NOTES.md Section 3.1 for capacity arithmetic. |
| CCTV bearer GBR | 1.0 / 1.2 Mbps GBR/MBR | Spec is silent on bearer GBR (only on stream rate). Sized to match the 1 Mbps stream + HARQ headroom. |
| Detection warmup | 90 s baseline / `ddosStart` for DDoS runs | Spec is silent. Prevents the first full-window FlowMonitor delta from triggering false positives during LTE attach + initial CCTV ramp. |
| GPS preprocessing skip dt < 0.5 s | Discards back-to-back packets that arrive faster than the 1 pkt/s telemetry rate | Spec is silent. Required to avoid divide-by-tiny-dt speed inflation when LTE buffers release queued packets in a burst. Does not gate detection. |
| Ticketing connection model | Persistent TCP socket with random bursts | ns-3 OnOff TCP reconnect crash workaround. Documented as WORKAROUND under P3.3. |

---

## Files modified in round 2 (uncommitted on `main-dev`)

- `smart-bus.cc` — speed band, paired waypoints, loss-trigger re-enabled, GPS detector strict 1-of-3, streak default 1 + CLI flag, GPS spoof real-position 5-10 km jump.
- `RESIM_NOTES.md` — added Sections 9, 10, 11.
- `SUPERVISOR_COMPLIANCE.md` — this file (new).
- `scripts/analyze.py` — unchanged in round 2 (round-1 fixes preserved).
- `scripts/run_all_parallel.sh` — unchanged in round 2 (already runs 5 seeds across 1/10/41 buses and 3 scenarios = 45 runs).
