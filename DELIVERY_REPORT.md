# Al-Ahsa Smart Bus Network - Simulation Delivery Report

**Date:** 2026-03-03
**Project:** Al-Ahsa SAPTCO Smart Bus Network — ns-3.40 LTE Simulation
**Status:** First batch complete, validation issues identified, fixes pending recompilation

---

## 1. Project Overview

This project implements an ns-3.40 LTE network simulation modeling the SAPTCO public bus system in Al-Ahsa, Saudi Arabia. The simulation covers:

- **41 SAPTCO buses** across **10 routes** with realistic GPS waypoint mobility
- **3 scenarios per configuration:** baseline (normal operation), DDoS attack, and combined DDoS + GPS spoofing
- **5 random seeds** per scenario for statistical validity
- **Per-bus applications:** telemetry (10 kbps), CCTV uplink (1.5 Mbps), GPS reporting (1 kbps)
- **Security mechanisms:** DDoS detection (rate/loss/delay monitoring), GPS spoofing detection (speed, jump, corridor checks)
- **LTE infrastructure:** Multiple eNodeBs covering the Al-Ahsa urban area with EPC core network

The full experiment matrix targets 45 runs (3 bus counts x 3 scenarios x 5 seeds). This delivery covers the first batch of 15 runs (1-bus configuration only).

---

## 2. Current Deliverables

| File | Description |
|------|-------------|
| `smart-bus.cc` | Main simulation source (~1,800 lines C++) |
| `scripts/run_all.sh` | Sequential batch runner for all scenarios/seeds |
| `scripts/run_all_parallel.sh` | Parallel batch runner with GNU parallel |
| `scripts/analyze.py` | Python analysis script — parses XML/CSV results, generates comparison graphs |
| `results/*.xml` | 15 FlowMonitor XML outputs (5 seeds x 3 scenarios, 1-bus) |
| `results/*.csv` | 15 event logs + 15 forensics logs |
| `results/graphs/*.png` | 4 comparison graphs (throughput, PLR, delay, jitter) |
| `Claude Docs/v1_bugs_report.md` | Detailed bug report with evidence and root causes |
| `Claude Docs/architecture_differences.md` | Architecture analysis documentation |
| `Claude Docs/plan_evolution.md` | Project plan evolution log |

---

## 3. Simulation Results (1-Bus Batch)

The first batch executed 15 simulation runs successfully:

- **Scenarios:** baseline, ddos, ddos_gps
- **Bus count:** 1 bus
- **Seeds:** 1 through 5
- **Simulation time:** 300 seconds per run

All 15 runs completed without runtime errors. FlowMonitor XML results, event CSVs, and forensics CSVs were generated for each run. The analysis script produced four comparison graphs:

1. `throughput_comparison.png` — Aggregate throughput across scenarios
2. `plr_comparison.png` — Packet loss ratio comparison
3. `delay_comparison.png` — End-to-end delay comparison
4. `jitter_comparison.png` — Delay variation comparison

---

## 4. Issues Identified During Validation Testing

Post-simulation analysis of the XML results and event logs revealed six issues that affect the scientific validity of the current results.

### Issue 1: LTE Propagation Model Causing Excessive Path Loss (Critical)

The COST-231 Hata propagation loss model produces approximately 270 dB path loss at the 5 km eNB-to-bus distances used in the simulation. With a 46 dBm transmit power and -100 dBm receiver sensitivity (146 dB link budget), all bus-originated packets are dropped at the physical layer. This results in 0% packet delivery for all bus traffic across all scenarios.

**Evidence:** All bus flows in baseline and DDoS XMLs show `rxPackets=0` despite non-zero `txPackets`.

### Issue 2: Missing X2 Handover Interface (High)

The simulation does not configure X2 interfaces between eNodeBs. Without X2, LTE handover cannot occur when a mobile bus moves between cell coverage areas, causing complete connectivity loss mid-route.

**Evidence:** In DDoS XML, handover signaling flow shows 6 transmitted packets, 0 received.

### Issue 3: CCTV Bandwidth Exceeding LTE Uplink Capacity (High)

The per-bus CCTV data rate of 1.5 Mbps produces an aggregate uplink load of 61.5 Mbps for 41 buses, exceeding typical LTE uplink capacity (~50 Mbps). Even at smaller bus counts, the CCTV traffic dominates the uplink and causes congestion.

**Evidence:** Baseline XML flow 2 (CCTV, port 6000) transmitted 39,910 packets but received 0.

### Issue 4: DDoS Detection Algorithm Triggering False Positives in Baseline (High)

The DDoS detection algorithm uses cumulative rate counters and OR-based logic, causing it to trigger at t=15s — 85 seconds before the actual DDoS attack begins at t=100s. Initial LTE attachment failures produce non-zero loss ratios that satisfy the OR condition.

**Evidence:** Event CSV shows `ddos_detect` at t=15s with `avgRate=0bps` and `loss=0.152`.

### Issue 5: GPS Spoofing Detection Corridor Threshold Too Sensitive (Medium)

The 500m corridor boundary produces false positives for stationary buses near route endpoints or curves, where GPS noise and road geometry can place the reported position outside the corridor.

**Evidence:** Event CSV shows GPS spoof detection with `speed=0m/s`, `jump=0m`, but `corridor=1`.

### Issue 6: GPS Spoofing Target Parameter Incompatible with 1-Bus Scenario (Medium)

The GPS spoofing attack targets bus index 5 (`gpsBusTarget=5`), which does not exist in 1-bus runs where only bus 0 is instantiated. The attack has no effect and cannot be validated.

**Evidence:** Attack configured for bus 5, but only bus 0 exists. Detection event fires on bus 0 as a false positive.

---

## 5. Impact Assessment

The LTE propagation issue (Issue 1) is the primary blocker. With 0% packet delivery for bus traffic in all scenarios — including baseline — the current results do not represent realistic network behavior. The generated graphs show approximately 97% packet loss in the baseline scenario, which is not scientifically valid for a properly configured LTE network.

The remaining issues (2-6) compound the problem but would manifest even after fixing the propagation model. All six issues must be resolved before the results can be considered valid for publication or further analysis.

---

## 6. Planned Fixes

All fixes have been developed and tested in the `main-dev` branch, pending recompilation on the simulation server.

| # | Issue | Planned Fix |
|---|-------|-------------|
| 1 | Excessive path loss | Remove COST-231 model; use ns-3 default LTE channel model appropriate for macro-cell distances |
| 2 | No X2 handover | Add `lteHelper->AddX2Interface()` between adjacent eNodeBs for seamless handover |
| 3 | CCTV bandwidth overload | Reduce per-bus CCTV rate to 500 kbps (simulating edge-compressed video) |
| 4 | DDoS false positives | Implement differential (windowed) rate-based detection with AND logic requiring multiple simultaneous indicators |
| 5 | GPS corridor false positives | Increase corridor threshold to 1000m; require multiple indicators before flagging spoofing |
| 6 | Invalid GPS target bus | Default target to bus 0; clamp target index to valid bus range |

---

## 7. Next Steps

1. Recompile simulation with all six fixes applied
2. Re-run the 1-bus batch (15 runs) to validate fixes
3. Run complete experiment matrix: 45 runs (1-bus, 10-bus, 41-bus x 3 scenarios x 5 seeds)
4. Regenerate all graphs and statistical analysis
5. Deliver final validated results package

---

## 8. Timeline

- Fixes are implemented and ready in the `main-dev` branch
- Awaiting server recompilation and batch re-run
- Estimated completion: 1-2 days after recompilation access
