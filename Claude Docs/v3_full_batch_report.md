# Smart-Bus v3 Full Batch Report

Date: 2026-03-04
Branch: main-dev (commit 01148bd)
Results directory: scratch/smart-bus/results/full_v3_20260304/
Total runs: 45 (3 bus counts x 3 scenarios x 5 seeds)

---

## 1. Test Matrix

| Bus Count | Baseline | DDoS Only | DDoS + GPS Spoof |
|-----------|----------|-----------|------------------|
| 1 bus     | 5 seeds  | 5 seeds   | 5 seeds          |
| 10 buses  | 5 seeds  | 5 seeds   | 5 seeds          |
| 41 buses  | 5 seeds  | 5 seeds   | 5 seeds          |

Each simulation runs for 200 seconds of simulated time. DDoS attack starts at t=100s. GPS spoofing starts at t=150s.

---

## 2. Flow Architecture

Each bus generates 3 application flows:

| Flow Type | Port | Protocol | Rate | Purpose |
|-----------|------|----------|------|---------|
| GPS Telemetry | 5000 | UDP | 200B every 0.5s | Real-time position reporting |
| CCTV Stream | 6000 | UDP | 500 kbps continuous | Video surveillance |
| Ticketing | 7000 | UDP | Event-driven bursts | Passenger transaction data |

Attack flows (when enabled):

| Flow Type | Port | Protocol | Source | Rate |
|-----------|------|----------|--------|------|
| DDoS Flood | 5000 | UDP | 2.0.0.2 | 30 Mbps continuous |
| GPS Spoof | 5000 | UDP | 3.0.0.2 | 30 packets total (1/s for 30s) |

---

## 3. Results: 1-Bus Scenarios

### 3.1 Network Performance (Averaged Across 5 Seeds)

| Metric | Baseline | DDoS | DDoS+GPS | DDoS Impact |
|--------|----------|------|----------|-------------|
| **GPS Telemetry** | | | | |
| Packet Delivery Ratio | 100.00% | 100.00% | 100.00% | None |
| Avg Delay | 21.29 ms | 21.16 ms | 21.16 ms | None |
| Packets Lost (avg) | 0 | 0 | 0 | None |
| **CCTV Stream** | | | | |
| Packet Delivery Ratio | 99.992% | 99.988% | 99.988% | -0.004% |
| Avg Delay | 23.44 ms | 23.16 ms | 23.16 ms | -0.28 ms |
| Packets Lost (avg) | 0 | 0.6 | 0.6 | +0.6 pkts |
| **Ticketing** | | | | |
| Packet Delivery Ratio | 100.00% | 100.00% | 100.00% | None |
| Avg Delay | 22.47 ms | 22.02 ms | 22.02 ms | -0.45 ms |
| Packets Lost (avg) | 0 | 0 | 0 | None |

### 3.2 DDoS Attacker Flow (1-Bus)

- txPackets: 160,714 (identical across all seeds)
- rxPackets: 160,714 (100% delivery)
- lostPackets: 0
- Avg Delay: 15.01 ms
- Total data: ~229.5 MB over 60s attack window

### 3.3 GPS Spoof Flow (1-Bus, ddos_gps only)

- txPackets: 30
- rxPackets: 30 (100% delivery)
- Avg Delay: 15.00 ms

### 3.4 Detection Events (1-Bus)

| Scenario | DDoS Detect | GPS Spoof Detect | Forensic Upload | False Positives |
|----------|-------------|------------------|-----------------|-----------------|
| Baseline (5/5 seeds) | None | None | None | **None** |
| DDoS (5/5 seeds) | t=105.0s | None | t=106.0s | **None** |
| DDoS+GPS (5/5 seeds) | t=105.0s | t=150.015s | t=106.0s | **None** |

DDoS detection details (consistent across all seeds):
- intervalRate: ~31.0 Mbps (threshold: 15 Mbps) -- EXCEEDED
- loss: 0% (threshold: 5%) -- not exceeded
- maxDelay: 23.4 ms (threshold: 20 ms) -- EXCEEDED
- 2-of-3 conditions met (rate + delay)

GPS spoof detection details:
- speed: ~6,699-7,798 m/s (threshold: 22.2 m/s) -- EXCEEDED
- jump: ~6,653-7,747 m (threshold: 1,000 m) -- EXCEEDED
- corridor: outside 1,500 m boundary -- EXCEEDED
- srcIP: different from legitimate bus -- EXCEEDED
- 4/4 anomaly indicators (threshold: 2)

### 3.5 1-Bus Assessment

The 1-bus scenario works perfectly. All detections fire correctly with zero false positives. However, the DDoS attack has negligible impact on legitimate traffic because the network has massive spare capacity at 1-bus scale. The 30 Mbps flood arrives via a dedicated P2P link and does not congest the LTE radio.

---

## 4. Results: 10-Bus Scenarios

### 4.1 Network Performance (Averaged Across 5 Seeds)

| Metric | Baseline | DDoS | DDoS+GPS | DDoS Impact |
|--------|----------|------|----------|-------------|
| **GPS Telemetry** | | | | |
| Packet Delivery Ratio | 100.00% | 100.00% | 100.00% | None |
| Avg Delay | 23.26 ms | 26.10 ms | 26.10 ms | +12.2% |
| **CCTV Stream** | | | | |
| Packet Delivery Ratio | 99.991% | 99.909% | 99.909% | -0.082% |
| Avg Delay | 29.10 ms | 32.98 ms | 32.98 ms | +13.3% |
| Total Lost (5 seeds) | ~12 | 475 | 475 | +463 pkts |
| **Ticketing** | | | | |
| Packet Delivery Ratio | 99.989% | 99.933% | 99.933% | -0.056% |
| Avg Delay | 26.54 ms | 29.58 ms | 29.58 ms | +11.4% |

### 4.2 Per-Bus Impact (10-Bus DDoS, Bus 1 vs Others)

Bus 1 (closest to attacker subnet) takes the hardest hit:
- CCTV PDR drops from 0.9999 to 0.9918 (from ~0 lost to ~109 lost packets)
- CCTV delay jumps from ~29 ms to ~46 ms (+62%)
- Other buses show less degradation

### 4.3 DDoS Attacker Flow (10-Bus)

Same as 1-bus: 160,714 packets, 100% delivery, 15.01 ms delay.

### 4.4 Detection Events (10-Bus)

| Scenario | DDoS Detect | GPS Spoof Detect | False Positives |
|----------|-------------|------------------|-----------------|
| Baseline (5/5 seeds) | **None** | None | **None** |
| DDoS (5/5 seeds) | t=105.0s | None | **None** |
| DDoS+GPS (5/5 seeds) | t=105.0s | t=150.015s | **None** |

DDoS detection details (10-bus):
- intervalRate: ~35.7-35.8 Mbps (threshold: 15 Mbps) -- EXCEEDED
- loss: 0% -- not exceeded
- maxDelay: ~33 ms (threshold: 20 ms) -- EXCEEDED
- 2-of-3 conditions met (rate + delay)

GPS spoof detection details (10-bus):
- speed: ~6,652-6,726 m/s -- EXCEEDED
- jump: 6,652.84 m (consistent across all seeds) -- EXCEEDED
- corridor: outside boundary -- EXCEEDED
- srcIP: different -- EXCEEDED
- 4/4 anomaly indicators

### 4.5 10-Bus Assessment

The 10-bus scenario works correctly. Detection is 100% consistent across all seeds with zero false positives in baseline. The DDoS attack causes measurable but moderate degradation: ~12% delay increase and minor packet loss in CCTV. The ddos and ddos_gps scenarios produce identical network metrics, confirming the GPS spoof (30 packets) adds no measurable network load.

---

## 5. Results: 41-Bus Scenarios

### 5.1 Detection Events (41-Bus)

| Scenario | DDoS Detect | GPS Spoof Detect | False Positives |
|----------|-------------|------------------|-----------------|
| Baseline (5/5 seeds) | **t=20.0s** | None | **YES -- FALSE POSITIVE** |
| DDoS (5/5 seeds) | t=20.0s | None | **AMBIGUOUS** |
| DDoS+GPS (5/5 seeds) | t=20.0s | t=150.015s | **AMBIGUOUS (DDoS detect)** |

### 5.2 False Positive Analysis (CRITICAL ISSUE)

All 5 baseline seeds fire ddos_detect at t=20.0s with no attack running:

| Seed | intervalRate (Mbps) | Loss Rate | maxDelay (s) | Conditions Met |
|------|---------------------|-----------|--------------|----------------|
| 1 | 7.22 | 16.5% | 1.545 | loss + delay (2/3) |
| 2 | 7.25 | 16.6% | 1.575 | loss + delay (2/3) |
| 3 | 7.36 | 16.7% | 2.489 | loss + delay (2/3) |
| 4 | 7.30 | 16.6% | 3.261 | loss + delay (2/3) |
| 5 | 7.59 | 16.4% | 2.658 | loss + delay (2/3) |

Root cause: 41 buses x (500 kbps CCTV + telemetry + ticketing) = ~25 Mbps total uplink. Three eNodeBs serve 41 UEs (~14 UEs per cell). The LTE radio capacity is legitimately overloaded at this scale, causing:
- ~16.5% baseline packet loss (exceeds 5% threshold)
- 1.5-3.3s baseline delay spikes (far exceeds 20 ms threshold)

The 2-of-3 voting fires on loss + delay even though the rate threshold (15 Mbps) is NOT exceeded.

### 5.3 DDoS Detection Indistinguishable from False Positive

The ddos_41buses events are byte-for-byte identical to baseline_41buses events:
- Same detection time (t=20.0s)
- Same intervalRate values
- Same loss percentages
- Same maxDelay values

This means the detection fires at t=20s due to baseline congestion BEFORE the DDoS attack even starts (attack begins at t=100s). The detector cannot distinguish baseline congestion from the actual attack.

### 5.4 GPS Spoof Detection (41-Bus)

GPS spoofing detection works correctly in all 5 ddos_gps seeds:

| Seed | Detection Time | Speed (m/s) | Jump (m) | Indicators |
|------|----------------|-------------|----------|------------|
| 1 | 150.015s | 10,542.1 | 6,652.84 | 4/4 |
| 2 | 150.015s | 10,958.9 | 6,652.84 | 4/4 |
| 3 | 150.015s | 10,887.1 | 6,652.84 | 4/4 |
| 4 | 150.015s | 10,542.1 | 6,652.84 | 4/4 |
| 5 | 150.015s | 11,105.2 | 6,652.84 | 4/4 |

The jump distance (6,652.84 m) is consistent because the spoofed position is fixed. Speed varies slightly due to different bus positions at t=150s across seeds.

### 5.5 Forensic Upload (41-Bus)

| Scenario | Forensics Triggered | Content |
|----------|---------------------|---------|
| Baseline | **None** (correct) | Header only |
| DDoS | **Yes** | 20.000,0,ddos |
| DDoS+GPS | **Yes** | 20.000,0,ddos |

Note: Forensics triggers in DDoS scenarios at t=20s, which is from the false positive detection, not from the actual attack at t=100s.

### 5.6 Flow Statistics (41-Bus)

| Scenario | Total Flows | Flows with lostPackets=0 | Flows with rxPackets=0 |
|----------|-------------|--------------------------|------------------------|
| Baseline | 127 | 4 (control only) | 0 |
| DDoS | 130 | 6 (control + attacker) | 0 |
| DDoS+GPS | 131 | 7 (control + attacker + spoof) | 0 |

123 out of 127 baseline flows show packet loss. This confirms the LTE network is genuinely congested at 41-bus scale even without attacks.

### 5.7 41-Bus Assessment

The 41-bus scenario has a critical false positive problem. The DDoS detection thresholds (5% loss, 20 ms delay) are calibrated for low-bus-count scenarios where baseline loss and delay are near zero. At 41-bus scale, baseline LTE congestion alone exceeds these thresholds. The GPS spoofing detection works correctly at all scales.

---

## 6. Cross-Scale Comparison

### 6.1 Baseline Performance Scaling

| Metric | 1 Bus | 10 Buses | 41 Buses |
|--------|-------|----------|----------|
| GPS PDR | 100.00% | 100.00% | ~97% (estimated from loss patterns) |
| CCTV PDR | 99.992% | 99.991% | ~83% (123/127 flows show loss) |
| GPS Delay | 21.29 ms | 23.26 ms | >> 100 ms |
| Baseline False Positives | None | None | **5/5 seeds** |

### 6.2 Detection Consistency

| Scale | DDoS Detection | GPS Detection | False Positive Rate |
|-------|----------------|---------------|---------------------|
| 1 bus | 5/5 correct at t=105s | 5/5 correct at t=150s | 0% |
| 10 buses | 5/5 correct at t=105s | 5/5 correct at t=150s | 0% |
| 41 buses | 5/5 at t=20s (WRONG TIME) | 5/5 correct at t=150s | **100% baseline FP** |

### 6.3 DDoS Impact Scaling

| Scale | CCTV PDR (baseline) | CCTV PDR (DDoS) | Degradation |
|-------|---------------------|------------------|-------------|
| 1 bus | 99.992% | 99.988% | -0.004% |
| 10 buses | 99.991% | 99.909% | -0.082% |
| 41 buses | ~83% | Worse than baseline | Masked by congestion |

---

## 7. Known Issues

### Issue v3-1: 41-Bus Baseline DDoS False Positive (SEVERITY: HIGH)

**Status:** Open
**Description:** DDoS detection fires at t=20s in all 5 baseline seeds with 41 buses. The 2-of-3 voting (loss + delay) triggers because the LTE network is genuinely congested at 41-bus scale.

**Why it matters:**
1. The baseline results for 41 buses are contaminated -- graphs will show a DDoS detection event where none should exist
2. The actual DDoS attack (starting at t=100s) is never separately detected because detection is a one-shot mechanism (g_ddosDetected flag prevents re-detection)
3. DDoS scenario results at 41-bus are indistinguishable from baseline

**Possible fixes (not yet implemented):**
1. Scale thresholds by bus count (e.g., loss threshold = 5% + numBuses * 0.5%)
2. Add a warm-up period (ignore first 30-60s while LTE radio stabilizes)
3. Filter CheckDDoS to only examine a subset of representative bus flows
4. Use baseline-relative detection (compare current metrics against running average)
5. Add rate threshold as a required condition (rate must exceed threshold for detection to fire)

### Issue v3-2: DDoS Impact Negligible at 1-Bus Scale (SEVERITY: LOW)

**Status:** Acknowledged
**Description:** The 30 Mbps DDoS flood causes near-zero impact on legitimate 1-bus traffic. The P2P link to the server absorbs the attack without congesting the LTE radio path. This is architecturally expected -- the attack floods the server's wired interface, not the wireless link.

**Why it matters for graphs:** The 1-bus baseline vs DDoS comparison will show nearly identical bars, which is a valid but potentially unimpressive result.

---

## 8. Detection System Summary

### What Works

1. **GPS Spoofing Detection:** 15/15 correct detections across all bus counts and seeds. Zero false positives in any non-GPS-spoof scenario. Detection timing consistent at t=150.015s.

2. **DDoS Detection at 1/10 bus scale:** 10/10 correct detections. Zero false positives. Detection timing consistent at t=105.0s. 2-of-3 voting (rate + delay) fires correctly.

3. **GPS Payload Signature (GPS1 magic):** Successfully prevents DDoS UDP traffic from triggering GPS false alerts.

4. **Forensic Upload Pipeline:** Triggers correctly after DDoS detection in all attack scenarios.

### What Does Not Work

1. **DDoS Detection at 41-bus scale:** 100% false positive rate in baseline. Cannot distinguish congestion from attack.

---

## 9. File Inventory

### Per Run (45 runs total)
- `.xml` -- FlowMonitor statistics (237 lines for 1-bus, ~2,500 for 10-bus, ~18,700 for 41-bus)
- `_events.csv` -- Detection events (header + 0-2 event rows)
- `_forensics.csv` -- Forensic upload triggers (header + 0-1 data rows)
- `.log` -- Build/compilation log (2-4 lines, minimal content)

### Counts
- 45 XML files (all present and valid)
- 45 events CSVs
- 45 forensics CSVs
- 45 log files
- Total: 180 files

---

## 10. Next Steps

1. **Fix v3-1:** Resolve 41-bus false positive (highest priority)
2. **Run analyze.py:** Generate graphs from the full_v3_20260304 results (script is compatible with the directory structure)
3. **Re-run 41-bus after fix:** Validate that false positive is eliminated
4. **Generate final delivery package:** Updated code, results, graphs, and reports
5. **Update Word reports:** Incorporate full batch data into EN and AR reports
