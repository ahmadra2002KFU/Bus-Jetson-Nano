# Smart-Bus v1 Bug Report

Date: 2026-03-03
Source files examined:
- `scratch/smart-bus/results/baseline_1buses_1.xml`
- `scratch/smart-bus/results/ddos_1buses_1.xml`
- `scratch/smart-bus/results/ddos_1buses_1_events.csv`

---

## Bug #1: Cost231PropagationLossModel Kills LTE Signal

**Evidence:**
In `baseline_1buses_1.xml`, all three bus flows (flowId 1, 2, 3) show `rxPackets="0"` and `rxBytes="0"` despite transmitting packets (298, 39910, 531 txPackets respectively). The `delaySum="+0ns"` and `timeFirstRxPacket="+0ns"` confirm no packet ever reached the destination. The same pattern appears in `ddos_1buses_1.xml` for bus flows 1-4 (all rxPackets=0).

**Root Cause:**
The COST-231 Hata propagation loss model produces approximately 270 dB path loss at the 5 km eNB-to-bus distances in the simulation. With a transmit power of 46 dBm and a receiver sensitivity of -100 dBm, the signal budget is only 146 dB. The 270 dB loss exceeds this by ~124 dB, meaning every LTE packet from the bus UE to the eNB is dropped at the physical layer.

**Impact:**
Total simulation failure. Zero data delivery for all bus applications (telemetry, CCTV, GPS). The baseline scenario produces 0% throughput, making all metrics meaningless.

**Fix:**
Replace Cost231PropagationLossModel with a model appropriate for LTE macro-cell (e.g., ns-3's default LTE pathloss, or reduce cell radius to match COST-231 valid range of ~1 km urban).

---

## Bug #2: No X2 Handover Interface Configured

**Evidence:**
In `ddos_1buses_1.xml`, flow 4 (TCP from bus 7.0.0.2 to server 1.0.0.2, port 8000) shows `txPackets="6"` and `rxPackets="0"` with `lostPackets="6"`. This is a handover signaling flow that fails completely. The bus is mobile and traverses multiple eNB coverage areas but cannot perform handover.

**Root Cause:**
The simulation does not configure X2 interfaces between eNBs. Without X2, LTE handover cannot occur. When a mobile UE moves out of one eNB's coverage and into another's, it loses connectivity entirely rather than handing over.

**Impact:**
Mobile buses lose all connectivity after leaving their initial serving eNB. Even if Bug #1 were fixed, long-route buses would still drop all traffic mid-journey.

**Fix:**
Add X2 interface configuration between adjacent eNBs using `lteHelper->AddX2Interface()`.

---

## Bug #3: CCTV Bandwidth Exceeds LTE Uplink Capacity

**Evidence:**
In `baseline_1buses_1.xml`, flow 2 (CCTV stream, port 6000) transmitted 39,910 packets / 56,991,480 bytes but received 0. Even ignoring the propagation loss bug, the aggregate CCTV load is unsustainable: 1.5 Mbps per camera x 41 buses = 61.5 Mbps total uplink demand, which exceeds the typical LTE uplink capacity of ~50 Mbps.

**Root Cause:**
The CCTV application data rate (1.5 Mbps per bus) was configured without accounting for the aggregate load across all buses sharing the same LTE cell. The uplink becomes a bottleneck even for smaller bus counts.

**Impact:**
Network saturation and packet drops for CCTV and all co-located flows (telemetry, GPS). In multi-bus scenarios, the LTE uplink is overwhelmed, causing cascading failures.

**Fix:**
Reduce per-bus CCTV bitrate or implement adaptive bitrate. Alternatively, distribute buses across multiple eNBs to spread the load.

---

## Bug #4: DDoS Detection Uses Cumulative Rate + OR Logic, False Triggers at t=15

**Evidence:**
In `ddos_1buses_1_events.csv`, line 2:
```
15.000,999,ddos_detect,0.000,0.152,"avgRate=0bps loss=0.151941 maxDelay=0s"
```
DDoS is detected at t=15s with `avgRate=0bps` -- meaning zero actual traffic rate. The detection triggered purely on `loss=0.152` (15.2% packet loss). The DDoS attack does not start until t=100s, yet detection fires at t=15s.

**Root Cause:**
The detection algorithm uses cumulative counters (total bytes / total time) rather than windowed rate measurement, and combines conditions with OR logic (high rate OR high loss OR high delay). At t=15s, the initial LTE attachment failures (from Bug #1) produce non-zero loss ratios, which alone trigger the OR-based detection threshold.

**Impact:**
False positive DDoS detection 85 seconds before the actual attack begins. The detection system is unreliable -- it flags normal network conditions as attacks, making it useless for real threat identification.

**Fix:**
Switch to windowed (sliding window) rate calculation. Use AND logic requiring multiple indicators simultaneously. Add a minimum traffic volume threshold before detection activates.

---

## Bug #5: GPS Corridor Threshold 500m Too Tight, Causes False Positives

**Evidence:**
In `ddos_1buses_1_events.csv`, line 3:
```
100.016,0,gps_spoof_detect,0.000,0.000,"speed=0m/s jump=0m corridor=1 srcIP=0"
```
GPS spoofing is detected at t=100s with `speed=0m/s`, `jump=0m`, and `corridor=1`. The `corridor=1` flag indicates the bus was detected as outside the allowed corridor, even though speed and jump are both 0 (no anomalous movement).

**Root Cause:**
The GPS corridor boundary is set at 500m from the route centerline. With GPS noise, multipath effects, and the actual road geometry (curves, intersections), a stationary or slow-moving bus can legitimately appear outside 500m from the idealized route, especially at route endpoints or turns.

**Impact:**
False GPS spoofing alerts during normal operation. Operators cannot distinguish real spoofing attacks from threshold noise, degrading trust in the security system.

**Fix:**
Widen corridor threshold (e.g., 1000m) or use adaptive thresholds based on route geometry. Add a persistence requirement (multiple consecutive violations before alerting).

---

## Bug #6: gpsBusTarget=5 Does Not Exist in 1-Bus Runs

**Evidence:**
In `ddos_1buses_1_events.csv`, the GPS spoof detection at t=100 targets `busId=0`, but the simulation's GPS spoofing attack is configured to target bus index 5 (`gpsBusTarget=5`). In a 1-bus scenario, only bus 0 exists. Bus 5 is never created.

**Root Cause:**
The GPS attack target parameter is hardcoded to bus 5 regardless of the actual number of buses in the scenario. When running with `nBuses=1`, only bus 0 exists, so the attack targets a nonexistent entity.

**Impact:**
The GPS spoofing attack has no effect in 1-bus runs. The spoofing scenario cannot be properly tested or validated at small scale. The detection event at busId=0 is a false positive unrelated to the configured attack.

**Fix:**
Clamp `gpsBusTarget` to `min(gpsBusTarget, nBuses - 1)` or parameterize it relative to the bus count.

---

## Summary Table

| # | Bug | Severity | Detected In |
|---|-----|----------|-------------|
| 1 | COST-231 path loss kills all LTE traffic | Critical | baseline + ddos XML (rxPackets=0) |
| 2 | No X2 handover interface | High | ddos XML (flow 4, 6 lost packets) |
| 3 | CCTV aggregate exceeds LTE uplink | High | baseline XML (flow 2, 39910 tx / 0 rx) |
| 4 | DDoS false detection at t=15 | High | events CSV (ddos_detect at t=15, avgRate=0) |
| 5 | GPS corridor 500m too tight | Medium | events CSV (corridor=1, speed=0, jump=0) |
| 6 | gpsBusTarget=5 invalid for 1-bus | Medium | events CSV + config mismatch |
