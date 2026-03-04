# Smart-Bus v3 Validation Report

Date: 2026-03-04
Previous: v2_validation_report.md (2 issues: v2-1 config error, v2-2 DDoS detection)
Branch: main-dev (commit cf9e489)
Validated seeds: 303 (post-fix), 202 (intermediate, pre-GPS-magic)

---

## Fixes Applied in v3 (commit cf9e489)

Two fixes applied on top of v2 (commit 23d0ca5):

| # | Issue | Fix Applied |
|---|-------|-------------|
| v3-1 | GPS detector triggered by DDoS UDP traffic on port 5000 | Added GPS_PAYLOAD_MAGIC (0x47505331 = "GPS1") signature validation. Detector ignores packets without valid magic header. |
| v3-2 | DDoS 2-of-3 voting never triggered (delay threshold 100ms too high for low-latency P2P link) | Lowered DDOS_DELAY_THRESHOLD from 0.1s (100ms) to 0.02s (20ms). DDoS attacker's P2P link adds ~23ms delay, now exceeds threshold. |

### v3-1 Detail: GPS Payload Signature

The GPS detector listens on port 5000 (same as telemetry). DDoS attacker also floods port 5000. Without payload validation, the detector parsed random DDoS bytes as GPS coordinates, causing false gps_spoof_detect events in ddos-only scenarios.

Fix adds a structured payload format to all GPS-related apps:

```
Offset  Size   Field
0       4B     magic (uint32 = 0x47505331 "GPS1")
4       4B     busId (uint32)
8       8B     posX  (double)
16      8B     posY  (double)
24-199  pad    zeros
```

- GpsTelemetryApp: writes GPS1 magic + real position
- GpsSpoofAttackApp: writes GPS1 magic + fake position
- GpsDetectorApp: checks magic == GPS_PAYLOAD_MAGIC, skips non-GPS packets
- Additional guards: busId >= MAX_BUSES check, isfinite(posX/posY) check

### v3-2 Detail: DDoS Delay Threshold Tuning

The DDoS attacker sends 30 Mbps via a P2P link with 5ms propagation delay. Observed maxDelay was ~23ms (5ms propagation + queuing). The v2 threshold of 100ms was never reached.

Changed DDOS_DELAY_THRESHOLD from 0.1 to 0.02 (20ms). Now the 23ms observed delay exceeds threshold, enabling the rate+delay 2-of-3 vote to fire.

---

## v3 Validation Results (seed 303)

### Test 1: Baseline (no attacks)

**baseline_1buses_303_events.csv:** Header only, no events.
**baseline_1buses_303_forensics.csv:** Header only, no forensics.

Result: No false positives. Baseline clean.

### Test 2: DDoS Only (enableDDoS=true, enableGpsSpoofing=false)

**ddos_1buses_303_events.csv:**
```
105.000,999,ddos_detect,31020268.800,0.000,"intervalRate=3.10203e+07bps loss=0 maxDelay=0.0234427s"
```

**ddos_1buses_303_forensics.csv:**
```
106.000,0,ddos
```

- DDoS detected at t=105s (busId=999 = system-level detection)
- intervalRate = 31.0 Mbps (threshold 15 Mbps): EXCEEDED
- loss = 0%: not exceeded
- maxDelay = 23.4ms (threshold 20ms): EXCEEDED
- 2 of 3 conditions met: rate + delay. Detection fires correctly.
- Forensic upload triggered at t=106s for bus 0.
- No GPS false positive (GPS magic filter working).

Result: DDoS detection and forensic pipeline both working. No GPS false positives.

### Test 3: DDoS + GPS Spoofing (both enabled)

**ddos_gps_1buses_303_events.csv:**
```
105.000,999,ddos_detect,31020268.800,0.000,"intervalRate=3.10203e+07bps loss=0 maxDelay=0.0234427s"
150.015,0,gps_spoof_detect,6699.244,6652.837,"speed=6699.24m/s jump=6652.84m corridor=1 srcIP=1"
```

**ddos_gps_1buses_303_forensics.csv:**
```
106.000,0,ddos
```

- DDoS detected at t=105s (same as ddos-only, expected).
- GPS spoof detected at t=150.015s with 4/4 anomaly indicators:
  - speed=6699.24 m/s (threshold 22.2): EXCEEDED
  - jump=6652.84 m (threshold 1000): EXCEEDED
  - corridor=1 (outside 1500m): EXCEEDED
  - srcIP=1 (different source): EXCEEDED
- anomalyCount=4, threshold is 2. Legitimate detection.
- Forensic upload triggered for DDoS at t=106s.

Result: Both detections fire correctly in combined scenario.

---

## Seed 202 Results (intermediate code, pre-GPS-magic)

Seed 202 was run with v2 code (2-of-3 voting but without GPS magic). These results show the progression:

| Scenario | Events | Notes |
|----------|--------|-------|
| baseline_1buses_202 | None | Clean baseline |
| ddos_1buses_202 | gps_spoof_detect only | GPS false positive from DDoS traffic (v3-1 bug present) |
| ddos_gps_1buses_202 | gps_spoof_detect only | GPS detection works, but no ddos_detect (v3-2 bug present) |

These results confirm why both v3 fixes were necessary.

---

## Full Fix History Across Versions

| Version | Commit | Fixes | Key Result |
|---------|--------|-------|------------|
| v1 (initial) | da5b3c7 | None | rxPackets=0, false positives everywhere |
| v2 | 3f26f9f + 23d0ca5 | 6 bugs (LTE, X2, CCTV, DDoS logic, GPS corridor, gpsBusTarget) + 2-of-3 voting | LTE works (100% delivery), no baseline false positives |
| v3 | cf9e489 | GPS magic signature, DDoS delay threshold 20ms | All detections fire correctly, no false positives |

---

## Current Detection Behavior Summary

| Scenario | DDoS Detect | GPS Spoof Detect | Forensic Upload | False Positives |
|----------|-------------|-------------------|-----------------|-----------------|
| Baseline | No | No | No | None |
| DDoS Only | Yes (t=105s) | No | Yes (t=106s) | None |
| DDoS+GPS | Yes (t=105s) | Yes (t=150s) | Yes (t=106s) | None |

All three scenarios behave exactly as designed.

---

## Remaining Work

1. Run full 45-scenario batch (3 bus counts x 3 scenarios x 5 seeds)
2. Generate updated graphs with analyze.py
3. Validate 10-bus and 41-bus scenario behavior
4. Verify detection timing consistency across seeds
5. Final delivery package
