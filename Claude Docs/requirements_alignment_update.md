# Requirements Alignment Update

Date: 2026-03-12
Workspace: `main-dev`

## Goal

Bring the simulation back into line with the agreed smart bus requirements in
`PROJECT_REQUIREMENTS_REFERENCE.md` and reduce the drift caused by recent tuning
commits.

## Requirements Locked In

The workspace now includes a canonical requirements reference at:

- `PROJECT_REQUIREMENTS_REFERENCE.md`

This file should be treated as the implementation source of truth for future
simulation changes.

## Code Changes Implemented

### 1. Ticketing traffic restored to requirement-compliant TCP bursts

- Replaced TCP `OnOffApplication` ticketing with a custom `TicketingApp`.
- The new app opens one TCP socket and sends small random bursts over the same
  connection.
- This keeps the traffic aligned with the requirement of random small TCP bursts
  while avoiding the known `OnOffApplication` reconnect crash in large runs.

### 2. DDoS detection re-aligned to the requirement model

- Removed the practical dependence on `any` vs `voting` for the detector logic.
- The detector now behaves as the requirements specify: trigger when any DDoS
  condition becomes true.
- Detection is no longer based on all traffic aggregated together.
- The detector now focuses on telemetry-port traffic to the cloud server so that
  normal CCTV load does not dominate the attack detector.

### 3. DDoS threshold returned to an attack-relevant value

- Restored the rate threshold to `15 Mbps`.
- This matches the requirement that the attacker generates `20-50 Mbps` UDP and
  avoids the invalid `100 Mbps` threshold that was suppressing real detections.

### 4. Queue delay metric added

- Added periodic `queue_delay` logging alongside existing `queue_status` logs.
- Current queue delay is logged as an estimated delay derived from queue bytes
  and bottleneck link rate.

### 5. Forensic trigger logic improved

- Forensic upload can now be triggered by either DDoS detection or GPS spoofing
  detection.
- Forensic event records still include start time, finish time, completion flag,
  and bytes received.

### 6. GPS spoof detection integrated with forensic state

- GPS detections now raise a global detection flag so the forensic workflow can
  respond to spoofing events instead of only DDoS events.

### 7. LTE attachment logic improved for moving buses

- UEs are now attached with `AttachToClosestEnb(...)` instead of plain attach.
- X2 support was re-enabled after the TCP ticketing crash source was removed.

### 8. CCTV traffic brought to the lower edge of the required range

- CCTV rate is now `1 Mbps` per bus.
- This keeps the model inside the required `1-2 Mbps UDP` range while reducing
  unnecessary congestion pressure during validation.

### 9. Detection warm-up window added

- Baseline detection now waits until after a configurable warm-up period before
  evaluating attack conditions.
- This is intended to suppress startup-only false positives that occur during
  initial LTE stabilization.

## Validation Snapshot Before Final Retest

Using the first post-fix validation batch (`results_requirements_fix_v2_20260312`):

- All 9 scenarios completed successfully.
- `1` bus baseline: clean.
- `10` bus baseline: clean.
- `41` bus runs: stable, no crash.
- `1` and `10` bus DDoS scenarios: DDoS detection fired around `105s`.
- `1` and `10` bus DDoS+GPS scenarios: both DDoS and GPS spoof detections fired.
- `41` bus DDoS and DDoS+GPS scenarios: completed and logged detections.
- Remaining issue before the next retest: `41` bus baseline still showed an
  early false DDoS detect driven by telemetry delay/loss.

## Current Status

- Requirements reference file added.
- Major code alignment work completed.
- Stability issue for `41` buses appears fixed.
- Final revalidation is still needed after the latest warm-up tuning change.
