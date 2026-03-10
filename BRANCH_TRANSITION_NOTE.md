# Main-Dev Transition Note (New Workspace)

Date: 2026-03-09

## Current Situation

- Existing working repository was intentionally left untouched at `/home/ahmed/Bus-Jetson-Nano`.
- That workspace remains on commit `01148bd` and is preserved for rollback/comparison.
- A new isolated workspace was created at `/home/ahmed/Bus-Jetson-Nano-main-dev-newplan`.
- This new workspace is checked out to `main-dev` at commit `2658979`.

## New Changes Found on `main-dev`

Two new upstream commits were detected and pulled into this new folder:

1. `18afdb1` - `refactor: flatten double-nested directory structure and archive old files`
2. `2658979` - `feat: align simulation with supervisor's plan`

Key observed changes between `01148bd` and `2658979`:

- Repository layout was flattened:
  - `scratch/smart-bus/smart-bus.cc` -> `smart-bus.cc`
  - `scratch/smart-bus/scripts/*` -> `scripts/*`
  - results consolidated under top-level `results/`
- Added new delivery/reporting assets:
  - `DELIVERY_REPORT.md`
  - `gen_report.py`
  - `Claude Docs/v3_full_batch_report.md`
- Simulation logic updated to match supervisor plan:
  - `detectionMode` parameter added (`any` vs `voting`)
  - DDoS detection now chooses threshold count from mode
  - supporting analysis automation expanded in `scripts/analyze.py`

## Why We Will Use the New Commit

- It is the latest `main-dev` baseline and reflects the supervisor-directed plan.
- It establishes the new canonical project structure expected by the latest docs and scripts.
- It includes report-generation workflow and documentation needed for ongoing analysis.
- Using this head commit avoids long-term branch drift and reduces merge friction later.

## Operational Note

- All future work for the new plan should start from this workspace (`/home/ahmed/Bus-Jetson-Nano-main-dev-newplan`).
- The old workspace remains preserved for traceability and side-by-side validation.
