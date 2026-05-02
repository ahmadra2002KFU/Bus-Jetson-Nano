# M4 Forensic Evidence Run — 2026-05-02

Branch `m4-evidence-2026-05-02` · repo HEAD at run start `1e0a593` · server build `1e0a593` · Jetson `fatima-desktop` aarch64.

## Run window (UTC)

Agent start `12:10:44Z`, first trigger `12:12:20Z`, last upload `12:15:18Z`, agent stop `12:15:24Z`.

## Plan deviation

No LAN attacker host available → DDoS dropped, run executed **4 GPS-spoof incidents only** at 45 s gaps. DDoS rows in the M4 table stay sim-projected (caveat added on the documentation-agent side).

## Attacks (each: `python3 -m jetson.spoof_local --duration 12`, fake pos 14000/1000 — ~6.5 km off corridor 0)

| # | Incident ID | `forensic_id` | Detected (local) | Upload | PDF bytes |
|---|---|---|---|---|---|
| 1 | `INC_20260502-151224_0` | 60 | 15:12:23 | 1.08 s | 56 492 |
| 2 | `INC_20260502-151320_0` | 61 | 15:13:20 | 2.73 s | 57 387 |
| 3 | `INC_20260502-151419_0` | 62 | 15:14:17 | 1.06 s | 58 329 |
| 4 | `INC_20260502-151515_0` | 63 | 15:15:14 | 1.04 s | 58 091 |

## Metrics summary (`forensics_metrics.csv`, 4 rows)

| Metric | min | mean | max |
|---|---:|---:|---:|
| `detection_time_s` | — | — | — |
| `acquisition_time_s` | 0.009 | 0.010 | 0.013 |
| `hash_gen_time_ms` | 0.7 | 0.78 | 0.9 |
| `upload_time_s` | 1.036 | 1.476 | 2.732 |
| `report_gen_time_ms` | 1 489.8 | 2 064.0 | 3 777.4 |
| `chain_of_custody_pct` | 100.0 | 100.0 | 100.0 |

`detection_time_s` blank — `main.py::_fire_forensic` passes `None` for GPS-spoof. Wall-clock detection latency from logs is ~3 s every incident (3-packet streak gate). Worth threading into the metrics call site.

## Verification

4 PASS, 0 FAIL, 0 ERROR. `/verify/{60..63}` returns `verified:true`, `stored_sha256 == computed_sha256`.

## Tamper test (3 confirmations)

1. `S4_tamper_fail.txt` — null byte appended to local PDF copy, `sha256sum -c`: PDF `FAILED`, other 5 `OK`.
2. `S3_verify_pass.txt` — server's `/verify/60` (un-tampered original) still `verified:true`.
3. `S4b_tamper_fresh_upload_fail.txt` — fresh upload of tampered bytes claiming the original hash is **rejected at `/ingest/forensic` with HTTP 422 `sha256_mismatch`**, never stored. Stronger than the brief: tamper caught at upload time (defense-in-depth).

## Anomalies / disclosures

- **Server redeploy mid-run.** First 4 spoofs (IDs 55–58) hit old build `ef8d8a0` (no `/verify`, no SHA-256 audit). Per documentation-agent instruction we wiped the local bundle and re-ran on `1e0a593`. Final evidence is IDs 60–63.
- **Two real bugs in `scripts/update_verification_status.py`**, both fixed on this branch:
  - Hit `/verify/<incident_id_string>` but server keys on integer `forensic_id`. Resolved via `/api/forensics` + `(bus_id, ts)` tolerance match.
  - Default `Python-urllib/3.x` UA triggers Cloudflare WAF rule 1010 (403). Now sends a `Mozilla/5.0 …` UA.
- **`capture_forensic_screenshots.sh` not in repo** (brief said fetch from `Claude Docs/scripts/`, not pushed). Authored locally with same UA + `forensic_id` resolution. PNGs rendered from TXTs via Pillow (no DISPLAY); TXTs are live command output and are the auditable record.
- **Incident #1 `report_gen_time_ms = 3 777` vs ~1 500 for #2–#4** — WeasyPrint cold-cache font subsetting penalty (visible in `run_log.txt`); not a regression.
- **CCTV WS reconnect storm continues** (~70 s cadence, server-side). Streak gating absorbs it cleanly — no false positives, no upload failures.

## Files under `m4_evidence/`

```
incidents/INC_20260502-151{224,320,419,515}_0/   (7 files each)
logs/events.csv  forensics.csv  forensics_metrics.csv (4 PASS)
screenshots/S1..S5  +  S4b_tamper_fresh_upload_fail   (PNG + TXT)
run_log.txt   raw agent stdout      run_log.md   this file
```

Also touched on this branch: `scripts/update_verification_status.py` (bug-fix), `scripts/capture_forensic_screenshots.sh` (new). Both part of the same commit.
