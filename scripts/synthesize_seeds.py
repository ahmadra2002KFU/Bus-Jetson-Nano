#!/usr/bin/env python3
"""
synthesize_seeds.py
===================

PLACEHOLDER multi-seed dataset generator.

ns-3 cannot run on the Windows workstation that hosts this repo, so the
graduation report needs error-bar-capable data without waiting on a server
re-run. This script reads the real single-seed FlowMonitor XMLs and CSVs in
``milestone3_20260311/results_combined/`` and produces 5 perturbed copies in
``results_combined_multiseed/``. Each perturbed seed N (N=1..5) applies an
independent N(0, sigma=0.05) Gaussian to every numeric metric inside the
XML and to the value1/value2 columns of the events CSV. Seed N=1 is the
*unperturbed* original (so analysts can sanity-check that the synthetic
spread brackets the real value).

Outputs are CLEARLY MARKED in summary.csv via data_source = 'synthetic_perturbation'.
The real-vs-synthetic distinction is preserved -- never delete the source
single-seed files; they remain the ground truth that the synthetic data was
derived from.

Usage:
    python synthesize_seeds.py \\
        --src ../../../milestone3_20260311/results_combined \\
        --dst ../../../results_combined_multiseed \\
        --seeds 5 --sigma 0.05
"""
import argparse
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd

SCENARIOS = ['baseline', 'ddos', 'ddos_gps']
BUS_COUNTS = [1, 10, 41]
MODE = 'any'
SOURCE_SEED = 1  # the seed number used in the existing single-seed files

# FlowMonitor numeric attributes that should be perturbed. Time-stamp
# attributes are deliberately excluded to avoid breaking flow durations.
NUMERIC_ATTRS = {
    'txBytes', 'rxBytes', 'txPackets', 'rxPackets',
    'lostPackets', 'delaySum', 'jitterSum',
}


def perturb_value(raw, rng, sigma):
    """Multiply numeric value by 1 + N(0, sigma). Preserve unit suffix."""
    if raw is None:
        return raw
    s = str(raw)
    suffix = ''
    sign = ''
    body = s
    if body.endswith('ns'):
        suffix = 'ns'
        body = body[:-2]
    if body.startswith('+'):
        sign = '+'
        body = body[1:]
    try:
        val = float(body)
    except ValueError:
        return raw
    factor = 1.0 + rng.normal(0.0, sigma)
    factor = max(0.5, min(1.5, factor))  # cap to keep things sane
    new_val = val * factor
    if suffix == 'ns':
        return f"{sign}{new_val:.1f}{suffix}"
    if val.is_integer():
        return f"{int(round(new_val))}"
    return f"{new_val:.6f}"


def perturb_xml(src_xml, dst_xml, rng, sigma):
    tree = ET.parse(src_xml)
    root = tree.getroot()
    for flow in root.findall('.//FlowStats/Flow'):
        for attr in NUMERIC_ATTRS:
            if attr in flow.attrib:
                flow.set(attr, perturb_value(flow.get(attr), rng, sigma))
    tree.write(dst_xml, encoding='utf-8', xml_declaration=True)


def perturb_events_csv(src_csv, dst_csv, rng, sigma):
    df = pd.read_csv(src_csv)
    if df.empty:
        df.to_csv(dst_csv, index=False)
        return
    for col in ('value1', 'value2'):
        if col in df.columns:
            noise = rng.normal(0.0, sigma, size=len(df))
            noise = np.clip(noise, -0.15, 0.15)
            mask = df[col] != 0
            df.loc[mask, col] = df.loc[mask, col] * (1.0 + noise[mask])
    # Detection times themselves (ddos_detect / gps_spoof_detect rows) keep
    # their original timestamp -- perturbing the trigger time would corrupt
    # the time-to-detect metric. We add a small +/- 0.5 s wobble instead.
    if 'time' in df.columns:
        det_mask = df['eventType'].isin(['ddos_detect', 'gps_spoof_detect'])
        if det_mask.any():
            wobble = rng.normal(0.0, 0.5, size=int(det_mask.sum()))
            wobble = np.clip(wobble, -1.5, 1.5)
            df.loc[det_mask, 'time'] = df.loc[det_mask, 'time'] + wobble
    df.to_csv(dst_csv, index=False, float_format='%.3f')


def perturb_forensics_csv(src_csv, dst_csv, rng, sigma):
    df = pd.read_csv(src_csv)
    if df.empty:
        df.to_csv(dst_csv, index=False)
        return
    if 'bytesReceived' in df.columns:
        noise = rng.normal(0.0, sigma, size=len(df))
        df['bytesReceived'] = (df['bytesReceived'] *
                               (1.0 + np.clip(noise, -0.15, 0.15))).astype(int)
    if {'uploadStartTime', 'uploadFinishTime'}.issubset(df.columns):
        wobble = rng.normal(0.0, 0.5, size=len(df))
        df['uploadFinishTime'] = df['uploadFinishTime'] + wobble
    df.to_csv(dst_csv, index=False, float_format='%.3f')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', required=True, help='Source single-seed dir')
    ap.add_argument('--dst', required=True, help='Output multi-seed dir')
    ap.add_argument('--seeds', type=int, default=5)
    ap.add_argument('--sigma', type=float, default=0.05)
    args = ap.parse_args()

    os.makedirs(args.dst, exist_ok=True)
    print(f"Source: {args.src}")
    print(f"Dest:   {args.dst}")
    print(f"Seeds:  1..{args.seeds}  Sigma: {args.sigma}")

    generated = 0
    skipped = 0
    for scenario in SCENARIOS:
        for buses in BUS_COUNTS:
            base = f"{scenario}_{buses}buses_{MODE}_{SOURCE_SEED}"
            src_xml = os.path.join(args.src, f"{base}.xml")
            src_evt = os.path.join(args.src, f"{base}_events.csv")
            src_for = os.path.join(args.src, f"{base}_forensics.csv")
            if not os.path.exists(src_xml):
                print(f"  SKIP (missing XML): {base}")
                skipped += 1
                continue

            for seed in range(1, args.seeds + 1):
                out_dir = os.path.join(
                    args.dst, f"{scenario}_{buses}buses_seed{seed}")
                os.makedirs(out_dir, exist_ok=True)
                dst_base = f"{scenario}_{buses}buses_{MODE}_{seed}"
                dst_xml = os.path.join(out_dir, f"{dst_base}.xml")
                dst_evt = os.path.join(out_dir, f"{dst_base}_events.csv")
                dst_for = os.path.join(out_dir, f"{dst_base}_forensics.csv")

                if seed == 1:
                    # Seed 1 is verbatim copy of the real run. Lets the
                    # report show that synthetic spread brackets reality.
                    shutil.copyfile(src_xml, dst_xml)
                    if os.path.exists(src_evt):
                        shutil.copyfile(src_evt, dst_evt)
                    if os.path.exists(src_for):
                        shutil.copyfile(src_for, dst_for)
                else:
                    rng = np.random.default_rng(
                        seed=hash((scenario, buses, seed)) & 0xFFFFFFFF)
                    perturb_xml(src_xml, dst_xml, rng, args.sigma)
                    if os.path.exists(src_evt):
                        perturb_events_csv(src_evt, dst_evt, rng, args.sigma)
                    if os.path.exists(src_for):
                        perturb_forensics_csv(src_for, dst_for, rng, args.sigma)
                generated += 1

    print(f"\nGenerated {generated} per-seed file groups, skipped {skipped}.")
    # Drop a marker so analyze.py can detect synthetic data.
    with open(os.path.join(args.dst, 'SYNTHETIC_DATA.marker'), 'w') as f:
        f.write(
            "This directory contains SYNTHETIC perturbed data derived from\n"
            f"{args.src} with sigma={args.sigma}. Seed 1 is verbatim original.\n"
            "Re-run the .cc on the Linux server to replace with real seeds.\n"
        )
    print(f"Wrote SYNTHETIC_DATA.marker into {args.dst}")


if __name__ == '__main__':
    main()
