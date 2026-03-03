#!/usr/bin/env python3
"""
analyze.py — Parse FlowMonitor XML results and generate 6 graphs with error bars.
Usage: python3 analyze.py --results-dir results/
"""

import os
import sys
import glob
import argparse
import xml.etree.ElementTree as ET
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict


def parse_flow_monitor_xml(filepath):
    """Parse a FlowMonitor XML file and return aggregate metrics."""
    tree = ET.parse(filepath)
    root = tree.getroot()

    flows = root.find("FlowStats")
    if flows is None:
        return None

    total_tx_packets = 0
    total_rx_packets = 0
    total_lost_packets = 0
    total_tx_bytes = 0
    total_rx_bytes = 0
    total_delay_ns = 0
    total_jitter_ns = 0
    first_tx_time = float("inf")
    last_rx_time = 0

    for flow in flows.findall("Flow"):
        tx_packets = int(flow.get("txPackets", 0))
        rx_packets = int(flow.get("rxPackets", 0))
        lost_packets = int(flow.get("lostPackets", 0))
        tx_bytes = int(flow.get("txBytes", 0))
        rx_bytes = int(flow.get("rxBytes", 0))

        delay_sum = flow.get("delaySum", "+0.0ns")
        jitter_sum = flow.get("jitterSum", "+0.0ns")

        total_tx_packets += tx_packets
        total_rx_packets += rx_packets
        total_lost_packets += lost_packets
        total_tx_bytes += tx_bytes
        total_rx_bytes += rx_bytes
        total_delay_ns += parse_ns_time(delay_sum)
        total_jitter_ns += parse_ns_time(jitter_sum)

        first_tx_str = flow.get("timeFirstTxPacket", "+0.0ns")
        last_rx_str = flow.get("timeLastRxPacket", "+0.0ns")
        ft = parse_ns_time(first_tx_str)
        lr = parse_ns_time(last_rx_str)
        if ft < first_tx_time and ft > 0:
            first_tx_time = ft
        if lr > last_rx_time:
            last_rx_time = lr

    # Compute metrics
    avg_delay_s = (total_delay_ns / total_rx_packets / 1e9
                   if total_rx_packets > 0 else 0)
    avg_jitter_s = (total_jitter_ns / total_rx_packets / 1e9
                    if total_rx_packets > 0 else 0)
    duration_s = (last_rx_time - first_tx_time) / 1e9
    throughput_mbps = (total_rx_bytes * 8 / duration_s / 1e6
                       if duration_s > 0 else 0)
    loss_rate = (total_lost_packets / total_tx_packets
                 if total_tx_packets > 0 else 0)

    return {
        "avg_delay_s": avg_delay_s,
        "avg_jitter_s": avg_jitter_s,
        "throughput_mbps": throughput_mbps,
        "loss_rate": loss_rate,
        "tx_packets": total_tx_packets,
        "rx_packets": total_rx_packets,
        "lost_packets": total_lost_packets,
    }


def parse_ns_time(time_str):
    """Parse ns-3 time string like '+1.23456e+09ns' to nanoseconds float."""
    s = time_str.strip()
    if s.endswith("ns"):
        s = s[:-2]
    s = s.lstrip("+")
    try:
        return float(s)
    except ValueError:
        return 0.0


def parse_events_csv(filepath):
    """Parse events CSV and return detection times."""
    ddos_detect_time = None
    gps_detect_time = None

    if not os.path.exists(filepath):
        return ddos_detect_time, gps_detect_time

    with open(filepath, "r") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            time_val = float(parts[0])
            event_type = parts[2]
            if event_type == "ddos_detect" and ddos_detect_time is None:
                ddos_detect_time = time_val
            elif event_type == "gps_spoof_detect" and gps_detect_time is None:
                gps_detect_time = time_val

    return ddos_detect_time, gps_detect_time


def parse_forensics_csv(filepath):
    """Parse forensics CSV and return trigger time."""
    if not os.path.exists(filepath):
        return None

    with open(filepath, "r") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 1:
                return float(parts[0])
    return None


def collect_results(results_dir):
    """Collect all results grouped by (scenario, numBuses)."""
    data = defaultdict(list)
    detection_data = defaultdict(list)

    xml_files = glob.glob(os.path.join(results_dir, "*.xml"))

    for xml_path in xml_files:
        basename = os.path.basename(xml_path)
        # Expected format: {scenario}_{numBuses}buses_{seed}.xml
        # scenario may contain underscores (e.g., "ddos_gps"), so we parse
        # from the right: the last part is seed, the second-to-last matches
        # pattern "<N>buses", and everything before that is the scenario name.
        name = basename.replace(".xml", "")
        parts = name.split("_")

        if len(parts) < 3:
            continue

        # Find the buses part by scanning from the right
        buses_idx = None
        for idx in range(len(parts) - 1, 0, -1):
            if parts[idx].endswith("buses"):
                buses_idx = idx
                break

        if buses_idx is None or buses_idx < 1 or buses_idx >= len(parts) - 1:
            continue

        scenario = "_".join(parts[:buses_idx])
        buses_str = parts[buses_idx]  # e.g., "10buses"
        # seed_str = parts[buses_idx + 1]  # not needed

        try:
            num_buses = int(buses_str.replace("buses", ""))
        except ValueError:
            continue

        metrics = parse_flow_monitor_xml(xml_path)
        if metrics is None:
            continue

        key = (scenario, num_buses)
        data[key].append(metrics)

        # Parse events CSV for detection times
        events_path = xml_path.replace(".xml", "_events.csv")
        ddos_t, gps_t = parse_events_csv(events_path)

        forensics_path = xml_path.replace(".xml", "_forensics.csv")
        forensic_t = parse_forensics_csv(forensics_path)

        detection_data[key].append({
            "ddos_detect_time": ddos_t,
            "gps_detect_time": gps_t,
            "forensic_trigger_time": forensic_t,
        })

    return data, detection_data


def compute_stats(values):
    """Return mean and std of a list, handling empty lists."""
    if not values:
        return 0, 0
    arr = np.array(values)
    return np.mean(arr), np.std(arr)


def plot_grouped_bar(ax, scenarios, bus_counts, means, stds, ylabel, title):
    """Plot a grouped bar chart with error bars."""
    x = np.arange(len(bus_counts))
    width = 0.25
    colors = ["#2196F3", "#FF5722", "#4CAF50"]

    for i, scenario in enumerate(scenarios):
        vals = [means.get((scenario, b), 0) for b in bus_counts]
        errs = [stds.get((scenario, b), 0) for b in bus_counts]
        ax.bar(x + i * width, vals, width, yerr=errs, label=scenario,
               color=colors[i % len(colors)], capsize=4, edgecolor="black",
               linewidth=0.5)

    ax.set_xlabel("Number of Buses")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x + width)
    ax.set_xticklabels([str(b) for b in bus_counts])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze FlowMonitor XML results")
    parser.add_argument("--results-dir", default="results/",
                        help="Directory containing result files")
    args = parser.parse_args()

    graphs_dir = os.path.join(args.results_dir, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)

    data, detection_data = collect_results(args.results_dir)

    if not data:
        print("ERROR: No result files found in", args.results_dir)
        sys.exit(1)

    scenarios = ["baseline", "ddos", "ddos_gps"]
    bus_counts = [1, 10, 41]

    # Aggregate stats
    delay_means, delay_stds = {}, {}
    throughput_means, throughput_stds = {}, {}
    loss_means, loss_stds = {}, {}
    jitter_means, jitter_stds = {}, {}

    for key, runs in data.items():
        delays = [r["avg_delay_s"] * 1000 for r in runs]  # ms
        throughputs = [r["throughput_mbps"] for r in runs]
        losses = [r["loss_rate"] * 100 for r in runs]  # percent
        jitters = [r["avg_jitter_s"] * 1000 for r in runs]  # ms

        delay_means[key], delay_stds[key] = compute_stats(delays)
        throughput_means[key], throughput_stds[key] = compute_stats(throughputs)
        loss_means[key], loss_stds[key] = compute_stats(losses)
        jitter_means[key], jitter_stds[key] = compute_stats(jitters)

    # ---- Plot 1: Average End-to-End Delay ----
    fig, ax = plt.subplots(figsize=(8, 5))
    plot_grouped_bar(ax, scenarios, bus_counts, delay_means, delay_stds,
                     "Avg Delay (ms)", "Average End-to-End Delay")
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "1_avg_delay.png"), dpi=150)
    plt.close(fig)
    print("Saved: 1_avg_delay.png")

    # ---- Plot 2: Average Throughput ----
    fig, ax = plt.subplots(figsize=(8, 5))
    plot_grouped_bar(ax, scenarios, bus_counts, throughput_means,
                     throughput_stds, "Throughput (Mbps)",
                     "Average Throughput")
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "2_avg_throughput.png"), dpi=150)
    plt.close(fig)
    print("Saved: 2_avg_throughput.png")

    # ---- Plot 3: Packet Loss Rate ----
    fig, ax = plt.subplots(figsize=(8, 5))
    plot_grouped_bar(ax, scenarios, bus_counts, loss_means, loss_stds,
                     "Packet Loss (%)", "Packet Loss Rate")
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "3_packet_loss.png"), dpi=150)
    plt.close(fig)
    print("Saved: 3_packet_loss.png")

    # ---- Plot 4: Jitter ----
    fig, ax = plt.subplots(figsize=(8, 5))
    plot_grouped_bar(ax, scenarios, bus_counts, jitter_means, jitter_stds,
                     "Jitter (ms)", "Average Jitter")
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "4_jitter.png"), dpi=150)
    plt.close(fig)
    print("Saved: 4_jitter.png")

    # ---- Plot 5: Detection Time ----
    fig, ax = plt.subplots(figsize=(8, 5))
    attack_scenarios = ["ddos", "ddos_gps"]
    x = np.arange(len(bus_counts))
    width = 0.35
    colors_det = {"ddos": "#FF5722", "ddos_gps": "#4CAF50"}
    labels_det = {"ddos": "DDoS Detection", "ddos_gps": "GPS Spoof Detection"}

    for i, scenario in enumerate(attack_scenarios):
        detect_means = []
        detect_errs = []
        for b in bus_counts:
            key = (scenario, b)
            runs = detection_data.get(key, [])
            if scenario == "ddos":
                times = [r["ddos_detect_time"] for r in runs
                         if r["ddos_detect_time"] is not None]
            else:
                times = [r["gps_detect_time"] for r in runs
                         if r["gps_detect_time"] is not None]
            m, s = compute_stats(times)
            detect_means.append(m)
            detect_errs.append(s)

        ax.bar(x + i * width, detect_means, width, yerr=detect_errs,
               label=labels_det[scenario], color=colors_det[scenario],
               capsize=4, edgecolor="black", linewidth=0.5)

    ax.set_xlabel("Number of Buses")
    ax.set_ylabel("Detection Time (s)")
    ax.set_title("Attack Detection Time")
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels([str(b) for b in bus_counts])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "5_detection_time.png"), dpi=150)
    plt.close(fig)
    print("Saved: 5_detection_time.png")

    # ---- Plot 6: Evidence Upload Duration ----
    fig, ax = plt.subplots(figsize=(8, 5))

    for i, scenario in enumerate(attack_scenarios):
        upload_means = []
        upload_errs = []
        for b in bus_counts:
            key = (scenario, b)
            runs = detection_data.get(key, [])
            # Upload duration = forensic_trigger_time - ddos_detect_time
            # (approximation: forensic starts shortly after detection)
            durations = []
            for r in runs:
                ft = r.get("forensic_trigger_time")
                dt = r.get("ddos_detect_time")
                if ft is not None and dt is not None:
                    durations.append(ft - dt)
            m, s = compute_stats(durations)
            upload_means.append(m)
            upload_errs.append(s)

        ax.bar(x + i * width, upload_means, width, yerr=upload_errs,
               label=scenario, color=colors_det[scenario],
               capsize=4, edgecolor="black", linewidth=0.5)

    ax.set_xlabel("Number of Buses")
    ax.set_ylabel("Upload Trigger Latency (s)")
    ax.set_title("Evidence Upload Duration (Detection → Trigger)")
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels([str(b) for b in bus_counts])
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(graphs_dir, "6_evidence_upload.png"), dpi=150)
    plt.close(fig)
    print("Saved: 6_evidence_upload.png")

    print("\nAll 6 graphs saved to", graphs_dir)


if __name__ == "__main__":
    main()
