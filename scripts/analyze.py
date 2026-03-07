#!/usr/bin/env python3
"""
analyze.py - Parse FlowMonitor XML results and generate comparison graphs.

Filters to only include legitimate bus flows (7.0.0.x source subnet),
excluding DDoS attacker (2.0.0.x), GPS spoof attacker (3.0.0.x),
control plane (13.x/14.x), and TCP forensic flows.
"""
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
import sys

# Constants
RESULTS_DIR = os.environ.get('RESULTS_DIR', '../results/full_v3_20260304')
GRAPHS_DIR = os.path.join(os.path.dirname(RESULTS_DIR), 'graphs')
os.makedirs(GRAPHS_DIR, exist_ok=True)

BUS_COUNTS = [1, 10, 41]
SCENARIOS = ['baseline', 'ddos', 'ddos_gps']
SEEDS = [1, 2, 3, 4, 5]
SIM_TIME = 200.0  # seconds

# Bus subnet prefix - only flows from this subnet are legitimate bus traffic
BUS_SUBNET_PREFIX = '7.0.0.'


def get_bus_flow_ids(root):
    """Parse Ipv4FlowClassifier to find flowIds originating from bus subnet (7.0.0.x)
    and using UDP (protocol 17). Excludes TCP forensic upload flows."""
    bus_flow_ids = set()
    classifier = root.find('.//Ipv4FlowClassifier')
    if classifier is None:
        return bus_flow_ids

    for flow in classifier.findall('Flow'):
        src = flow.get('sourceAddress', '')
        proto = flow.get('protocol', '')
        if src.startswith(BUS_SUBNET_PREFIX) and proto == '17':
            fid = int(flow.get('flowId'))
            bus_flow_ids.add(fid)

    return bus_flow_ids


def parse_xml(xml_file):
    """Parse a FlowMonitor XML file, returning metrics for bus flows only."""
    if not os.path.exists(xml_file):
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception:
        return None

    bus_flow_ids = get_bus_flow_ids(root)

    total_tx_bytes = 0
    total_rx_bytes = 0
    total_tx_packets = 0
    total_rx_packets = 0
    total_lost_packets = 0
    total_delay_sum_ns = 0
    total_jitter_sum_ns = 0
    flow_count = 0

    for flow in root.findall('.//FlowStats/Flow'):
        fid = int(flow.get('flowId'))
        if fid not in bus_flow_ids:
            continue

        tx_bytes = int(flow.get('txBytes', 0))
        rx_bytes = int(flow.get('rxBytes', 0))
        tx_packets = int(flow.get('txPackets', 0))
        rx_packets = int(flow.get('rxPackets', 0))
        lost_packets = int(flow.get('lostPackets', 0))

        delay_sum_str = flow.get('delaySum', '0ns')[:-2]
        jitter_sum_str = flow.get('jitterSum', '0ns')[:-2]

        if delay_sum_str.startswith('+'):
            delay_sum_str = delay_sum_str[1:]
        if jitter_sum_str.startswith('+'):
            jitter_sum_str = jitter_sum_str[1:]

        delay_sum = float(delay_sum_str) if delay_sum_str else 0.0
        jitter_sum = float(jitter_sum_str) if jitter_sum_str else 0.0

        total_tx_bytes += tx_bytes
        total_rx_bytes += rx_bytes
        total_tx_packets += tx_packets
        total_rx_packets += rx_packets
        total_lost_packets += lost_packets
        total_delay_sum_ns += delay_sum
        total_jitter_sum_ns += jitter_sum
        flow_count += 1

    if flow_count == 0:
        return None

    avg_delay_ms = (total_delay_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    avg_jitter_ms = (total_jitter_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    throughput_mbps = (total_rx_bytes * 8) / (SIM_TIME * 1e6)
    plr = (total_lost_packets / total_tx_packets * 100.0) if total_tx_packets > 0 else 0

    return {
        'throughput_mbps': throughput_mbps,
        'delay_ms': avg_delay_ms,
        'jitter_ms': avg_jitter_ms,
        'plr_percent': plr,
        'bus_flows': flow_count,
        'total_rx_packets': total_rx_packets,
        'total_tx_packets': total_tx_packets,
        'total_lost_packets': total_lost_packets,
    }


def main():
    print("Parsing FlowMonitor XML files (bus flows only)...")
    data = []

    for bus in BUS_COUNTS:
        for scenario in SCENARIOS:
            for seed in SEEDS:
                xml_filename = f"{scenario}_{bus}buses_{seed}.xml"
                xml_path = os.path.join(RESULTS_DIR, xml_filename)

                metrics = parse_xml(xml_path)
                if metrics:
                    metrics['bus_count'] = bus
                    metrics['scenario'] = scenario
                    metrics['seed'] = seed
                    data.append(metrics)
                    print(f"  {xml_filename}: {metrics['bus_flows']} bus flows, "
                          f"PDR={100-metrics['plr_percent']:.2f}%, "
                          f"delay={metrics['delay_ms']:.1f}ms")
                else:
                    print(f"  MISSING: {xml_filename}")

    df = pd.DataFrame(data)

    if df.empty:
        print("No valid XML results found.")
        return

    print(f"\nParsed {len(data)} files successfully.")

    # Print summary table
    print("\n=== Summary (mean across 5 seeds) ===")
    summary = df.groupby(['bus_count', 'scenario']).agg(
        delay=('delay_ms', 'mean'),
        throughput=('throughput_mbps', 'mean'),
        plr=('plr_percent', 'mean'),
        jitter=('jitter_ms', 'mean'),
    ).reset_index()
    for _, row in summary.iterrows():
        print(f"  {row['scenario']:10s} {row['bus_count']:2.0f} buses: "
              f"delay={row['delay']:7.1f}ms  throughput={row['throughput']:5.2f}Mbps  "
              f"PLR={row['plr']:5.2f}%  jitter={row['jitter']:6.2f}ms")

    # Calculate means and stddevs for plotting
    grouped = df.groupby(['bus_count', 'scenario']).agg(
        throughput_mean=('throughput_mbps', 'mean'),
        throughput_std=('throughput_mbps', 'std'),
        delay_mean=('delay_ms', 'mean'),
        delay_std=('delay_ms', 'std'),
        jitter_mean=('jitter_ms', 'mean'),
        jitter_std=('jitter_ms', 'std'),
        plr_mean=('plr_percent', 'mean'),
        plr_std=('plr_percent', 'std')
    ).reset_index()
    grouped = grouped.fillna(0)

    # Scenario display names and colors
    scenario_labels = {
        'baseline': 'Baseline',
        'ddos': 'DDoS Attack',
        'ddos_gps': 'DDoS + GPS Spoof'
    }
    scenario_colors = {
        'baseline': '#4A90D9',
        'ddos': '#E8793A',
        'ddos_gps': '#5CB85C'
    }

    def plot_metric(metric_mean, metric_std, ylabel, title, filename):
        fig, ax = plt.subplots(figsize=(10, 6))

        bar_width = 0.25
        index = np.arange(len(BUS_COUNTS))

        for i, scenario in enumerate(SCENARIOS):
            scenario_data = grouped[grouped['scenario'] == scenario]

            means = []
            stds = []
            for b in BUS_COUNTS:
                row = scenario_data[scenario_data['bus_count'] == b]
                if not row.empty:
                    means.append(row[metric_mean].values[0])
                    stds.append(row[metric_std].values[0])
                else:
                    means.append(0)
                    stds.append(0)

            ax.bar(index + i * bar_width, means, bar_width,
                   yerr=stds, label=scenario_labels[scenario],
                   color=scenario_colors[scenario],
                   capsize=5, edgecolor='black', linewidth=0.5)

        ax.set_xlabel('Number of Buses', fontsize=12)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xticks(index + bar_width)
        ax.set_xticklabels(BUS_COUNTS)
        ax.legend(fontsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.5)

        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, filename), dpi=150)
        plt.close()
        print(f"Generated {filename}")

    print("\nGenerating graphs...")
    plot_metric('delay_mean', 'delay_std',
                'Avg End-to-End Delay (ms)',
                'End-to-End Delay Comparison (Bus Traffic Only)',
                'delay_comparison.png')
    plot_metric('throughput_mean', 'throughput_std',
                'Avg Throughput (Mbps)',
                'Throughput Comparison (Bus Traffic Only)',
                'throughput_comparison.png')
    plot_metric('plr_mean', 'plr_std',
                'Packet Loss Rate (%)',
                'Packet Loss Rate Comparison (Bus Traffic Only)',
                'plr_comparison.png')
    plot_metric('jitter_mean', 'jitter_std',
                'Avg Jitter (ms)',
                'Jitter Comparison (Bus Traffic Only)',
                'jitter_comparison.png')

    print(f"\nAnalysis complete. Graphs saved to {GRAPHS_DIR}/")


if __name__ == '__main__':
    main()
