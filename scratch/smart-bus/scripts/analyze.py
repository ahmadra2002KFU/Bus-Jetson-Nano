#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import glob

# Constants
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results')
GRAPHS_DIR = os.path.join(RESULTS_DIR, 'graphs')
os.makedirs(GRAPHS_DIR, exist_ok=True)

BUS_COUNTS = [1, 10, 41]
SCENARIOS = ['baseline', 'ddos', 'ddos_gps']
SEEDS = [1, 2, 3, 4, 5]

def parse_xml(xml_file):
    if not os.path.exists(xml_file):
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except:
        return None

    total_tx_bytes = 0
    total_rx_bytes = 0
    total_tx_packets = 0
    total_rx_packets = 0
    total_lost_packets = 0
    total_delay_sum_ns = 0
    total_jitter_sum_ns = 0
    flow_count = 0
    valid_rx_flows = 0

    for flow in root.findall('.//Flow'):
        tx_bytes = int(flow.get('txBytes', 0))
        rx_bytes = int(flow.get('rxBytes', 0))
        tx_packets = int(flow.get('txPackets', 0))
        rx_packets = int(flow.get('rxPackets', 0))
        lost_packets = int(flow.get('lostPackets', 0))

        delay_sum_str = flow.get('delaySum', '0ns')[:-2]
        jitter_sum_str = flow.get('jitterSum', '0ns')[:-2]

        if delay_sum_str.startswith('+'): delay_sum_str = delay_sum_str[1:]
        if jitter_sum_str.startswith('+'): jitter_sum_str = jitter_sum_str[1:]

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
        if rx_packets > 0:
            valid_rx_flows += 1

    avg_delay_ms = (total_delay_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    avg_jitter_ms = (total_jitter_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    throughput_mbps = (total_rx_bytes * 8) / (300.0 * 1e6)
    plr = (total_lost_packets / total_tx_packets * 100.0) if total_tx_packets > 0 else 0

    return {
        'throughput_mbps': throughput_mbps,
        'delay_ms': avg_delay_ms,
        'jitter_ms': avg_jitter_ms,
        'plr_percent': plr
    }


def parse_events_csv(csv_file):
    """Parse events CSV for queue delay, detection metrics, upload success rate."""
    if not os.path.exists(csv_file):
        return {}
    try:
        df = pd.read_csv(csv_file)
    except:
        return {}
    if df.empty:
        return {}

    result = {}

    # Queue delay
    qd = df[df['eventType'] == 'queue_delay_avg']
    if not qd.empty:
        result['queue_delay_ms'] = qd.iloc[0]['value1']
        result['max_queue_delay_ms'] = qd.iloc[0]['value2']

    # DDoS detection time
    ddt = df[df['eventType'] == 'ddos_detection_time']
    if not ddt.empty:
        result['ddos_detection_time_s'] = ddt.iloc[0]['value1']

    # GPS detection time
    gdt = df[df['eventType'] == 'gps_detection_time']
    if not gdt.empty:
        result['gps_detection_time_s'] = gdt.iloc[0]['value1']

    # Detection accuracy
    da = df[df['eventType'] == 'detection_accuracy']
    if not da.empty:
        result['precision'] = da.iloc[0]['value1']
        result['recall'] = da.iloc[0]['value2']

    # F1 score
    f1 = df[df['eventType'] == 'detection_f1']
    if not f1.empty:
        result['f1_score'] = f1.iloc[0]['value1']

    # Upload success rate
    usr = df[df['eventType'] == 'upload_success_rate']
    if not usr.empty:
        result['upload_success_rate'] = usr.iloc[0]['value1']

    return result


def parse_forensics_csv(csv_file):
    """Parse forensics CSV for upload duration and completion stats."""
    if not os.path.exists(csv_file):
        return {}
    try:
        df = pd.read_csv(csv_file)
    except:
        return {}
    if df.empty:
        return {}

    result = {}
    completed = df[df['completed'] == 1]
    result['upload_duration_s'] = completed['uploadDuration'].mean() if not completed.empty else -1.0
    result['uploads_triggered'] = len(df)
    result['uploads_completed'] = len(completed)
    return result


def main():
    print("Parsing FlowMonitor XML files and metric CSVs...")
    data = []

    for bus in BUS_COUNTS:
        for scenario in SCENARIOS:
            for seed in SEEDS:
                xml_filename = f"{scenario}_{bus}buses_{seed}.xml"
                xml_path = os.path.join(RESULTS_DIR, xml_filename)

                metrics = parse_xml(xml_path)
                if metrics:
                    # Parse events CSV
                    events_file = os.path.join(RESULTS_DIR, f"{scenario}_{bus}buses_{seed}_events.csv")
                    event_metrics = parse_events_csv(events_file)
                    metrics.update(event_metrics)

                    # Parse forensics CSV
                    forensics_file = os.path.join(RESULTS_DIR, f"{scenario}_{bus}buses_{seed}_forensics.csv")
                    forensic_metrics = parse_forensics_csv(forensics_file)
                    metrics.update(forensic_metrics)

                    metrics['bus_count'] = bus
                    metrics['scenario'] = scenario
                    metrics['seed'] = seed
                    data.append(metrics)

    df = pd.DataFrame(data)

    if df.empty:
        print("No valid XML results found. Simulation may still be running.")
        return

    # Network metrics aggregation
    agg_dict = {
        'throughput_mbps': ['mean', 'std'],
        'delay_ms': ['mean', 'std'],
        'jitter_ms': ['mean', 'std'],
        'plr_percent': ['mean', 'std'],
    }
    # Add queue delay if present
    if 'queue_delay_ms' in df.columns:
        agg_dict['queue_delay_ms'] = ['mean', 'std']

    grouped = df.groupby(['bus_count', 'scenario']).agg(agg_dict)
    grouped.columns = ['_'.join(col) for col in grouped.columns]
    grouped = grouped.reset_index().fillna(0)

    # Plotting helper
    def plot_metric(metric_mean, metric_std, ylabel, title, filename):
        if metric_mean not in grouped.columns:
            print(f"Skipping {filename} — column {metric_mean} not found")
            return
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
                   yerr=stds, label=scenario, capsize=5)

        ax.set_xlabel('Number of Buses')
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.set_xticks(index + bar_width)
        ax.set_xticklabels(BUS_COUNTS)
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.7)

        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, filename))
        plt.close()
        print(f"Generated {filename}")

    # Generate Network Metric Graphs
    print("Generating graphs...")
    plot_metric('delay_ms_mean', 'delay_ms_std', 'Avg End-to-End Delay (ms)', 'End-to-End Delay Comparison', 'delay_comparison.png')
    plot_metric('throughput_mbps_mean', 'throughput_mbps_std', 'Avg Throughput (Mbps)', 'Throughput Comparison', 'throughput_comparison.png')
    plot_metric('plr_percent_mean', 'plr_percent_std', 'Packet Loss Rate (%)', 'Packet Loss Rate Comparison', 'plr_comparison.png')
    plot_metric('jitter_ms_mean', 'jitter_ms_std', 'Avg Jitter (ms)', 'Jitter Comparison', 'jitter_comparison.png')
    plot_metric('queue_delay_ms_mean', 'queue_delay_ms_std', 'Avg Queue Delay (ms)', 'Queue Delay Comparison', 'queue_delay_comparison.png')

    # Generate Forensic Metrics Summary (attack scenarios only)
    forensic_cols = ['upload_duration_s', 'upload_success_rate',
                     'ddos_detection_time_s', 'gps_detection_time_s',
                     'precision', 'recall', 'f1_score']
    existing_cols = [c for c in forensic_cols if c in df.columns]

    if existing_cols:
        attack_df = df[df['scenario'] != 'baseline']
        if not attack_df.empty:
            forensic_summary = attack_df.groupby(['bus_count', 'scenario'])[existing_cols].agg(['mean', 'std']).round(3)
            forensic_path = os.path.join(GRAPHS_DIR, 'forensic_metrics.csv')
            forensic_summary.to_csv(forensic_path)
            print(f"Generated forensic_metrics.csv")

            # Print forensic summary table
            print("\n=== FORENSIC METRICS SUMMARY ===")
            for col in existing_cols:
                if col in attack_df.columns:
                    print(f"\n{col}:")
                    summary = attack_df.groupby(['bus_count', 'scenario'])[col].agg(['mean', 'std']).round(3)
                    print(summary.to_string())

    print("\nAnalysis complete. Graphs saved to results/graphs/")

if __name__ == '__main__':
    main()
