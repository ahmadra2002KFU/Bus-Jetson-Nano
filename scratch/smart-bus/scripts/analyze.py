#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import glob

# Constants
RESULTS_DIR = '../../../results'
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

    # We will accumulate metrics across all flows
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
        
        # Strip trailing 'ns'
        delay_sum_str = flow.get('delaySum', '0ns')[:-2]
        jitter_sum_str = flow.get('jitterSum', '0ns')[:-2]
        
        # Remove '+' if present
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

    # Conversions
    avg_delay_ms = (total_delay_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    avg_jitter_ms = (total_jitter_sum_ns / total_rx_packets / 1e6) if total_rx_packets > 0 else 0
    
    # Calculate Throughput assuming 300s sim time (approximate, since start/end times vary)
    # 8 bits/byte, 300 seconds -> Mbps
    throughput_mbps = (total_rx_bytes * 8) / (300.0 * 1e6)
    
    plr = (total_lost_packets / total_tx_packets * 100.0) if total_tx_packets > 0 else 0

    return {
        'throughput_mbps': throughput_mbps,
        'delay_ms': avg_delay_ms,
        'jitter_ms': avg_jitter_ms,
        'plr_percent': plr
    }

def main():
    print("Parsing FlowMonitor XML files...")
    data = []

    for bus in BUS_COUNTS:
        for scenario in SCENARIOS:
            for seed in SEEDS:
                # Our C++ script prefixes the output
                # Example: baseline_1buses_1.xml
                xml_filename = f"{scenario}_{bus}buses_{seed}.xml"
                xml_path = os.path.join(RESULTS_DIR, xml_filename)
                
                metrics = parse_xml(xml_path)
                if metrics:
                    metrics['bus_count'] = bus
                    metrics['scenario'] = scenario
                    metrics['seed'] = seed
                    data.append(metrics)

    df = pd.DataFrame(data)
    
    if df.empty:
        print("No valid XML results found. Simulation may still be running.")
        return

    # Calculate means and stddevs
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

    # Fill NaNs in std with 0 (if only 1 seed completed so far)
    grouped = grouped.fillna(0)

    # Plotting helper
    def plot_metric(metric_mean, metric_std, ylabel, title, filename):
        fig, ax = plt.subplots(figsize=(10, 6))
        
        bar_width = 0.25
        index = np.arange(len(BUS_COUNTS))
        
        for i, scenario in enumerate(SCENARIOS):
            scenario_data = grouped[grouped['scenario'] == scenario]
            
            # Align data to BUS_COUNTS just in case some runs are missing
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

    # Generate Graphs
    print("Generating graphs...")
    plot_metric('delay_mean', 'delay_std', 'Avg End-to-End Delay (ms)', 'End-to-End Delay Comparison', 'delay_comparison.png')
    plot_metric('throughput_mean', 'throughput_std', 'Avg Throughput (Mbps)', 'Throughput Comparison', 'throughput_comparison.png')
    plot_metric('plr_mean', 'plr_std', 'Packet Loss Rate (%)', 'Packet Loss Rate Comparison', 'plr_comparison.png')
    plot_metric('jitter_mean', 'jitter_std', 'Avg Jitter (ms)', 'Jitter Comparison', 'jitter_comparison.png')

    print("Analysis complete. Graphs saved to results/graphs/")

if __name__ == '__main__':
    main()
