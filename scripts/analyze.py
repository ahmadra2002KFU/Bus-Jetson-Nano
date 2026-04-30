#!/usr/bin/env python3
"""
analyze.py - Parse FlowMonitor XML results and generate comparison graphs.

Filters to only include legitimate bus flows (7.0.0.x source subnet),
excluding DDoS attacker (2.0.0.x), GPS spoof attacker (3.0.0.x),
control plane (13.x/14.x), and TCP forensic flows (port 8000).

Supports both 'any' and 'voting' detection modes.
"""
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os
import sys
import glob as globmod

# Constants
RESULTS_DIR = os.environ.get('RESULTS_DIR', '../results')
GRAPHS_DIR = os.path.join(os.path.dirname(RESULTS_DIR), 'graphs')
os.makedirs(GRAPHS_DIR, exist_ok=True)

BUS_COUNTS = [1, 10, 41]
SCENARIOS = ['baseline', 'ddos', 'ddos_gps']
DETECTION_MODES = ['any']
# All 5 seeds produced by run_all_parallel.sh. Previously this was [1] only,
# which silently dropped 80% of replicate data and reported single-seed values
# as if they were means.
SEEDS = [1, 2, 3, 4, 5]
SIM_TIME = 300.0  # seconds

# 10 MB forensic upload target (must match smart-bus.cc TARGET_BYTES).
FORENSIC_TARGET_BYTES = 10 * 1024 * 1024

# Bus subnet prefix - only flows from this subnet are legitimate bus traffic
BUS_SUBNET_PREFIX = '7.0.0.'

# Ground truth for detection accuracy
DDOS_START_TIME = 100.0
GPS_START_TIME = 150.0
DETECTION_WINDOW = 30.0  # seconds after attack start to count as true positive


def get_bus_flow_ids(root):
    """Parse Ipv4FlowClassifier to find flowIds originating from bus subnet (7.0.0.x).
    Includes UDP (proto 17) and TCP (proto 6) but excludes forensic port 8000."""
    bus_flow_ids = set()
    classifier = root.find('.//Ipv4FlowClassifier')
    if classifier is None:
        return bus_flow_ids

    for flow in classifier.findall('Flow'):
        src = flow.get('sourceAddress', '')
        proto = flow.get('protocol', '')
        dst_port = flow.get('destinationPort', '')
        if src.startswith(BUS_SUBNET_PREFIX) and (
            proto == '17' or (proto == '6' and dst_port != '8000')
        ):
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
    # Sum of per-flow throughput so the aggregate isn't depressed by the
    # warm-up gap between sim start and the first packet of each flow.
    sum_flow_throughput_mbps = 0.0

    def _parse_time_ns(raw):
        """FlowMonitor times look like '+12345.0ns' -- strip sign + unit."""
        if not raw:
            return 0.0
        s = raw
        if s.endswith('ns'):
            s = s[:-2]
        if s.startswith('+'):
            s = s[1:]
        try:
            return float(s)
        except ValueError:
            return 0.0

    for flow in root.findall('.//FlowStats/Flow'):
        fid = int(flow.get('flowId'))
        if fid not in bus_flow_ids:
            continue

        tx_bytes = int(flow.get('txBytes', 0))
        rx_bytes = int(flow.get('rxBytes', 0))
        tx_packets = int(flow.get('txPackets', 0))
        rx_packets = int(flow.get('rxPackets', 0))
        lost_packets = int(flow.get('lostPackets', 0))

        delay_sum = _parse_time_ns(flow.get('delaySum', '0ns'))
        jitter_sum = _parse_time_ns(flow.get('jitterSum', '0ns'))
        first_tx_ns = _parse_time_ns(flow.get('timeFirstTxPacket', '0ns'))
        last_rx_ns = _parse_time_ns(flow.get('timeLastRxPacket', '0ns'))

        # Per-flow active duration: first transmit to last successful receive.
        # Using SIM_TIME (300 s) instead of this duration depresses each
        # flow's reported throughput by the pre-attack idle window, even
        # though the network was carrying nothing there. ns-3 stores both
        # timestamps in nanoseconds.
        active_seconds = (last_rx_ns - first_tx_ns) / 1e9
        if active_seconds > 0 and rx_bytes > 0:
            sum_flow_throughput_mbps += (rx_bytes * 8.0) / (active_seconds * 1e6)

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
    # Aggregate goodput across all bus flows, each measured over its own
    # active window (timeLastRxPacket - timeFirstTxPacket).
    throughput_mbps = sum_flow_throughput_mbps
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


def parse_events_csv(events_file):
    """Parse events CSV and extract detection events."""
    if not os.path.exists(events_file):
        return None
    try:
        df = pd.read_csv(events_file)
        return df
    except Exception:
        return None


def compute_queue_delay_ms(events_df):
    """Mean PGW->server queue delay (ms) from queue_delay event rows.

    smart-bus.cc:LogQueueStatus emits a 'queue_delay' row every 5s with
    value1 = nBytes_in_queue * 8 / SERVER_LINK_RATE_BPS (i.e. instantaneous
    queueing delay in seconds). We average across the full simulation here.
    Replaces the old `max(0, avg_delay_ms - 25)` stub which subtracted a
    hard-coded 25 ms propagation guess from the end-to-end delay.
    """
    if events_df is None or events_df.empty:
        return 0.0
    qrows = events_df[events_df['eventType'] == 'queue_delay']
    if qrows.empty:
        return 0.0
    # value1 is queue delay in seconds; convert to ms.
    return float(qrows['value1'].mean()) * 1000.0


def compute_queue_delay_attack_window(events_df, start, end):
    """Mean queue delay (ms) over [start, end] -- attack-window slice."""
    if events_df is None or events_df.empty:
        return 0.0
    qrows = events_df[(events_df['eventType'] == 'queue_delay')
                       & (events_df['time'] >= start)
                       & (events_df['time'] <= end)]
    if qrows.empty:
        return 0.0
    return float(qrows['value1'].mean()) * 1000.0


def parse_forensics_csv(forensics_file):
    """Parse forensics CSV with upload timing data."""
    if not os.path.exists(forensics_file):
        return None
    try:
        df = pd.read_csv(forensics_file)
        return df
    except Exception:
        return None


def compute_detection_accuracy(events_df, scenario):
    """Compute detection accuracy metrics against ground truth."""
    result = {
        'ddos_detected': False,
        'ddos_time_to_detect': None,
        'ddos_true_positive': False,
        'ddos_false_positive': False,
        'gps_detected': False,
        'gps_time_to_detect': None,
        'gps_true_positive': False,
        'gps_false_positive': False,
    }
    if events_df is None or events_df.empty:
        return result

    # DDoS detection
    ddos_events = events_df[events_df['eventType'] == 'ddos_detect']
    if not ddos_events.empty:
        detect_time = ddos_events.iloc[0]['time']
        result['ddos_detected'] = True
        if scenario in ('ddos', 'ddos_gps'):
            result['ddos_time_to_detect'] = detect_time - DDOS_START_TIME
            result['ddos_true_positive'] = True
        else:
            result['ddos_false_positive'] = True

    # GPS detection
    gps_events = events_df[events_df['eventType'] == 'gps_spoof_detect']
    if not gps_events.empty:
        detect_time = gps_events.iloc[0]['time']
        result['gps_detected'] = True
        if scenario == 'ddos_gps':
            result['gps_time_to_detect'] = detect_time - GPS_START_TIME
            result['gps_true_positive'] = True
        else:
            result['gps_false_positive'] = True

    return result


def compute_forensic_metrics(forensics_df):
    """Extract forensic upload metrics.

    Completion is now derived from the real bytesReceived measured at the
    server-side PacketSink (smart-bus.cc::PollForensicCompletion) rather
    than from the old fixed +16.5s timer that lied about success.

    Adds:
      upload_success_rate -- fraction of the 10 MB target that actually
                             arrived at the server during this run.
    """
    result = {
        'upload_started': False,
        'upload_completed': False,
        'upload_duration': None,
        'upload_bytes': 0,
        'upload_success_rate': 0.0,
    }
    if forensics_df is None or forensics_df.empty:
        return result

    row = forensics_df.iloc[0]
    result['upload_started'] = True
    bytes_received = int(row.get('bytesReceived', 0))
    result['upload_bytes'] = bytes_received
    result['upload_success_rate'] = min(
        1.0, bytes_received / float(FORENSIC_TARGET_BYTES))
    if row.get('uploadCompleted', 0) == 1:
        result['upload_completed'] = True
        result['upload_duration'] = row['uploadFinishTime'] - row['uploadStartTime']
    else:
        # Partial: report duration up to the recorded finish (deadline) so
        # the duration field still reflects real elapsed time, not None.
        finish = row.get('uploadFinishTime', 0)
        start = row.get('uploadStartTime', 0)
        if finish and finish > start:
            result['upload_duration'] = finish - start

    return result


def main():
    print("Parsing FlowMonitor XML files (bus flows only)...")
    data = []
    detection_data = []
    forensic_data = []

    for mode in DETECTION_MODES:
        for bus in BUS_COUNTS:
            for scenario in SCENARIOS:
                for seed in SEEDS:
                    xml_filename = f"{scenario}_{bus}buses_{mode}_{seed}.xml"
                    xml_path = os.path.join(RESULTS_DIR, xml_filename)

                    metrics = parse_xml(xml_path)
                    # Parse events CSV first so we can join queue_delay onto
                    # the FlowMonitor-derived metrics row.
                    events_file = os.path.join(
                        RESULTS_DIR,
                        f"{scenario}_{bus}buses_{mode}_{seed}_events.csv")
                    events_df = parse_events_csv(events_file)

                    if metrics:
                        # Real measured queue delay from the PGW->server
                        # P2P queue (LogQueueStatus rows in events CSV).
                        metrics['queue_delay_ms'] = compute_queue_delay_ms(
                            events_df)
                        metrics['bus_count'] = bus
                        metrics['scenario'] = scenario
                        metrics['seed'] = seed
                        metrics['mode'] = mode
                        data.append(metrics)
                        print(f"  {xml_filename}: {metrics['bus_flows']} bus flows, "
                              f"PDR={100-metrics['plr_percent']:.2f}%, "
                              f"delay={metrics['delay_ms']:.1f}ms, "
                              f"qDelay={metrics['queue_delay_ms']:.1f}ms")
                    else:
                        print(f"  MISSING: {xml_filename}")

                    accuracy = compute_detection_accuracy(events_df, scenario)
                    accuracy['bus_count'] = bus
                    accuracy['scenario'] = scenario
                    accuracy['seed'] = seed
                    accuracy['mode'] = mode
                    detection_data.append(accuracy)

                    # Parse forensics CSV for upload metrics
                    forensics_file = os.path.join(
                        RESULTS_DIR,
                        f"{scenario}_{bus}buses_{mode}_{seed}_forensics.csv")
                    forensics_df = parse_forensics_csv(forensics_file)
                    fmetrics = compute_forensic_metrics(forensics_df)
                    fmetrics['bus_count'] = bus
                    fmetrics['scenario'] = scenario
                    fmetrics['seed'] = seed
                    fmetrics['mode'] = mode
                    forensic_data.append(fmetrics)

    df = pd.DataFrame(data)
    det_df = pd.DataFrame(detection_data)
    for_df = pd.DataFrame(forensic_data)

    if df.empty:
        print("No valid XML results found.")
        return

    print(f"\nParsed {len(data)} files successfully.")

    # Print summary table per mode
    for mode in DETECTION_MODES:
        mode_df = df[df['mode'] == mode]
        if mode_df.empty:
            continue
        print(f"\n=== Summary [{mode} mode] (mean across 5 seeds) ===")
        summary = mode_df.groupby(['bus_count', 'scenario']).agg(
            delay=('delay_ms', 'mean'),
            throughput=('throughput_mbps', 'mean'),
            plr=('plr_percent', 'mean'),
            jitter=('jitter_ms', 'mean'),
            queue_delay=('queue_delay_ms', 'mean'),
        ).reset_index()
        for _, row in summary.iterrows():
            print(f"  {row['scenario']:10s} {row['bus_count']:2.0f} buses: "
                  f"delay={row['delay']:7.1f}ms  throughput={row['throughput']:5.2f}Mbps  "
                  f"PLR={row['plr']:5.2f}%  jitter={row['jitter']:6.2f}ms  "
                  f"queueDelay={row['queue_delay']:6.2f}ms")

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
    mode_colors = {
        'any': '#4A90D9',
        'voting': '#E8793A'
    }

    def plot_metric(grouped_df, metric_mean, metric_std, ylabel, title, filename,
                    mode_filter=None):
        gdf = grouped_df if mode_filter is None else grouped_df[
            grouped_df['mode'] == mode_filter]
        if gdf.empty:
            return

        fig, ax = plt.subplots(figsize=(10, 6))
        bar_width = 0.25
        index = np.arange(len(BUS_COUNTS))

        for i, scenario in enumerate(SCENARIOS):
            scenario_data = gdf[gdf['scenario'] == scenario]
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

        suffix = f" [{mode_filter}]" if mode_filter else ""
        ax.set_xlabel('Number of Buses', fontsize=12)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.set_title(title + suffix, fontsize=14, fontweight='bold')
        ax.set_xticks(index + bar_width)
        ax.set_xticklabels(BUS_COUNTS)
        ax.legend(fontsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.5)

        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, filename), dpi=150)
        plt.close()
        print(f"Generated {filename}")

    # Generate per-mode grouped stats
    for mode in DETECTION_MODES:
        mode_df = df[df['mode'] == mode]
        if mode_df.empty:
            continue

        grouped = mode_df.groupby(['bus_count', 'scenario', 'mode']).agg(
            throughput_mean=('throughput_mbps', 'mean'),
            throughput_std=('throughput_mbps', 'std'),
            delay_mean=('delay_ms', 'mean'),
            delay_std=('delay_ms', 'std'),
            jitter_mean=('jitter_ms', 'mean'),
            jitter_std=('jitter_ms', 'std'),
            plr_mean=('plr_percent', 'mean'),
            plr_std=('plr_percent', 'std'),
            queue_delay_mean=('queue_delay_ms', 'mean'),
            queue_delay_std=('queue_delay_ms', 'std'),
        ).reset_index()
        grouped = grouped.fillna(0)

        print(f"\nGenerating graphs for {mode} mode...")
        plot_metric(grouped, 'delay_mean', 'delay_std',
                    'Avg End-to-End Delay (ms)',
                    'End-to-End Delay Comparison',
                    f'delay_comparison_{mode}.png', mode)
        plot_metric(grouped, 'throughput_mean', 'throughput_std',
                    'Avg Throughput (Mbps)',
                    'Throughput Comparison',
                    f'throughput_comparison_{mode}.png', mode)
        plot_metric(grouped, 'plr_mean', 'plr_std',
                    'Packet Loss Rate (%)',
                    'Packet Loss Rate Comparison',
                    f'plr_comparison_{mode}.png', mode)
        plot_metric(grouped, 'jitter_mean', 'jitter_std',
                    'Avg Jitter (ms)',
                    'Jitter Comparison',
                    f'jitter_comparison_{mode}.png', mode)
        plot_metric(grouped, 'queue_delay_mean', 'queue_delay_std',
                    'Estimated Queue Delay (ms)',
                    'Queue Delay Comparison',
                    f'queue_delay_comparison_{mode}.png', mode)

    # === Detection time comparison (any vs voting) ===
    print("\nGenerating detection comparison graphs...")
    det_attack_df = det_df[det_df['scenario'].isin(['ddos', 'ddos_gps'])]
    if not det_attack_df.empty:
        # DDoS detection time: any vs voting
        ddos_det = det_attack_df[det_attack_df['ddos_detected'] == True].copy()
        if not ddos_det.empty:
            fig, ax = plt.subplots(figsize=(10, 6))
            bar_width = 0.35
            index = np.arange(len(BUS_COUNTS))
            for i, mode in enumerate(DETECTION_MODES):
                mode_data = ddos_det[ddos_det['mode'] == mode]
                means = []
                stds = []
                for b in BUS_COUNTS:
                    bdata = mode_data[mode_data['bus_count'] == b]['ddos_time_to_detect'].dropna()
                    means.append(bdata.mean() if len(bdata) > 0 else 0)
                    stds.append(bdata.std() if len(bdata) > 1 else 0)
                ax.bar(index + i * bar_width, means, bar_width,
                       yerr=stds, label=f'{mode} mode',
                       color=mode_colors[mode], capsize=5,
                       edgecolor='black', linewidth=0.5)
            ax.set_xlabel('Number of Buses', fontsize=12)
            ax.set_ylabel('Time to Detect DDoS (s)', fontsize=12)
            ax.set_title('DDoS Detection Time: Any vs Voting', fontsize=14, fontweight='bold')
            ax.set_xticks(index + bar_width / 2)
            ax.set_xticklabels(BUS_COUNTS)
            ax.legend(fontsize=10)
            ax.grid(axis='y', linestyle='--', alpha=0.5)
            plt.tight_layout()
            plt.savefig(os.path.join(GRAPHS_DIR, 'ddos_detection_time_comparison.png'), dpi=150)
            plt.close()
            print("Generated ddos_detection_time_comparison.png")

    # GPS detection time comparison
    gps_det = det_df[(det_df['scenario'] == 'ddos_gps') & (det_df['gps_detected'] == True)].copy()
    if not gps_det.empty:
        fig, ax = plt.subplots(figsize=(10, 6))
        bar_width = 0.35
        index = np.arange(len(BUS_COUNTS))
        for i, mode in enumerate(DETECTION_MODES):
            mode_data = gps_det[gps_det['mode'] == mode]
            means = []
            stds = []
            for b in BUS_COUNTS:
                bdata = mode_data[mode_data['bus_count'] == b]['gps_time_to_detect'].dropna()
                means.append(bdata.mean() if len(bdata) > 0 else 0)
                stds.append(bdata.std() if len(bdata) > 1 else 0)
            ax.bar(index + i * bar_width, means, bar_width,
                   yerr=stds, label=f'{mode} mode',
                   color=mode_colors[mode], capsize=5,
                   edgecolor='black', linewidth=0.5)
        ax.set_xlabel('Number of Buses', fontsize=12)
        ax.set_ylabel('Time to Detect GPS Spoof (s)', fontsize=12)
        ax.set_title('GPS Spoof Detection Time: Any vs Voting', fontsize=14, fontweight='bold')
        ax.set_xticks(index + bar_width / 2)
        ax.set_xticklabels(BUS_COUNTS)
        ax.legend(fontsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, 'gps_detection_time_comparison.png'), dpi=150)
        plt.close()
        print("Generated gps_detection_time_comparison.png")

    # === Forensic upload duration ===
    for_started = for_df[for_df['upload_started'] == True].copy()
    if not for_started.empty:
        fig, ax = plt.subplots(figsize=(10, 6))
        bar_width = 0.35
        index = np.arange(len(BUS_COUNTS))
        for i, mode in enumerate(DETECTION_MODES):
            mode_data = for_started[for_started['mode'] == mode]
            means = []
            stds = []
            for b in BUS_COUNTS:
                bdata = mode_data[mode_data['bus_count'] == b]['upload_duration'].dropna()
                means.append(bdata.mean() if len(bdata) > 0 else 0)
                stds.append(bdata.std() if len(bdata) > 1 else 0)
            ax.bar(index + i * bar_width, means, bar_width,
                   yerr=stds, label=f'{mode} mode',
                   color=mode_colors[mode], capsize=5,
                   edgecolor='black', linewidth=0.5)
        ax.set_xlabel('Number of Buses', fontsize=12)
        ax.set_ylabel('Upload Duration (s)', fontsize=12)
        ax.set_title('Forensic Upload Duration (10MB)', fontsize=14, fontweight='bold')
        ax.set_xticks(index + bar_width / 2)
        ax.set_xticklabels(BUS_COUNTS)
        ax.legend(fontsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, 'forensic_upload_duration.png'), dpi=150)
        plt.close()
        print("Generated forensic_upload_duration.png")

    # === Detection accuracy summary ===
    print("\n=== Detection Accuracy Summary ===")
    for mode in DETECTION_MODES:
        mode_det = det_df[det_df['mode'] == mode]
        for scenario in SCENARIOS:
            s_det = mode_det[mode_det['scenario'] == scenario]
            if s_det.empty:
                continue
            n = len(s_det)
            ddos_tp = s_det['ddos_true_positive'].sum()
            ddos_fp = s_det['ddos_false_positive'].sum()
            gps_tp = s_det['gps_true_positive'].sum()
            gps_fp = s_det['gps_false_positive'].sum()
            ddos_ttd = s_det['ddos_time_to_detect'].dropna()
            gps_ttd = s_det['gps_time_to_detect'].dropna()
            print(f"  [{mode}] {scenario}: "
                  f"DDoS TP={ddos_tp}/{n} FP={ddos_fp}/{n} "
                  f"avgTTD={ddos_ttd.mean():.1f}s | " if len(ddos_ttd) > 0 else
                  f"  [{mode}] {scenario}: "
                  f"DDoS TP={ddos_tp}/{n} FP={ddos_fp}/{n} | ", end='')
            if len(gps_ttd) > 0:
                print(f"GPS TP={gps_tp}/{n} FP={gps_fp}/{n} avgTTD={gps_ttd.mean():.1f}s")
            else:
                print(f"GPS TP={gps_tp}/{n} FP={gps_fp}/{n}")

    # === Upload success rate ===
    # Now driven by real bytes received at the server-side PacketSink
    # (smart-bus.cc::PollForensicCompletion).
    print("\n=== Forensic Upload Success Rate ===")
    for mode in DETECTION_MODES:
        mode_for = for_df[(for_df['mode'] == mode) & (for_df['upload_started'] == True)]
        if mode_for.empty:
            continue
        completed = int(mode_for['upload_completed'].sum())
        total = len(mode_for)
        avg_dur = mode_for['upload_duration'].dropna().mean()
        avg_pct = mode_for['upload_success_rate'].mean() * 100.0
        comp_pct = (completed / total * 100.0) if total > 0 else 0.0
        if total > 0 and not np.isnan(avg_dur):
            print(f"  [{mode}]: {completed}/{total} fully completed "
                  f"({comp_pct:.0f}%), avg bytes delivered={avg_pct:.1f}% "
                  f"of 10 MB, avg duration={avg_dur:.1f}s")
        else:
            print(f"  [{mode}]: {completed}/{total} fully completed, "
                  f"avg bytes delivered={avg_pct:.1f}% of 10 MB")

    print(f"\nAnalysis complete. Graphs saved to {GRAPHS_DIR}/")


if __name__ == '__main__':
    main()
