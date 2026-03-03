# Plan Evolution: V1 vs V2 vs Final

This document tracks the evolution of the Smart Bus Network simulation architecture.

## Version 1: The Initial Concept (Hardware-in-the-Loop)
**Focus:** Live demo connecting ns-3 to a Jetson Orin Nano physical device.
* **Core Architecture:** ns-3 acts as a network generator, sending TCP packets via a socket bridge to the Jetson Nano.
* **Detection:** Jetson runs a Machine Learning model (Random Forest/NN) trained on the external CIC-IDS2017 dataset.
* **Flaws Identified:** 
  1. *Time Sync:* ns-3 runs in virtual time; Jetson runs in real time. Blasting packets over a socket would ruin any time-based ML features unless `RealtimeSimulator` and `TapBridge` were used.
  2. *Dataset Mismatch:* Training ML on enterprise traffic (CIC-IDS2017) and testing on synthetic ns-3 traffic (`OnOffApplication`) guarantees model failure due to completely different statistical distributions.
  3. *LTE Bottleneck:* Baseline traffic was 61.5 Mbps uplink (1.5 Mbps CCTV x 41 buses). This instantly exceeds single-cell LTE capacity, causing massive packet loss before any attack starts.

## Version 2: Pivot to Pure Simulation
**Focus:** Isolating the ns-3 environment to generate scientifically valid synthetic datasets and metrics before hardware integration.
* **Core Architecture:** ns-3 handles traffic generation, attack modeling, and threshold-based detection internally. No Jetson or ML yet.
* **Metrics:** Introduced outputting CSVs for delays, throughput, and packet loss.
* **Flaws Identified:**
  1. *Single Run Fallacy:* Running a simulation once uses a single random seed. The results are statistically invalid for scientific graphs.
  2. *Manual Metrics:* Attempting to manually calculate end-to-end delay and jitter in C++ is highly prone to errors and drops.
  3. *Unrealistic Spoofing:* Attempting to override the physical `WaypointMobilityModel` to simulate a GPS spoofing attack is a simulator hack, not a network-layer attack.

## Version 3 (Final): Scientifically Rigorous Simulation
**Focus:** A robust, statistically valid ns-3.40 simulation designed to handle application-layer attacks and proper metric extraction.
* **Core Architecture:**
  1. **Multiple Runs:** Implementing 5 random seeds (`--RngRun=1..5`) per scenario, generating standard deviation error bars for analysis.
  2. **FlowMonitor:** Using ns-3's built-in `FlowMonitor` to export standard XML trace files, eliminating manual C++ metric calculations.
  3. **Application-Layer Spoofing:** GPS spoofing is modeled properly as a custom malicious C++ `ns3::Application` that sends UDP packets with false coordinates and spoofed bus IDs to the server.
  4. **ns-3.40 API Compliance:** Strict adherence to ns-3.40 rules: no lambdas in `Simulator::Schedule` (using free functions) and pre-scheduling `BulkSendApplication` for forensic uploads.
  5. **Realistic LTE:** eNodeBs are explicitly positioned to force LTE handovers, generating realistic latency spikes in the baseline traffic.