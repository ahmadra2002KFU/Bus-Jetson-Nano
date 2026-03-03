# Architecture Differences: Smart Bus Network Simulation

This document outlines the specific architectural changes made to the ns-3 simulation between the initial concept and the final implemented design.

### 1. The Real-Time vs. Virtual-Time Dilemma

*   **Initial Plan:** The ns-3 script would open a standard TCP socket and stream traffic to a physical Jetson Nano.
*   **The Flaw:** ns-3 runs a discrete-event simulation as fast as the CPU allows. The Jetson processes data in real-time. If ns-3 simulates 10 minutes of traffic in 5 seconds, the Jetson receives an impossible burst of data, ruining any time-based ML features (e.g., packets/sec, flow duration).
*   **Final Plan:** The project is entirely decoupled for Phase 1. ns-3 generates traffic, executes attacks, and outputs scientifically valid synthetic datasets (CSVs/XML) purely in simulation. The physical hardware loop (Jetson) is shelved until the simulation is proven mathematically sound.

### 2. The Machine Learning Dataset Mismatch

*   **Initial Plan:** Train the Jetson's ML model on the real-world **CIC-IDS2017** enterprise dataset, then feed it synthetic ns-3 simulated traffic.
*   **The Flaw:** The statistical distribution of real-world enterprise web/DB traffic (variable packet sizes, complex inter-arrival times) is fundamentally different from synthetic ns-3 mathematical traffic (e.g., `OnOffApplication` with perfect exponential bursts). The ML model would fail completely on the synthetic data.
*   **Final Plan:** Abandon CIC-IDS2017. The ns-3 simulation itself generates the "Baseline" (clean) and "Attack" (DDoS) CSV datasets, which will later be used to train the ML model, ensuring 100% coherence.

### 3. LTE Uplink Bottlenecking

*   **Initial Plan:** 41 buses stream 1.5 Mbps of CCTV traffic = ~61.5 Mbps of Uplink traffic.
*   **The Flaw:** A standard LTE cell (20 MHz) has a peak Uplink of ~50 Mbps. This design saturates the LTE RLC buffers instantly, causing massive packet loss *before* any DDoS attack starts.
*   **Final Plan:** The CCTV bandwidth is reduced to realistic edge-compressed levels (~500 kbps per bus), and the 3 eNBs are strategically positioned across a 15x20 km area to force realistic handovers and distribute the load.

### 4. Simulating GPS Spoofing

*   **Initial Plan:** Override the `WaypointMobilityModel` in ns-3 to instantly teleport a bus's physical node coordinates.
*   **The Flaw:** This is a simulator hack, not a network attack. It breaks the internal ns-3 mobility scheduler.
*   **Final Plan:** GPS Spoofing is modeled correctly at the Application Layer. A custom malicious `ns3::Application` (`GpsSpoofAttackApp`) sends UDP packets containing fake coordinates and a spoofed bus ID to the server, mimicking a true Man-in-the-Middle injection.

### 5. Metric Collection and Statistical Validity

*   **Initial Plan:** Calculate End-to-End delay, throughput, and packet loss manually via C++ tracking variables. Run each scenario exactly once.
*   **The Flaw:** Manual metric tracking is prone to severe bugs (dropped packet miscalculations). A single simulation run is statistically meaningless due to the use of a single pseudo-random seed.
*   **Final Plan:** Use ns-3's robust, built-in `FlowMonitor` module to track all packets at the IP layer and export an XML file. Run each scenario 5 times (`--RngRun=1..5`) and use a Python script (`analyze.py`) to parse the XML, average the results, and generate matplotlib graphs with standard deviation error bars.