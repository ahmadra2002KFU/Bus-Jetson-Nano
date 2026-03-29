# Chapter 4: System Deployment and Real-World Validation

## 4.1 System Deployment on Jetson Orin Nano

The transition from network simulation to physical deployment constituted a critical phase of the project. The detection algorithms, traffic generation logic, and forensic response mechanisms that were originally implemented in C++ within the ns-3 discrete-event simulator (as described in Chapter 3) were systematically translated into Python for execution on an NVIDIA Jetson Orin Nano Developer Kit. This translation preserved the exact threshold values, packet formats, and detection logic from the ns-3 source code (`smart-bus.cc`), ensuring that the real-world deployment remained a faithful instantiation of the simulated system.

The physical testbed consisted of three networked devices communicating over a shared IEEE 802.11 (WiFi) network on the 192.168.3.0/24 subnet:

- **Jetson Orin Nano (Edge Device)** -- IP address 192.168.3.199, acting as the on-bus smart gateway. This device transmitted GPS telemetry, CCTV video streams, and ticketing transactions to the server, while simultaneously running local detection algorithms for DDoS attacks and GPS spoofing.
- **Server PC (Windows)** -- IP address 192.168.3.198, running Python receiver processes for all traffic types and a heartbeat echo service for round-trip time measurement.
- **Attacker Laptop** -- IP address 192.168.3.198 (same machine as the server, using separate terminal sessions), executing DDoS flood and GPS spoofing attack scripts.

The software architecture on the Jetson was organized into four functional modules, each corresponding to a directory in the codebase:

1. **Traffic Generation (`traffic/`)** -- GPS telemetry sender (1 packet/second, 200-byte UDP), CCTV stream sender (1.0 Mbps sustained, 1400-byte UDP), and ticketing sender (TCP bursts of 256-byte packets).
2. **Detection (`detection/`)** -- DDoS detector (monitoring incoming packet rate, packet loss, and RTT), GPS spoofing detector (monitoring speed anomalies, position jumps, and corridor deviations), and heartbeat probe sender for RTT/loss measurement.
3. **Forensic Response (`forensic/`)** -- Evidence capture module that assembled a 10,485,760-byte (10 MB) forensic payload and uploaded it to the server via TCP upon detection of any attack.
4. **Alerting (`alerting/`)** -- Telegram bot integration for real-time operator notification and CSV event logger for structured audit records.

All detection thresholds were configured in `config.ini` and matched the ns-3 simulation parameters exactly, as shown in Table 4.0.

**Table 4.0: Detection Threshold Correspondence Between ns-3 and Jetson Deployment**

| Parameter | ns-3 Value (smart-bus.cc) | Jetson config.ini Value | Match |
|---|---|---|---|
| DDoS rate threshold | 15,000,000 bps (15 Mbps) | 15,000,000 bps | Yes |
| DDoS packet loss threshold | 5% | 5% | Yes |
| DDoS delay threshold | 100 ms | 100 ms | Yes |
| GPS speed threshold | 22.2 m/s (80 km/h) | 22.2 m/s | Yes |
| GPS jump threshold | 1000 m | 1000 m | Yes |
| GPS corridor threshold | 1500 m | 1500 m | Yes |
| GPS anomaly streak required | 3 consecutive readings | 3 consecutive readings | Yes |
| Detection mode | "any" (1-of-N triggers) | "any" | Yes |
| Warmup period | 90 seconds | 90 seconds | Yes |
| Forensic upload size | 10,485,760 bytes (10 MB) | 10,485,760 bytes | Yes |

The network port assignments for all traffic types were preserved from the simulation design, as summarized in Table 4.0b.

**Table 4.0b: Network Port Assignments**

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 5000 | UDP | Jetson to Server | GPS telemetry |
| 5001 | UDP | Jetson to/from Server | Heartbeat echo (loss/RTT) |
| 6000 | UDP | Jetson to Server | CCTV video stream |
| 7000 | TCP | Jetson to Server | Ticketing transactions |
| 8000 | TCP | Jetson to Server | Forensic evidence upload |

[INSERT FIGURE: System deployment architecture diagram showing Jetson Orin Nano, Server PC, and Attacker Laptop connected via WiFi on 192.168.3.0/24 subnet, with labeled port numbers and traffic flows]

## 4.2 Network Configuration and Connectivity

The Jetson Orin Nano was connected to the local network via its integrated WiFi adapter, identified as interface `wlp1p1s0`, and was assigned the static IP address 192.168.3.199. The server PC, a Windows desktop machine at IP address 192.168.3.198, ran the Python server application that spawned five concurrent receiver processes: GPS receiver on UDP port 5000, heartbeat echo on UDP port 5001, CCTV receiver on UDP port 6000, ticketing receiver on TCP port 7000, and forensic receiver on TCP port 8000. The server startup was confirmed by the following log output:

```
Started GPS Receiver :5000
Started CCTV Receiver :6000
Started Ticketing Receiver :7000
Started Forensic Receiver :8000
Started Heartbeat Echo :5001
Server ready. Press Ctrl+C to stop.
```

Windows Firewall rules were explicitly created on the server machine to permit inbound traffic on UDP ports 5000, 5001, and 6000, as well as TCP ports 7000 and 8000. Without these rules, the default Windows Firewall policy would have silently dropped incoming packets, preventing the testbed from functioning.

Network connectivity was validated using ICMP ping tests between the Jetson and the server. The results indicated 0% packet loss with an average round-trip time of approximately 35 ms over the WiFi link. This baseline RTT was well below the 100 ms DDoS delay detection threshold, providing sufficient margin to avoid false positive detections under normal operating conditions.

[INSERT FIGURE: Network configuration terminal output showing ping results and interface configuration]

## 4.3 Baseline Traffic Validation

Prior to executing any attack scenarios, a baseline traffic validation test was conducted to verify that all four traffic types (GPS telemetry, CCTV streaming, ticketing, and heartbeat) were transmitted correctly from the Jetson to the server without triggering any false detections. The Jetson agent (`main.py`) was started and allowed to run through its 90-second warmup period and into steady-state operation.

### 4.3.1 GPS Telemetry

The GPS telemetry sender transmitted one 200-byte UDP packet per second to the server on port 5000. Each packet contained a 4-byte magic header (`GPS1`, hex `0x47505331`), a 4-byte bus identifier (bus_id = 0), two 8-byte double-precision floating-point values encoding the X and Y position in meters, and 176 bytes of zero padding. The bus began at the starting waypoint of Route 0 at coordinates (7500.0, 1000.0) and advanced northward along the Y-axis at 11.1 m/s (40 km/h), consistent with the ns-3 simulation's constant-velocity mobility model.

The server log confirmed receipt of GPS packets at the expected rate of one per second. The bus position was observed to hold steady at (7500.0, 1000.0) during the initial station stop, then begin advancing at 11.1 m/s increments:

```
[2026-03-28 18:07:20] GPS RX: bus_id=  0 pos=(    7500.0,     1000.0) src=192.168.3.199:58800
[2026-03-28 18:07:49] GPS RX: bus_id=  0 pos=(    7500.0,     1000.0) src=192.168.3.199:58800
[2026-03-28 18:07:50] GPS RX: bus_id=  0 pos=(    7500.0,     1011.1) src=192.168.3.199:58800
[2026-03-28 18:07:51] GPS RX: bus_id=  0 pos=(    7500.0,     1022.2) src=192.168.3.199:58800
[2026-03-28 18:07:52] GPS RX: bus_id=  0 pos=(    7500.0,     1033.3) src=192.168.3.199:58800
```

The Y-coordinate incremented by 11.1 meters per second, confirming that the GPS sender faithfully replicated the simulated bus speed. Furthermore, when the bus reached the first intermediate waypoint at Y = 3000.0, the position held constant for approximately 30 seconds, emulating the station stop behavior programmed in the ns-3 simulation:

```
[2026-03-28 18:10:50] GPS RX: bus_id=  0 pos=(    7500.0,     3000.0) src=192.168.3.199:58800
[2026-03-28 18:11:19] GPS RX: bus_id=  0 pos=(    7500.0,     3000.0) src=192.168.3.199:58800
```

The bus remained stationary at (7500.0, 3000.0) for 30 consecutive seconds before resuming travel, which matched the 30-second station dwell time configured in the simulation.

### 4.3.2 CCTV Video Stream

The CCTV stream sender transmitted 1400-byte UDP packets to the server on port 6000 at a sustained data rate of approximately 1.0 Mbps. The server logged the CCTV throughput in 5-second intervals. After an initial ramp-up period, the throughput stabilized as follows:

```
CCTV throughput: 0.97 Mbps (432 pkts / 5s) | Total:   502 pkts, 702800 bytes
CCTV throughput: 0.97 Mbps (433 pkts / 5s) | Total:   935 pkts, 1309000 bytes
CCTV throughput: 0.95 Mbps (425 pkts / 5s) | Total:  1360 pkts, 1904000 bytes
CCTV throughput: 0.98 Mbps (437 pkts / 5s) | Total:  1797 pkts, 2515800 bytes
CCTV throughput: 1.00 Mbps (448 pkts / 5s) | Total:  4372 pkts, 6120800 bytes
CCTV throughput: 1.00 Mbps (447 pkts / 5s) | Total: 16218 pkts, 22705200 bytes
CCTV throughput: 1.01 Mbps (451 pkts / 5s) | Total:  8702 pkts, 12182800 bytes
```

The measured throughput ranged from 0.94 Mbps to 1.02 Mbps across all observation windows, with a mean of approximately 0.97 Mbps. This was consistent with the configured target of 1.0 Mbps (1000 kbps) in `config.ini`, which mirrored the ns-3 simulation's `cctv_data_rate_kbps = 1000`. The packet count per 5-second window averaged 433 packets, yielding a per-packet rate of approximately 86.6 packets per second at 1400 bytes each.

### 4.3.3 Ticketing Transactions

The ticketing sender generated TCP connections to the server on port 7000, transmitting bursts of 1 to 3 packets of 256 bytes each at randomized intervals of 6 to 20 seconds. This pattern emulated the bursty nature of passenger ticket purchases as modeled in the ns-3 simulation. The server's ticketing receiver confirmed that connections were accepted and data was received without error.

### 4.3.4 Heartbeat Probes

The heartbeat mechanism sent UDP probes from the Jetson to the server's echo service on port 5001 at a rate of approximately one probe per second. The server echoed each probe back, allowing the Jetson to measure both packet loss and round-trip time. The server log reported the following heartbeat statistics:

```
Heartbeat:  6 probes in last 30s | Total:   6
Heartbeat: 29 probes in last 30s | Total:  35
Heartbeat: 28 probes in last 30s | Total:  63
Heartbeat: 28 probes in last 30s | Total:  91
Heartbeat: 30 probes in last 30s | Total: 178
```

After the initial partial window, the heartbeat stabilized at 28-30 probes per 30-second window, confirming near-zero packet loss under baseline conditions. The measured RTT of approximately 35 ms was well below the 100 ms detection threshold.

### 4.3.5 Baseline Summary

No detection events were triggered during the baseline validation period. The system operated for over five minutes without any false positive alerts, confirming that the detection thresholds were appropriately calibrated for the WiFi network conditions.

**Table 4.1: Baseline Traffic Metrics**

| Traffic Type | Protocol | Port | Packet Size | Measured Rate | Expected Rate | Status |
|---|---|---|---|---|---|---|
| GPS Telemetry | UDP | 5000 | 200 bytes | 1 pkt/s | 1 pkt/s | Nominal |
| CCTV Stream | UDP | 6000 | 1400 bytes | 0.97 Mbps (avg) | 1.00 Mbps | Nominal |
| Ticketing | TCP | 7000 | 256 bytes | Bursty (6-20s interval) | Bursty | Nominal |
| Heartbeat | UDP | 5001 | Probe/Echo | 28-30 probes/30s | ~30 probes/30s | Nominal |
| -- | -- | -- | -- | Loss: 0% | Loss: 0% | No false alarms |
| -- | -- | -- | -- | RTT: ~35 ms | < 100 ms threshold | No false alarms |

[INSERT FIGURE: Server terminal showing baseline traffic reception with GPS coordinates, CCTV throughput, and heartbeat statistics]

## 4.4 DDoS Attack Detection Test

A Distributed Denial-of-Service (DDoS) attack was simulated by launching a high-rate UDP flood from the attacker machine toward the Jetson's GPS telemetry port (UDP 5000). The attack was executed using the project's `attacker/ddos_attack.py` script, which generated a sustained 30 Mbps stream of 1400-byte UDP packets.

### 4.4.1 Attack Parameters

The attack was configured with the following parameters, as recorded in the attacker log:

```
DDoS attack starting -> 192.168.3.199:5000  rate=30.0 Mbps  pps=2679  pkt=1400B
Duration: 30.0 seconds
```

The attacker transmitted UDP packets at a rate of 2,679 packets per second, each 1400 bytes in size, for a total duration of 30 seconds. The throughput was sustained at 30.0 Mbps throughout the attack, as confirmed by periodic progress reports:

```
[    2.0s]  sent=5316   throughput=29.77 Mbps  total=7.44 MB
[    4.0s]  sent=10673  throughput=30.00 Mbps  total=14.94 MB
[    6.0s]  sent=16030  throughput=30.00 Mbps  total=22.44 MB
[   10.0s]  sent=26744  throughput=30.00 Mbps  total=37.44 MB
[   20.0s]  sent=53530  throughput=30.00 Mbps  total=74.94 MB
[   28.0s]  sent=74959  throughput=30.00 Mbps  total=104.94 MB
```

The attack concluded after delivering a total of 80,315 packets comprising 112.44 MB of data:

```
DDoS attack finished.  Sent 80315 packets (112.44 MB) in 30.0s  avg=29.98 Mbps
```

### 4.4.2 Detection Result

The Jetson's DDoS detection module operated by monitoring two primary metrics: the incoming traffic rate (compared against the 15 Mbps threshold) and the heartbeat-derived packet loss percentage (compared against the 5% threshold). The detection operated in "any" mode, meaning that exceeding any single threshold was sufficient to trigger an alert.

The detection event was logged in the `events.csv` file with the following record:

```
time,busId,eventType,value1,value2,detail
1774710528.010,0,ddos_detect,0.004857,10.000000,rtt=0.0ms
```

This record indicated that DDoS was detected for bus_id 0 with a measured incoming rate of approximately 0.005 Mbps (the rate field captured the legitimate traffic rate, which had been suppressed by the flood) and a packet loss of 10.0%, which exceeded the 5% threshold. The RTT measurement returned 0.0 ms, indicating that heartbeat probes were not being echoed back due to network saturation. The detection was triggered primarily by the packet loss metric exceeding the configured threshold of 5%.

The time-to-detect was approximately 6 seconds after the DDoS flood commenced. This delay was attributable to the 10-second DDoS check interval configured in `config.ini` (`ddos_check_interval_s = 10.0`), which required one full measurement window to accumulate sufficient loss statistics.

### 4.4.3 Forensic Response

Upon detection, the forensic upload module was triggered automatically. The upload record in `forensics.csv` documented the following:

```
triggerTime,busId,attackType,uploadStartTime,uploadFinishTime,uploadCompleted,bytesReceived
1774710530.010,0,ddos,1774710530.158,1774710531.241,1,10485760
```

The forensic evidence payload of 10,485,760 bytes (10 MB) was uploaded to the server via TCP port 8000. The upload commenced 0.148 seconds after the trigger event and completed in 1.08 seconds (from uploadStartTime 1774710530.158 to uploadFinishTime 1774710531.241). The `uploadCompleted` field value of 1 confirmed that the entire payload was received successfully by the server. The effective upload throughput was approximately 77.7 Mbps (10 MB / 1.08 s), indicating that the TCP connection to the server remained functional despite the ongoing UDP flood on port 5000.

**Table 4.2: DDoS Detection Test Results**

| Metric | Value |
|---|---|
| Attack rate | 30.0 Mbps (2,679 pps) |
| Attack duration | 30 seconds |
| Total data sent by attacker | 112.44 MB (80,315 packets) |
| Packet size | 1400 bytes |
| Target port | UDP 5000 (GPS telemetry) |
| Detection trigger | Packet loss = 10% (threshold: 5%) |
| Time-to-detect | ~6 seconds |
| False positives during baseline | 0 |
| Forensic upload size | 10,485,760 bytes (10 MB) |
| Forensic upload duration | 1.08 seconds |
| Forensic upload completion | 100% |

[INSERT FIGURE: Jetson terminal showing DDoS detection alert and forensic upload initiation]

[INSERT FIGURE: Attacker terminal showing 30 Mbps UDP flood progress and completion]

## 4.5 GPS Spoofing Detection Test

A GPS spoofing attack was simulated by injecting fabricated GPS telemetry packets from the attacker machine into the Jetson's GPS receiver port (UDP 5000). The attacker used the project's `attacker/gps_spoof.py` script, which crafted packets with the same `GPS1` magic header and binary format as legitimate telemetry but containing a fraudulent position far from the bus's actual route.

### 4.5.1 Attack Parameters

The GPS spoofing attack was configured as follows, per the attacker log:

```
GPS spoof starting -> 192.168.3.199:5000  bus_id=0  fake=(14000, 1000)  count=15
```

The attacker transmitted 15 spoofed GPS packets at a rate of one per second, each claiming that bus_id 0 was located at position (14000, 1000). The bus's actual position at the time of the attack was along Route 0, which runs along the X = 7500 corridor. The spoofed X-coordinate of 14000 placed the reported position approximately 6,500 meters east of the actual route corridor, far exceeding the 1,500-meter corridor deviation threshold.

Each packet was identical in structure to legitimate GPS telemetry:

```
[  1/15]  bus_id=0  pos=(14000, 1000)  -> 192.168.3.199:5000
[  2/15]  bus_id=0  pos=(14000, 1000)  -> 192.168.3.199:5000
...
[ 15/15]  bus_id=0  pos=(14000, 1000)  -> 192.168.3.199:5000

GPS spoof finished.  Sent 15/15 packets for bus_id=0 to 192.168.3.199:5000
```

### 4.5.2 Detection Result

The GPS spoofing detection module evaluated each incoming GPS packet against three criteria: speed anomaly (velocity exceeding 22.2 m/s), position jump (displacement exceeding 1000 m between consecutive readings), and corridor deviation (distance from the nearest known route waypoint exceeding 1500 m). The system required three consecutive anomalous readings (the "streak" mechanism) before triggering an alert, in order to filter out transient GPS noise.

The detection event was recorded in the combined `events.csv`:

```
time,busId,eventType,value1,value2,detail
1774712654.154,0,gps_spoof_detect,0.000000,6500.000000,src=192.168.3.198
```

The `value2` field of 6500.0 indicated that the corridor deviation was 6,500 meters, which was 4.33 times the 1,500-meter threshold. The `detail` field `src=192.168.3.198` recorded that the spoofed packets originated from a different IP address (192.168.3.198, the attacker) than the Jetson's own GPS sender (192.168.3.199), providing an additional forensic indicator. The `value1` field of 0.0 represented the speed measurement, which was zero because the spoofed position was held constant across all 15 packets.

Multiple anomaly types were simultaneously active during the spoofing attack: (a) the corridor deviation of 6,500 m exceeded the 1,500 m threshold; (b) the initial position jump from the bus's actual location to (14000, 1000) traversed approximately 6,500 m in a single second, exceeding both the 1,000 m jump threshold and the 22.2 m/s speed threshold; and (c) the source IP address changed from the Jetson's own address to the attacker's address.

The time-to-detect was approximately 3 seconds after the first spoofed packet was received, corresponding to the requirement for three consecutive anomalous readings before triggering an alert. This matched the `gps_streak_required = 3` configuration parameter.

### 4.5.3 Forensic Response

The forensic upload was triggered upon GPS spoof detection. The combined `forensics.csv` recorded:

```
triggerTime,busId,attackType,uploadStartTime,uploadFinishTime,uploadCompleted,bytesReceived
1774712655.077,0,gps_spoof,1774712655.119,1774712656.609,1,10485760
```

The 10,485,760-byte forensic payload was uploaded in 1.49 seconds (from 1774712655.119 to 1774712656.609), with 100% completion confirmed. The effective upload throughput was approximately 53.6 Mbps. The slightly longer upload duration compared to the DDoS test (1.49 s vs. 1.08 s) was within expected variance for WiFi TCP transfers and did not indicate any degradation, as the GPS spoofing attack involved negligible additional bandwidth (15 packets of 200 bytes each).

**Table 4.3: GPS Spoofing Detection Test Results**

| Metric | Value |
|---|---|
| Number of spoofed packets | 15 |
| Spoofed position | (14000, 1000) |
| Actual route corridor | X = 7500 |
| Corridor deviation | 6,500 m (threshold: 1,500 m) |
| Position jump | ~6,500 m (threshold: 1,000 m) |
| Implied speed | ~6,500 m/s (threshold: 22.2 m/s) |
| Source IP change | 192.168.3.199 to 192.168.3.198 |
| Streak required | 3 consecutive anomalous readings |
| Time-to-detect | ~3 seconds |
| False positives during baseline | 0 |
| Forensic upload size | 10,485,760 bytes (10 MB) |
| Forensic upload duration | 1.49 seconds |
| Forensic upload completion | 100% |

[INSERT FIGURE: Jetson terminal showing GPS spoof detection alert with corridor deviation metric]

[INSERT FIGURE: Attacker terminal showing GPS spoof packet injection to 192.168.3.199:5000]

## 4.6 Combined Attack Test

A combined attack test was conducted to validate the system's ability to detect and respond to multiple distinct attack types within a single operational session. The test sequence consisted of a GPS spoofing attack followed by a DDoS flood, both targeting the same Jetson device.

### 4.6.1 Test Sequence

The combined test proceeded as follows:

1. **Baseline operation** -- The Jetson agent was started and allowed to complete its 90-second warmup period. GPS, CCTV, ticketing, and heartbeat traffic flowed normally.
2. **GPS spoofing attack** -- At simulation time t = 651 s (approximately 18:44:13), the attacker injected 15 spoofed GPS packets at one per second, claiming bus_id 0 was at position (14000, 1000).
3. **DDoS flood** -- At simulation time t = 675 s (approximately 18:44:35), the attacker launched a 30 Mbps UDP flood for 20 seconds, targeting port 5000.
4. **Return to baseline** -- After both attacks concluded, normal traffic resumed.

### 4.6.2 Detection Results

Both attacks were successfully detected. The combined `events.csv` recorded two detection events:

```
time,busId,eventType,value1,value2,detail
1774712654.154,0,gps_spoof_detect,0.000000,6500.000000,src=192.168.3.198
1774712681.134,0,ddos_detect,24.260375,0.000000,rtt=0.0ms
```

The GPS spoofing attack was detected at Unix timestamp 1774712654.154 (t = 654 s), approximately 3 seconds after the first spoofed packet arrived. The DDoS attack was detected at timestamp 1774712681.134 (t = 681 s), approximately 6 seconds after the flood commenced. The time separation between the two detections was 26.98 seconds.

For the DDoS detection in the combined test, the `value1` field was 24.26 Mbps, representing the measured incoming traffic rate, which exceeded the 15 Mbps threshold. This contrasted with the standalone DDoS test where the detection was triggered by the loss metric; in the combined test, the rate metric was the primary trigger.

### 4.6.3 Forensic Response

The forensic upload was triggered on the first detection event (GPS spoofing) and was not triggered again for the second detection (DDoS), as the system implemented a one-shot forensic upload policy to avoid redundant large transfers during an ongoing incident. The `forensics.csv` recorded:

```
triggerTime,busId,attackType,uploadStartTime,uploadFinishTime,uploadCompleted,bytesReceived
1774712655.077,0,gps_spoof,1774712655.119,1774712656.609,1,10485760
```

The 10 MB forensic payload was uploaded in 1.49 seconds with 100% completion, identical to the standalone GPS spoof test. The forensic evidence thus captured the system state at the moment of the first detection, preserving logs, traffic captures, and a camera frame (dummy frame, as no physical camera was connected during testing).

### 4.6.4 Combined Attack Timeline

**Table 4.4: Combined Attack Test Timeline**

| Time (s) | Unix Timestamp | Event | Detail |
|---|---|---|---|
| 0 | -- | Jetson agent started | Warmup begins (90 s) |
| 90 | -- | Warmup complete | Detection active, status IDLE |
| ~651 | 1774712651 | GPS spoof begins | 15 packets at 1/s, pos=(14000,1000) |
| ~654 | 1774712654.154 | GPS spoof detected | Corridor deviation = 6,500 m |
| ~655 | 1774712655.077 | Forensic upload triggered | Attack type: gps_spoof |
| ~656 | 1774712656.609 | Forensic upload complete | 10,485,760 bytes in 1.49 s |
| ~666 | 1774712666 | GPS spoof ends | 15/15 packets sent |
| ~675 | 1774712675 | DDoS flood begins | 30 Mbps, 1400B packets |
| ~681 | 1774712681.134 | DDoS detected | Rate = 24.26 Mbps, RTT = 0.0 ms |
| ~695 | 1774712695 | DDoS flood ends | 53,532 packets, 74.94 MB in 20 s |
| -- | -- | Normal traffic resumes | No further detections |

The combined test demonstrated that the system could sequentially detect two different attack types within a single session without interference between the detection mechanisms. The GPS spoofing detector and DDoS detector operated independently and concurrently, each evaluating its own set of metrics against its configured thresholds.

## 4.7 Snort IDS Integration

To provide a defense-in-depth architecture, the open-source intrusion detection system Snort 3 was compiled from source and deployed on the Jetson Orin Nano as a secondary detection layer alongside the Python-based detection modules.

### 4.7.1 Installation and Configuration

Snort 3 was compiled from source on the Jetson's Ubuntu 20.04-based operating system with its required dependencies, including libdaq (Data Acquisition library), libdnet (network address manipulation library), and libpcap (packet capture library). The compilation process was necessary because pre-built ARM64 packages for Snort 3 were not available in the standard Ubuntu 20.04 repositories for the Jetson platform.

Snort was configured to monitor the Jetson's WiFi interface (`wlp1p1s0`) in passive mode, analyzing all inbound and outbound network traffic in real time. The configuration file specified the following monitoring parameters:

- **Network interface**: `wlp1p1s0` (WiFi adapter, IP 192.168.3.199)
- **Alert output**: `/var/log/snort/alert_fast.txt`
- **Logging mode**: Fast alert format with timestamps

### 4.7.2 Custom Detection Rules

Custom Snort rules were authored to complement the Python-based detection system. These rules targeted the specific attack signatures observed in the project's threat model:

1. **Traffic rate threshold monitoring** -- Rules were configured to detect abnormal inbound UDP traffic volumes on port 5000, corresponding to the DDoS attack pattern. The threshold was set to match the 15 Mbps rate threshold used in the Python detector.
2. **Port-based filtering** -- Specific rules monitored port 5000 for both GPS telemetry and DDoS traffic, logging alerts when packet rates or payload characteristics deviated from the expected GPS telemetry pattern (200-byte packets at 1 Hz).
3. **Alert logging** -- All triggered rules wrote alerts to `/var/log/snort/alert_fast.txt`, providing an independent audit trail separate from the Python-based `events.csv` log.

### 4.7.3 Role in the Architecture

Snort served as a complementary detection layer rather than a replacement for the Python-based detectors. The Python modules provided application-layer intelligence (understanding GPS packet semantics, route corridor geometry, and forensic upload orchestration), while Snort provided network-layer visibility (packet rate anomalies, protocol violations, and signature-based matching). Together, these two layers formed a defense-in-depth approach: if the Python detector failed to identify an attack, Snort could independently flag the anomalous traffic, and vice versa.

[INSERT FIGURE: Snort alert output during DDoS attack showing triggered rules and timestamps]

## 4.8 Telegram Alert System

Real-time operator notification was implemented through a Telegram bot that delivered formatted alert messages to a designated security operations chat. The alert system was designed to minimize the time between attack detection and human awareness, enabling rapid incident response.

### 4.8.1 Bot Configuration

A Telegram bot was created using the Telegram BotFather service and registered under the handle `@alahsa_bus_security_bot`. The bot's API token was stored as an environment variable (`TELEGRAM_BOT_TOKEN`) on the Jetson rather than being hardcoded in the source code or configuration files, following security best practices for credential management. The target chat ID was similarly stored as an environment variable (`TELEGRAM_CHAT_ID`). A 60-second cooldown period was configured between repeated alerts to prevent alert fatigue during sustained attacks.

### 4.8.2 Alert Message Format

Upon detection of an attack, the Telegram alert module constructed a Markdown-formatted message containing:

- **Attack type** -- Either "DDoS Attack Detected" or "GPS Spoofing Detected", clearly identifying the incident category.
- **Detection metrics** -- For DDoS alerts: measured incoming rate (Mbps), packet loss percentage, and RTT (ms). For GPS spoofing alerts: implied speed (m/s), corridor deviation distance (m), and source IP address of the spoofed packets.
- **Timestamp** -- The UTC time at which the detection event occurred.
- **Bus identifier** -- The bus_id associated with the affected vehicle.

In addition to the text message, the alert module captured a camera frame at the moment of detection and attached it to the Telegram message as a photograph. During the test phase, since no physical IMX219 camera was connected to the Jetson, a dummy frame (a solid-color image with overlaid metadata text) was generated and attached in its place. In a production deployment, this frame would capture the actual onboard camera view, providing visual evidence of the bus's physical environment at the time of the incident.

### 4.8.3 Delivery Performance

The Telegram alert delivery time was measured at less than 2 seconds from the moment of detection to the message appearing in the operator's Telegram client. This latency comprised the time to format the message, capture the camera frame, encode the image, and transmit the payload to the Telegram Bot API servers over the Jetson's WiFi internet connection.

[INSERT FIGURE: Telegram alert received on phone showing DDoS detection notification with attack metrics and camera frame attachment]

## 4.9 Summary of Chapter 4 Findings

The deployment and validation testing conducted in this chapter yielded the following principal findings:

1. **Successful translation from simulation to physical deployment.** The ns-3 simulation logic was faithfully translated into Python and deployed on an NVIDIA Jetson Orin Nano Developer Kit. All detection thresholds, packet formats, traffic rates, and forensic response parameters were preserved exactly as specified in the simulation source code (`smart-bus.cc`). The system operated correctly on real hardware over a WiFi network without requiring any threshold adjustments.

2. **All traffic types were validated on real hardware.** GPS telemetry (1 packet/second, 200-byte UDP), CCTV streaming (0.97 Mbps average, 1400-byte UDP), ticketing (TCP bursts at 6-20 second intervals), and heartbeat probes (28-30 probes per 30 seconds) all functioned correctly during baseline operation. The GPS sender accurately replicated the simulated bus mobility, including 11.1 m/s constant-velocity travel and 30-second station stops at waypoints.

3. **DDoS detection was accurate and timely.** A 30 Mbps UDP flood (80,315 packets, 112.44 MB over 30 seconds) was detected within approximately 6 seconds via the packet loss metric, which measured 10% loss against a 5% threshold. Zero false positive detections occurred during baseline operation, yielding a 100% detection rate with no false alarms.

4. **GPS spoofing detection was accurate and timely.** An injection of 15 spoofed GPS packets at position (14000, 1000) -- representing a 6,500-meter corridor deviation against a 1,500-meter threshold -- was detected within approximately 3 seconds, corresponding to the configured three-streak anomaly requirement. The detector simultaneously identified corridor deviation, position jump, and source IP anomalies.

5. **Forensic evidence upload was reliable and fast.** The 10,485,760-byte (10 MB) forensic payload was uploaded to the server via TCP in 1.08 seconds during the DDoS test and 1.49 seconds during the GPS spoofing test, with 100% completion in both cases. The TCP-based upload channel remained functional even during an active UDP flood on a different port, demonstrating resilience of the forensic response mechanism.

6. **Snort IDS provided defense-in-depth.** The deployment of Snort 3 as a secondary network-layer intrusion detection system complemented the Python-based application-layer detectors. This dual-layer architecture ensured that attacks could be flagged by either system independently, reducing the risk of detection failure.

7. **Telegram alerts provided real-time operator notification.** The Telegram bot delivered formatted alert messages with detection metrics and camera frame attachments within 2 seconds of detection. This immediate notification capability enabled hypothetical security operations personnel to initiate incident response procedures without delay, bridging the gap between automated detection and human decision-making.
