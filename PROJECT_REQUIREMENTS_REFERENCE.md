# Smart Bus Network Simulation Requirements Reference

This file is the canonical implementation reference for this workspace.
Every future code change, simulation run, validation step, and analysis update
 should be checked against these requirements.

## Part 1 - Real System Overview

- Operator: SAPTCO
- Fleet Size: 41 buses
- Number of Lines: 10
- Stations: 135
- Total Route Length: 336 km combined
- Operating Hours: 05:30 AM - 11:30 PM (18 hours daily)
- Operational Area: urban cluster only, about 250-400 km^2

Each bus contains:

- 4G/5G router
- GPS module
- CCTV cameras
- Ticketing system
- Edge device (Jetson Orin Nano)

Communication path:

- Bus -> LTE Tower -> Core Network -> Cloud Server -> Monitoring Dashboard
- No direct bus-to-bus communication
- All communication passes through LTE infrastructure

## Part 2 - Simulation Architecture in ns-3

Simulation area:

- 15 km x 20 km grid representing the urban Al-Ahsa cluster

Network nodes:

- 41 bus nodes (UEs)
- 3 LTE towers (eNBs)
- 1 cloud server
- 1 attacker node

Mobility model:

- `WaypointMobilityModel`
- Speed: 30-50 km/h
- Stop duration: 30 seconds per station
- Route repeats in loop

## Part 3 - Traffic Modeling

Normal traffic per bus:

- Telemetry (GPS): 1 packet per second
- CCTV stream: 1-2 Mbps UDP
- Ticketing: random small TCP bursts

Forensic event simulation:

- Triggered when attack detected
- Simulate 10 MB evidence upload
- Record upload start and finish times

## Part 4 - Attack Scenarios

Attack 1 - DDoS:

- Attacker sends 20-50 Mbps UDP traffic to the cloud server
- Observe delay increase, packet loss, queue buildup, and upload delay

Attack 2 - GPS Spoofing:

- Inject false GPS coordinates
- Simulate sudden jump of 5-10 km
- Simulate impossible speed above 120 km/h
- Detect route deviation outside corridor

## Part 5 - Detection Logic

DDoS detection conditions:

- Traffic rate exceeds defined threshold
- Packet loss greater than 5%
- Delay greater than 100 ms

GPS spoofing detection conditions:

- Calculated speed greater than 80 km/h
- Location outside route boundary
- Sudden jump greater than 1 km within 1 second

Detection rule:

- If any condition is true, trigger forensic event

## Part 6 - Performance Metrics

Network metrics:

- End-to-End Delay
- Throughput
- Packet Loss
- Jitter
- Queue Delay

Forensic metrics:

- Detection Time
- Evidence Upload Time
- Upload Success Rate
- Detection Accuracy

## Part 7 - Scalability Testing

Required scenarios:

- 1 bus
- 10 buses
- 41 buses

Required comparison areas:

- latency
- congestion
- detection stability
- upload timing

## Part 8 - Final Execution Flow

1. Initialize LTE network
2. Deploy bus nodes
3. Assign mobility routes
4. Start normal traffic
5. Run baseline
6. Launch DDoS attack
7. Launch GPS spoofing attack
8. Trigger forensic event
9. Measure and log metrics
10. Generate graphs and analysis

## Working Rule For This Repository

Any future simulation or code change should be evaluated against this file
first. If implementation behavior and this reference conflict, this reference
should be treated as the source of truth unless the project owner explicitly
changes the requirements.
