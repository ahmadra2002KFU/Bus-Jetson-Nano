/*
 * ==============================================================================
 * AL-AHSA SMART BUS NETWORK - BUG FIXES & NS-3.40 MIGRATION NOTES
 * ==============================================================================
 * 
 * 1. EventId API Change (ns-3.40 Compatibility):
 *    Changed m_sendEvent.IsPending() to m_sendEvent.IsRunning() in both 
 *    GpsTelemetryApp and GpsSpoofAttackApp. The IsPending() method was 
 *    deprecated and removed in recent ns-3 versions.
 * 
 * 2. Ticketing TCP Reconnection Bug (Runtime Crash Fix):
 *    Replaced TCP OnOff ticketing with a custom TicketingApp that keeps one
 *    TCP socket open and emits small random bursts. This matches the project
 *    requirement without triggering the known OnOff TCP reconnect crash.
 * ==============================================================================
 */

/* smart-bus.cc
 * Al-Ahsa Smart Bus Network — ns-3 LTE Simulation
 * Models DDoS and GPS spoofing attacks, detection logic,
 * forensic evidence upload. Compares 1/10/41 bus scenarios.
 *
 * CRITICAL: No lambdas in Simulator::Schedule — all callbacks
 * are free functions or member functions.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lte-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/config-store-module.h"
#include "ns3/propagation-module.h"

#include <fstream>
#include <iomanip>
#include <cmath>
#include <sstream>
#include <map>
#include <algorithm>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SmartBusSimulation");

// ============================================================
// CONSTANTS
// ============================================================
static const uint32_t MAX_BUSES = 41;
static const uint32_t NUM_ENB = 3;
static const double STATION_STOP_TIME = 30.0;
// Supervisor spec: bus speed 30-50 km/h, "variable, not fixed".
// We assign each bus a constant speed sampled uniformly from [30,50] km/h
// (~ [8.33, 13.89] m/s) at simulation start. Per-bus constant (not
// per-segment) was chosen so mobility waypoint timing is deterministic
// per bus and so logged speed anomalies remain comparable across runs.
static const double BUS_SPEED_MIN_MS = 8.33;   // 30 km/h
static const double BUS_SPEED_MAX_MS = 13.89;  // 50 km/h

// Detection thresholds
static const double DDOS_RATE_THRESHOLD = 15e6;    // 15 Mbps
static const double DDOS_LOSS_THRESHOLD = 0.05;     // 5%
static const double DDOS_DELAY_THRESHOLD = 0.1;     // 100ms
static const double GPS_SPEED_THRESHOLD = 22.2;     // 80 km/h
static const double GPS_JUMP_THRESHOLD = 1000.0;    // 1 km
static const double GPS_CORRIDOR_THRESHOLD = 1500.0; // 1500m
static const double DETECTION_WARMUP_TIME = 90.0;
// Backhaul/transit from PGW to the analytics server.
// 100 Mbps models a realistic operator-to-customer backhaul; this is the
// link where the DDoS attacker traffic mixes with legitimate aggregated
// uplink before hitting the analytics server. Sized so:
//   - Baseline aggregated bus traffic (~43 Mbps offered, ~41 Mbps delivered)
//     fits comfortably (<50% utilisation -> no queue, ~0 queue delay).
//   - DDoS at 30 Mbps + legit 41 Mbps = 71 Mbps -> ~71% utilisation,
//     causing queue build-up and visible delay/PLR jump in the metrics.
// Previously 1 Gbps, which made the DDoS invisible because the server
// link absorbed everything trivially.
static const double SERVER_LINK_RATE_BPS = 100e6;

// GPS telemetry packet format:
// [0..3]   magic (uint32)
// [4..7]   busId (uint32)
// [8..15]  posX (double)
// [16..23] posY (double)
static const uint32_t GPS_PAYLOAD_MAGIC = 0x47505331; // "GPS1"
static const uint32_t GPS_PAYLOAD_MIN_SIZE = 24;

// Ports
static const uint16_t TELEMETRY_PORT = 5000;
static const uint16_t CCTV_PORT = 6000;
static const uint16_t TICKET_PORT = 7000;
static const uint16_t FORENSIC_PORT = 8000;
// GPS spoofing uses TELEMETRY_PORT directly

// ============================================================
// DATA STRUCTURES
// ============================================================
struct RouteDefinition {
    std::vector<Vector> stations;
};

struct GpsState {
    Vector lastPosition;
    double lastTime;
    bool initialized;
    uint32_t routeIndex;
    bool spoofDetected;
};

struct MetricsRecord {
    double time;
    uint32_t busId;
    std::string eventType;
    double value1;
    double value2;
    std::string detail;
};

struct ForensicEvent {
    double triggerTime;
    uint32_t busId;
    std::string attackType;
    double uploadStartTime;
    double uploadFinishTime;
    bool uploadCompleted;
    uint64_t bytesReceived;
};

// ============================================================
// GLOBALS
// ============================================================
static std::map<uint32_t, GpsState> g_gpsStates;
static std::vector<MetricsRecord> g_metricsLog;
static std::vector<ForensicEvent> g_forensicEvents;
static bool g_ddosDetected = false;
static double g_ddosDetectionTime = 0.0;
static bool g_gpsSpoofDetected = false;
static double g_gpsSpoofDetectionTime = 0.0;
static bool g_forensicTriggered = false;
static std::string g_detectionMode = "any";
static Ptr<PacketSink> g_forensicSinkApp;
static double g_simTime = 300.0;  // Set in main(); used by forensic poller.

// Forensic upload: hand-rolled UDP sender state (Round 4 fix).
// Bypasses ns-3 OnOffApplication entirely because mid-simulation
// Application::SetStartTime is unreliable (DoInitialize schedules
// StartApplication using m_startTime as a delay-from-now, so passing an
// absolute timestamp pushes the start event past sim end). The sender
// chain below runs on plain Simulator::Schedule so its lifecycle is
// deterministic regardless of ns-3 Application semantics.
static Ptr<Socket> g_forensicSocket;
static uint64_t g_forensicBytesSent = 0;
static bool g_forensicSendingActive = false;
// GPS detector streak gate. Supervisor spec is "any 1-of-3 condition
// triggers" -> default 1. Configurable via --gpsStreakRequired for noise
// experiments; the compliance baseline is 1.
static uint32_t g_gpsStreakRequired = 1;

// ============================================================
// HELPER: Activate one uplink dedicated bearer by server port
// ============================================================
static void
ActivateUplinkBearer(Ptr<LteHelper> lteHelper,
                     Ptr<NetDevice> ueDevice,
                     uint16_t remotePort,
                     EpsBearer::Qci qci,
                     uint64_t gbrUl,
                     uint64_t mbrUl)
{
    Ptr<EpcTft> tft = Create<EpcTft>();
    EpcTft::PacketFilter ulpf;
    ulpf.remotePortStart = remotePort;
    ulpf.remotePortEnd = remotePort;
    tft->Add(ulpf);

    if (gbrUl > 0)
    {
        GbrQosInformation qos;
        qos.gbrDl = 0;
        qos.mbrDl = 0;
        qos.gbrUl = gbrUl;
        qos.mbrUl = std::max(gbrUl, mbrUl);
        EpsBearer bearer(qci, qos);
        lteHelper->ActivateDedicatedEpsBearer(ueDevice, bearer, tft);
    }
    else
    {
        EpsBearer bearer(qci);
        lteHelper->ActivateDedicatedEpsBearer(ueDevice, bearer, tft);
    }
}

// ============================================================
// HELPER: Log a metric
// ============================================================
static void
LogMetric(double time, uint32_t busId, const std::string &eventType,
          double v1, double v2, const std::string &detail)
{
    MetricsRecord r;
    r.time = time;
    r.busId = busId;
    r.eventType = eventType;
    r.value1 = v1;
    r.value2 = v2;
    r.detail = detail;
    g_metricsLog.push_back(r);
}

// ============================================================
// ROUTE DEFINITIONS (10 routes across Al-Ahsa)
// ============================================================
static std::vector<RouteDefinition>
CreateRoutes()
{
    std::vector<RouteDefinition> routes(10);

    routes[0].stations = {
        Vector(7500, 1000, 0), Vector(7500, 3000, 0), Vector(7500, 5000, 0),
        Vector(7500, 7000, 0), Vector(7500, 9000, 0), Vector(7500, 11000, 0),
        Vector(7500, 13000, 0), Vector(7500, 15000, 0), Vector(7500, 17000, 0),
        Vector(7500, 19000, 0)
    };

    routes[1].stations = {
        Vector(1000, 10000, 0), Vector(3000, 10000, 0), Vector(5000, 10000, 0),
        Vector(7000, 10000, 0), Vector(9000, 10000, 0), Vector(11000, 10000, 0),
        Vector(13000, 10000, 0), Vector(15000, 10000, 0)
    };

    routes[2].stations = {
        Vector(1000, 1000, 0), Vector(3000, 3000, 0), Vector(5000, 5000, 0),
        Vector(7000, 7000, 0), Vector(9000, 9000, 0), Vector(11000, 11000, 0),
        Vector(13000, 13000, 0)
    };

    routes[3].stations = {
        Vector(14000, 1000, 0), Vector(12000, 3000, 0), Vector(10000, 5000, 0),
        Vector(8000, 7000, 0), Vector(6000, 9000, 0), Vector(4000, 11000, 0),
        Vector(2000, 13000, 0)
    };

    routes[4].stations = {
        Vector(3000, 2000, 0), Vector(5000, 1000, 0), Vector(7000, 2000, 0),
        Vector(9000, 1000, 0), Vector(11000, 2000, 0), Vector(13000, 1000, 0),
        Vector(11000, 3000, 0), Vector(9000, 4000, 0), Vector(7000, 3000, 0),
        Vector(5000, 4000, 0), Vector(3000, 3000, 0)
    };

    routes[5].stations = {
        Vector(3000, 17000, 0), Vector(5000, 18000, 0), Vector(7000, 17000, 0),
        Vector(9000, 18000, 0), Vector(11000, 17000, 0), Vector(13000, 18000, 0),
        Vector(11000, 19000, 0), Vector(9000, 19000, 0), Vector(7000, 19000, 0),
        Vector(5000, 19000, 0)
    };

    routes[6].stations = {
        Vector(5000, 7000, 0), Vector(7000, 5000, 0), Vector(10000, 7000, 0),
        Vector(12000, 10000, 0), Vector(10000, 13000, 0), Vector(7000, 15000, 0),
        Vector(5000, 13000, 0), Vector(3000, 10000, 0)
    };

    routes[7].stations = {
        Vector(13000, 2000, 0), Vector(14000, 4000, 0), Vector(13000, 6000, 0),
        Vector(14000, 8000, 0), Vector(13000, 10000, 0), Vector(14000, 12000, 0),
        Vector(13000, 14000, 0), Vector(14000, 16000, 0)
    };

    routes[8].stations = {
        Vector(2000, 2000, 0), Vector(1000, 4000, 0), Vector(2000, 6000, 0),
        Vector(1000, 8000, 0), Vector(2000, 10000, 0), Vector(1000, 12000, 0),
        Vector(2000, 14000, 0), Vector(1000, 16000, 0)
    };

    routes[9].stations = {
        Vector(1000, 1000, 0), Vector(5000, 5000, 0), Vector(7500, 10000, 0),
        Vector(10000, 15000, 0), Vector(14000, 19000, 0)
    };

    return routes;
}

// ============================================================
// BUS ROUTE ASSIGNMENT (41 buses, ~4 per route)
// ============================================================
static std::vector<uint32_t>
GetBusRouteAssignment()
{
    return {
        0,0,0,0,  1,1,1,1,  2,2,2,2,  3,3,3,3,
        4,4,4,4,  5,5,5,5,  6,6,6,6,  7,7,7,7,
        8,8,8,8,  9,9,9,9,9
    };
}

// ============================================================
// DISTANCE FROM POINT TO ROUTE (nearest segment)
// ============================================================
static double
DistanceToRoute(Vector pos, const RouteDefinition &route)
{
    double minDist = 1e9;
    for (uint32_t i = 0; i + 1 < route.stations.size(); i++)
    {
        Vector a = route.stations[i];
        Vector b = route.stations[i + 1];
        double dx = b.x - a.x;
        double dy = b.y - a.y;
        double lenSq = dx * dx + dy * dy;
        double t = 0.0;
        if (lenSq > 0)
        {
            t = ((pos.x - a.x) * dx + (pos.y - a.y) * dy) / lenSq;
            t = std::max(0.0, std::min(1.0, t));
        }
        Vector closest(a.x + t * dx, a.y + t * dy, 0);
        double dist = CalculateDistance(pos, closest);
        if (dist < minDist) minDist = dist;
    }
    return minDist;
}

// ============================================================
// MOBILITY SETUP
// ============================================================
static void
SetupBusMobility(NodeContainer &busNodes,
                  std::vector<RouteDefinition> &routes,
                  std::vector<uint32_t> &routeAssignment,
                  double simTime)
{
    MobilityHelper mobilityHelper;
    mobilityHelper.SetMobilityModel("ns3::WaypointMobilityModel");
    mobilityHelper.Install(busNodes);

    // Per-bus speed sampler, uniform in supervisor's 30-50 km/h band.
    Ptr<UniformRandomVariable> speedRv = CreateObject<UniformRandomVariable>();
    speedRv->SetAttribute("Min", DoubleValue(BUS_SPEED_MIN_MS));
    speedRv->SetAttribute("Max", DoubleValue(BUS_SPEED_MAX_MS));

    for (uint32_t i = 0; i < busNodes.GetN(); i++)
    {
        uint32_t routeIdx = routeAssignment[i];
        RouteDefinition &route = routes[routeIdx];

        Ptr<WaypointMobilityModel> mobility =
            busNodes.Get(i)->GetObject<WaypointMobilityModel>();

        g_gpsStates[i].routeIndex = routeIdx;
        g_gpsStates[i].initialized = false;
        g_gpsStates[i].spoofDetected = false;

        // Distribute buses spatially across the full route loop at t=0.
        // A pure time offset leaves later buses parked at the first station,
        // which can place them outside LTE coverage for long periods.
        uint32_t busOnRoute = 0;
        uint32_t busesOnThisRoute = 0;
        for (uint32_t j = 0; j < i; j++)
        {
            if (routeAssignment[j] == routeIdx) busOnRoute++;
        }
        for (uint32_t j = 0; j < routeAssignment.size(); ++j)
        {
            if (routeAssignment[j] == routeIdx) busesOnThisRoute++;
        }

        std::vector<uint32_t> cycleIndices;
        for (uint32_t s = 0; s < route.stations.size(); ++s)
        {
            cycleIndices.push_back(s);
        }
        for (int s = static_cast<int>(route.stations.size()) - 2; s >= 1; --s)
        {
            cycleIndices.push_back(static_cast<uint32_t>(s));
        }

        uint32_t cycleSize = cycleIndices.size();
        uint32_t startCycleIndex = 0;
        if (busesOnThisRoute > 0 && cycleSize > 0)
        {
            startCycleIndex = (busOnRoute * cycleSize) / busesOnThisRoute;
            startCycleIndex %= cycleSize;
        }

        double currentTime = 0.0;

        if (cycleSize == 0)
        {
            continue;
        }

        uint32_t currentCycleIndex = startCycleIndex;

        // Per-bus constant speed in [30, 50] km/h (supervisor spec).
        double busSpeedMs = speedRv->GetValue();

        while (currentTime < simTime)
        {
            uint32_t stationIndex = cycleIndices[currentCycleIndex];
            // OkumuraHata requires node height > 0; use 1.5m for bus-mounted UE
            Vector stPos = route.stations[stationIndex];
            stPos.z = 1.5;
            // Insert paired waypoints (arrive, depart) so the bus actually
            // dwells STATION_STOP_TIME seconds at every station, not only
            // the first/last (supervisor: 30 s stop per station).
            mobility->AddWaypoint(
                Waypoint(Seconds(currentTime), stPos));

            currentTime += STATION_STOP_TIME;
            mobility->AddWaypoint(
                Waypoint(Seconds(currentTime), stPos));

            uint32_t nextCycleIndex = (currentCycleIndex + 1) % cycleSize;
            uint32_t nextStationIndex = cycleIndices[nextCycleIndex];
            double dist = CalculateDistance(route.stations[stationIndex],
                                            route.stations[nextStationIndex]);
            currentTime += dist / busSpeedMs;
            currentCycleIndex = nextCycleIndex;
        }
    }
}

// ============================================================
// CUSTOM APPLICATION: GpsTelemetryApp
// Each bus sends its real GPS position to the server periodically
// ============================================================
class GpsTelemetryApp : public Application
{
public:
    static TypeId GetTypeId(void);
    GpsTelemetryApp();
    virtual ~GpsTelemetryApp();

    void Setup(Address serverAddress, uint32_t busId, double interval);

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    void SendPacket(void);
    void ScheduleNextSend(void);

    Ptr<Socket> m_socket;
    Address m_serverAddress;
    uint32_t m_busId;
    double m_interval;
    EventId m_sendEvent;
    bool m_running;
};

NS_OBJECT_ENSURE_REGISTERED(GpsTelemetryApp);

TypeId
GpsTelemetryApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::GpsTelemetryApp")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<GpsTelemetryApp>();
    return tid;
}

GpsTelemetryApp::GpsTelemetryApp()
    : m_socket(0), m_busId(0), m_interval(1.0), m_running(false)
{
}

GpsTelemetryApp::~GpsTelemetryApp()
{
    m_socket = 0;
}

void
GpsTelemetryApp::Setup(Address serverAddress, uint32_t busId, double interval)
{
    m_serverAddress = serverAddress;
    m_busId = busId;
    m_interval = interval;
}

void
GpsTelemetryApp::StartApplication(void)
{
    m_running = true;
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Connect(m_serverAddress);
    SendPacket();
}

void
GpsTelemetryApp::StopApplication(void)
{
    m_running = false;
    if (m_sendEvent.IsRunning())
    {
        Simulator::Cancel(m_sendEvent);
    }
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
GpsTelemetryApp::SendPacket(void)
{
    if (!m_running) return;

    // Get current position from mobility model
    Ptr<MobilityModel> mob = GetNode()->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    // Build payload: magic(4B) + busId(4B) + posX(8B) + posY(8B) + padding
    uint8_t buffer[200];
    std::memset(buffer, 0, 200);

    uint32_t magic = GPS_PAYLOAD_MAGIC;
    std::memcpy(buffer, &magic, sizeof(uint32_t));

    uint32_t busId = m_busId;
    std::memcpy(buffer + 4, &busId, sizeof(uint32_t));

    double posX = pos.x;
    double posY = pos.y;
    std::memcpy(buffer + 8, &posX, sizeof(double));
    std::memcpy(buffer + 16, &posY, sizeof(double));

    Ptr<Packet> packet = Create<Packet>(buffer, 200);
    m_socket->Send(packet);

    ScheduleNextSend();
}

void
GpsTelemetryApp::ScheduleNextSend(void)
{
    if (m_running)
    {
        m_sendEvent = Simulator::Schedule(Seconds(m_interval),
                                          &GpsTelemetryApp::SendPacket, this);
    }
}

// ============================================================
// CUSTOM APPLICATION: TicketingApp
// Keeps one TCP socket open and emits small random bursts.
// ============================================================
class TicketingApp : public Application
{
public:
    TicketingApp();
    virtual ~TicketingApp();
    static TypeId GetTypeId(void);

    void Setup(Address serverAddress,
               double minInterval,
               double maxInterval,
               uint32_t packetSize,
               uint32_t minBurstPackets,
               uint32_t maxBurstPackets);

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void HandleConnectSuccess(Ptr<Socket> socket);
    void HandleConnectFail(Ptr<Socket> socket);
    void ScheduleNextBurst(void);
    void SendBurst(void);

    Ptr<Socket> m_socket;
    Address m_serverAddress;
    bool m_running;
    bool m_connected;
    EventId m_burstEvent;
    EventId m_retryEvent;
    Ptr<UniformRandomVariable> m_intervalRv;
    Ptr<UniformRandomVariable> m_burstRv;
    double m_minInterval;
    double m_maxInterval;
    uint32_t m_packetSize;
    uint32_t m_minBurstPackets;
    uint32_t m_maxBurstPackets;
};

NS_OBJECT_ENSURE_REGISTERED(TicketingApp);

TypeId
TicketingApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::TicketingApp")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<TicketingApp>();
    return tid;
}

TicketingApp::TicketingApp()
    : m_socket(0),
      m_running(false),
      m_connected(false),
      m_minInterval(6.0),
      m_maxInterval(20.0),
      m_packetSize(256),
      m_minBurstPackets(1),
      m_maxBurstPackets(3)
{
    m_intervalRv = CreateObject<UniformRandomVariable>();
    m_burstRv = CreateObject<UniformRandomVariable>();
}

TicketingApp::~TicketingApp()
{
    m_socket = 0;
}

void
TicketingApp::Setup(Address serverAddress,
                    double minInterval,
                    double maxInterval,
                    uint32_t packetSize,
                    uint32_t minBurstPackets,
                    uint32_t maxBurstPackets)
{
    m_serverAddress = serverAddress;
    m_minInterval = minInterval;
    m_maxInterval = maxInterval;
    m_packetSize = packetSize;
    m_minBurstPackets = minBurstPackets;
    m_maxBurstPackets = maxBurstPackets;
}

void
TicketingApp::StartApplication(void)
{
    m_running = true;
    m_connected = false;

    if (!m_socket)
    {
        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_socket->SetConnectCallback(
            MakeCallback(&TicketingApp::HandleConnectSuccess, this),
            MakeCallback(&TicketingApp::HandleConnectFail, this));
    }

    m_socket->Connect(m_serverAddress);
}

void
TicketingApp::StopApplication(void)
{
    m_running = false;
    m_connected = false;

    if (m_burstEvent.IsRunning())
    {
        Simulator::Cancel(m_burstEvent);
    }
    if (m_retryEvent.IsRunning())
    {
        Simulator::Cancel(m_retryEvent);
    }
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
TicketingApp::HandleConnectSuccess(Ptr<Socket> socket)
{
    m_connected = true;
    ScheduleNextBurst();
}

void
TicketingApp::HandleConnectFail(Ptr<Socket> socket)
{
    m_connected = false;
    if (m_running)
    {
        m_retryEvent = Simulator::Schedule(Seconds(2.0),
                                           &TicketingApp::StartApplication,
                                           this);
    }
}

void
TicketingApp::ScheduleNextBurst(void)
{
    if (!m_running || !m_connected)
    {
        return;
    }

    double nextInterval = m_intervalRv->GetValue(m_minInterval, m_maxInterval);
    m_burstEvent = Simulator::Schedule(Seconds(nextInterval),
                                       &TicketingApp::SendBurst,
                                       this);
}

void
TicketingApp::SendBurst(void)
{
    if (!m_running || !m_connected || !m_socket)
    {
        return;
    }

    uint32_t burstPackets = static_cast<uint32_t>(
        std::floor(m_burstRv->GetValue(m_minBurstPackets,
                                       m_maxBurstPackets + 1)));
    if (burstPackets < m_minBurstPackets)
    {
        burstPackets = m_minBurstPackets;
    }

    for (uint32_t i = 0; i < burstPackets; ++i)
    {
        Ptr<Packet> packet = Create<Packet>(m_packetSize);
        int sent = m_socket->Send(packet);
        if (sent < 0)
        {
            break;
        }
    }

    ScheduleNextBurst();
}

// ============================================================
// CUSTOM APPLICATION: GpsSpoofAttackApp
// Attacker sends fake GPS telemetry UDP to server with spoofed busId
// ============================================================
class GpsSpoofAttackApp : public Application
{
public:
    static TypeId GetTypeId(void);
    GpsSpoofAttackApp();
    virtual ~GpsSpoofAttackApp();

    void Setup(Address serverAddress, uint32_t targetBusId,
               Vector fakePosition, double interval, uint32_t numPackets);

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    void SendPacket(void);
    void ScheduleNextSend(void);

    Ptr<Socket> m_socket;
    Address m_serverAddress;
    uint32_t m_targetBusId;
    Vector m_fakePosition;
    double m_interval;
    uint32_t m_numPackets;
    uint32_t m_sent;
    EventId m_sendEvent;
    bool m_running;
};

NS_OBJECT_ENSURE_REGISTERED(GpsSpoofAttackApp);

TypeId
GpsSpoofAttackApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::GpsSpoofAttackApp")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<GpsSpoofAttackApp>();
    return tid;
}

GpsSpoofAttackApp::GpsSpoofAttackApp()
    : m_socket(0), m_targetBusId(0), m_fakePosition(0,0,0),
      m_interval(1.0), m_numPackets(30), m_sent(0), m_running(false)
{
}

GpsSpoofAttackApp::~GpsSpoofAttackApp()
{
    m_socket = 0;
}

void
GpsSpoofAttackApp::Setup(Address serverAddress, uint32_t targetBusId,
                          Vector fakePosition, double interval,
                          uint32_t numPackets)
{
    m_serverAddress = serverAddress;
    m_targetBusId = targetBusId;
    m_fakePosition = fakePosition;
    m_interval = interval;
    m_numPackets = numPackets;
}

void
GpsSpoofAttackApp::StartApplication(void)
{
    m_running = true;
    m_sent = 0;
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Connect(m_serverAddress);
    SendPacket();
}

void
GpsSpoofAttackApp::StopApplication(void)
{
    m_running = false;
    if (m_sendEvent.IsRunning())
    {
        Simulator::Cancel(m_sendEvent);
    }
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
GpsSpoofAttackApp::SendPacket(void)
{
    if (!m_running || m_sent >= m_numPackets) return;

    // Build payload: magic(4B) + busId(4B) + fakeX(8B) + fakeY(8B) + padding
    uint8_t buffer[200];
    std::memset(buffer, 0, 200);

    uint32_t magic = GPS_PAYLOAD_MAGIC;
    std::memcpy(buffer, &magic, sizeof(uint32_t));

    uint32_t busId = m_targetBusId;
    std::memcpy(buffer + 4, &busId, sizeof(uint32_t));

    // Increment position by 50m per packet (50m/s = 180 km/h > 120 km/h threshold)
    double fakeX = m_fakePosition.x + m_sent * 50.0;
    double fakeY = m_fakePosition.y;
    std::memcpy(buffer + 8, &fakeX, sizeof(double));
    std::memcpy(buffer + 16, &fakeY, sizeof(double));

    Ptr<Packet> packet = Create<Packet>(buffer, 200);
    m_socket->Send(packet);
    m_sent++;

    NS_LOG_INFO("[GPS SPOOF TX] Fake bus " << m_targetBusId
                << " pos=(" << fakeX << "," << fakeY << ")"
                << " pkt " << m_sent << "/" << m_numPackets);

    ScheduleNextSend();
}

void
GpsSpoofAttackApp::ScheduleNextSend(void)
{
    if (m_running && m_sent < m_numPackets)
    {
        m_sendEvent = Simulator::Schedule(Seconds(m_interval),
                                          &GpsSpoofAttackApp::SendPacket, this);
    }
}

// ============================================================
// CUSTOM APPLICATION: GpsDetectorApp
// Server-side: receives GPS UDP, detects spoofing anomalies
// ============================================================
class GpsDetectorApp : public Application
{
public:
    static TypeId GetTypeId(void);
    GpsDetectorApp();
    virtual ~GpsDetectorApp();

    void SetRoutes(const std::vector<RouteDefinition> *routes);
    void SetRouteAssignment(const std::vector<uint32_t> *assignment);

private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    void HandleRead(Ptr<Socket> socket);

    Ptr<Socket> m_socket;
    const std::vector<RouteDefinition> *m_routes;
    const std::vector<uint32_t> *m_routeAssignment;

    struct PerBusState {
        Vector lastPos;
        double lastTime;
        bool init;
        bool detected;
        Address lastSrcAddr;
        bool hasSrcAddr;
        uint32_t anomalyStreak;  // consecutive anomalous readings
    };
    std::map<uint32_t, PerBusState> m_busState;
};

NS_OBJECT_ENSURE_REGISTERED(GpsDetectorApp);

TypeId
GpsDetectorApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::GpsDetectorApp")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<GpsDetectorApp>();
    return tid;
}

GpsDetectorApp::GpsDetectorApp()
    : m_socket(0), m_routes(0), m_routeAssignment(0)
{
}

GpsDetectorApp::~GpsDetectorApp()
{
    m_socket = 0;
}

void
GpsDetectorApp::SetRoutes(const std::vector<RouteDefinition> *routes)
{
    m_routes = routes;
}

void
GpsDetectorApp::SetRouteAssignment(const std::vector<uint32_t> *assignment)
{
    m_routeAssignment = assignment;
}

void
GpsDetectorApp::StartApplication(void)
{
    if (!m_socket)
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(),
                                                     TELEMETRY_PORT);
        m_socket->Bind(local);
    }
    m_socket->SetRecvCallback(MakeCallback(&GpsDetectorApp::HandleRead, this));
}

void
GpsDetectorApp::StopApplication(void)
{
    if (m_socket)
    {
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
    }
}

void
GpsDetectorApp::HandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from)))
    {
        if (packet->GetSize() < GPS_PAYLOAD_MIN_SIZE) continue;

        uint8_t buffer[200];
        uint32_t copied = packet->CopyData(buffer, std::min((uint32_t)200,
                                                             packet->GetSize()));
        if (copied < GPS_PAYLOAD_MIN_SIZE) continue;

        uint32_t magic;
        uint32_t busId;
        double posX, posY;
        std::memcpy(&magic, buffer, sizeof(uint32_t));
        if (magic != GPS_PAYLOAD_MAGIC) continue;

        std::memcpy(&busId, buffer + 4, sizeof(uint32_t));
        std::memcpy(&posX, buffer + 8, sizeof(double));
        std::memcpy(&posY, buffer + 16, sizeof(double));

        if (busId >= MAX_BUSES) continue;
        if (!std::isfinite(posX) || !std::isfinite(posY)) continue;

        Vector currentPos(posX, posY, 0);
        double now = Simulator::Now().GetSeconds();

        PerBusState &state = m_busState[busId];

        if (!state.init)
        {
            state.lastPos = currentPos;
            state.lastTime = now;
            state.init = true;
            state.detected = false;
            state.lastSrcAddr = from;
            state.hasSrcAddr = true;
            state.anomalyStreak = 0;
            continue;
        }

        double dt = now - state.lastTime;
        if (dt <= 0)
        {
            state.lastPos = currentPos;
            state.lastTime = now;
            continue;
        }

        // Skip readings arriving too close together (< 0.5s).
        // Telemetry is 1 pkt/s; sub-second gaps happen when multiple
        // packets queue behind each other in LTE buffers. Computing
        // speed over such tiny dt amplifies noise (e.g. 10m / 0.02s
        // = 500 m/s appears as a false speed anomaly).
        if (dt < 0.5)
        {
            continue;
        }

        double distance = CalculateDistance(state.lastPos, currentPos);
        double speed = distance / dt;

        // Check 1: Speed > 80 km/h
        bool speedAnomaly = speed > GPS_SPEED_THRESHOLD;

        // Check 2: Jump > 1km in 1s
        bool jumpAnomaly = (dt <= 1.5 && distance > GPS_JUMP_THRESHOLD);

        // Check 3: Outside route corridor
        bool corridorAnomaly = false;
        if (m_routes && m_routeAssignment && busId < m_routeAssignment->size())
        {
            uint32_t rIdx = (*m_routeAssignment)[busId];
            if (rIdx < m_routes->size())
            {
                double routeDist = DistanceToRoute(currentPos,
                                                    (*m_routes)[rIdx]);
                corridorAnomaly = routeDist > GPS_CORRIDOR_THRESHOLD;
            }
        }

        // Engineering side-channel kept for forensic logging only.
        // NOTE: supervisor spec lists exactly THREE GPS conditions
        // (speed, corridor, jump). Source-IP mismatch is recorded in
        // the event detail but MUST NOT contribute to anomalyCount.
        bool srcAnomaly = false;
        if (state.hasSrcAddr)
        {
            InetSocketAddress curSrc = InetSocketAddress::ConvertFrom(from);
            InetSocketAddress prevSrc = InetSocketAddress::ConvertFrom(
                                            state.lastSrcAddr);
            if (curSrc.GetIpv4() != prevSrc.GetIpv4())
            {
                srcAnomaly = true;
            }
        }

        // Supervisor spec: 3 conditions joined by "any" -> 1-of-3 fires.
        uint32_t anomalyCount = (speedAnomaly ? 1 : 0) + (jumpAnomaly ? 1 : 0)
                               + (corridorAnomaly ? 1 : 0);
        uint32_t requiredCount = (g_detectionMode == "any") ? 1 : 2;
        bool isAnomalous = (anomalyCount >= requiredCount);

        // Streak gate: supervisor says "if any condition is true ->
        // trigger" which is literally a 1-streak. Default 1 here for
        // strict compliance; CLI flag --gpsStreakRequired allows a
        // higher value if startup-transient noise filtering is needed.
        uint32_t GPS_STREAK_REQUIRED = g_gpsStreakRequired;

        if (isAnomalous)
        {
            state.anomalyStreak++;
        }
        else
        {
            state.anomalyStreak = 0;
        }

        if (state.anomalyStreak >= GPS_STREAK_REQUIRED && !state.detected)
        {
            state.detected = true;

            std::ostringstream detail;
            detail << "mode=" << g_detectionMode
                   << " speed=" << speed << "m/s"
                   << " jump=" << distance << "m"
                   << " corridor=" << corridorAnomaly
                   << " srcIP=" << srcAnomaly;

            LogMetric(now, busId, "gps_spoof_detect", speed, distance,
                      detail.str());

            if (!g_gpsSpoofDetected)
            {
                g_gpsSpoofDetected = true;
                g_gpsSpoofDetectionTime = now;
            }

            NS_LOG_WARN("[GPS SPOOF DETECTED] Bus " << busId
                        << " at t=" << now << " " << detail.str());
        }

        state.lastPos = currentPos;
        state.lastTime = now;
        state.lastSrcAddr = from;
    }
}

// ============================================================
// FREE FUNCTION: CheckDDoS (scheduled periodically)
// ============================================================
static void
CheckDDoS(Ptr<FlowMonitor> flowMonitor,
           Ptr<Ipv4FlowClassifier> classifier,
           Ipv4Address serverAddr,
           double interval,
           double detectionStartTime)
{
    static uint64_t s_prevRxBytes = 0;
    static uint64_t s_prevTxPackets = 0;
    static uint64_t s_prevRxPackets = 0;
    double now = Simulator::Now().GetSeconds();
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    if (now < detectionStartTime)
    {
        // During warmup, still accumulate baseline counters so the first
        // real check after warmup computes a meaningful delta.
        uint64_t warmupRxBytes = 0;
        uint64_t warmupTxPkts = 0;
        uint64_t warmupRxPkts = 0;
        for (auto &flow : stats)
        {
            Ipv4FlowClassifier::FiveTuple tuple = classifier->FindFlow(flow.first);
            bool isServerTelemetry = (tuple.destinationAddress == serverAddr)
                && (tuple.destinationPort == TELEMETRY_PORT);
            bool isBusFlow = tuple.sourceAddress.CombineMask(Ipv4Mask("255.0.0.0"))
                == Ipv4Address("7.0.0.0");

            if (isServerTelemetry)
            {
                warmupRxBytes += flow.second.rxBytes;
            }
            if (isServerTelemetry && isBusFlow && flow.second.rxPackets > 0)
            {
                warmupTxPkts += flow.second.txPackets;
                warmupRxPkts += flow.second.rxPackets;
            }
        }
        s_prevRxBytes = warmupRxBytes;
        s_prevTxPackets = warmupTxPkts;
        s_prevRxPackets = warmupRxPkts;

        Simulator::Schedule(Seconds(interval),
                            &CheckDDoS,
                            flowMonitor,
                            classifier,
                            serverAddr,
                            interval,
                            detectionStartTime);
        return;
    }

    uint64_t telemetryRxBytes = 0;
    uint64_t telemetryTxPackets = 0;
    uint64_t telemetryRxPackets = 0;
    double telemetryDelaySum = 0;       // weighted sum for average
    uint64_t telemetryDelayPktCount = 0; // total rx pkts for delay averaging

    for (auto &flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple tuple = classifier->FindFlow(flow.first);
        bool isServerTelemetry = (tuple.destinationAddress == serverAddr)
            && (tuple.destinationPort == TELEMETRY_PORT);
        bool isBusFlow = tuple.sourceAddress.CombineMask(Ipv4Mask("255.0.0.0"))
            == Ipv4Address("7.0.0.0");

        if (!isServerTelemetry)
        {
            continue;
        }

        telemetryRxBytes += flow.second.rxBytes;

        if (!isBusFlow)
        {
            continue;
        }

        // Only include flows that have demonstrated some connectivity.
        // Flows with zero rxPackets are coverage gaps, not DDoS indicators.
        // Including them inflates loss rate and causes false positives.
        if (flow.second.rxPackets == 0)
        {
            continue;
        }

        telemetryTxPackets += flow.second.txPackets;
        telemetryRxPackets += flow.second.rxPackets;
        if (flow.second.rxPackets > 0)
        {
            telemetryDelaySum += flow.second.delaySum.GetSeconds();
            telemetryDelayPktCount += flow.second.rxPackets;
        }
    }

    // Weighted average delay across all connected telemetry flows.
    // Using average (not max-per-flow) avoids false positives from
    // individual flows that happen to have high latency due to
    // cell-edge scheduling rather than actual DDoS congestion.
    double telemetryAvgDelay = (telemetryDelayPktCount > 0) ?
                                (telemetryDelaySum / telemetryDelayPktCount) : 0;

    // Delta-based metrics: compute loss over THIS interval only,
    // not cumulative. Cumulative loss includes in-flight packets
    // that will eventually arrive, causing false DDoS positives.
    uint64_t deltaTxPkts = telemetryTxPackets - s_prevTxPackets;
    uint64_t deltaRxPkts = telemetryRxPackets - s_prevRxPackets;
    double deltaLossRate = 0.0;
    // Require at least 10 packets in the interval for reliable loss measurement.
    // With fewer packets, loss variance is too high for meaningful detection.
    static const uint64_t MIN_INTERVAL_PKTS = 10;
    if (deltaTxPkts >= MIN_INTERVAL_PKTS)
    {
        uint64_t deltaLost = (deltaTxPkts > deltaRxPkts) ?
                              (deltaTxPkts - deltaRxPkts) : 0;
        deltaLossRate = static_cast<double>(deltaLost) / deltaTxPkts;
    }

    double intervalBytes = static_cast<double>(telemetryRxBytes - s_prevRxBytes);
    double intervalRate = intervalBytes * 8.0 / interval;
    s_prevRxBytes = telemetryRxBytes;
    s_prevTxPackets = telemetryTxPackets;
    s_prevRxPackets = telemetryRxPackets;

    bool rateExceeded = intervalRate > DDOS_RATE_THRESHOLD;
    bool lossExceeded = deltaLossRate > DDOS_LOSS_THRESHOLD;
    bool delayExceeded = telemetryAvgDelay > DDOS_DELAY_THRESHOLD;
    // Supervisor spec: detection fires if ANY of (rate > threshold,
    // packet loss > 5%, delay > 100 ms) is true. Round-1 fixes
    // (100 Mbps backhaul + GBR 1.0/1.2 Mbps) brought baseline PLR
    // back below 5%, so the loss condition is now safe to include.

    if ((rateExceeded || lossExceeded || delayExceeded) && !g_ddosDetected)
    {
        g_ddosDetected = true;
        g_ddosDetectionTime = now;

        std::ostringstream detail;
        detail << "mode=requirements_any"
               << " telemetryRate=" << intervalRate
               << "bps deltaLoss=" << deltaLossRate
               << " avgDelay=" << telemetryAvgDelay << "s"
               << " trip=" << (rateExceeded ? "R" : "-")
               << (lossExceeded ? "L" : "-")
               << (delayExceeded ? "D" : "-");

        LogMetric(now, 999, "ddos_detect", intervalRate,
                  deltaLossRate, detail.str());

        NS_LOG_WARN("[DDoS DETECTED] t=" << now << " " << detail.str());
    }

    Simulator::Schedule(Seconds(interval),
                        &CheckDDoS,
                        flowMonitor,
                        classifier,
                        serverAddr,
                        interval,
                        detectionStartTime);
}

// ============================================================
// FREE FUNCTION: LogQueueStatus
// Periodically logs P2P server link queue size
// ============================================================
static void
LogQueueStatus(Ptr<NetDevice> device, double interval)
{
    double now = Simulator::Now().GetSeconds();
    Ptr<PointToPointNetDevice> p2pDev = DynamicCast<PointToPointNetDevice>(device);
    uint32_t nPkts = 0;
    uint32_t nBytes = 0;
    if (p2pDev)
    {
        Ptr<Queue<Packet>> queue = p2pDev->GetQueue();
        if (queue)
        {
            nPkts = queue->GetNPackets();
            nBytes = queue->GetNBytes();
        }
    }
    LogMetric(now, 999, "queue_status", (double)nPkts, (double)nBytes,
              "server_p2p_queue");
    LogMetric(now, 999, "queue_delay", (nBytes * 8.0) / SERVER_LINK_RATE_BPS,
              (double)nPkts, "estimated_server_queue_delay_seconds");

    Simulator::Schedule(Seconds(interval),
                        &LogQueueStatus, device, interval);
}

// ============================================================
// FREE FUNCTION: ForensicSinkBaselineBytes
// Captures the PacketSink's TotalRx() at the moment the forensic
// upload starts so we can compute how many bytes of THIS upload
// actually arrived at the server.
// ============================================================
static uint64_t g_forensicSinkBaselineBytes = 0;

// ============================================================
// FREE FUNCTION: PollForensicCompletion
// Periodically polls the forensic PacketSink for delivered bytes.
// When 10 MB have actually arrived the upload is marked complete;
// otherwise we record the partial completion at simulation tear-down.
// Replaces the old fixed-16.5s timer that lied about completion.
// ============================================================
static void
PollForensicCompletion(double interval, double deadline)
{
    if (g_forensicEvents.empty()) return;
    ForensicEvent &evt = g_forensicEvents.back();
    if (evt.uploadCompleted) return;

    double now = Simulator::Now().GetSeconds();
    bool sinkOk = (g_forensicSinkApp != 0);
    uint64_t totalRxNow = sinkOk ? g_forensicSinkApp->GetTotalRx() : 0;
    uint64_t delivered = (totalRxNow > g_forensicSinkBaselineBytes) ?
                         (totalRxNow - g_forensicSinkBaselineBytes) : 0;
    evt.bytesReceived = delivered;

    static const uint64_t TARGET_BYTES = 10485760; // 10 MB

    // Round 3 diagnostic: surface raw counter values every 5 seconds so the
    // Linux agent can tell whether 0-byte runs are caused by a null sink, a
    // baseline-snapshot race, or the upload genuinely producing nothing on
    // the wire. Stderr is captured by run_all_parallel.sh.
    static double lastDiagLog = -1e9;
    if (now - lastDiagLog >= 5.0)
    {
        lastDiagLog = now;
        std::cerr << "[FORENSIC-DIAG] t=" << std::fixed << std::setprecision(2)
                  << now
                  << " sinkPtrValid=" << (sinkOk ? 1 : 0)
                  << " totalRxNow=" << totalRxNow
                  << " baseline=" << g_forensicSinkBaselineBytes
                  << " delivered=" << delivered
                  << " target=" << TARGET_BYTES
                  << " triggerTime=" << evt.triggerTime
                  << "\n";
    }

    if (delivered >= TARGET_BYTES)
    {
        evt.uploadFinishTime = now;
        evt.uploadCompleted = true;
        LogMetric(now, evt.busId, "forensic_complete",
                  now - evt.triggerTime, (double)delivered, "upload_done");
        NS_LOG_INFO("[FORENSIC] Upload complete at t=" << now
                    << " bytes=" << delivered
                    << " duration=" << (now - evt.triggerTime) << "s");
        std::cerr << "[FORENSIC-DIAG] COMPLETE at t=" << now
                  << " delivered=" << delivered
                  << " duration=" << (now - evt.triggerTime) << "s\n";
        return;
    }

    if (now >= deadline)
    {
        // Final tally: upload did not complete in time.
        evt.uploadFinishTime = now;
        evt.uploadCompleted = false;
        double pct = 100.0 * delivered / static_cast<double>(TARGET_BYTES);
        LogMetric(now, evt.busId, "forensic_partial",
                  now - evt.triggerTime, (double)delivered,
                  "upload_incomplete");
        NS_LOG_WARN("[FORENSIC] Upload INCOMPLETE at deadline t=" << now
                    << " bytes=" << delivered << " ("
                    << std::fixed << std::setprecision(1) << pct << "%)");
        std::cerr << "[FORENSIC-DIAG] DEADLINE at t=" << now
                  << " delivered=" << delivered
                  << " (" << pct << "% of target)\n";
        return;
    }

    Simulator::Schedule(Seconds(interval),
                        &PollForensicCompletion, interval, deadline);
}

// ============================================================
// FREE FUNCTION: SendForensicChunk
// Round 4: hand-rolled UDP sender driven directly by Simulator::Schedule.
// Replaces the OnOffApplication injection that produced 0-byte runs.
// At 5 Mbps with 1400-byte packets the inter-packet interval is
// 1400 * 8 / 5e6 = 2.24 ms, so 10 MB takes ~16 s of wall sim time and
// ~7490 reschedules.
// ============================================================
static const uint32_t FORENSIC_PKT_SIZE = 1400;
static const uint64_t FORENSIC_TARGET_BYTES = 10485760; // 10 MB
static const double FORENSIC_RATE_BPS = 5e6;             // 5 Mbps
static const double FORENSIC_PKT_INTERVAL =
    (FORENSIC_PKT_SIZE * 8.0) / FORENSIC_RATE_BPS;       // ~0.00224 s

static void
SendForensicChunk()
{
    if (!g_forensicSendingActive) return;
    if (g_forensicBytesSent >= FORENSIC_TARGET_BYTES)
    {
        if (g_forensicSocket) { g_forensicSocket->Close(); }
        g_forensicSendingActive = false;
        std::cerr << "[FORENSIC-DIAG] SENDER finished at t="
                  << Simulator::Now().GetSeconds()
                  << " bytesSent=" << g_forensicBytesSent << "\n";
        return;
    }

    uint64_t remaining = FORENSIC_TARGET_BYTES - g_forensicBytesSent;
    uint32_t toSend = (remaining < FORENSIC_PKT_SIZE) ?
                      static_cast<uint32_t>(remaining) : FORENSIC_PKT_SIZE;
    Ptr<Packet> pkt = Create<Packet>(toSend);
    int sent = g_forensicSocket ? g_forensicSocket->Send(pkt) : -1;
    if (sent > 0)
    {
        g_forensicBytesSent += static_cast<uint64_t>(sent);
    }

    // Periodic sender-side diagnostic so we can compare with the
    // sink-side PollForensicCompletion poll lines.
    static double lastSenderDiag = -1e9;
    double now = Simulator::Now().GetSeconds();
    if (now - lastSenderDiag >= 5.0)
    {
        lastSenderDiag = now;
        std::cerr << "[FORENSIC-DIAG] SENDER t=" << std::fixed
                  << std::setprecision(2) << now
                  << " bytesSent=" << g_forensicBytesSent
                  << " target=" << FORENSIC_TARGET_BYTES
                  << " lastSendRet=" << sent << "\n";
    }

    Simulator::Schedule(Seconds(FORENSIC_PKT_INTERVAL),
                        &SendForensicChunk);
}

// ============================================================
// FREE FUNCTION: StartForensicUpload
// Round 4: bypass ns-3 Application lifecycle entirely. Open a raw UDP
// socket on the bus UE, Connect() to the server's forensic port, and
// drive sending through Simulator::Schedule chained calls. This avoids
// the Application::SetStartTime / DoInitialize delay-vs-absolute
// ambiguity that left the Round-3 OnOffApplication-based path producing
// 0 delivered bytes when triggered mid-simulation.
// ============================================================
static void
StartForensicUpload(Ptr<Node> busNode, Ipv4Address serverAddr)
{
    double now = Simulator::Now().GetSeconds();
    NS_LOG_INFO("[FORENSIC] Starting 10MB evidence upload at t=" << now);

    g_forensicSocket = Socket::CreateSocket(busNode,
        TypeId::LookupByName("ns3::UdpSocketFactory"));
    int bindRet = g_forensicSocket->Bind();
    int connectRet = g_forensicSocket->Connect(
        InetSocketAddress(serverAddr, FORENSIC_PORT));
    g_forensicBytesSent = 0;
    g_forensicSendingActive = (bindRet == 0 && connectRet == 0);

    ForensicEvent evt;
    evt.triggerTime = now;
    evt.busId = 0;
    evt.attackType = g_ddosDetected ? "ddos" : "gps_spoof";
    evt.uploadStartTime = now;
    evt.uploadFinishTime = 0.0;
    evt.uploadCompleted = false;
    evt.bytesReceived = 0;
    g_forensicEvents.push_back(evt);

    uint64_t baseline = (g_forensicSinkApp != 0) ?
                        g_forensicSinkApp->GetTotalRx() : 0;
    g_forensicSinkBaselineBytes = baseline;

    std::cerr << "[FORENSIC-DIAG] StartForensicUpload triggered t=" << now
              << " busNode=" << (busNode ? busNode->GetId() : 9999)
              << " serverAddr=" << serverAddr
              << " sinkPtrValid=" << (g_forensicSinkApp ? 1 : 0)
              << " baseline=" << baseline
              << " bindRet=" << bindRet
              << " connectRet=" << connectRet
              << " sendingActive=" << (g_forensicSendingActive ? 1 : 0)
              << " attackType=" << evt.attackType
              << "\n";

    if (g_forensicSendingActive)
    {
        Simulator::ScheduleNow(&SendForensicChunk);
    }
    else
    {
        std::cerr << "[FORENSIC-DIAG] SENDER refused to start: "
                  << "bind/connect failed\n";
    }

    // Poll real bytes received every 0.5s.
    // Deadline = whichever comes first: a 60s allowance (gives slow uploads
    // time to finish under congestion) or 0.5s before sim end.
    double deadline = std::min(now + 60.0, g_simTime - 0.5);
    Simulator::Schedule(Seconds(0.5),
                        &PollForensicCompletion, 0.5, deadline);
}

// ============================================================
// FREE FUNCTION: LaunchGpsSpoof
// Reads target bus's REAL position at attack-start time, samples a
// 5-10 km random offset (supervisor: "sudden jump 5-10 km"),
// constructs the fake start position, then creates+starts a
// GpsSpoofAttackApp on the attacker node. Subsequent packets continue
// drifting at +50 m/pkt -> 180 km/h apparent speed (>120 km/h spec).
// ============================================================
static void
LaunchGpsSpoof(Ptr<Node> attackerNode,
               Ptr<Node> targetBus,
               Ipv4Address serverAddr,
               uint32_t gpsBusTarget,
               double duration)
{
    Ptr<MobilityModel> mob = targetBus->GetObject<MobilityModel>();
    Vector realPos = mob ? mob->GetPosition() : Vector(0, 0, 0);

    Ptr<UniformRandomVariable> distRv = CreateObject<UniformRandomVariable>();
    distRv->SetAttribute("Min", DoubleValue(5000.0));
    distRv->SetAttribute("Max", DoubleValue(10000.0));
    Ptr<UniformRandomVariable> angRv = CreateObject<UniformRandomVariable>();
    angRv->SetAttribute("Min", DoubleValue(0.0));
    angRv->SetAttribute("Max", DoubleValue(6.283185307179586));  // 2*pi

    double offset = distRv->GetValue();
    double angle = angRv->GetValue();
    double fakeX = realPos.x + offset * std::cos(angle);
    double fakeY = realPos.y + offset * std::sin(angle);
    Vector fakePos(fakeX, fakeY, 0.0);

    double now = Simulator::Now().GetSeconds();
    NS_LOG_INFO("[GPS SPOOF] launch t=" << now
                << " bus=" << gpsBusTarget
                << " real=(" << realPos.x << "," << realPos.y << ")"
                << " fake=(" << fakeX << "," << fakeY << ")"
                << " jump=" << offset << "m");
    LogMetric(now, gpsBusTarget, "gps_spoof_launch", offset, 0,
              "real_to_fake_jump_meters");

    Ptr<GpsSpoofAttackApp> spoofApp = CreateObject<GpsSpoofAttackApp>();
    spoofApp->Setup(InetSocketAddress(serverAddr, TELEMETRY_PORT),
                    gpsBusTarget, fakePos, 1.0, 30);
    attackerNode->AddApplication(spoofApp);
    spoofApp->SetStartTime(Seconds(now + 0.001));
    spoofApp->SetStopTime(Seconds(now + duration));
}

// ============================================================
// FREE FUNCTION: CheckForensicTrigger
// Polls g_ddosDetected and triggers upload once
// ============================================================
static void
CheckForensicTrigger(Ptr<Node> busNode, Ipv4Address serverAddr, double interval)
{
    if ((g_ddosDetected || g_gpsSpoofDetected) && !g_forensicTriggered)
    {
        g_forensicTriggered = true;
        StartForensicUpload(busNode, serverAddr);
    }

    if (!g_forensicTriggered)
    {
        Simulator::Schedule(Seconds(interval),
                            &CheckForensicTrigger, busNode, serverAddr,
                            interval);
    }
}

// ============================================================
// WRITE RESULTS
// ============================================================
static void
WriteEventsCsv(const std::string &filename)
{
    std::ofstream file(filename);
    file << "time,busId,eventType,value1,value2,detail\n";
    for (size_t i = 0; i < g_metricsLog.size(); i++)
    {
        const MetricsRecord &r = g_metricsLog[i];
        file << std::fixed << std::setprecision(3)
             << r.time << "," << r.busId << ","
             << r.eventType << "," << r.value1 << ","
             << r.value2 << ",\"" << r.detail << "\"\n";
    }
    file.close();
}

static void
WriteForensicsCsv(const std::string &filename)
{
    std::ofstream file(filename);
    file << "triggerTime,busId,attackType,uploadStartTime,uploadFinishTime,uploadCompleted,bytesReceived\n";
    for (size_t i = 0; i < g_forensicEvents.size(); i++)
    {
        const ForensicEvent &evt = g_forensicEvents[i];
        file << std::fixed << std::setprecision(3)
             << evt.triggerTime << "," << evt.busId << ","
             << evt.attackType << ","
             << evt.uploadStartTime << ","
             << evt.uploadFinishTime << ","
             << (evt.uploadCompleted ? 1 : 0) << ","
             << evt.bytesReceived << "\n";
    }
    file.close();
}

// ============================================================
// COUNT GPS SPOOF DETECTIONS (no lambda)
// ============================================================
static uint32_t
CountGpsSpoofDetections()
{
    uint32_t count = 0;
    for (size_t i = 0; i < g_metricsLog.size(); i++)
    {
        if (g_metricsLog[i].eventType == "gps_spoof_detect") count++;
    }
    return count;
}

// ============================================================
// MAIN
// ============================================================
int
main(int argc, char *argv[])
{
    // Command line parameters
    uint32_t numBuses = MAX_BUSES;
    double simTime = 300.0;
    std::string scenario = "baseline";
    bool enableDDoS = false;
    bool enableGpsSpoofing = false;
    double ddosRate = 30e6;
    double ddosStart = 100.0;
    double ddosDuration = 60.0;
    double gpsStart = 150.0;
    uint32_t gpsBusTarget = 0;
    std::string resultsDir = "results/";
    std::string detectionMode = "any";

    CommandLine cmd;
    cmd.AddValue("numBuses", "Number of buses (1, 10, or 41)", numBuses);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("scenario", "Scenario name", scenario);
    cmd.AddValue("enableDDoS", "Enable DDoS attack", enableDDoS);
    cmd.AddValue("enableGpsSpoofing", "Enable GPS spoofing", enableGpsSpoofing);
    cmd.AddValue("ddosRate", "DDoS rate in bps", ddosRate);
    cmd.AddValue("ddosStart", "DDoS start time", ddosStart);
    cmd.AddValue("ddosDuration", "DDoS duration", ddosDuration);
    cmd.AddValue("gpsStart", "GPS spoofing start time", gpsStart);
    cmd.AddValue("gpsBusTarget", "Target bus ID for GPS spoofing", gpsBusTarget);
    cmd.AddValue("resultsDir", "Output directory", resultsDir);
    cmd.AddValue("detectionMode", "Detection mode: any or voting", detectionMode);
    uint32_t gpsStreakRequired = 1;
    cmd.AddValue("gpsStreakRequired",
                 "Consecutive anomalous GPS readings required before firing"
                 " (supervisor spec: 1)",
                 gpsStreakRequired);
    cmd.Parse(argc, argv);
    g_detectionMode = detectionMode;
    g_simTime = simTime;  // expose to forensic poller and other helpers
    g_gpsStreakRequired = (gpsStreakRequired == 0) ? 1 : gpsStreakRequired;

    if (numBuses > MAX_BUSES) numBuses = MAX_BUSES;
    if (gpsBusTarget >= numBuses) gpsBusTarget = 0;

    NS_LOG_INFO("=== Al-Ahsa Smart Bus Simulation ===");
    NS_LOG_INFO("Scenario: " << scenario << " | Buses: " << numBuses
                << " | DDoS: " << (enableDDoS ? "ON" : "OFF")
                << " | GPS Spoof: " << (enableGpsSpoofing ? "ON" : "OFF")
                << " | Detection: " << g_detectionMode);

    // Clear globals for fresh run
    g_gpsStates.clear();
    g_metricsLog.clear();
    g_forensicEvents.clear();
    g_ddosDetected = false;
    g_ddosDetectionTime = 0.0;
    g_gpsSpoofDetected = false;
    g_gpsSpoofDetectionTime = 0.0;
    g_forensicTriggered = false;
    g_forensicSinkApp = 0;
    g_forensicSinkBaselineBytes = 0;
    g_forensicSocket = 0;
    g_forensicBytesSent = 0;
    g_forensicSendingActive = false;

    // ========== LTE + EPC Setup ==========
    Config::SetDefault("ns3::LteEnbPhy::TxPower", DoubleValue(46.0));  // 46 dBm macro cell
    Config::SetDefault("ns3::LteUePhy::TxPower", DoubleValue(33.0));   // Bus-mounted 4G/5G router proxy
    Config::SetDefault("ns3::LteUePowerControl::Pcmax", DoubleValue(33.0));

    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    lteHelper->SetAttribute("UseIdealRrc", BooleanValue(true));
    lteHelper->SetSchedulerType("ns3::PssFfMacScheduler");
    lteHelper->SetSchedulerAttribute("UlCqiFilter",
                                     EnumValue(FfMacScheduler::SRS_UL_CQI));
    lteHelper->SetHandoverAlgorithmType("ns3::A3RsrpHandoverAlgorithm");
    lteHelper->SetHandoverAlgorithmAttribute("Hysteresis", DoubleValue(3.0));
    lteHelper->SetHandoverAlgorithmAttribute("TimeToTrigger",
                                             TimeValue(MilliSeconds(256)));

    // Pathloss: Use default Friis (free-space) propagation model.
    // While not perfectly realistic for urban environments, it provides
    // reasonable LTE connectivity with only 3 eNBs covering a 15km x 20km
    // area (300 km²). Real deployments would have more towers, but the
    // simulation architecture specifies exactly 3 eNBs. Friis ensures the
    // baseline network operates normally so attack effects are clearly visible.
    // (OkumuraHata Urban and SubUrban were tested but both cause >95% packet
    // loss with only 3 eNBs at this scale.)

    // 20 MHz bandwidth (100 RBs) per cell.
    // Capacity arithmetic with the supervisor-pinned 41 buses + 3 eNBs:
    //   - Per-bus offered uplink: 1 Mbps CCTV + ~3 kbps GPS + ~20 kbps tickets
    //     ~= 1.025 Mbps per bus.
    //   - Roughly even bus-to-eNB distribution: ~14 buses per cell.
    //   - Per-cell offered UL: ~14.4 Mbps.
    //   - 100 RBs (20 MHz) UL practical throughput in ns-3 LTE: ~18-20 Mbps
    //     under good SINR, dropping to ~12-15 Mbps with cell-edge UEs.
    //   - GBR-CONV-VIDEO bearer is provisioned at 1.0/1.2 Mbps GBR/MBR
    //     (lowered from 1.2/1.5 below) so the scheduler can admit all 14 UEs
    //     in a cell without rejecting bearers, leaving headroom for control
    //     and HARQ retransmits.
    // Round 4: revert to 100 RBs (20 MHz, the maximum single-carrier value
    // ns-3 LENA accepts). The earlier Round-3 attempt at 200 RBs aborted
    // immediately at startup with "invalid bandwidth value 200" because
    // ns-3 LENA only enumerates {6, 15, 25, 50, 75, 100} RBs. 40 MHz total
    // bandwidth in real LTE requires Carrier Aggregation (2 component
    // carriers), which is a separate, follow-up change tracked under the
    // bandwidth audit. For now this build runs on a single 20 MHz cell.
    lteHelper->SetEnbDeviceAttribute("DlBandwidth", UintegerValue(100));
    lteHelper->SetEnbDeviceAttribute("UlBandwidth", UintegerValue(100));

    Ptr<Node> pgw = epcHelper->GetPgwNode();

    // ========== Remote Server ==========
    NodeContainer remoteServerContainer;
    remoteServerContainer.Create(1);
    Ptr<Node> remoteServer = remoteServerContainer.Get(0);

    InternetStackHelper internet;
    internet.Install(remoteServerContainer);

    PointToPointHelper p2pServer;
    // PGW <-> analytics server backhaul. Rate sourced from
    // SERVER_LINK_RATE_BPS so the queue-delay metric and DDoS impact
    // are sized against a realistic transit link (see constants block).
    std::ostringstream serverLinkRateStr;
    serverLinkRateStr << static_cast<uint64_t>(SERVER_LINK_RATE_BPS) << "bps";
    p2pServer.SetDeviceAttribute("DataRate", DataRateValue(DataRate(serverLinkRateStr.str())));
    p2pServer.SetDeviceAttribute("Mtu", UintegerValue(1500));
    p2pServer.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer serverDevices = p2pServer.Install(pgw, remoteServer);
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer serverInterfaces = ipv4h.Assign(serverDevices);
    Ipv4Address serverAddr = serverInterfaces.GetAddress(1);

    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteRouting =
        ipv4RoutingHelper.GetStaticRouting(remoteServer->GetObject<Ipv4>());
    remoteRouting->AddNetworkRouteTo(
        Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    // ========== eNBs ==========
    NodeContainer enbNodes;
    enbNodes.Create(NUM_ENB);

    MobilityHelper enbMobility;
    Ptr<ListPositionAllocator> enbPos = CreateObject<ListPositionAllocator>();
    // Route-weighted 3-site placement chosen to minimize worst-case distance
    // to the 10 bus corridors while preserving the required 3-eNB topology.
    enbPos->Add(Vector(4500, 6000, 30));
    enbPos->Add(Vector(12000, 6500, 30));
    enbPos->Add(Vector(8000, 16000, 30));
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.SetPositionAllocator(enbPos);
    enbMobility.Install(enbNodes);

    NetDeviceContainer enbDevices = lteHelper->InstallEnbDevice(enbNodes);
    lteHelper->AddX2Interface(enbNodes);

    // ========== Bus UEs ==========
    NodeContainer busNodes;
    busNodes.Create(numBuses);

    std::vector<RouteDefinition> routes = CreateRoutes();
    std::vector<uint32_t> routeAssignment = GetBusRouteAssignment();
    routeAssignment.resize(numBuses);
    SetupBusMobility(busNodes, routes, routeAssignment, simTime);

    NetDeviceContainer busDevices = lteHelper->InstallUeDevice(busNodes);
    internet.Install(busNodes);
    Ipv4InterfaceContainer busInterfaces =
        epcHelper->AssignUeIpv4Address(busDevices);

    for (uint32_t i = 0; i < busNodes.GetN(); i++)
    {
        Ptr<Ipv4StaticRouting> ueRouting =
            ipv4RoutingHelper.GetStaticRouting(
                busNodes.Get(i)->GetObject<Ipv4>());
        ueRouting->SetDefaultRoute(
            epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    // Initial closest-cell attachment with LTE handover support.
    lteHelper->AttachToClosestEnb(busDevices, enbDevices);

    for (uint32_t i = 0; i < busDevices.GetN(); ++i)
    {
        Ptr<NetDevice> ueDevice = busDevices.Get(i);
        ActivateUplinkBearer(lteHelper,
                             ueDevice,
                             TELEMETRY_PORT,
                             EpsBearer::GBR_CONV_VOICE,
                             64000,
                             128000);
        // CCTV bearer GBR/MBR trimmed to 1.0/1.2 Mbps (was 1.2/1.5 Mbps).
        // Actual CCTV stream offered load is 1.0 Mbps; the previous 1.2 Mbps
        // GBR over-reserved scheduler tokens and -- with ~14 UEs per eNB --
        // exceeded the per-cell 20 MHz UL budget, causing the GBR admission
        // ratio to drop and producing the 35.92% baseline PLR. 1.0/1.2 GBR/MBR
        // matches the actual 1 Mbps stream and leaves headroom for HARQ.
        ActivateUplinkBearer(lteHelper,
                             ueDevice,
                             CCTV_PORT,
                             EpsBearer::GBR_CONV_VIDEO,
                             1000000,
                             1200000);
        ActivateUplinkBearer(lteHelper,
                             ueDevice,
                             TICKET_PORT,
                             EpsBearer::NGBR_IMS,
                             0,
                             0);
        ActivateUplinkBearer(lteHelper,
                             ueDevice,
                             FORENSIC_PORT,
                             EpsBearer::GBR_NON_CONV_VIDEO,
                             2000000,
                             4000000);
    }

    // ========== Normal Traffic ==========

    // GPS Telemetry: UDP 1 pkt/s, 200B per bus
    // NOTE: GpsDetectorApp on server handles receive + detection
    Ptr<GpsDetectorApp> gpsDetector = CreateObject<GpsDetectorApp>();
    gpsDetector->SetRoutes(&routes);
    gpsDetector->SetRouteAssignment(&routeAssignment);
    remoteServer->AddApplication(gpsDetector);
    gpsDetector->SetStartTime(Seconds(1.0));
    gpsDetector->SetStopTime(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        Ptr<GpsTelemetryApp> telemetryApp = CreateObject<GpsTelemetryApp>();
        telemetryApp->Setup(
            InetSocketAddress(serverAddr, TELEMETRY_PORT), i, 1.0);
        busNodes.Get(i)->AddApplication(telemetryApp);
        telemetryApp->SetStartTime(Seconds(10.0 + i * 0.1));
        telemetryApp->SetStopTime(Seconds(simTime));
    }

    // CCTV: 1 Mbps UDP per bus (within the required 1-2 Mbps range)
    uint16_t cctvPort = CCTV_PORT;
    UdpServerHelper cctvServer(cctvPort);
    ApplicationContainer cctvSink = cctvServer.Install(remoteServer);
    cctvSink.Start(Seconds(1.0));
    cctvSink.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        OnOffHelper cctvStream("ns3::UdpSocketFactory",
            InetSocketAddress(serverAddr, cctvPort));
        cctvStream.SetAttribute("DataRate",
            DataRateValue(DataRate("1000kbps")));
        cctvStream.SetAttribute("PacketSize", UintegerValue(1400));
        cctvStream.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        cctvStream.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer app = cctvStream.Install(busNodes.Get(i));
        app.Start(Seconds(10.0 + i * 0.1));
        app.Stop(Seconds(simTime));
    }

    // Ticketing: random small TCP bursts over one persistent connection.
    PacketSinkHelper ticketSink("ns3::TcpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), TICKET_PORT));
    ApplicationContainer ticketSinkApps = ticketSink.Install(remoteServer);
    ticketSinkApps.Start(Seconds(1.0));
    ticketSinkApps.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        Ptr<TicketingApp> ticketApp = CreateObject<TicketingApp>();
        ticketApp->Setup(InetSocketAddress(serverAddr, TICKET_PORT),
                         6.0,
                         20.0,
                         256,
                         1,
                         3);
        busNodes.Get(i)->AddApplication(ticketApp);
        ticketApp->SetStartTime(Seconds(15.0 + i * 0.2));
        ticketApp->SetStopTime(Seconds(simTime));
    }

    // Forensic upload sink (UDP — matches forensic upload sender)
    PacketSinkHelper forensicSink("ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), FORENSIC_PORT));
    ApplicationContainer forensicSinkApps = forensicSink.Install(remoteServer);
    forensicSinkApps.Start(Seconds(1.0));
    forensicSinkApps.Stop(Seconds(simTime));
    g_forensicSinkApp = DynamicCast<PacketSink>(forensicSinkApps.Get(0));

    // ========== DDoS Attack ==========
    NodeContainer attackerNode;
    if (enableDDoS || enableGpsSpoofing)
    {
        attackerNode.Create(1);
        internet.Install(attackerNode);

        PointToPointHelper attackP2p;
        attackP2p.SetDeviceAttribute("DataRate",
            DataRateValue(DataRate("10Gbps")));
        attackP2p.SetDeviceAttribute("Mtu", UintegerValue(1500));
        attackP2p.SetChannelAttribute("Delay", StringValue("5ms"));

        NetDeviceContainer attackDevices =
            attackP2p.Install(pgw, attackerNode.Get(0));
        Ipv4AddressHelper attackIpv4;
        attackIpv4.SetBase("2.0.0.0", "255.0.0.0");
        attackIpv4.Assign(attackDevices);

        Ptr<Ipv4StaticRouting> attackerRouting =
            ipv4RoutingHelper.GetStaticRouting(
                attackerNode.Get(0)->GetObject<Ipv4>());
        attackerRouting->AddNetworkRouteTo(
            Ipv4Address("1.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

        MobilityHelper attackMob;
        attackMob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        attackMob.Install(attackerNode);
    }

    if (enableDDoS)
    {
        NS_LOG_INFO("DDoS: rate=" << ddosRate << "bps start=" << ddosStart
                    << " duration=" << ddosDuration);

        std::ostringstream ddosRateStr;
        ddosRateStr << static_cast<uint64_t>(ddosRate) << "bps";

        OnOffHelper ddosAttack("ns3::UdpSocketFactory",
            InetSocketAddress(serverAddr, TELEMETRY_PORT));
        ddosAttack.SetAttribute("DataRate",
            DataRateValue(DataRate(ddosRateStr.str())));
        ddosAttack.SetAttribute("PacketSize", UintegerValue(1400));
        ddosAttack.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        ddosAttack.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer ddosApp = ddosAttack.Install(attackerNode.Get(0));
        ddosApp.Start(Seconds(ddosStart));
        ddosApp.Stop(Seconds(ddosStart + ddosDuration));
    }

    // ========== GPS Spoofing Attack ==========
    // Supervisor spec: "simulate sudden jump 5-10 km" relative to the
    // bus's real position. We schedule LaunchGpsSpoof at gpsStart so it
    // can read the bus's *actual* position from its mobility model and
    // construct a fake position 5-10 km away in a random direction.
    // Subsequent fake packets drift at +50 m/pkt (1 pkt/s) -> 180 km/h
    // apparent speed, satisfying the >120 km/h spec.
    if (enableGpsSpoofing && gpsBusTarget < numBuses)
    {
        NS_LOG_INFO("GPS Spoofing: target bus " << gpsBusTarget
                    << " scheduled at t=" << gpsStart);
        Simulator::Schedule(Seconds(gpsStart),
                            &LaunchGpsSpoof,
                            attackerNode.Get(0),
                            busNodes.Get(gpsBusTarget),
                            serverAddr,
                            gpsBusTarget,
                            35.0);
    }

    // ========== Flow Monitor ==========
    FlowMonitorHelper flowMonHelper;
    Ptr<FlowMonitor> flowMonitor = flowMonHelper.InstallAll();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonHelper.GetClassifier());

    // ========== Schedule Monitoring ==========
    // DDoS detection every 10s
    double detectionStartTime = enableDDoS ? ddosStart : DETECTION_WARMUP_TIME;
    Simulator::Schedule(Seconds(10.0),
                        &CheckDDoS,
                        flowMonitor,
                        classifier,
                        serverAddr,
                        10.0,
                        detectionStartTime);

    // Queue status logging every 5s on the PGW-side P2P device
    Simulator::Schedule(Seconds(5.0),
                        &LogQueueStatus, serverDevices.Get(0), 5.0);

    // Forensic trigger polling every 2s (checks if DDoS detected)
    if ((enableDDoS || enableGpsSpoofing) && numBuses > 0)
    {
        Simulator::Schedule(Seconds(10.0),
                            &CheckForensicTrigger, busNodes.Get(0),
                            serverAddr, 2.0);
    }

    // ========== RUN ==========
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ========== POST-RUN: Write Results ==========
    flowMonitor->CheckForLostPackets();

    // Build output prefix
    uint32_t rngRun = RngSeedManager::GetRun();
    std::ostringstream prefix;
    prefix << resultsDir << scenario << "_" << numBuses << "buses_"
           << g_detectionMode << "_" << rngRun;

    // FlowMonitor XML
    std::string xmlFile = prefix.str() + ".xml";
    flowMonitor->SerializeToXmlFile(xmlFile, true, true);
    NS_LOG_INFO("FlowMonitor XML: " << xmlFile);

    // Summary
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();
    uint64_t totalTx = 0, totalRx = 0, totalLost = 0;
    double totalDelay = 0;

    for (auto it = stats.begin(); it != stats.end(); ++it)
    {
        totalTx += it->second.txPackets;
        totalRx += it->second.rxPackets;
        totalLost += it->second.lostPackets;
        totalDelay += it->second.delaySum.GetSeconds();
    }

    double avgDelay = (totalRx > 0) ? (totalDelay / totalRx) : 0;
    double lossRate = (totalTx > 0) ? ((double)totalLost / totalTx) : 0;

    NS_LOG_INFO("=== RESULTS SUMMARY ===");
    NS_LOG_INFO("TX: " << totalTx << " | RX: " << totalRx
                << " | Lost: " << totalLost);
    NS_LOG_INFO("Avg Delay: " << avgDelay << "s | Loss: "
                << lossRate * 100 << "%");
    NS_LOG_INFO("Forensic events: " << g_forensicEvents.size());
    NS_LOG_INFO("GPS spoof detections: " << CountGpsSpoofDetections());

    // ========== Detection Accuracy & Time ==========
    uint32_t ddosTP = 0, ddosFP = 0, ddosFN = 0;
    uint32_t gpsTP = 0, gpsFP = 0, gpsFN = 0;
    double firstGpsSpoofTime = -1.0;

    for (size_t i = 0; i < g_metricsLog.size(); i++)
    {
        if (g_metricsLog[i].eventType == "ddos_detect")
        {
            if (enableDDoS && g_metricsLog[i].time >= ddosStart
                && g_metricsLog[i].time <= ddosStart + ddosDuration + 10.0)
                ddosTP++;
            else
                ddosFP++;
        }
        if (g_metricsLog[i].eventType == "gps_spoof_detect")
        {
            if (enableGpsSpoofing && g_metricsLog[i].time >= gpsStart
                && g_metricsLog[i].time <= gpsStart + 40.0)
            {
                gpsTP++;
                if (firstGpsSpoofTime < 0) firstGpsSpoofTime = g_metricsLog[i].time;
            }
            else
                gpsFP++;
        }
    }

    if (enableDDoS && ddosTP == 0) ddosFN = 1;
    if (enableGpsSpoofing && gpsTP == 0) gpsFN = 1;

    double precision = 0, recall = 0, f1 = 0;
    uint32_t totalTP = ddosTP + gpsTP;
    uint32_t totalFP = ddosFP + gpsFP;
    uint32_t totalFN = ddosFN + gpsFN;

    if (totalTP + totalFP > 0)
        precision = (double)totalTP / (totalTP + totalFP);
    if (totalTP + totalFN > 0)
        recall = (double)totalTP / (totalTP + totalFN);
    if (precision + recall > 0)
        f1 = 2.0 * precision * recall / (precision + recall);

    LogMetric(simTime, 999, "detection_accuracy", precision * 100.0,
              recall * 100.0, "precision_recall");
    LogMetric(simTime, 999, "detection_f1", f1 * 100.0, 0, "f1_score");

    // Detection Time
    if (enableDDoS && g_ddosDetected)
    {
        double ddosDetDelay = g_ddosDetectionTime - ddosStart;
        LogMetric(simTime, 999, "ddos_detection_time", ddosDetDelay,
                  g_ddosDetectionTime, "seconds_from_attack_start");
        NS_LOG_INFO("DDoS Detection Time: " << ddosDetDelay << "s");
    }
    if (enableGpsSpoofing && firstGpsSpoofTime > 0)
    {
        double gpsDetDelay = firstGpsSpoofTime - gpsStart;
        LogMetric(simTime, 999, "gps_detection_time", gpsDetDelay,
                  firstGpsSpoofTime, "seconds_from_attack_start");
        NS_LOG_INFO("GPS Detection Time: " << gpsDetDelay << "s");
    }

    // Upload Success Rate
    uint32_t forensicTriggered = g_forensicEvents.size();
    uint32_t forensicCompleted = 0;
    for (size_t i = 0; i < g_forensicEvents.size(); i++)
    {
        if (g_forensicEvents[i].uploadCompleted) forensicCompleted++;
    }
    double uploadSuccessRate = (forensicTriggered > 0) ?
        ((double)forensicCompleted / forensicTriggered * 100.0) : 0.0;
    LogMetric(simTime, 999, "upload_success_rate", uploadSuccessRate,
              (double)forensicTriggered, "percent");

    NS_LOG_INFO("Detection: TP=" << totalTP << " FP=" << totalFP
                << " FN=" << totalFN << " P=" << precision
                << " R=" << recall << " F1=" << f1);
    NS_LOG_INFO("Upload Success Rate: " << uploadSuccessRate << "%");

    // Write CSVs AFTER all LogMetric calls
    WriteEventsCsv(prefix.str() + "_events.csv");
    WriteForensicsCsv(prefix.str() + "_forensics.csv");

    Simulator::Destroy();
    return 0;
}
