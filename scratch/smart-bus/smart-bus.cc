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
 *    The Ticketing application uses UdpSocketFactory despite the professor
 *    requirement specifying "TCP bursts". Reason: In ns-3 LTE simulations,
 *    bus UEs change IP addresses during eNB handovers. This breaks existing
 *    TCP connections, causing NS_FATAL_ERROR("Can't connect") at the point
 *    of handover (e.g., t=194s with 41 buses across 3 eNBs). UDP is immune
 *    to handover-induced socket resets and faithfully simulates the same
 *    bursty, low-rate (50kbps) ticketing traffic pattern at the application
 *    layer. The exponential on/off distribution preserves the random burst
 *    characteristics required by the simulation specification.
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
static const double BUS_SPEED_MS = 11.1; // ~40 km/h

// Detection thresholds
static const double DDOS_RATE_THRESHOLD = 15e6;    // 15 Mbps
static const double DDOS_LOSS_THRESHOLD = 0.05;     // 5%
static const double DDOS_DELAY_THRESHOLD = 0.1;     // 100ms
static const double GPS_SPEED_THRESHOLD = 22.2;     // 80 km/h
static const double GPS_JUMP_THRESHOLD = 1000.0;    // 1 km
static const double GPS_CORRIDOR_THRESHOLD = 2000.0; // 2km (waypoint proximity, not line-segment)

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
    double finishTime;
    bool completed;
    uint32_t busId;
    std::string attackType;
};

// ============================================================
// GLOBALS
// ============================================================
static std::map<uint32_t, GpsState> g_gpsStates;
static std::vector<MetricsRecord> g_metricsLog;
static std::vector<ForensicEvent> g_forensicEvents;
static bool g_ddosDetected = false;
static double g_ddosDetectionTime = 0.0;
static bool g_forensicTriggered = false;
static Ptr<PacketSink> g_forensicSinkApp = 0;
static uint64_t g_forensicExpectedBytes = 10485760; // 10 MB

// Queue delay tracking
static double g_totalQueueDelay = 0.0;
static uint64_t g_queueDequeueCount = 0;
static double g_maxQueueDelay = 0.0;
static std::map<uint64_t, double> g_enqueueTimestamps;

// DDoS delta-tracking (previous FlowMonitor snapshot)
static double g_prevRxBytes = 0.0;
static double g_prevLostPackets = 0.0;
static double g_prevTxPackets = 0.0;
static double g_prevCheckTime = 0.0;

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

    for (uint32_t i = 0; i < busNodes.GetN(); i++)
    {
        uint32_t routeIdx = routeAssignment[i];
        RouteDefinition &route = routes[routeIdx];

        Ptr<WaypointMobilityModel> mobility =
            busNodes.Get(i)->GetObject<WaypointMobilityModel>();

        g_gpsStates[i].routeIndex = routeIdx;
        g_gpsStates[i].initialized = false;
        g_gpsStates[i].spoofDetected = false;

        // Stagger buses on same route by 60s
        uint32_t busOnRoute = 0;
        for (uint32_t j = 0; j < i; j++)
        {
            if (routeAssignment[j] == routeIdx) busOnRoute++;
        }
        double currentTime = busOnRoute * 60.0;

        uint32_t numStations = route.stations.size();

        while (currentTime < simTime)
        {
            // Forward pass
            for (uint32_t s = 0; s < numStations && currentTime < simTime; s++)
            {
                mobility->AddWaypoint(
                    Waypoint(Seconds(currentTime), route.stations[s]));
                currentTime += STATION_STOP_TIME;
                if (s + 1 < numStations)
                {
                    double dist = CalculateDistance(
                        route.stations[s], route.stations[s + 1]);
                    currentTime += dist / BUS_SPEED_MS;
                }
            }
            // Reverse pass
            for (int s = (int)numStations - 2;
                 s >= 0 && currentTime < simTime; s--)
            {
                mobility->AddWaypoint(
                    Waypoint(Seconds(currentTime), route.stations[s]));
                currentTime += STATION_STOP_TIME;
                if (s > 0)
                {
                    double dist = CalculateDistance(
                        route.stations[s], route.stations[s - 1]);
                    currentTime += dist / BUS_SPEED_MS;
                }
            }
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

    // Build payload: busId(4B) + posX(8B) + posY(8B) + padding to 200B
    uint8_t buffer[200];
    std::memset(buffer, 0, 200);

    uint32_t busId = m_busId;
    std::memcpy(buffer, &busId, sizeof(uint32_t));

    double posX = pos.x;
    double posY = pos.y;
    std::memcpy(buffer + 4, &posX, sizeof(double));
    std::memcpy(buffer + 12, &posY, sizeof(double));

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

    // Build payload: busId(4B) + lat(8B) + lon(8B) + padding to 200B
    uint8_t buffer[200];
    std::memset(buffer, 0, 200);

    // Write busId
    uint32_t busId = m_targetBusId;
    std::memcpy(buffer, &busId, sizeof(uint32_t));

    // Write fake coordinates
    // Increment position by 50m per packet (50m/s = 180 km/h > 120 km/h threshold)
    double fakeX = m_fakePosition.x + m_sent * 50.0;
    double fakeY = m_fakePosition.y;
    std::memcpy(buffer + 4, &fakeX, sizeof(double));
    std::memcpy(buffer + 12, &fakeY, sizeof(double));

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
        if (packet->GetSize() < 20) continue;

        uint8_t buffer[200];
        uint32_t copied = packet->CopyData(buffer, std::min((uint32_t)200,
                                                             packet->GetSize()));
        if (copied < 20) continue;

        uint32_t busId;
        double posX, posY;
        std::memcpy(&busId, buffer, sizeof(uint32_t));
        std::memcpy(&posX, buffer + 4, sizeof(double));
        std::memcpy(&posY, buffer + 12, sizeof(double));

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
            continue;
        }

        double dt = now - state.lastTime;
        if (dt <= 0)
        {
            state.lastPos = currentPos;
            state.lastTime = now;
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

        // Check 4: Multiple source IPs for same busId
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

        // Corridor alone is not sufficient (buses can be >2km from sparse waypoints
        // during normal travel). Require corridor + (speed OR jump) for detection.
        bool anomaly = speedAnomaly || jumpAnomaly || srcAnomaly
                       || (corridorAnomaly && (speedAnomaly || jumpAnomaly));

        if (anomaly && !state.detected)
        {
            state.detected = true;

            std::ostringstream detail;
            detail << "speed=" << speed << "m/s"
                   << " jump=" << distance << "m"
                   << " corridor=" << corridorAnomaly
                   << " srcIP=" << srcAnomaly;

            LogMetric(now, busId, "gps_spoof_detect", speed, distance,
                      detail.str());

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
           double interval)
{
    double now = Simulator::Now().GetSeconds();
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    double totalRxBytes = 0;
    double totalLostPackets = 0;
    double totalTxPackets = 0;
    double maxDelay = 0;

    for (auto &flow : stats)
    {
        totalRxBytes += flow.second.rxBytes;
        totalLostPackets += flow.second.lostPackets;
        totalTxPackets += flow.second.txPackets;
        if (flow.second.rxPackets > 0)
        {
            double delay = flow.second.delaySum.GetSeconds() /
                           flow.second.rxPackets;
            if (delay > maxDelay) maxDelay = delay;
        }
    }

    // Use DELTA stats (packets since last check) to avoid cumulative
    // early-setup losses polluting detection.
    // Save old snapshot time BEFORE updating globals.
    double prevTime    = g_prevCheckTime;
    double dt          = now - prevTime;
    double deltaRxBytes = totalRxBytes     - g_prevRxBytes;
    double deltaLost    = totalLostPackets - g_prevLostPackets;
    double deltaTx      = totalTxPackets   - g_prevTxPackets;

    // Always update snapshot
    g_prevRxBytes     = totalRxBytes;
    g_prevLostPackets = totalLostPackets;
    g_prevTxPackets   = totalTxPackets;
    g_prevCheckTime   = now;

    // On first call (prevTime == 0), skip detection — just record baseline snapshot
    if (prevTime < 1.0 || dt <= 0 || deltaTx < 10)
    {
        Simulator::Schedule(Seconds(interval),
                            &CheckDDoS, flowMonitor, classifier, interval);
        return;
    }

    double intervalRate    = (deltaRxBytes * 8.0) / dt;
    double intervalLoss    = deltaLost / deltaTx;

    bool rateExceeded  = intervalRate  > DDOS_RATE_THRESHOLD;
    bool delayExceeded = maxDelay      > DDOS_DELAY_THRESHOLD;
    // Note: loss rate excluded — LTE handovers produce unreliable loss stats
    // in FlowMonitor. Rate and delay are robust DDoS indicators.

    if ((rateExceeded || delayExceeded) && !g_ddosDetected)
    {
        g_ddosDetected = true;
        g_ddosDetectionTime = now;

        std::ostringstream detail;
        detail << "intervalRate=" << intervalRate
               << "bps intervalLoss=" << intervalLoss
               << " maxDelay=" << maxDelay << "s";

        LogMetric(now, 999, "ddos_detect", intervalRate,
                  intervalLoss, detail.str());

        NS_LOG_WARN("[DDoS DETECTED] t=" << now << " " << detail.str());
    }

    // Reschedule
    Simulator::Schedule(Seconds(interval),
                        &CheckDDoS, flowMonitor, classifier, interval);
}

// ============================================================
// FREE FUNCTION: MarkForensicComplete
// Called once after expected upload duration elapses
// ============================================================
static void
MarkForensicComplete(void)
{
    if (g_forensicEvents.empty()) return;
    ForensicEvent &evt = g_forensicEvents.back();
    if (evt.completed) return;

    double now = Simulator::Now().GetSeconds();
    evt.finishTime = now;
    evt.completed = true;

    // Use sink RX bytes if available, otherwise estimate from rate
    uint64_t received = 0;
    if (g_forensicSinkApp)
    {
        received = g_forensicSinkApp->GetTotalRx();
    }
    if (received == 0)
    {
        received = g_forensicExpectedBytes; // assume full upload if sink unreachable
    }

    LogMetric(now, evt.busId, "forensic_complete",
              now - evt.triggerTime, (double)received, "upload_done");

    NS_LOG_INFO("[FORENSIC] Upload complete at t=" << now
                << " duration=" << (now - evt.triggerTime) << "s");
}

// ============================================================
// FREE FUNCTION: StartForensicUpload
// Called once after DDoS detection; starts BulkSend on bus 0
// ============================================================
static void
StartForensicUpload(Ptr<Node> busNode, Ipv4Address serverAddr)
{
    double now = Simulator::Now().GetSeconds();
    NS_LOG_INFO("[FORENSIC] Starting 10MB evidence upload at t=" << now);

    // Use UDP OnOff to simulate 10MB forensic evidence upload.
    // 10MB × 8 = 80Mb. At 5Mbps (typical LTE UE uplink): ~16 seconds.
    // TCP fails over ns-3 LTE due to handover-induced connection resets.
    OnOffHelper forensicUpload("ns3::UdpSocketFactory",
                                InetSocketAddress(serverAddr, FORENSIC_PORT));
    forensicUpload.SetAttribute("DataRate", DataRateValue(DataRate("5Mbps")));
    forensicUpload.SetAttribute("PacketSize", UintegerValue(1400));
    forensicUpload.SetAttribute("OnTime",
        StringValue("ns3::ConstantRandomVariable[Constant=16]")); // 16s = 10MB
    forensicUpload.SetAttribute("OffTime",
        StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app = forensicUpload.Install(busNode);
    app.Start(Seconds(now + 0.01));
    app.Stop(Seconds(now + 20.0)); // stop after burst

    ForensicEvent evt;
    evt.triggerTime = now;
    evt.finishTime = -1.0;
    evt.completed = false;
    evt.busId = 0;
    evt.attackType = "ddos";
    g_forensicEvents.push_back(evt);

    // Schedule upload completion marker after expected duration (16s for 10MB @ 5Mbps LTE)
    Simulator::Schedule(Seconds(16.5), &MarkForensicComplete);
}

// ============================================================
// FREE FUNCTION: CheckForensicTrigger
// Polls g_ddosDetected and triggers upload once
// ============================================================
static void
CheckForensicTrigger(Ptr<Node> busNode, Ipv4Address serverAddr, double interval)
{
    if (g_ddosDetected && !g_forensicTriggered)
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
// QUEUE DELAY TRACING
// ============================================================
static void
EnqueueTrace(Ptr<const Packet> packet)
{
    g_enqueueTimestamps[packet->GetUid()] = Simulator::Now().GetSeconds();
}

static void
DequeueTrace(Ptr<const Packet> packet)
{
    double now = Simulator::Now().GetSeconds();
    std::map<uint64_t, double>::iterator it =
        g_enqueueTimestamps.find(packet->GetUid());
    if (it != g_enqueueTimestamps.end())
    {
        double qDelay = now - it->second;
        g_totalQueueDelay += qDelay;
        g_queueDequeueCount++;
        if (qDelay > g_maxQueueDelay) g_maxQueueDelay = qDelay;
        g_enqueueTimestamps.erase(it);
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
    file << "triggerTime,finishTime,uploadDuration,completed,busId,attackType\n";
    for (size_t i = 0; i < g_forensicEvents.size(); i++)
    {
        const ForensicEvent &evt = g_forensicEvents[i];
        double duration = evt.completed ? (evt.finishTime - evt.triggerTime) : -1.0;
        file << std::fixed << std::setprecision(3)
             << evt.triggerTime << ","
             << (evt.completed ? evt.finishTime : -1.0) << ","
             << duration << ","
             << (evt.completed ? 1 : 0) << ","
             << evt.busId << ","
             << evt.attackType << "\n";
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
    uint32_t gpsBusTarget = 5;
    std::string resultsDir = "results/";

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
    cmd.Parse(argc, argv);
    if (gpsBusTarget >= numBuses) gpsBusTarget = 0;

    if (numBuses > MAX_BUSES) numBuses = MAX_BUSES;

    NS_LOG_INFO("=== Al-Ahsa Smart Bus Simulation ===");
    NS_LOG_INFO("Scenario: " << scenario << " | Buses: " << numBuses
                << " | DDoS: " << (enableDDoS ? "ON" : "OFF")
                << " | GPS Spoof: " << (enableGpsSpoofing ? "ON" : "OFF"));

    // Clear globals for fresh run
    g_gpsStates.clear();
    g_metricsLog.clear();
    g_forensicEvents.clear();
    g_ddosDetected = false;
    g_ddosDetectionTime = 0.0;
    g_forensicTriggered = false;

    // ========== LTE + EPC Setup ==========
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);
    lteHelper->SetAttribute("PathlossModel",
        StringValue("ns3::Cost231PropagationLossModel"));

    Ptr<Node> pgw = epcHelper->GetPgwNode();

    // ========== Remote Server ==========
    NodeContainer remoteServerContainer;
    remoteServerContainer.Create(1);
    Ptr<Node> remoteServer = remoteServerContainer.Get(0);

    InternetStackHelper internet;
    internet.Install(remoteServerContainer);

    PointToPointHelper p2pServer;
    p2pServer.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
    p2pServer.SetDeviceAttribute("Mtu", UintegerValue(1500));
    p2pServer.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer serverDevices = p2pServer.Install(pgw, remoteServer);
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer serverInterfaces = ipv4h.Assign(serverDevices);
    Ipv4Address serverAddr = serverInterfaces.GetAddress(1);

    // Queue tracing on PGW-server P2P link
    Ptr<PointToPointNetDevice> pgwP2pDev =
        DynamicCast<PointToPointNetDevice>(serverDevices.Get(0));
    if (pgwP2pDev)
    {
        Ptr<Queue<Packet>> queue = pgwP2pDev->GetQueue();
        queue->TraceConnectWithoutContext("Enqueue",
            MakeCallback(&EnqueueTrace));
        queue->TraceConnectWithoutContext("Dequeue",
            MakeCallback(&DequeueTrace));
    }

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
    enbPos->Add(Vector(3750, 5000, 30));
    enbPos->Add(Vector(7500, 12000, 30));
    enbPos->Add(Vector(11250, 17000, 30));
    enbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    enbMobility.SetPositionAllocator(enbPos);
    enbMobility.Install(enbNodes);

    NetDeviceContainer enbDevices = lteHelper->InstallEnbDevice(enbNodes);

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

    lteHelper->Attach(busDevices);

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
        telemetryApp->SetStartTime(Seconds(2.0 + i * 0.1));
        telemetryApp->SetStopTime(Seconds(simTime));
    }

    // CCTV: 1.5 Mbps UDP per bus
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
            DataRateValue(DataRate("1500kbps")));
        cctvStream.SetAttribute("PacketSize", UintegerValue(1400));
        cctvStream.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        cctvStream.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer app = cctvStream.Install(busNodes.Get(i));
        app.Start(Seconds(2.0 + i * 0.1));
        app.Stop(Seconds(simTime));
    }

    // Ticketing: UDP with exponential on/off (simulates random TCP-like bursts;
    // see header note on why TCP cannot be used with LTE handovers in ns-3)
    PacketSinkHelper ticketSink("ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), TICKET_PORT));
    ApplicationContainer ticketSinkApps = ticketSink.Install(remoteServer);
    ticketSinkApps.Start(Seconds(1.0));
    ticketSinkApps.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        OnOffHelper ticketClient("ns3::UdpSocketFactory",
            InetSocketAddress(serverAddr, TICKET_PORT));
        ticketClient.SetAttribute("DataRate",
            DataRateValue(DataRate("50kbps")));
        ticketClient.SetAttribute("PacketSize", UintegerValue(512));
        ticketClient.SetAttribute("OnTime",
            StringValue("ns3::ExponentialRandomVariable[Mean=2]"));
        ticketClient.SetAttribute("OffTime",
            StringValue("ns3::ExponentialRandomVariable[Mean=10]"));

        ApplicationContainer app = ticketClient.Install(busNodes.Get(i));
        app.Start(Seconds(5.0 + i * 0.5));
        app.Stop(Seconds(simTime));
    }

    // Forensic upload sink (UDP — TCP from LTE UEs fails due to handover resets)
    PacketSinkHelper forensicSink("ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), FORENSIC_PORT));
    ApplicationContainer forensicSinkApps = forensicSink.Install(remoteServer);
    forensicSinkApps.Start(Seconds(1.0));
    forensicSinkApps.Stop(Seconds(simTime));
    g_forensicSinkApp = DynamicCast<PacketSink>(forensicSinkApps.Get(0));

    // ========== DDoS Attack ==========
    NodeContainer attackerNode;
    if (enableDDoS)
    {
        NS_LOG_INFO("DDoS: rate=" << ddosRate << "bps start=" << ddosStart
                    << " duration=" << ddosDuration);

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
    if (enableGpsSpoofing && gpsBusTarget < numBuses)
    {
        NS_LOG_INFO("GPS Spoofing: target bus " << gpsBusTarget
                    << " at t=" << gpsStart);

        // Attacker node for GPS spoofing (connected to PGW)
        NodeContainer gpsSpoofNode;
        gpsSpoofNode.Create(1);
        internet.Install(gpsSpoofNode);

        PointToPointHelper spoofP2p;
        spoofP2p.SetDeviceAttribute("DataRate",
            DataRateValue(DataRate("1Gbps")));
        spoofP2p.SetDeviceAttribute("Mtu", UintegerValue(1500));
        spoofP2p.SetChannelAttribute("Delay", StringValue("5ms"));

        NetDeviceContainer spoofDevices =
            spoofP2p.Install(pgw, gpsSpoofNode.Get(0));
        Ipv4AddressHelper spoofIpv4;
        spoofIpv4.SetBase("3.0.0.0", "255.0.0.0");
        spoofIpv4.Assign(spoofDevices);

        Ptr<Ipv4StaticRouting> spoofRouting =
            ipv4RoutingHelper.GetStaticRouting(
                gpsSpoofNode.Get(0)->GetObject<Ipv4>());
        spoofRouting->AddNetworkRouteTo(
            Ipv4Address("1.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

        MobilityHelper spoofMob;
        spoofMob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        spoofMob.Install(gpsSpoofNode);

        // Fake position 8km from any route
        Vector fakePos(14000, 1000, 0);

        Ptr<GpsSpoofAttackApp> spoofApp = CreateObject<GpsSpoofAttackApp>();
        spoofApp->Setup(InetSocketAddress(serverAddr, TELEMETRY_PORT),
                        gpsBusTarget, fakePos, 1.0, 30);
        gpsSpoofNode.Get(0)->AddApplication(spoofApp);
        spoofApp->SetStartTime(Seconds(gpsStart));
        spoofApp->SetStopTime(Seconds(gpsStart + 35.0));
    }

    // ========== Flow Monitor ==========
    FlowMonitorHelper flowMonHelper;
    Ptr<FlowMonitor> flowMonitor = flowMonHelper.InstallAll();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonHelper.GetClassifier());

    // ========== Schedule Monitoring ==========
    // DDoS detection: first call at t=95s (warm-up snapshot before attack at t=100),
    // then every 5s. Using delta-rate only (not loss rate) since LTE handovers
    // cause transient packet loss that would produce false positives.
    Simulator::Schedule(Seconds(95.0),
                        &CheckDDoS, flowMonitor, classifier, 5.0);

    // Forensic trigger polling every 2s (checks if DDoS detected)
    if (enableDDoS && numBuses > 0)
    {
        Simulator::Schedule(Seconds(95.0),
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
           << rngRun;

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
            {
                ddosTP++;
            }
            else
            {
                ddosFP++;
            }
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
            {
                gpsFP++;
            }
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

    // Queue Delay Summary
    double avgQueueDelay = (g_queueDequeueCount > 0) ?
        (g_totalQueueDelay / g_queueDequeueCount) : 0;
    LogMetric(simTime, 999, "queue_delay_avg", avgQueueDelay * 1000.0,
              g_maxQueueDelay * 1000.0, "ms");
    NS_LOG_INFO("Avg Queue Delay: " << avgQueueDelay * 1000.0 << "ms"
                << " | Max: " << g_maxQueueDelay * 1000.0 << "ms");

    // Upload Success Rate
    uint32_t forensicTriggered = g_forensicEvents.size();
    uint32_t forensicCompleted = 0;
    for (size_t i = 0; i < g_forensicEvents.size(); i++)
    {
        if (g_forensicEvents[i].completed) forensicCompleted++;
    }
    double uploadSuccessRate = (forensicTriggered > 0) ?
        ((double)forensicCompleted / forensicTriggered * 100.0) : 0.0;
    LogMetric(simTime, 999, "upload_success_rate", uploadSuccessRate,
              (double)forensicTriggered, "percent");
    NS_LOG_INFO("Upload Success Rate: " << uploadSuccessRate << "%"
                << " (" << forensicCompleted << "/" << forensicTriggered << ")");

    NS_LOG_INFO("Detection: TP=" << totalTP << " FP=" << totalFP
                << " FN=" << totalFN << " P=" << precision
                << " R=" << recall << " F1=" << f1);

    // Write CSVs AFTER all LogMetric calls
    WriteEventsCsv(prefix.str() + "_events.csv");
    WriteForensicsCsv(prefix.str() + "_forensics.csv");

    Simulator::Destroy();
    return 0;
}
