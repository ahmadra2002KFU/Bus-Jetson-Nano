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
static const double GPS_CORRIDOR_THRESHOLD = 1500.0; // 1500m
static const double DETECTION_WARMUP_TIME = 60.0;
static const double SERVER_LINK_RATE_BPS = 1e9;

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

    double fakeX = m_fakePosition.x;
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

        uint32_t anomalyCount = (speedAnomaly ? 1 : 0) + (jumpAnomaly ? 1 : 0)
                               + (corridorAnomaly ? 1 : 0) + (srcAnomaly ? 1 : 0);
        uint32_t requiredCount = (g_detectionMode == "any") ? 1 : 2;
        if (anomalyCount >= requiredCount && !state.detected)
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
    double now = Simulator::Now().GetSeconds();
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    if (now < detectionStartTime)
    {
        Simulator::Schedule(Seconds(interval),
                            &CheckDDoS,
                            flowMonitor,
                            classifier,
                            serverAddr,
                            interval,
                            detectionStartTime);
        return;
    }

    double telemetryRxBytes = 0;
    double telemetryLostPackets = 0;
    double telemetryTxPackets = 0;
    double telemetryMaxDelay = 0;

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

        telemetryLostPackets += flow.second.lostPackets;
        telemetryTxPackets += flow.second.txPackets;
        if (flow.second.rxPackets > 0)
        {
            double delay = flow.second.delaySum.GetSeconds() /
                           flow.second.rxPackets;
            if (delay > telemetryMaxDelay) telemetryMaxDelay = delay;
        }
    }

    double lossRate = (telemetryTxPackets > 0) ?
                      (telemetryLostPackets / telemetryTxPackets) : 0;

    double intervalBytes = telemetryRxBytes - s_prevRxBytes;
    double intervalRate = intervalBytes * 8.0 / interval;
    s_prevRxBytes = telemetryRxBytes;

    bool rateExceeded = intervalRate > DDOS_RATE_THRESHOLD;
    bool lossExceeded = lossRate > DDOS_LOSS_THRESHOLD;
    bool delayExceeded = telemetryMaxDelay > DDOS_DELAY_THRESHOLD;

    if ((rateExceeded || lossExceeded || delayExceeded) && !g_ddosDetected)
    {
        g_ddosDetected = true;
        g_ddosDetectionTime = now;

        std::ostringstream detail;
        detail << "mode=requirements_any"
               << " telemetryRate=" << intervalRate
               << "bps loss=" << lossRate
               << " maxDelay=" << telemetryMaxDelay << "s";

        LogMetric(now, 999, "ddos_detect", intervalRate,
                  lossRate, detail.str());

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
// FREE FUNCTION: CheckForensicUploadComplete
// Polls PacketSink::GetTotalRx() every 1s to detect upload finish
// ============================================================
static void
CheckForensicUploadComplete(uint32_t evtIndex)
{
    if (evtIndex >= g_forensicEvents.size()) return;
    ForensicEvent &evt = g_forensicEvents[evtIndex];
    if (evt.uploadCompleted) return;

    uint64_t rxBytes = 0;
    if (g_forensicSinkApp)
    {
        rxBytes = g_forensicSinkApp->GetTotalRx();
    }
    evt.bytesReceived = rxBytes;

    if (rxBytes >= 10485760) // 10 MB
    {
        evt.uploadFinishTime = Simulator::Now().GetSeconds();
        evt.uploadCompleted = true;
        NS_LOG_INFO("[FORENSIC] Upload complete at t=" << evt.uploadFinishTime
                    << " bytes=" << rxBytes);
    }
    else
    {
        Simulator::Schedule(Seconds(1.0),
                            &CheckForensicUploadComplete, evtIndex);
    }
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

    BulkSendHelper bulkSend("ns3::TcpSocketFactory",
                             InetSocketAddress(serverAddr, FORENSIC_PORT));
    bulkSend.SetAttribute("MaxBytes", UintegerValue(10485760)); // 10 MB
    bulkSend.SetAttribute("SendSize", UintegerValue(1448));

    ApplicationContainer app = bulkSend.Install(busNode);
    app.Start(Seconds(now + 0.01)); // schedule slightly in the future
    app.Stop(Seconds(now + 200.0)); // generous timeout

    ForensicEvent evt;
    evt.triggerTime = now;
    evt.busId = 0;
    evt.attackType = g_ddosDetected ? "ddos" : "gps_spoof";
    evt.uploadStartTime = now;
    evt.uploadFinishTime = 0.0;
    evt.uploadCompleted = false;
    evt.bytesReceived = 0;
    g_forensicEvents.push_back(evt);

    // Schedule polling to track upload completion
    uint32_t evtIndex = g_forensicEvents.size() - 1;
    Simulator::Schedule(Seconds(1.0),
                        &CheckForensicUploadComplete, evtIndex);
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
    cmd.Parse(argc, argv);
    g_detectionMode = detectionMode;

    if (numBuses > MAX_BUSES) numBuses = MAX_BUSES;

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

    // ========== LTE + EPC Setup ==========
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);

    // 20 MHz bandwidth (100 RBs) — matches real LTE deployment capacity
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
    p2pServer.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1Gbps")));
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
    enbPos->Add(Vector(3750, 5000, 30));
    enbPos->Add(Vector(7500, 12000, 30));
    enbPos->Add(Vector(11250, 17000, 30));
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
        app.Start(Seconds(2.0 + i * 0.1));
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
        ticketApp->SetStartTime(Seconds(5.0 + i * 0.2));
        ticketApp->SetStopTime(Seconds(simTime));
    }

    // Forensic upload sink (TCP)
    PacketSinkHelper forensicSink("ns3::TcpSocketFactory",
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
    // DDoS detection every 5s
    double detectionStartTime = enableDDoS ? ddosStart : DETECTION_WARMUP_TIME;
    Simulator::Schedule(Seconds(10.0),
                        &CheckDDoS,
                        flowMonitor,
                        classifier,
                        serverAddr,
                        5.0,
                        detectionStartTime);

    // Queue status logging every 5s on the PGW-side P2P device
    Simulator::Schedule(Seconds(5.0),
                        &LogQueueStatus, serverDevices.Get(0), 5.0);

    // Forensic trigger polling every 2s (checks if DDoS detected)
    if (enableDDoS && numBuses > 0)
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

    // Events CSV
    WriteEventsCsv(prefix.str() + "_events.csv");

    // Forensics CSV
    WriteForensicsCsv(prefix.str() + "_forensics.csv");

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

    Simulator::Destroy();
    return 0;
}
