/*
 * smart-bus-lite.cc
 * Al-Ahsa Smart Bus Network — Baseline-Only Lite Version
 *
 * Stripped-down version for quick testing on any platform (macOS/Linux).
 * Runs baseline scenarios only (no attacks, no detection, no forensics).
 * Tests 1, 10, and 40 bus configurations.
 *
 * Same network architecture as the full version:
 *   - LTE + EPC with 3 eNodeBs covering 15x20 km Al-Ahsa area
 *   - 10 bus routes with WaypointMobilityModel
 *   - Per-bus traffic: GPS telemetry (UDP), CCTV (UDP), Ticketing (UDP)
 *   - FlowMonitor XML output for analysis
 *
 * Usage:
 *   ./ns3 run "smart-bus-lite --numBuses=1 --simTime=200"
 *   ./ns3 run "smart-bus-lite --numBuses=10 --simTime=200"
 *   ./ns3 run "smart-bus-lite --numBuses=40 --simTime=200"
 *
 * CRITICAL: No lambdas in Simulator::Schedule — all callbacks
 * are free functions or member functions (ns-3.40 compliance).
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

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SmartBusLite");

// ============================================================
// CONSTANTS
// ============================================================
static const uint32_t MAX_BUSES = 41;
static const uint32_t NUM_ENB = 3;
static const double STATION_STOP_TIME = 30.0;
static const double BUS_SPEED_MS = 11.1; // ~40 km/h

// Ports
static const uint16_t TELEMETRY_PORT = 5000;
static const uint16_t CCTV_PORT = 6000;
static const uint16_t TICKET_PORT = 7000;

// GPS telemetry packet format:
// [0..3]   magic (uint32)
// [4..7]   busId (uint32)
// [8..15]  posX (double)
// [16..23] posY (double)
static const uint32_t GPS_PAYLOAD_MAGIC = 0x47505331; // "GPS1"

// ============================================================
// DATA STRUCTURES
// ============================================================
struct RouteDefinition {
    std::vector<Vector> stations;
};

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
// BUS ROUTE ASSIGNMENT (up to 41 buses, ~4 per route)
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
// MAIN
// ============================================================
int
main(int argc, char *argv[])
{
    // Command line parameters
    uint32_t numBuses = 1;
    double simTime = 200.0;
    std::string resultsDir = "results/";

    CommandLine cmd;
    cmd.AddValue("numBuses", "Number of buses (1, 10, or 40)", numBuses);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("resultsDir", "Output directory", resultsDir);
    cmd.Parse(argc, argv);

    if (numBuses > MAX_BUSES) numBuses = MAX_BUSES;

    NS_LOG_INFO("=== Al-Ahsa Smart Bus Simulation (Lite - Baseline Only) ===");
    NS_LOG_INFO("Buses: " << numBuses << " | SimTime: " << simTime << "s");

    // ========== LTE + EPC Setup ==========
    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);

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

    lteHelper->Attach(busDevices);

    // ========== Normal Traffic ==========

    // GPS Telemetry: UDP 1 pkt/s, 200B per bus
    // Simple sink on server (no detection logic in lite version)
    PacketSinkHelper telemetrySink("ns3::UdpSocketFactory",
        InetSocketAddress(Ipv4Address::GetAny(), TELEMETRY_PORT));
    ApplicationContainer telemetrySinkApps = telemetrySink.Install(remoteServer);
    telemetrySinkApps.Start(Seconds(1.0));
    telemetrySinkApps.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        Ptr<GpsTelemetryApp> telemetryApp = CreateObject<GpsTelemetryApp>();
        telemetryApp->Setup(
            InetSocketAddress(serverAddr, TELEMETRY_PORT), i, 1.0);
        busNodes.Get(i)->AddApplication(telemetryApp);
        telemetryApp->SetStartTime(Seconds(2.0 + i * 0.1));
        telemetryApp->SetStopTime(Seconds(simTime));
    }

    // CCTV: 500 kbps UDP per bus
    UdpServerHelper cctvServer(CCTV_PORT);
    ApplicationContainer cctvSink = cctvServer.Install(remoteServer);
    cctvSink.Start(Seconds(1.0));
    cctvSink.Stop(Seconds(simTime));

    for (uint32_t i = 0; i < numBuses; i++)
    {
        OnOffHelper cctvStream("ns3::UdpSocketFactory",
            InetSocketAddress(serverAddr, CCTV_PORT));
        cctvStream.SetAttribute("DataRate",
            DataRateValue(DataRate("500kbps")));
        cctvStream.SetAttribute("PacketSize", UintegerValue(1400));
        cctvStream.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        cctvStream.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer app = cctvStream.Install(busNodes.Get(i));
        app.Start(Seconds(2.0 + i * 0.1));
        app.Stop(Seconds(simTime));
    }

    // Ticketing: UDP with exponential on/off
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

    // ========== Flow Monitor ==========
    FlowMonitorHelper flowMonHelper;
    Ptr<FlowMonitor> flowMonitor = flowMonHelper.InstallAll();

    // ========== RUN ==========
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ========== POST-RUN: Write Results ==========
    flowMonitor->CheckForLostPackets();

    uint32_t rngRun = RngSeedManager::GetRun();
    std::ostringstream prefix;
    prefix << resultsDir << "baseline_" << numBuses << "buses_" << rngRun;

    // FlowMonitor XML
    std::string xmlFile = prefix.str() + ".xml";
    flowMonitor->SerializeToXmlFile(xmlFile, true, true);

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

    std::cout << "\n=== RESULTS SUMMARY ===" << std::endl;
    std::cout << "Buses: " << numBuses << " | SimTime: " << simTime << "s" << std::endl;
    std::cout << "TX: " << totalTx << " | RX: " << totalRx
              << " | Lost: " << totalLost << std::endl;
    std::cout << "Avg Delay: " << std::fixed << std::setprecision(4)
              << avgDelay * 1000 << " ms | Loss: "
              << std::setprecision(2) << lossRate * 100 << "%" << std::endl;
    std::cout << "FlowMonitor XML: " << xmlFile << std::endl;

    Simulator::Destroy();
    return 0;
}
