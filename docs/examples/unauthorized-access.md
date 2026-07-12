# Unauthorized Access: Attack & Mitigation

This pair of examples demonstrates the same threat twice: first with **no Zero Trust controls** in place, then again with the full stack — identity, certificates, TLS-style handshake, encryption, and policy enforcement — switched on.

| | Description |
|---|---|
| **Attack** — `unauthorized-access-attack.cc` | A simple TCP client sends data straight to a peer with no authentication or authorization step at all, showing how easily an unauthorized device can inject traffic into a network with no Zero Trust enforcement. |
| **Mitigation** — `unauthorized-access-mitigation.cc` | The sending application is replaced with a secure application that authenticates and encrypts before sending, so data injection from a device that hasn't been issued (and hasn't proven) a valid identity certificate is rejected by the policy engine at the gateway. |

**Components used in the mitigation:** [`Certificate Authority & Certificate-Based Policy`](../model/zt-certificate.md), [`Policy Engine`](../model/zt-policy-engine.md), [`TLS Handshake`](../model/zt-tls-handshake.md), [`Encryption Utilities`](../model/zt-encryption-utils.md), [`Logger`](../model/zt-logger.md)

## Attack — `unauthorized-access-attack.cc`

A simple TCP client sends data straight to a peer with no authentication or authorization step at all, showing how easily an unauthorized device can inject traffic into a network with no Zero Trust enforcement.

```cpp title="unauthorized-access-attack.cc"
/**
 * @file unauthorized-access-attack.cc
 * @brief Simulates unauthorized access in an NS-3 IoT setup without Zero Trust enforcement.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UnauthorizedAccessAttack");

/**
 * @class SimpleTcpApp
 * @brief Simulates a simple TCP client application that sends a message to a given peer.
 */
class SimpleTcpApp : public Application {
public:
  /**
   * @brief Sets up the application with peer address and payload.
   * @param peerAddr The destination address.
   * @param message The data to send.
   */
  void Setup(Address peerAddr, std::string message);

private:
  virtual void StartApplication();   ///< Called at application start.
  virtual void StopApplication();    ///< Called at application stop.

  /**
   * @brief Sends the configured payload to the peer.
   */
  void SendData();

  Ptr<Socket> m_socket;      ///< TCP socket used by the app.
  Address m_peer;            ///< Destination address.
  std::string m_message;     ///< Payload to send.
};

void SimpleTcpApp::Setup(Address peerAddr, std::string message) {
  m_peer = peerAddr;
  m_message = message;
}

void SimpleTcpApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Connect(m_peer);
  Simulator::Schedule(Seconds(2.0), &SimpleTcpApp::SendData, this);
}

void SimpleTcpApp::SendData() {
  Ptr<Packet> packet = Create<Packet>((uint8_t*)m_message.c_str(), m_message.size());
  m_socket->Send(packet);
}

void SimpleTcpApp::StopApplication() {
  if (m_socket) m_socket->Close();
}

/**
 * @class BasicSink
 * @brief A simple TCP server that logs incoming messages.
 */
class BasicSink : public Application {
private:
  virtual void StartApplication();  ///< Called at application start.
  virtual void StopApplication();   ///< Called at application stop.

  /**
   * @brief Handles incoming connections.
   * @param socket Pointer to the socket.
   * @param address Remote address.
   */
  void HandleAccept(Ptr<Socket> socket, const Address& address);

  /**
   * @brief Reads data from connected clients and logs the content.
   * @param socket Socket to read from.
   */
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_socket; ///< Server socket.
};

void BasicSink::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9090));
  m_socket->Listen();
  m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&BasicSink::HandleAccept, this));
}

void BasicSink::HandleAccept(Ptr<Socket> s, const Address&) {
  s->SetRecvCallback(MakeCallback(&BasicSink::HandleRead, this));
}

void BasicSink::HandleRead(Ptr<Socket> socket) {
  while (Ptr<Packet> packet = socket->Recv()) {
    Address from;
    socket->GetPeerName(from);

    uint32_t size = packet->GetSize();
    uint8_t* buffer = new uint8_t[size];
    packet->CopyData(buffer, size);
    std::string data(reinterpret_cast<char*>(buffer), size);
    delete[] buffer;

    std::ostringstream log;
    log << "[RECEIVED from " << InetSocketAddress::ConvertFrom(from).GetIpv4() << "] Payload: " << data;
    NS_LOG_UNCOND(log.str());
  }
}

void BasicSink::StopApplication() {
  if (m_socket) m_socket->Close();
}

/**
 * @brief Main function to simulate a TCP-based unauthorized access attack scenario.
 * 
 * - Node 0: legitimate sensor
 * - Node 1: sink
 * - Node 2: unauthorized attacker
 */
int main(int argc, char* argv[]) {
  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: sink, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = address.Assign(d1);
  address.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = address.Assign(d2);

  // Sink application
  Ptr<BasicSink> sink = CreateObject<BasicSink>();
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Legitimate sensor application
  Ptr<SimpleTcpApp> sensor = CreateObject<SimpleTcpApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 9090), "TEMP:25.0");
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(5.0));

  // Unauthorized attacker application
  Ptr<SimpleTcpApp> attacker = CreateObject<SimpleTcpApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 9090), "DELETE ALL DATA");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(3.0));
  attacker->SetStopTime(Seconds(7.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
```


## Mitigation — `unauthorized-access-mitigation.cc`

The sending application is replaced with a secure application that authenticates and encrypts before sending, so data injection from a device that hasn't been issued (and hasn't proven) a valid identity certificate is rejected by the policy engine at the gateway.

```cpp title="unauthorized-access-mitigation.cc"
/// \file unauthorized-access-mitigation.cc
/// \brief Secure simulation using Zero Trust architecture for IoT in ns-3.
/// \details Implements certificate-based authentication and TLS-like session handling
///          to defend against unauthorized data injection in IoT networks.

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UnauthorizedAccessMitigated");

/// \class SecureSensorApp
/// \brief A secure application that performs authentication and encryption before sending data.
class SecureSensorApp : public Application {
public:
  /**
   * \brief Configure the secure sensor application.
   * \param peer Destination address
   * \param nodeId Unique ID of the node
   * \param role Role (e.g., "sensor")
   * \param payload The data to be sent
   * \param policy Pointer to policy engine
   * \param ca Pointer to certificate authority
   * \param handshake TLS-like handshake handler
   */
  void Setup(Address peer, uint32_t nodeId, std::string role, std::string payload,
             Ptr<ZtPolicyEngine> policy, CertificateAuthority* ca, Ptr<ZtTlsHandshake> handshake);

private:
  virtual void StartApplication();
  virtual void StopApplication();
  void SendEncrypted();

  Ptr<Socket> m_socket;
  Address m_peer;
  uint32_t m_nodeId;
  std::string m_role, m_payload;
  Ptr<ZtPolicyEngine> m_policy;
  CertificateAuthority* m_ca;
  Ptr<ZtTlsHandshake> m_handshake;
};

void SecureSensorApp::Setup(Address peer, uint32_t nodeId, std::string role, std::string payload,
                            Ptr<ZtPolicyEngine> policy, CertificateAuthority* ca, Ptr<ZtTlsHandshake> handshake) {
  m_peer = peer;
  m_nodeId = nodeId;
  m_role = role;
  m_payload = payload;
  m_policy = policy;
  m_ca = ca;
  m_handshake = handshake;
}

void SecureSensorApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Connect(m_peer);

  time_t expiry = std::time(nullptr) + 60;
  std::string cert = m_ca->SignIdentity(m_nodeId, m_role, expiry);
  ZtLogger::LogCertIssued(m_nodeId, m_role, expiry);
  Ptr<Packet> certPkt = Create<Packet>((uint8_t*)cert.c_str(), cert.size());
  m_socket->Send(certPkt);

  m_handshake->StartHandshake(GetNode(), GetNode(), m_nodeId, 1);
  Simulator::Schedule(Seconds(2.0), &SecureSensorApp::SendEncrypted, this);
}

void SecureSensorApp::SendEncrypted() {
  if (!m_handshake->HasSession(m_nodeId)) {
    ZtLogger::Log("ZT", "Sensor node has no session key – skipping encryption");
    return;
  }
  std::string sessionKey = m_handshake->GetSessionKey(m_nodeId);
  std::vector<byte> rawKey = HexToBytes(sessionKey);
  std::string iv;
  std::string encrypted = EncryptPayload(m_payload, rawKey.data(), iv);
  ZtLogger::LogEncryption(m_payload, iv);
  Ptr<Packet> pkt = Create<Packet>((uint8_t*)encrypted.c_str(), encrypted.size());
  m_socket->Send(pkt);
}

void SecureSensorApp::StopApplication() {
  if (m_socket) m_socket->Close();
}

/// \class SecureSink
/// \brief A secure receiver that verifies certificates and decrypts data if authorized.
class SecureSink : public Application {
public:
  /**
   * \brief Configure the secure sink.
   * \param listen Local address to bind
   * \param policy Pointer to policy engine
   * \param handshake TLS-like handshake handler
   */
  void Setup(Address listen, Ptr<ZtPolicyEngine> policy, Ptr<ZtTlsHandshake> handshake);

private:
  virtual void StartApplication();
  virtual void StopApplication();
  void HandleAccept(Ptr<Socket> s, const Address&);
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_socket;
  Address m_local;
  Ptr<ZtPolicyEngine> m_policy;
  Ptr<ZtTlsHandshake> m_handshake;
  std::map<uint32_t, bool> m_authorized;
};

void SecureSink::Setup(Address listen, Ptr<ZtPolicyEngine> policy, Ptr<ZtTlsHandshake> handshake) {
  m_local = listen;
  m_policy = policy;
  m_handshake = handshake;
}

void SecureSink::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Bind(m_local);
  m_socket->Listen();
  m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&SecureSink::HandleAccept, this));
}

void SecureSink::HandleAccept(Ptr<Socket> s, const Address&) {
  s->SetRecvCallback(MakeCallback(&SecureSink::HandleRead, this));
}

void SecureSink::HandleRead(Ptr<Socket> socket) {
  while (Ptr<Packet> pkt = socket->Recv()) {
    uint32_t size = pkt->GetSize();
    std::vector<uint8_t> buffer(size);
    pkt->CopyData(buffer.data(), size);
    std::string data(reinterpret_cast<char*>(buffer.data()), size);

    if (data.find("ID:") == 0) {
      try {
        uint32_t nodeId = std::stoi(data.substr(3, data.find("|ROLE:") - 3));
        std::string role = data.substr(data.find("|ROLE:") + 6, data.find("|EXP:") - data.find("|ROLE:") - 6);

        bool valid = m_policy->AuthorizeWithCert(nodeId, role, data);
        ZtLogger::LogCertValidationResult(nodeId, valid);
        m_authorized[nodeId] = valid;

        if (valid) {
          m_handshake->StartHandshake(GetNode(), GetNode(), nodeId, 1);
        }
      } catch (...) {
        ZtLogger::Log("ZT", "Malformed certificate – ignored");
      }
      continue;
    }

    bool validPacket = false;
    for (const auto& entry : m_authorized) {
      if (entry.second && m_handshake->HasSession(entry.first)) {
        try {
          std::string sessionKey = m_handshake->GetSessionKey(entry.first);
          std::vector<byte> rawKey = HexToBytes(sessionKey);
          std::string decrypted = DecryptPayload(data, rawKey.data());
          ZtLogger::LogDecryption(decrypted);
          validPacket = true;
          break;
        } catch (...) {
          ZtLogger::LogDecryptionFailure();
          break;
        }
      }
    }

    if (!validPacket) {
      ZtLogger::Log("ZT", "Unauthorized data attempt - dropped");
    }
  }
}

void SecureSink::StopApplication() {
  if (m_socket) m_socket->Close();
}

/// \class AttackerApp
/// \brief Simulates an unauthorized device attempting to inject malicious payload.
class AttackerApp : public Application {
public:
  /**
   * \brief Configure attacker node.
   * \param peer Destination address
   * \param payload Malicious payload to send
   */
  void Setup(Address peer, std::string payload);

private:
  virtual void StartApplication();
  virtual void StopApplication();
  void SendFake();

  Ptr<Socket> m_socket;
  Address m_peer;
  std::string m_payload;
};

void AttackerApp::Setup(Address peer, std::string payload) {
  m_peer = peer;
  m_payload = payload;
}

void AttackerApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Connect(m_peer);
  Simulator::Schedule(Seconds(3.0), &AttackerApp::SendFake, this);
}

void AttackerApp::SendFake() {
  ZtLogger::Log("ATTACKER", "Sending unauthorized payload");
  Ptr<Packet> pkt = Create<Packet>((uint8_t*)m_payload.c_str(), m_payload.size());
  m_socket->Send(pkt);
}

void AttackerApp::StopApplication() {
  if (m_socket) m_socket->Close();
}

/// \brief Main function setting up the topology and Zero Trust protection logic.
int main(int argc, char* argv[]) {
  ZtLogger::EnableTimestamps(true);

  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: sink, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = ip.Assign(d1);
  ip.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = ip.Assign(d2);

  Ptr<ZtPolicyEngine> policy = CreateObject<ZtPolicyEngine>();
  CertificateAuthority ca;
  Ptr<ZtTlsHandshake> handshake = CreateObject<ZtTlsHandshake>();
  policy->SetCaPublicKey(ca.GetPublicKey());
  policy->AddAuthorized(0, "sensor");

  Ptr<SecureSink> sink = CreateObject<SecureSink>();
  sink->Setup(InetSocketAddress(Ipv4Address::GetAny(), 9090), policy, handshake);
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  Ptr<SecureSensorApp> sensor = CreateObject<SecureSensorApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 9090), 0, "sensor", "TEMP:25.5", policy, &ca, handshake);
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(5.0));

  Ptr<AttackerApp> attacker = CreateObject<AttackerApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 9090), "ERASE:ALL");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(2.5));
  attacker->SetStopTime(Seconds(6.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
```
