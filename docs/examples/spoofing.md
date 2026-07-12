# Identity Spoofing: Attack & Mitigation

This pair of examples demonstrates the same threat twice: first with **no Zero Trust controls** in place, then again with the full stack — identity, certificates, TLS-style handshake, encryption, and policy enforcement — switched on.

| | Description |
|---|---|
| **Attack** — `spoofing-attack.cc` | A legitimate sensor and a spoofed attacker both open TCP connections to the same gateway. With no identity verification in place, the gateway accepts and logs data from both indiscriminately. |
| **Mitigation** — `spoofing-mitigation.cc` | The gateway only accepts a session after the peer completes a Zero Trust handshake and its certificate is validated by the policy engine, so a node that cannot present a valid, non-revoked certificate for its claimed identity is rejected before any data is processed. |

**Components used in the mitigation:** [`Certificate Authority & Certificate-Based Policy`](../model/zt-certificate.md), [`Policy Engine`](../model/zt-policy-engine.md), [`TLS Handshake`](../model/zt-tls-handshake.md), [`Encryption Utilities`](../model/zt-encryption-utils.md), [`Logger`](../model/zt-logger.md)

## Attack — `spoofing-attack.cc`

A legitimate sensor and a spoofed attacker both open TCP connections to the same gateway. With no identity verification in place, the gateway accepts and logs data from both indiscriminately.

```cpp title="spoofing-attack.cc"
/**
 * @file spoofing-attack.cc
 * @brief Demonstrates a spoofing attack scenario in an NS-3 TCP-based IoT setup.
 *
 * This simulation consists of a legitimate sensor node and a spoofed attacker,
 * both sending data to a gateway over TCP. The gateway receives and logs the data.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SpoofingAttack");

/**
 * @class SimpleTcpApp
 * @brief A simple TCP-based application to send data to a remote peer.
 *
 * This application is used by both the legitimate sensor and the spoofed attacker
 * to transmit a message to the gateway node.
 */
class SimpleTcpApp : public Application {
public:
  /**
   * @brief Set up the TCP app with destination address and message.
   * @param addr The destination Address to connect to.
   * @param message The message payload to send.
   */
  void Setup(Address addr, std::string message);

private:
  /**
   * @brief Called when the application starts. Connects the socket and schedules Send().
   */
  virtual void StartApplication();

  /**
   * @brief Sends the message to the peer via TCP.
   */
  void Send();

  /**
   * @brief Called when the application stops. Closes the socket.
   */
  virtual void StopApplication();

  Ptr<Socket> socket;      ///< TCP socket used to send data.
  Address peer;            ///< Destination address to send data to.
  std::string data;        ///< Message payload.
};

void SimpleTcpApp::Setup(Address addr, std::string message) {
  peer = addr;
  data = message;
}

void SimpleTcpApp::StartApplication() {
  socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Connect(peer);
  Simulator::Schedule(Seconds(1.0), &SimpleTcpApp::Send, this);
}

void SimpleTcpApp::Send() {
  Ptr<Packet> packet = Create<Packet>((uint8_t*)data.c_str(), data.size());
  socket->Send(packet);
}

void SimpleTcpApp::StopApplication() {
  if (socket) socket->Close();
}

/**
 * @class TcpReceiver
 * @brief A simple TCP server application that receives and logs incoming messages.
 *
 * Acts as the gateway receiving messages from both legitimate and spoofed sources.
 */
class TcpReceiver : public Application {
public:
  /**
   * @brief Sets the address on which the receiver should listen.
   * @param listen The address to bind and listen on.
   */
  void Setup(Address listen);

private:
  /**
   * @brief Called when the application starts. Binds and listens on the socket.
   */
  virtual void StartApplication();

  /**
   * @brief Accepts a new incoming connection.
   * @param s The accepted socket.
   * @param address The remote address (not used).
   */
  void HandleAccept(Ptr<Socket> s, const Address &address);

  /**
   * @brief Reads incoming data and logs it.
   * @param s The socket from which to receive data.
   */
  void HandleRead(Ptr<Socket> s);

  /**
   * @brief Called when the application stops. Closes the socket.
   */
  virtual void StopApplication();

  Ptr<Socket> socket;  ///< TCP server socket.
  Address local;       ///< Address to listen on.
};

void TcpReceiver::Setup(Address listen) {
  local = listen;
}

void TcpReceiver::StartApplication() {
  socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Bind(local);
  socket->Listen();
  socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                            MakeCallback(&TcpReceiver::HandleAccept, this));
}

void TcpReceiver::HandleAccept(Ptr<Socket> s, const Address &) {
  s->SetRecvCallback(MakeCallback(&TcpReceiver::HandleRead, this));
}

void TcpReceiver::HandleRead(Ptr<Socket> s) {
  while (Ptr<Packet> packet = s->Recv()) {
    uint32_t len = packet->GetSize();
    uint8_t *buffer = new uint8_t[len];
    packet->CopyData(buffer, len);
    std::string received((char*)buffer, len);
    delete[] buffer;
    NS_LOG_UNCOND("[Gateway] Received: " << received);
  }
}

void TcpReceiver::StopApplication() {
  if (socket) socket->Close();
}

/**
 * @brief Main function to run the spoofing attack simulation.
 *
 * This sets up three nodes: a legitimate sensor, a spoofed attacker,
 * and a gateway. Both sensor and attacker send TCP messages to the gateway.
 */
int main(int argc, char *argv[]) {
  NodeContainer nodes;
  nodes.Create(3); // [0]=sensor, [1]=gateway, [2]=spoofed attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = ip.Assign(d1);
  ip.SetBase("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = ip.Assign(d2);

  // Legitimate sensor node
  Ptr<SimpleTcpApp> sensorApp = CreateObject<SimpleTcpApp>();
  sensorApp->Setup(InetSocketAddress(iface1.GetAddress(1), 8080), "TEMP:25.0");
  nodes.Get(0)->AddApplication(sensorApp);
  sensorApp->SetStartTime(Seconds(0.5));
  sensorApp->SetStopTime(Seconds(10.0));

  // Attacker sends garbage
  Ptr<SimpleTcpApp> spoofedApp = CreateObject<SimpleTcpApp>();
  spoofedApp->Setup(InetSocketAddress(iface2.GetAddress(1), 8080), "@$%!@garbageDATA#");
  nodes.Get(2)->AddApplication(spoofedApp);
  spoofedApp->SetStartTime(Seconds(1.5));
  spoofedApp->SetStopTime(Seconds(10.0));

  // Gateway receiver
  Ptr<TcpReceiver> recvApp = CreateObject<TcpReceiver>();
  recvApp->Setup(InetSocketAddress(Ipv4Address::GetAny(), 8080));
  nodes.Get(1)->AddApplication(recvApp);
  recvApp->SetStartTime(Seconds(0.0));
  recvApp->SetStopTime(Seconds(15.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
```


## Mitigation — `spoofing-mitigation.cc`

The gateway only accepts a session after the peer completes a Zero Trust handshake and its certificate is validated by the policy engine, so a node that cannot present a valid, non-revoked certificate for its claimed identity is rejected before any data is processed.

```cpp title="spoofing-mitigation.cc"
/**
 * @file spoofing-mitigation.cc
 * @brief Secure simulation against spoofing attacks using Zero Trust policy and certificate verification.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SpoofingMitigated");

/**
 * @brief Secure TCP-based sensor application that sends encrypted data after Zero Trust handshake and certificate validation.
 */
class SecureSensorApp : public Application {
public:
  /**
   * @brief Configure the sensor application.
   * @param peerAddr Address of the sink (gateway).
   * @param nodeId Unique sensor node ID.
   * @param role Role string (e.g., "temp-sensor").
   * @param sensorData Payload to be transmitted.
   * @param policy Zero Trust policy engine.
   * @param ca Certificate authority for signing.
   * @param handshake TLS-like session key exchange.
   */
  void Setup(Address peerAddr, uint32_t nodeId, std::string role, std::string sensorData,
             Ptr<ZtPolicyEngine> policy, CertificateAuthority* ca, Ptr<ZtTlsHandshake> handshake) {
    peer = peerAddr;
    nid = nodeId;
    this->role = role;
    this->sensorData = sensorData;
    this->zt = policy;
    this->ca = ca;
    this->handshake = handshake;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Connect(peer);

    handshake->StartHandshake(GetNode(), GetNode(), nid, 1);
    time_t expiry = std::time(nullptr) + 60;
    std::string cert = ca->SignIdentity(nid, role, expiry);
    ZtLogger::LogCertIssued(nid, role, expiry);
    Ptr<Packet> certPkt = Create<Packet>((uint8_t*)cert.c_str(), cert.size());
    socket->Send(certPkt);

    Simulator::Schedule(Seconds(2.0), &SecureSensorApp::SendEncrypted, this);
  }

  /**
   * @brief Encrypt and send sensor data using session key.
   */
  void SendEncrypted() {
    std::string sessionHexKey = handshake->GetSessionKey(nid);
    std::vector<byte> rawKey = HexToBytes(sessionHexKey);
    std::string iv;
    std::string encrypted = EncryptPayload(sensorData, rawKey.data(), iv);
    ZtLogger::LogEncryption(sensorData, iv);
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)encrypted.c_str(), encrypted.size());
    socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address peer;
  uint32_t nid;
  std::string role, sensorData;
  Ptr<ZtPolicyEngine> zt;
  CertificateAuthority* ca;
  Ptr<ZtTlsHandshake> handshake;
};

/**
 * @brief Secure receiver (gateway) that authorizes senders and decrypts valid messages.
 */
class SecureSinkApp : public Application {
public:
  /**
   * @brief Setup receiver application with policy engine and TLS handshake support.
   * @param listen Address to bind the receiver.
   * @param policy Zero Trust policy engine.
   * @param handshake TLS handshake object.
   */
  void Setup(Address listen, Ptr<ZtPolicyEngine> policy, Ptr<ZtTlsHandshake> handshake) {
    local = listen;
    zt = policy;
    this->handshake = handshake;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Bind(local);
    socket->Listen();
    socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&SecureSinkApp::HandleAccept, this));
  }

  void HandleAccept(Ptr<Socket> s, const Address&) {
    s->SetRecvCallback(MakeCallback(&SecureSinkApp::HandleRead, this));
  }

  /**
   * @brief Handle incoming packets, validate certificate, and decrypt authorized data.
   */
  void HandleRead(Ptr<Socket> s) {
    while (Ptr<Packet> pkt = s->Recv()) {
      uint32_t size = pkt->GetSize();
      uint8_t* buffer = new uint8_t[size];
      pkt->CopyData(buffer, size);
      std::string data(reinterpret_cast<char*>(buffer), size);
      delete[] buffer;

      // Certificate validation
      if (data.find("ID:") == 0) {
        size_t idPos = data.find("ID:");
        size_t rolePos = data.find("|ROLE:");
        size_t expPos = data.find("|EXP:");
        uint32_t nodeId = std::stoul(data.substr(idPos + 3, rolePos - idPos - 3));
        std::string role = data.substr(rolePos + 6, expPos - rolePos - 6);

        bool valid = zt->AuthorizeWithCert(nodeId, role, data);
        ZtLogger::LogCertValidationResult(nodeId, valid);
        authorized[nodeId] = valid;

        handshake->StartHandshake(GetNode(), GetNode(), nodeId, 1);
        return;
      }

      // Decryption only if authorized
      uint32_t peerId = 0;
      if (authorized[peerId]) {
        try {
          std::string sessionHexKey = handshake->GetSessionKey(1);
          std::vector<byte> rawKey = HexToBytes(sessionHexKey);
          std::string decrypted = DecryptPayload(data, rawKey.data());
          ZtLogger::LogDecryption(decrypted);
        } catch (...) {
          ZtLogger::LogDecryptionFailure();
        }
      } else {
        ZtLogger::Log("ZT", "Unauthorized data attempt");
      }
    }
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address local;
  Ptr<ZtPolicyEngine> zt;
  Ptr<ZtTlsHandshake> handshake;
  std::map<uint32_t, bool> authorized;
};

/**
 * @brief Simple untrusted TCP application used by attacker to send garbage payloads.
 */
class SimpleTcpApp : public Application {
public:
  /**
   * @brief Configure attacker app.
   * @param address Target address (usually the gateway).
   * @param payload Malicious or spoofed data string.
   */
  void Setup(Address address, std::string payload) {
    m_peer = address;
    m_payload = payload;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Connect(m_peer);
    Simulator::Schedule(Seconds(2.0), &SimpleTcpApp::SendData, this);
  }

  void SendData() {
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)m_payload.c_str(), m_payload.size());
    m_socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  std::string m_payload;
};

/**
 * @brief Main function to simulate spoofing attack with Zero Trust defense.
 */
int main(int argc, char* argv[]) {
  ZtLogger::EnableTimestamps(true);

  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: gateway, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("2Mbps"));
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

  // Zero Trust configuration
  Ptr<ZtPolicyEngine> policy = CreateObject<ZtPolicyEngine>();
  CertificateAuthority ca;
  Ptr<ZtTlsHandshake> handshake = CreateObject<ZtTlsHandshake>();
  policy->SetCaPublicKey(ca.GetPublicKey());
  policy->AddAuthorized(0, "temp-sensor");

  // Setup Gateway (secure sink)
  Ptr<SecureSinkApp> sink = CreateObject<SecureSinkApp>();
  sink->Setup(InetSocketAddress(Ipv4Address::GetAny(), 8080), policy, handshake);
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Setup Legitimate Sensor
  Ptr<SecureSensorApp> sensor = CreateObject<SecureSensorApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 8080), 0, "temp-sensor", "TEMP:22.5", policy, &ca, handshake);
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(10.0));

  // Setup Attacker (unverified, garbage sender)
  Ptr<SimpleTcpApp> attacker = CreateObject<SimpleTcpApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 8080), "MALICIOUS#@garbage$");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(3.0));
  attacker->SetStopTime(Seconds(10.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
```
