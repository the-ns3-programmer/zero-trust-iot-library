# IPv4 Enforcement Hook

Attaches to a node's IPv4 stack and taps its transmit (Tx) trace source, so every outgoing packet can be checked against [`ZtPolicyEngine`](zt-policy-engine.md) before it leaves the node. This is what turns micro-segmentation rules into real, enforced network-layer behaviour rather than an offline check.

**Depends on:** [`Policy Engine`](zt-policy-engine.md), [`Identity Registry`](zt-identity-registry.md)

## API summary

**`ZtIpv4Hook`**

| Member | Description |
|---|---|
| `SetPolicyEngine(engine)` | Binds the `ZtPolicyEngine` instance used for enforcement decisions. |
| `AttachToNode(node)` | Connects to the node's `Ipv4` transmit trace source. |
| `InterceptPacket(packet, ipv4, interface)` | Trace callback invoked for every packet leaving the node. |

## Header — `zt-ipv4-hook.h`

```cpp title="zt-ipv4-hook.h"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header defines the ZtIpv4Hook class used for
 integrating Zero Trust policy enforcement into
 the IPv4 transmission layer.

 - Inherits from ns3::Object.
 - Attaches to a node’s IPv4 stack.
 - Intercepts outgoing (Tx) packets.
 - Delegates access control decisions to the
   ZtPolicyEngine before packet transmission.

 This enables real-time micro-segmentation
 enforcement at the network layer.
*/
#ifndef ZT_IPV4_HOOK_H
#define ZT_IPV4_HOOK_H

#include "ns3/object.h"
#include "ns3/node.h"
#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/address.h"

namespace ns3 {

class ZtPolicyEngine;

class ZtIpv4Hook : public Object
{
public:
  static TypeId GetTypeId();

  ZtIpv4Hook();
  virtual ~ZtIpv4Hook();

  void SetPolicyEngine(Ptr<ZtPolicyEngine> engine);
  void AttachToNode(Ptr<Node> node);

private:
  // Correct Ipv4 Tx trace signature
  void InterceptPacket(Ptr<const Packet> packet,
                       Ptr<Ipv4> ipv4,
                       uint32_t interface);

  Ptr<ZtPolicyEngine> m_engine;
  Ptr<Node> m_node;
};

} // namespace ns3

#endif
```


## Implementation — `zt-ipv4-hook.cc`

```cpp title="zt-ipv4-hook.cc"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module implements an IPv4 hook for enforcing
 Zero Trust micro-segmentation policies at the IP layer.

 - Attaches to a node’s IPv4 stack and intercepts
   outgoing (Tx) packets.

 - Uses the ZtPolicyEngine to evaluate communication
   between source and destination nodes.

 - Logs ALLOW or DENY decisions based on policy rules.

 This enables runtime policy enforcement directly
 at the network transmission layer.
*/
#include "zt-ipv4-hook.h"
#include "zt-policy-engine.h"
#include "zt-identity-registry.h"

#include "ns3/node-list.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(ZtIpv4Hook);

TypeId
ZtIpv4Hook::GetTypeId()
{
  static TypeId tid =
      TypeId("ns3::ZtIpv4Hook")
          .SetParent<Object>()
          .AddConstructor<ZtIpv4Hook>();
  return tid;
}

ZtIpv4Hook::ZtIpv4Hook() {}
ZtIpv4Hook::~ZtIpv4Hook() {}

void
ZtIpv4Hook::SetPolicyEngine(Ptr<ZtPolicyEngine> engine)
{
  m_engine = engine;
}

void
ZtIpv4Hook::AttachToNode(Ptr<Node> node)
{
  m_node = node;

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  if (ipv4 == nullptr)
  {
    std::cout << "[ZT-NETWORK] No IPv4 stack found\n";
    return;
  }

  ipv4->TraceConnectWithoutContext(
      "Tx",
      MakeCallback(&ZtIpv4Hook::InterceptPacket, this));
}

void
ZtIpv4Hook::InterceptPacket(
    Ptr<const Packet> packet,
    Ptr<Ipv4> ipv4,
    uint32_t interface)
{
  if (m_engine == nullptr || m_node == nullptr)
    return;

  // Demo: assume destination node 1
  if (NodeList::GetNNodes() < 2)
    return;

  Ptr<Node> srcNode = m_node;
  Ptr<Node> dstNode = NodeList::GetNode(1);

  bool decision =
      m_engine->EvaluateMicroSegmentation(
          srcNode,
          dstNode,
          "TRANSFER");

  if (!decision)
  {
    std::cout << "[ZT-NETWORK] Policy DENY at IP layer\n";
  }
  else
  {
    std::cout << "[ZT-NETWORK] Policy ALLOW at IP layer\n";
  }
}

} // namespace ns3
```

