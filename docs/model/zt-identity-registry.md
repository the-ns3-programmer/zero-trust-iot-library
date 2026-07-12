# Identity Registry

A process-wide singleton mapping `ns3::Node` to its assigned role and a SHA-256 identity hash (via [`ComputeSha256`](zt-hash-utils.md)). [`ZtPolicyEngine`](zt-policy-engine.md) consults this registry to resolve roles for micro-segmentation decisions.

**Depends on:** [`Hash Utilities`](zt-hash-utils.md)

**Used in examples:** [Micro-Segmentation Test](../examples/micro-segmentation-test.md)

## API summary

**`IdentityRegistry`**

| Member | Description |
|---|---|
| `GetInstance()` | Returns the single process-wide registry instance. |
| `RegisterNode(node, role)` | Registers a node's role and derives its identity hash. |
| `GetIdentityHash(node)` | Returns the stored SHA-256 identity hash for a node. |
| `GetRole(node)` | Returns the stored role string for a node. |

## Header — `zt-identity-registry.h`

```cpp title="zt-identity-registry.h"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header defines the IdentityRegistry class used for
 managing node identities in a Zero Trust network.

 - Implements a singleton pattern to ensure a single
   centralized identity registry.

 - Stores mapping of node ID to:
     (assigned role, SHA-256 identity hash).

 - Provides functions to register nodes and retrieve
   their role or identity hash.

 This supports secure identity verification and
 role-based access enforcement.
*/
#ifndef IDENTITY_REGISTRY_H
#define IDENTITY_REGISTRY_H

#include <map>
#include <string>
#include "ns3/node.h"

namespace ns3 {

class IdentityRegistry
{
public:
  static IdentityRegistry& GetInstance();

  void RegisterNode(Ptr<Node> node, const std::string& role);

  std::string GetIdentityHash(Ptr<Node> node) const;
  std::string GetRole(Ptr<Node> node) const;

private:
  IdentityRegistry() {}

  // nodeId -> (role, identityHash)
  std::map<uint32_t, std::pair<std::string, std::string>> m_identityMap;
};

}

#endif
```


## Implementation — `zt-identity-registry.cc`

```cpp title="zt-identity-registry.cc"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module implements a singleton Identity Registry used
 to manage node identities in the Zero Trust architecture.

 - GetInstance():
   Provides a single global instance of the registry.

 - RegisterNode():
   Registers a node with its role and generates a SHA-256
   identity hash based on node ID and role.

 - GetIdentityHash():
   Retrieves the stored identity hash for a node.

 - GetRole():
   Retrieves the assigned role of a node.

 This enables secure identity tracking and role-based
 validation within the network.
*/
#include "zt-identity-registry.h"
#include "zt-hash-utils.h"

namespace ns3 {

IdentityRegistry&
IdentityRegistry::GetInstance()
{
  static IdentityRegistry instance;
  return instance;
}

void
IdentityRegistry::RegisterNode(Ptr<Node> node, const std::string& role)
{
  std::string input = std::to_string(node->GetId()) + role;
  std::string hash = ComputeSha256(input);

  m_identityMap[node->GetId()] = {role, hash};
}

std::string
IdentityRegistry::GetIdentityHash(Ptr<Node> node) const
{
  auto it = m_identityMap.find(node->GetId());
  if (it != m_identityMap.end())
    return it->second.second;

  return "";
}

std::string
IdentityRegistry::GetRole(Ptr<Node> node) const
{
  auto it = m_identityMap.find(node->GetId());
  if (it != m_identityMap.end())
    return it->second.first;

  return "";
}

} // namespace ns3
```

