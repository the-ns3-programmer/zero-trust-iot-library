# Context Drift Validator

Implements continuous re-authorization: even after a node passes its initial handshake, its behavioural context (time of day, network congestion, physical/topological proximity) is compared against a stored baseline on every tick. `ContextAttributeStore` tracks the baseline and current context per node and turns the deviation into a decaying trust score. `PeriodicRevalidator` runs on a timer, recomputes drift for every active node, and calls [`ZtPolicyEngine::Revoke`](zt-policy-engine.md) the moment a node's trust falls under a configurable threshold.

**Depends on:** [`Policy Engine`](zt-policy-engine.md)

**Used in examples:** [Context Drift Test](../examples/context-drift-test.md)

## API summary

**`ContextAttributeStore`**

| Member | Description |
|---|---|
| `StoreBaseline(nodeId, timeOfDay, congestion, proximity)` | Captures the trusted baseline context for a node at onboarding time. |
| `UpdateCurrentContext(nodeId, timeOfDay, congestion, proximity)` | Records the node's most recent observed context. |
| `CalculateDrift(nodeId, wt, wc, wp)` | Weighted absolute deviation between current and baseline context. |
| `UpdateTrust(nodeId, drift, lambda)` | Applies exponential decay `trust *= e^(-lambda * drift)`. |
| `GetTrust(nodeId)` | Returns the node's current trust score (0 if unknown). |

**`PeriodicRevalidator`**

| Member | Description |
|---|---|
| `PeriodicRevalidator(policy, store)` | Binds a `ZtPolicyEngine*` and a `ContextAttributeStore*` (non-owning). |
| `SetParameters(wt, wc, wp, lambda, threshold)` | Configures drift weights, decay rate, and the revocation trust threshold. |
| `AddActiveNode(nodeId)` | Registers a node for periodic revalidation. |
| `Revalidate()` | Recomputes drift/trust for every active node and revokes nodes below the threshold. |

## Header — `zt-context-drift-validator.h`

```cpp title="zt-context-drift-validator.h"
// zt-context-drift-validator.h

/*
Authors: Rahul R, Dr. Subbulakshmi T, Arun Santhosh R A
Github id: Rahul2671
VIT Chennai, India
*/


/* 
The below code does the following:
Even after a node is authenticated and authorized successfully,
its access should NOT remain permanent. The node's operational
context is continuously monitored. If the context drifts too much
from the baseline captured during handshake, trust is gradually
reduced and access is revoked.
*/


#ifndef ZT_CONTEXT_DRIFT_VALIDATOR_H
#define ZT_CONTEXT_DRIFT_VALIDATOR_H

#include <map>
#include <set>
#include <cstdint>

#include "zt-policy-engine.h"   // MUST be here, before namespace

namespace ns3 {

/**
 * ============================================================
 * // Zero Trust Context Drift Validator
 * ============================================================
 */

/**
 * ============================================================
 * CLASS: ContextAttributeStore
 * ============================================================
 */
 
 // Stores baseline and runtime context of nodes

class ContextAttributeStore
{
public:

  void StoreBaseline(uint32_t nodeId,
                     double timeOfDay,
                     double congestion,
                     uint32_t proximity);

  void UpdateCurrentContext(uint32_t nodeId,
                            double timeOfDay,
                            double congestion,
                            uint32_t proximity);

  double CalculateDrift(uint32_t nodeId,
                      double wt,
                      double wc,
                      double wp) const;

  void UpdateTrust(uint32_t nodeId,
                   double drift,
                   double lambda);

  double GetTrust(uint32_t nodeId) const;

private:

  std::map<uint32_t, double> baselineTime;
  std::map<uint32_t, double> baselineCongestion;
  std::map<uint32_t, uint32_t> baselineProximity;

  std::map<uint32_t, double> currentTime;
  std::map<uint32_t, double> currentCongestion;
  std::map<uint32_t, uint32_t> currentProximity;

  std::map<uint32_t, double> trustScore;
};


/**
 * ============================================================
 * CLASS: PeriodicRevalidator
 * ============================================================
 */
 
 // Periodically evaluates node trust and revokes low-trust compromised nodes

class PeriodicRevalidator
{
public:

  PeriodicRevalidator(ZtPolicyEngine* policy,
                      ContextAttributeStore* store);

  void SetParameters(double wt,
                     double wc,
                     double wp,
                     double lambda,
                     double threshold);

  void AddActiveNode(uint32_t nodeId);

  void Revalidate();

private:

  ZtPolicyEngine* m_policy;
  ContextAttributeStore* m_store;
  // Non-owning pointers (lifetime managed externally)

  std::set<uint32_t> activeNodes;

  double WT = 0.0;
  double WC = 0.0;
  double WP = 0.0;
  double LAMBDA = 0.0;
  double TRUST_THRESHOLD = 0.0;
};

} // namespace ns3

#endif // ZT_CONTEXT_DRIFT_VALIDATOR_H
```


## Implementation — `zt-context-drift-validator.cc`

```cpp title="zt-context-drift-validator.cc"
// zt-context-drift-validator.cc

/*
Authors: Rahul R, Dr. Subbulakshmi T, Arun Santhosh R A
Github id: Rahul2671
VIT Chennai, India
*/


/* 
The below code does the following:
Even after a node is authenticated and authorized successfully,
its access should NOT remain permanent. The node's operational
context is continuously monitored. If the context drifts too much
from the baseline captured during handshake, trust is gradually
reduced and access is revoked.
*/


#include "zt-context-drift-validator.h"
#include "zt-policy-engine.h"

#include <cmath>
#include <iostream>

namespace ns3 {

/**
 * ============================================================
 * ContextAttributeStore IMPLEMENTATION
 * ============================================================
 */
 
 // Baseline operating context captured during node onboarding

void
ContextAttributeStore::StoreBaseline(uint32_t nodeId,
                                     double timeOfDay,
                                     double congestion,
                                     uint32_t proximity)
// Baseline captured when node is first authorized

{
  baselineTime[nodeId] = timeOfDay;
  baselineCongestion[nodeId] = congestion;
  baselineProximity[nodeId] = proximity;

  currentTime[nodeId] = timeOfDay;
  currentCongestion[nodeId] = congestion;
  currentProximity[nodeId] = proximity;

  trustScore[nodeId] = 1.0;
}

void
ContextAttributeStore::UpdateCurrentContext(uint32_t nodeId,
                                            double timeOfDay,
                                            double congestion,
                                            uint32_t proximity)
{
  currentTime[nodeId] = timeOfDay;
  currentCongestion[nodeId] = congestion;
  currentProximity[nodeId] = proximity;
}

double
ContextAttributeStore::CalculateDrift(uint32_t nodeId,
                                      double wt,
                                      double wc,
                                      double wp)

{
  // Time deviation
  double dt = std::abs(currentTime[nodeId] - baselineTime[nodeId]);
  // Network deviation
  double dc = std::abs(currentCongestion[nodeId] - baselineCongestion[nodeId]);
  // Location deviation
  double dp = std::abs((double)currentProximity[nodeId] -
                        (double)baselineProximity[nodeId]);

  return wt * dt + wc * dc + wp * dp;
}

void
ContextAttributeStore::UpdateTrust(uint32_t nodeId,
                                   double drift,
                                   double lambda)
{
  trustScore[nodeId] *= std::exp(-lambda * drift);

  if (trustScore[nodeId] < 0.0)
    trustScore[nodeId] = 0.0;
}

double
ContextAttributeStore::GetTrust(uint32_t nodeId) const
{
  auto it = trustScore.find(nodeId);
  if (it != trustScore.end())
    return it->second;

  return 0.0;
}

/**
 * ============================================================
 * PeriodicRevalidator IMPLEMENTATION
 * ============================================================
 */ 

PeriodicRevalidator::PeriodicRevalidator(ZtPolicyEngine* policy,
                                         ContextAttributeStore* store)
{
  m_policy = policy;
  m_store = store;
}

void
PeriodicRevalidator::SetParameters(double wt,
                                   double wc,
                                   double wp,
                                   double lambda,
                                   double threshold)
{
  WT = wt;
  WC = wc;
  WP = wp;
  LAMBDA = lambda;
  TRUST_THRESHOLD = threshold;
}

void
PeriodicRevalidator::AddActiveNode(uint32_t nodeId)
{
  activeNodes.insert(nodeId);
}

void
PeriodicRevalidator::Revalidate()
{
  for (auto nodeId : activeNodes)
  {
    double drift = m_store->CalculateDrift(nodeId, WT, WC, WP);

    m_store->UpdateTrust(nodeId, drift, LAMBDA);

    double trust = m_store->GetTrust(nodeId);

    std::cout << "[ZeroTrust] Node"
 << nodeId
              << " Drift=" << drift
              << " Trust=" << trust << std::endl;

    if (trust < TRUST_THRESHOLD)

      m_policy->Revoke(nodeId);

      std::cout << "[ZeroTrust] Node "
 << nodeId
                << " revoked due to low trust" << std::endl;
    }
  }
}

} 
```

