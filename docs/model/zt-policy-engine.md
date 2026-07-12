# Policy Engine

The central Zero Trust decision point. It combines identity-based authorization, certificate validation (delegating signature checks the same way [`zt-certificate`](zt-certificate.md) does), revocation, and a **micro-segmentation** extension: role-to-role rules with time-of-day windows and rate limits, evaluated through [`IdentityRegistry`](zt-identity-registry.md) and fingerprinted with [`ComputeSha256`](zt-hash-utils.md). Every decision that is not explicitly allowed defaults to **DENY** (least privilege).

**Depends on:** [`Identity Registry`](zt-identity-registry.md), [`Hash Utilities`](zt-hash-utils.md)

**Used in examples:** [Man-in-the-Middle: Attack & Mitigation](../examples/mitm.md), [Identity Spoofing: Attack & Mitigation](../examples/spoofing.md), [Unauthorized Access: Attack & Mitigation](../examples/unauthorized-access.md), [Context Drift Test](../examples/context-drift-test.md), [Micro-Segmentation Test](../examples/micro-segmentation-test.md)

## API summary

**`ZtPolicyEngine`**

| Member | Description |
|---|---|
| `AddAuthorized(nodeId, role)` | Registers a node/role pair as authorized. |
| `Authorize(nodeId, role)` | Simple identity-based authorization check. |
| `SetCaPublicKey(pub)` | Registers the CA public key for certificate-based checks. |
| `Revoke(nodeId)` | Revokes a node, blocking all further authorization for it. |
| `AuthorizeWithCert(nodeId, role, certStr)` | Certificate-based authorization (signature, identity, expiry, revocation). |
| `AddRolePolicyRule(rule)` | Adds a `RolePolicyRule` (src role, dst role, action, time window, rate limit, ALLOW/DENY) and bumps the policy version. |
| `EvaluateMicroSegmentation(srcNode, dstNode, action)` | Resolves roles via `IdentityRegistry`, matches rules, checks time window and rate limit, computes the Ψ fingerprint, and returns ALLOW/DENY. |
| `GetPolicyVersion()` | Returns how many rules have been added (a monotonically increasing version counter). |
| `GetPolicyIntegrityHash()` | Returns a SHA-256 fingerprint over the full rule set, for tamper detection. |

## Header — `zt-policy-engine.h`

```cpp title="zt-policy-engine.h"
#ifndef ZT_POLICY_ENGINE_H
#define ZT_POLICY_ENGINE_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include <ns3/object.h>
#include <ns3/node.h>

#include <cryptopp/rsa.h>

using namespace CryptoPP;

namespace ns3 {

/**
 * \ingroup zerotrust
 * \brief Zero Trust Policy Engine with:
 * - Identity-based authorization
 * - Certificate validation
 * - Revocation support
 * - Micro-segmentation (custom extension)
 */
class ZtPolicyEngine : public Object
{
public:
  static TypeId GetTypeId();

  ZtPolicyEngine();
  virtual ~ZtPolicyEngine();

  /* =====================================================
     EXISTING FUNCTIONALITY (DO NOT MODIFY)
  ===================================================== */

  void AddAuthorized(uint32_t nodeId, const std::string& role);

  bool Authorize(uint32_t nodeId, const std::string& role);

  void SetCaPublicKey(RSA::PublicKey pub);

  void Revoke(uint32_t nodeId);

  bool AuthorizeWithCert(uint32_t nodeId,
                         const std::string& role,
                         const std::string& certStr);

  /* =====================================================
     NEW: MICRO-SEGMENTATION EXTENSION
  ===================================================== */

  enum RuleEffect
  {
    ALLOW = 0,
    DENY  = 1
  };

  struct RolePolicyRule
  {
    std::string srcRole;
    std::string dstRole;
    std::string action;

    uint32_t startHour;
    uint32_t endHour;

    uint32_t windowSeconds;
    uint32_t maxTransfers;

    RuleEffect effect;
  };

  void AddRolePolicyRule(const RolePolicyRule& rule);

  bool EvaluateMicroSegmentation(
      Ptr<Node> srcNode,
      Ptr<Node> dstNode,
      const std::string& action);

  uint32_t GetPolicyVersion() const;

  std::string GetPolicyIntegrityHash() const;

private:
  /* ================= EXISTING ================= */
  std::unordered_map<uint32_t, std::string> authTable;
  std::unordered_set<uint32_t> revoke;
  RSA::PublicKey caPublicKey;

  /* ================= NEW ================= */
  bool IsWithinTime(uint32_t startHour,
                    uint32_t endHour);

  uint32_t GetBehaviorState(uint32_t nodeId,
                           uint32_t windowSeconds);

private:
  /* ================= NEW STORAGE ================= */
  std::vector<RolePolicyRule> m_rules;

  std::map<uint32_t, std::vector<uint64_t>> m_transferHistory;

  uint32_t m_policyVersion;
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H
```


## Implementation — `zt-policy-engine.cc`

```cpp title="zt-policy-engine.cc"


// === zt-policy-engine.cc ===
#include "zt-policy-engine.h"
#include "zt-identity-registry.h"
#include "zt-hash-utils.h"

#include <ns3/log.h>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <iostream>

// Crypto++
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ZtPolicyEngine");
NS_OBJECT_ENSURE_REGISTERED(ZtPolicyEngine);

// ===================== TypeId =====================
TypeId ZtPolicyEngine::GetTypeId() {
  static TypeId tid = TypeId("ZtPolicyEngine")
    .SetParent<Object>()
    .SetGroupName("ZeroTrust")
    .AddConstructor<ZtPolicyEngine>();
  return tid;
}

// ===================== Constructor =====================
ZtPolicyEngine::ZtPolicyEngine()
  : m_policyVersion(0)
{
}

// ===================== Destructor (ADDED FIX) =====================
ZtPolicyEngine::~ZtPolicyEngine()
{
}

// ===================== BASIC AUTH =====================
void ZtPolicyEngine::AddAuthorized(uint32_t nodeId, const std::string& role) {
  authTable[nodeId] = role;
}

bool ZtPolicyEngine::Authorize(uint32_t nodeId, const std::string& role) {
  return authTable.find(nodeId) != authTable.end() &&
         authTable[nodeId] == role;
}

// ===================== CERTIFICATE =====================
void ZtPolicyEngine::SetCaPublicKey(RSA::PublicKey pub) {
  caPublicKey = pub;
}

void ZtPolicyEngine::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

bool ZtPolicyEngine::AuthorizeWithCert(uint32_t nodeId,
                                       const std::string& role,
                                       const std::string& certStr) {
  if (revoke.find(nodeId) != revoke.end()) {
    NS_LOG_UNCOND("ZT-CERT: Node " << nodeId << " is revoked");
    return false;
  }

  std::string content, sig;
  size_t sigPos = certStr.find("|SIG:");
  if (sigPos == std::string::npos) return false;

  content = certStr.substr(0, sigPos);
  sig = certStr.substr(sigPos + 5);

  std::string decodedSig;
  CryptoPP::StringSource(sig, true,
    new CryptoPP::Base64Decoder(
      new CryptoPP::StringSink(decodedSig)));

  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA1>::Verifier verifier(caPublicKey);

  bool valid = false;
  CryptoPP::StringSource(decodedSig + content, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier,
      new CryptoPP::ArraySink((byte*)&valid, sizeof(valid)),
      CryptoPP::SignatureVerificationFilter::PUT_RESULT |
      CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN));

  if (!valid) {
    NS_LOG_UNCOND("ZT-CERT: Signature invalid");
    return false;
  }

  std::istringstream ss(content);
  std::string token;
  uint32_t idParsed = 0;
  std::string roleParsed;
  time_t expiry = 0;

  while (std::getline(ss, token, '|')) {
    if (token.find("ID:") == 0)
      idParsed = std::stoul(token.substr(3));
    else if (token.find("ROLE:") == 0)
      roleParsed = token.substr(5);
    else if (token.find("EXP:") == 0)
      expiry = std::stol(token.substr(4));
  }

  if (idParsed != nodeId || roleParsed != role) {
    NS_LOG_UNCOND("ZT-CERT: Identity mismatch");
    return false;
  }

  if (std::time(nullptr) > expiry) {
    NS_LOG_UNCOND("ZT-CERT: Certificate expired");
    return false;
  }

  return true;
}

// ===================== MICRO-SEGMENTATION =====================

// Add rule
void ZtPolicyEngine::AddRolePolicyRule(const RolePolicyRule& rule) {
  m_rules.push_back(rule);
  m_policyVersion++;

  std::cout << "[POLICY] Rule Added. Version: "
            << m_policyVersion << "\n";
}

// Time check
bool ZtPolicyEngine::IsWithinTime(uint32_t startHour,
                                 uint32_t endHour) {
  std::time_t now = std::time(nullptr);
  std::tm* local = std::localtime(&now);
  uint32_t hour = local->tm_hour;

  return (hour >= startHour && hour < endHour);
}

// Behavior tracking
uint32_t ZtPolicyEngine::GetBehaviorState(uint32_t nodeId,
                                          uint32_t windowSeconds) {
  uint64_t now = std::time(nullptr);
  auto& history = m_transferHistory[nodeId];

  history.erase(
    std::remove_if(history.begin(), history.end(),
      [&](uint64_t t) { return now - t > windowSeconds; }),
    history.end());

  return history.size();
}

// Core evaluation
bool ZtPolicyEngine::EvaluateMicroSegmentation(
    Ptr<Node> srcNode,
    Ptr<Node> dstNode,
    const std::string& action) {

  if (!srcNode || !dstNode) {
    std::cout << "[MICRO-SEG] Invalid Node Pointer\n";
    return false;
  }

  IdentityRegistry& registry =
      IdentityRegistry::GetInstance();

  std::string Hs = registry.GetIdentityHash(srcNode);
  std::string Hd = registry.GetIdentityHash(dstNode);

  std::string srcRole = registry.GetRole(srcNode);
  std::string dstRole = registry.GetRole(dstNode);

  uint32_t nodeId = srcNode->GetId();

  std::time_t now = std::time(nullptr);
  std::tm* local = std::localtime(&now);
  uint32_t currentHour = local->tm_hour;

  for (const auto& rule : m_rules) {
    if (rule.srcRole == srcRole &&
        rule.dstRole == dstRole &&
        (rule.action == action || rule.action == "*")) {

      if (!IsWithinTime(rule.startHour, rule.endHour))
        continue;

      uint32_t transferCount =
          GetBehaviorState(nodeId, rule.windowSeconds);

      uint32_t behaviorState =
          (transferCount <= rule.maxTransfers) ? 0 : 1;

      std::string S =
          Hs + Hd +
          action +
          std::to_string(currentHour) +
          rule.srcRole +
          rule.dstRole +
          std::to_string(behaviorState);

      std::string Psi = ns3::ComputeSha256(S);

      std::cout << "[MICRO-SEG] Ψ: " << Psi << "\n";

      if (behaviorState == 0 &&
          rule.effect == ALLOW) {

        if (action == "TRANSFER" || action == "WITHDRAW") {
          m_transferHistory[nodeId].push_back(now);
        }

        return true;
      }

      if (rule.effect == DENY) {
        return false;
      }
    }
  }

  std::cout << "[MICRO-SEG] Default DENY (Least Privilege)\n";
  return false;
}

// ===================== POLICY INTEGRITY =====================
uint32_t ZtPolicyEngine::GetPolicyVersion() const {
  return m_policyVersion;
}

std::string ZtPolicyEngine::GetPolicyIntegrityHash() const {
  std::stringstream ss;

  ss << m_policyVersion;

  for (const auto& rule : m_rules) {
    ss << rule.srcRole
       << rule.dstRole
       << rule.action
       << rule.startHour
       << rule.endHour
       << rule.windowSeconds
       << rule.maxTransfers
       << rule.effect;
  }

  return ns3::ComputeSha256(ss.str());
}

} // namespace ns3
```

