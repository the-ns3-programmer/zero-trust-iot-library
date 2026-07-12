# TLS Handshake

Simulates a Zero Trust TLS-style handshake between two ns-3 nodes. Before any key is generated it runs both peers through an injected policy validator function (normally backed by [`ZtPolicyEngine::Authorize`](zt-policy-engine.md)); only if both sides pass does it generate a shared AES session key (via Crypto++), store it per node ID, and log the event through an injectable logger or [`ZtLogger`](zt-logger.md) fallback.

**Used in examples:** [Man-in-the-Middle: Attack & Mitigation](../examples/mitm.md), [Identity Spoofing: Attack & Mitigation](../examples/spoofing.md), [Unauthorized Access: Attack & Mitigation](../examples/unauthorized-access.md)

## API summary

**`ZtTlsHandshake`**

| Member | Description |
|---|---|
| `StartHandshake(client, server, clientId, serverId)` | Validates both peers against the policy validator, then generates and stores a shared AES session key. |
| `HasSession(peerId)` | Returns whether a session key exists for a peer. |
| `GetSessionKey(peerId)` | Returns the hex-encoded session key for a peer. |
| `SetExternalLogger(logger)` | Injects a custom logging function. |
| `SetPolicyValidator(validator)` | Injects the `(nodeId, role) -> bool` authorization callback. |

## Header — `zt-tls-handshake.h`

```cpp title="zt-tls-handshake.h"


#ifndef ZT_TLS_HANDSHAKE_H
#define ZT_TLS_HANDSHAKE_H

#include "ns3/object.h"
#include "ns3/node.h"
#include <map>
#include <string>
#include <functional>

namespace ns3 {

/**
 * \ingroup zerotrust
 * \class ZtTlsHandshake
 * \brief Simulates a Zero Trust-based TLS handshake mechanism between NS-3 nodes.
 *
 * This class is responsible for performing identity-validated TLS-like handshakes
 * between IoT nodes, establishing symmetric session keys, and enforcing policy-based
 * authentication using injected policy validation logic.
 */
class ZtTlsHandshake : public Object {
public:
  /**
   * \brief Get the NS-3 TypeId.
   * \return TypeId of the ZtTlsHandshake class.
   */
  static TypeId GetTypeId();

  /**
   * \brief Constructor.
   */
  ZtTlsHandshake();

  /**
   * \brief Start a simulated TLS handshake between client and server nodes.
   *
   * Performs mutual policy validation and generates a symmetric session key
   * shared by both nodes.
   *
   * \param client Pointer to the client node.
   * \param server Pointer to the server node.
   * \param clientId Unique identifier for the client node.
   * \param serverId Unique identifier for the server node.
   */
  void StartHandshake(Ptr<Node> client, Ptr<Node> server, uint32_t clientId, uint32_t serverId);

  /**
   * \brief Check if a session exists for a given peer.
   * \param peerId Node ID of the peer.
   * \return true if a session exists, false otherwise.
   */
  bool HasSession(uint32_t peerId) const;

  /**
   * \brief Retrieve the session key for a peer in hexadecimal string format.
   * \param peerId Node ID of the peer.
   * \return Hex-encoded session key if it exists, empty string otherwise.
   */
  std::string GetSessionKey(uint32_t peerId) const;

  /**
   * \brief Set an external logger for emitting TLS logs.
   * \param logger Function accepting a string message.
   */
  void SetExternalLogger(std::function<void(std::string)> logger);

  /**
   * \brief Set a policy validator for enforcing Zero Trust identity checks.
   * \param validator Function taking node ID and role string, returns true if authorized.
   */
  void SetPolicyValidator(std::function<bool(uint32_t, std::string)> validator);

private:
  /**
   * \brief Emit a log message using the external logger or NS_LOG fallback.
   * \param msg The message to log.
   */
  void Log(const std::string& msg) const;

  std::map<uint32_t, std::string> m_sessionKeys;               //!< Maps node IDs to session keys.
  std::function<void(std::string)> m_logger;                   //!< Optional external logger.
  std::function<bool(uint32_t, std::string)> m_policyValidator; //!< Optional external policy validator.
};

} // namespace ns3

#endif // ZT_TLS_HANDSHAKE_H
```


## Implementation — `zt-tls-handshake.cc`

```cpp title="zt-tls-handshake.cc"


#include "zt-tls-handshake.h"
#include "ns3/log.h"
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ZtTlsHandshake");

/*
 * \brief Get the ns-3 TypeId for ZtTlsHandshake
 * \return The TypeId
 */
TypeId ZtTlsHandshake::GetTypeId() {
  static TypeId tid = TypeId("ns3::ZtTlsHandshake")
    .SetParent<Object>()
    .SetGroupName("ZeroTrust")
    .AddConstructor<ZtTlsHandshake>();
  return tid;
}

/**
 * \brief Constructor
 */
ZtTlsHandshake::ZtTlsHandshake() {
  NS_LOG_FUNCTION(this);
}

/**
 * \brief Start a simulated handshake between client and server.
 * 
 * \param client Pointer to the client Node
 * \param server Pointer to the server Node
 * \param clientId ID of the client node
 * \param serverId ID of the server node
 */
void ZtTlsHandshake::StartHandshake(Ptr<Node> client, Ptr<Node> server, uint32_t clientId, uint32_t serverId) {
  NS_LOG_FUNCTION(this << client << server);

  if (m_policyValidator && !m_policyValidator(clientId, "client")) {
    Log("[ZT-HANDSHAKE] Client not authorized by policy");
    return;
  }

  if (m_policyValidator && !m_policyValidator(serverId, "server")) {
    Log("[ZT-HANDSHAKE] Server not authorized by policy");
    return;
  }

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  std::string encoded;
  CryptoPP::StringSource ss(key, sizeof(key), true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));

  m_sessionKeys[serverId] = encoded;
  m_sessionKeys[clientId] = encoded;

  Log("[ZT-HANDSHAKE] Session established between Client " + std::to_string(clientId) +
      " and Server " + std::to_string(serverId) + " | Key: " + encoded);
}

/**
 * \brief Check if a session key exists for a peer
 * 
 * \param peerId Node ID of the peer
 * \return True if session exists, otherwise false
 */
bool ZtTlsHandshake::HasSession(uint32_t peerId) const {
  return m_sessionKeys.find(peerId) != m_sessionKeys.end();
}

/**
 * \brief Retrieve session key for a given peer
 * 
 * \param peerId Node ID of the peer
 * \return Hex-encoded session key, or empty string if not found
 */
std::string ZtTlsHandshake::GetSessionKey(uint32_t peerId) const {
  auto it = m_sessionKeys.find(peerId);
  return (it != m_sessionKeys.end()) ? it->second : "";
}

/**
 * \brief Set external logging function
 * 
 * \param logger Function to be used for logging
 */
void ZtTlsHandshake::SetExternalLogger(std::function<void(std::string)> logger) {
  m_logger = logger;
}

/**
 * \brief Set policy validation function for authorization
 * 
 * \param validator Function that validates (nodeId, role)
 */
void ZtTlsHandshake::SetPolicyValidator(std::function<bool(uint32_t, std::string)> validator) {
  m_policyValidator = validator;
}

/**
 * \brief Internal logging wrapper
 * 
 * \param msg Log message
 */
void ZtTlsHandshake::Log(const std::string& msg) const {
  if (m_logger) {
    m_logger(msg);
  } else {
    NS_LOG_INFO(msg);
  }
}

} // namespace ns3
```

