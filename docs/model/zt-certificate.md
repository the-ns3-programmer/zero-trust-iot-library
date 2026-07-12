# Certificate Authority & Certificate-Based Policy

Simulates a lightweight X.509-style Certificate Authority (CA) for the Zero Trust fabric. `CertificateAuthority` generates an RSA key pair and signs identity certificates that bind a node ID, role, and expiry time. `ZtPolicyEngineWithCert` is a companion policy engine that verifies those signatures, checks expiry, and honours a revocation list before granting access — a certificate-only alternative to the main [`ZtPolicyEngine`](zt-policy-engine.md).

**Used in examples:** [Man-in-the-Middle: Attack & Mitigation](../examples/mitm.md), [Identity Spoofing: Attack & Mitigation](../examples/spoofing.md), [Unauthorized Access: Attack & Mitigation](../examples/unauthorized-access.md)

## API summary

**`CertificateAuthority`**

| Member | Description |
|---|---|
| `CertificateAuthority()` | Generates a fresh 1024-bit RSA key pair for the CA. |
| `SignIdentity(nodeId, role, expiry)` | Signs `ID:.. | ROLE:.. | EXP:..` and returns the certificate string with a base64-encoded RSA-PSS signature. |
| `GetPublicKey()` | Returns the CA's public key so it can be distributed to verifiers. |

**`ZtPolicyEngineWithCert`**

| Member | Description |
|---|---|
| `SetCaPublicKey(pub)` | Registers the trusted CA public key used for signature verification. |
| `Revoke(nodeId)` | Adds a node ID to the revocation set. |
| `Authorize(nodeId, role, certStr)` | Verifies the signature, checks node ID/role match, expiry, and revocation status. |

## Header — `zt-certificate.h`

```cpp title="zt-certificate.h"

#ifndef ZT_CERTIFICATE_H
#define ZT_CERTIFICATE_H

#include <string>
#include <ctime>
#include <unordered_set>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>

/**
 * \class CertificateAuthority
 * \brief Simulates a Certificate Authority (CA) that issues and signs identity certificates.
 *
 * The CA generates a public-private RSA key pair and uses it to sign certificates
 * for nodes, which include identity, role, and expiry information.
 */
class CertificateAuthority {
public:
  /**
   * \brief Constructor that initializes and generates RSA key pair.
   */
  CertificateAuthority();

  /**
   * \brief Signs an identity certificate with node ID, role, and expiry.
   * \param nodeId The unique identifier of the node.
   * \param role The assigned role of the node (e.g., "sensor", "gateway").
   * \param expiry Expiry timestamp for the certificate.
   * \return A signed certificate string in plain format with a base64-encoded signature.
   */
  std::string SignIdentity(uint32_t nodeId, const std::string& role, time_t expiry);

  /**
   * \brief Retrieves the public RSA key of the CA.
   * \return The public key corresponding to the CA's private key.
   */
  CryptoPP::RSA::PublicKey GetPublicKey() const;

private:
  CryptoPP::RSA::PrivateKey privateKey; ///< RSA private key used for signing certificates.
  CryptoPP::RSA::PublicKey publicKey;   ///< RSA public key distributed for verification.
};

/**
 * \class ZtPolicyEngineWithCert
 * \brief Simulates a Zero Trust policy engine that enforces access control using certificates.
 *
 * This engine validates node certificates, verifies digital signatures, checks role and expiry,
 * and maintains a list of revoked node IDs.
 */
class ZtPolicyEngineWithCert {
public:
  /**
   * \brief Sets the CA's public key used for certificate verification.
   * \param pub The public RSA key of the trusted Certificate Authority.
   */
  void SetCaPublicKey(CryptoPP::RSA::PublicKey pub);

  /**
   * \brief Revokes a node by its ID, preventing it from being authorized.
   * \param nodeId The node ID to be added to the revocation list.
   */
  void Revoke(uint32_t nodeId);

  /**
   * \brief Authorizes a node based on its certificate.
   * \param nodeId The node's claimed ID.
   * \param role The role the node claims to perform.
   * \param certStr The certificate string presented by the node.
   * \return True if the certificate is valid, not expired, matches the node, and not revoked.
   */
  bool Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  CryptoPP::RSA::PublicKey caPublicKey; ///< Trusted public key used for signature verification.
  std::unordered_set<uint32_t> revoke;  ///< Set of node IDs that are explicitly revoked.
};

#endif // ZT_CERTIFICATE_H
```


## Implementation — `zt-certificate.cc`

```cpp title="zt-certificate.cc"

#include "zt-certificate.h"
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <sstream>
#include <ns3/core-module.h>

using namespace CryptoPP;

/**
 * \class CertificateAuthority
 * \brief Issues and signs certificates for Zero Trust identity validation.
 */
CertificateAuthority::CertificateAuthority() {
  AutoSeededRandomPool prng;
  privateKey.GenerateRandomWithKeySize(prng, 1024);
  publicKey = privateKey;
}

/**
 * \brief Signs a certificate with node ID, role, and expiry.
 * \param nodeId ID of the node requesting certificate
 * \param role Role assigned to the node (e.g., sensor, gateway)
 * \param expiry Expiry timestamp of the certificate
 * \return Signed certificate string with base64-encoded signature
 */
std::string CertificateAuthority::SignIdentity(uint32_t nodeId, const std::string& role, time_t expiry) {
  AutoSeededRandomPool prng;

  std::ostringstream cert;
  cert << "ID:" << nodeId << "|ROLE:" << role << "|EXP:" << expiry;

  RSASS<PSSR, SHA1>::Signer signer(privateKey);
  std::string signature;
  StringSource(cert.str(), true,
    new SignerFilter(prng, signer,
      new StringSink(signature)));

  std::string encodedSig;
  StringSource(signature, true,
    new Base64Encoder(new StringSink(encodedSig), false));

  return cert.str() + "|SIG:" + encodedSig;
}

/**
 * \brief Returns the public key of the Certificate Authority.
 * \return RSA public key
 */
RSA::PublicKey CertificateAuthority::GetPublicKey() const {
  return publicKey;
}

/**
 * \brief Sets the CA public key for the policy engine.
 * \param pub RSA public key of the certificate authority
 */
void ZtPolicyEngineWithCert::SetCaPublicKey(RSA::PublicKey pub) {
  caPublicKey = pub;
}

/**
 * \brief Revokes access for a specific node.
 * \param nodeId ID of the node to be revoked
 */
void ZtPolicyEngineWithCert::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

/**
 * \brief Verifies and authorizes a node based on its certificate.
 * \param nodeId ID of the node attempting access
 * \param role Role of the node
 * \param certStr Certificate string to validate
 * \return True if the certificate is valid and authorization succeeds
 */
bool ZtPolicyEngineWithCert::Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr) {
  using namespace ns3;

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
  StringSource(sig, true, new Base64Decoder(new StringSink(decodedSig)));

  RSASS<PSSR, SHA1>::Verifier verifier(caPublicKey);
  bool valid = false;
  StringSource(decodedSig + content, true,
    new SignatureVerificationFilter(verifier,
      new ArraySink((byte*)&valid, sizeof(valid)),
      SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_BEGIN));

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

  time_t now = std::time(nullptr);
  if (now > expiry) {
    NS_LOG_UNCOND("ZT-CERT: Certificate expired");
    return false;
  }

  return true;
}
```

