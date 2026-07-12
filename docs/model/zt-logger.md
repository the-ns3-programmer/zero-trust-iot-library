# Logger

A small static logging façade used across every module so that certificate, encryption, and general Zero Trust events share one consistent, optionally timestamped log format.

**Used in examples:** [Man-in-the-Middle: Attack & Mitigation](../examples/mitm.md), [Identity Spoofing: Attack & Mitigation](../examples/spoofing.md), [Unauthorized Access: Attack & Mitigation](../examples/unauthorized-access.md), [Context Drift Test](../examples/context-drift-test.md), [Dynamic Trust Scorer Test](../examples/trust-scorer-test.md)

## API summary

**`ZtLogger`**

| Member | Description |
|---|---|
| `EnableTimestamps(enable)` | Turns timestamp prefixes on or off for all subsequent log lines. |
| `Log(tag, message)` | Generic tagged log line. |
| `LogCertIssued(nodeId, role, expiry)` | Logs a certificate issuance event. |
| `LogCertValidationResult(nodeId, valid)` | Logs the outcome of a certificate validation. |
| `LogCertRevoked(nodeId)` | Logs a certificate revocation. |
| `LogCertRejected(reason)` | Logs a rejected certificate attempt with a reason string. |
| `LogEncryption(payload, ivHex)` | Logs an encryption event including the IV. |
| `LogDecryption(payload)` | Logs a successful decryption. |
| `LogDecryptionFailure()` | Logs a failed decryption attempt. |

## Header — `zt-logger.h`

```cpp title="zt-logger.h"

#ifndef ZT_LOGGER_H
#define ZT_LOGGER_H

#include <string>
#include <ctime>
#include <cstdint>

/**
 * \class ZtLogger
 * \brief Logging utility for Zero Trust simulation modules in NS-3.
 *
 * Provides logging functions for general events, certificate-related events,
 * and encryption/decryption actions. Supports optional timestamps.
 */
class ZtLogger {
public:
  /**
   * \brief Enables or disables timestamp logging.
   * \param enable True to include timestamps in logs, false to omit them.
   */
  static void EnableTimestamps(bool enable);

  /**
   * \brief Logs a general message with a specified tag.
   * \param tag Context label (e.g., "INFO", "ERROR").
   * \param message The message content.
   */
  static void Log(const std::string &tag, const std::string &message);

  /**
   * \brief Logs a certificate issuance event.
   * \param nodeId ID of the node receiving the certificate.
   * \param role Assigned role for the node.
   * \param expiry Expiry time of the certificate.
   */
  static void LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry);

  /**
   * \brief Logs the result of certificate validation.
   * \param nodeId ID of the node whose certificate was validated.
   * \param valid True if the certificate is valid, false otherwise.
   */
  static void LogCertValidationResult(uint32_t nodeId, bool valid);

  /**
   * \brief Logs a certificate revocation event.
   * \param nodeId ID of the node whose certificate was revoked.
   */
  static void LogCertRevoked(uint32_t nodeId);

  /**
   * \brief Logs a rejected certificate attempt with a reason.
   * \param reason Description of the rejection cause.
   */
  static void LogCertRejected(const std::string &reason);

  /**
   * \brief Logs an encryption event with payload and IV.
   * \param payload The encrypted data.
   * \param ivHex Initialization Vector in hex string format.
   */
  static void LogEncryption(const std::string &payload, const std::string &ivHex);

  /**
   * \brief Logs a successful decryption event.
   * \param payload The decrypted plaintext data.
   */
  static void LogDecryption(const std::string &payload);

  /**
   * \brief Logs a decryption failure event.
   */
  static void LogDecryptionFailure();

private:
  static bool timestampsEnabled; ///< Flag to indicate if timestamps are enabled in logs.
};

#endif // ZT_LOGGER_H
```


## Implementation — `zt-logger.cc`

```cpp title="zt-logger.cc"

#include "zt-logger.h"
#include <ns3/core-module.h>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace ns3;

/// Static flag to control timestamp display
bool ZtLogger::timestampsEnabled = true;

/**
 * \brief Enables or disables timestamps in log messages.
 * \param enable If true, timestamps will be included in logs.
 */
void ZtLogger::EnableTimestamps(bool enable) {
  timestampsEnabled = enable;
}

/**
 * \brief Logs a message with a given tag and optional timestamp.
 * \param tag A short string indicating the type or source of the message.
 * \param message The actual log message content.
 */
void ZtLogger::Log(const std::string &tag, const std::string &message) {
  std::ostringstream output;

  if (timestampsEnabled) {
    std::time_t now = std::time(nullptr);
    std::tm *lt = std::localtime(&now);
    output << "[" << std::put_time(lt, "%H:%M:%S") << "] ";
  }

  output << "[" << tag << "] " << message;
  NS_LOG_UNCOND(output.str());
}

// === Certificate Logs ===

/**
 * \brief Logs the issuance of a certificate.
 * \param nodeId The ID of the node receiving the certificate.
 * \param role The assigned role in the certificate.
 * \param expiry The expiration time of the certificate.
 */
void ZtLogger::LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry) {
  std::ostringstream msg;
  msg << "Issued certificate to Node " << nodeId << " | Role: " << role
      << " | Expiry: " << expiry;
  Log("ZT-CERT", msg.str());
}

/**
 * \brief Logs the result of a certificate validation attempt.
 * \param nodeId The node whose certificate was validated.
 * \param valid True if the certificate is valid, false otherwise.
 */
void ZtLogger::LogCertValidationResult(uint32_t nodeId, bool valid) {
  Log("ZT-CERT", "Validation for Node " + std::to_string(nodeId) +
      (valid ? ": VALID" : ": INVALID"));
}

/**
 * \brief Logs the revocation of a certificate.
 * \param nodeId The ID of the node whose certificate was revoked.
 */
void ZtLogger::LogCertRevoked(uint32_t nodeId) {
  Log("ZT-CERT", "Node " + std::to_string(nodeId) + " certificate revoked");
}

/**
 * \brief Logs a rejection reason for a certificate.
 * \param reason The explanation for why the certificate was rejected.
 */
void ZtLogger::LogCertRejected(const std::string &reason) {
  Log("ZT-CERT", "Certificate rejected: " + reason);
}

// === Encryption Logs ===

/**
 * \brief Logs encryption activity with IV and encrypted data.
 * \param payload The encrypted data in hex or readable format.
 * \param ivHex The IV used during encryption, in hex format.
 */
void ZtLogger::LogEncryption(const std::string &payload, const std::string &ivHex) {
  Log("ZT-ENC", "Payload encrypted | IV: " + ivHex + " | Data: " + payload);
}

/**
 * \brief Logs a successful decryption result.
 * \param payload The decrypted plaintext.
 */
void ZtLogger::LogDecryption(const std::string &payload) {
  Log("ZT-DEC", "Decrypted Payload: " + payload);
}

/**
 * \brief Logs a failure during decryption due to invalid session or corrupted data.
 */
void ZtLogger::LogDecryptionFailure() {
  Log("ZT-DEC", "Decryption failed: Invalid session or corrupt data");
}
```

