# Hash Utilities

A single free function, `ComputeSha256`, that returns the hex-encoded SHA-256 digest of a string. Used for identity hashing in [`IdentityRegistry`](zt-identity-registry.md) and for the micro-segmentation policy fingerprint (Ψ) and policy-integrity hash in [`ZtPolicyEngine`](zt-policy-engine.md).

## API summary

**`Free functions`**

| Member | Description |
|---|---|
| `ComputeSha256(input)` | Returns the SHA-256 digest of `input` as a lowercase hex string. |

## Header — `zt-hash-utils.h`

```cpp title="zt-hash-utils.h"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header declares the SHA-256 hashing utility function
 used for data integrity and security verification.

 - ComputeSha256():
   Computes and returns the SHA-256 hash of an input string
   as a hexadecimal-encoded digest.

 This function supports secure identity validation and
 integrity checking in the system.
*/
#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <string>

namespace ns3 {

std::string ComputeSha256(const std::string& input);

}

#endif
```


## Implementation — `zt-hash-utils.cc`

```cpp title="zt-hash-utils.cc"
/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This module provides a utility function to compute the SHA-256
 hash of a given input string using the Crypto++ library.

 - ComputeSha256():
   Generates a SHA-256 digest of the input data and returns
   it as a hexadecimal-encoded string.

 This is typically used for data integrity verification,
 authentication, or secure identity validation.
*/
#include "zt-hash-utils.h"

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

namespace ns3 {

std::string
ComputeSha256(const std::string& input)
{
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(
        input,
        true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest),
                false
            )
        )
    );

    return digest;
}

}
```

