# Rsrp.Security.Core

Cryptographic primitives and post-quantum extensions for RSRP.

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

## Overview

Rsrp.Security.Core provides:
- **Modern signature algorithms** — Ed25519, RSA-PSS
- **Post-quantum cryptography** — Dilithium, Falcon, Kyber
- **Hybrid signatures** — Classical + PQ for long-term security
- **Key management abstraction** — HSM-ready interface
- **FIPS-aware RNG** — Compliant random number generation

## Why Post-Quantum?

Quantum computers will break RSA and ECDSA. Hybrid cryptography provides:
- **Immediate security** — Classical algorithms protect today
- **Future-proofing** — PQ algorithms survive quantum attacks
- **NIST compliance** — Standardized algorithms (2024)

## Quick Start

```bash
dotnet add package Rsrp.Security.Core
```

```csharp
// Generate a key pair
var keyPair = await Ed25519.GenerateKeyPairAsync();

// Sign data
var signature = await Ed25519.SignAsync(data, keyPair.PrivateKey);

// Verify
bool valid = await Ed25519.VerifyAsync(data, signature, keyPair.PublicKey);
```

### Post-Quantum

```csharp
// Hybrid signing (Classical + PQ)
var hybridKey = await HybridKeyPair.GenerateAsync(Algorithm.Dilithium2);
var hybridSig = await hybridKey.SignAsync(data);

// Verify
bool valid = await hybridKey.VerifyAsync(data, hybridSig);
```

## Algorithms

### Classical (Available)

| Algorithm | Use Case | Security Level |
|-----------|----------|----------------|
| Ed25519 | Signatures | 128-bit |
| RSA-PSS 2048 | Signatures | 112-bit |
| RSA-PSS 4096 | Signatures | 128-bit |
| SHA-256 | Hashing | 128-bit |
| SHA-512 | Hashing | 256-bit |
| BLAKE3 | Hashing | 256-bit |

### Post-Quantum (NIST 2024)

| Algorithm | Type | Security Level |
|-----------|------|----------------|
| Dilithium2 | Signature | 128-bit |
| Dilithium3 | Signature | 192-bit |
| Dilithium5 | Signature | 256-bit |
| Falcon-512 | Signature | 128-bit |
| Falcon-1024 | Signature | 256-bit |
| Kyber512 | KEM | 128-bit |
| Kyber768 | KEM | 192-bit |
| Kyber1024 | KEM | 256-bit |

### Hybrid Signatures

Combine classical + PQ for defense-in-depth:
```csharp
var hybrid = new HybridSignatureProvider(
    classical: new Ed25519Provider(),
    pq: new Dilithium2Provider()
);
```

## Key Management

```csharp
public interface IKeyManager
{
    Task<KeyHandle> GenerateKeyAsync(Algorithm algorithm);
    Task<KeyHandle> ImportKeyAsync(byte[] key, KeyType type);
    Task<byte[]> ExportPublicKeyAsync(KeyHandle handle);
    Task DeleteKeyAsync(KeyHandle handle);
}
```

### HSM Support (Enterprise)

```csharp
// Rsrp.Enterprise.HSM (Commercial)
var hsm = new Pkcs11HsmProvider("/usr/lib/pkcs11/luna.so");
var key = await hsm.GenerateKeyAsync(Algorithm.Ed25519);

// Sign with HSM
var sig = await hsm.SignAsync(data, key);
```

## FIPS Compliance

```csharp
// Use FIPS-approved algorithms
var provider = new FipsCompliantProvider();

// Verify FIPS mode
bool fips = provider.IsFipsMode();
```

## Random Number Generation

```csharp
// Secure RNG
var rng = new FipsAwareRng();
var bytes = rng.GetBytes(32);
```

## API Reference

### Providers

```csharp
ISignatureProvider    // Sign/verify interface
IKeyManager           // Key lifecycle
IPqcProvider          // Post-quantum operations
IHashProvider         // Hashing operations
IRngProvider          // Random number generation
```

### Hybrid Mode

```csharp
IHybridSignatureProvider    // Classical + PQ
IHybridKEMProvider         // Key encapsulation
```

## Use Cases

- **Long-term document signing** — Legal, medical records
- **Blockchain/tamper-proof logs** — Future-proof audit trails
- **Financial transactions** — Regulatory compliance
- **Government systems** — Classified communications

## Installation

```bash
# Core crypto
dotnet add package Rsrp.Security.Core

# With PQ support
dotnet add package Rsrp.Security.Core.PQ

# Enterprise HSM (commercial)
dotnet add package Rsrp.Enterprise.HSM
```

## Security Model

| Component | Implementation |
|-----------|----------------|
| Hashing | SHA-256, BLAKE3 (constant-time) |
| Signatures | Ed25519, Dilithium (RFC 8032, Draft 15) |
| Key Derivation | HKDF, PBKDF2 |
| RNG | CSPRNG, FIPS 140-2 approved |

## Performance

| Operation | Classical | Hybrid |
|-----------|-----------|--------|
| Sign | ~10μs | ~50μs |
| Verify | ~20μs | ~80μs |
| KeyGen | ~50μs | ~200μs |

## Enterprise Features

Need HSM or advanced key management? Contact: **enterprise@rsrp.io**

- PKCS#11 HSM integration
- Thales Luna Network HSM
- AWS CloudHSM / Azure Key Vault
- Vault integration
- Key ceremony support

## Documentation

- [Crypto Architecture](https://docs.rsrp.io/crypto)
- [PQ Implementation](https://docs.rsrp.io/crypto/pq)
- [HSM Integration](https://docs.rsrp.io/crypto/hsm)

## License

Apache 2.0 — Core crypto primitives
Commercial — HSM and advanced features

---

**Rsrp.Security.Core** — Cryptography for the quantum era.
