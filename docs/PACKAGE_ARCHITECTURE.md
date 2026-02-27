# RSRP Package Architecture Specification

*Publisher: Rsrp Systems | Author: Aymeric Le Cloitre-Maternat (ALM)*

## Overview

This document defines the modular package structure for RSRP, aligning the existing Rust crates with the recommended NuGet-style organization for publication.

---

## Current Crate → Package Mapping

| Recommended Package | Rust Crate(s) | Status | Description |
|---------------------|---------------|--------|-------------|
| **Rsrp.ProofEngine** | `crue-engine` + `crue-dsl` | ✅ Public | Deterministic decision engine, policy evaluation, proof generation |
| **Rsrp.ImmutableLedger** | `immutable-logging` | ✅ Public | Append-only ledger, Merkle trees, proof verification |
| **Rsrp.Security.Core** | `pqcrypto` + `crypto-core` | ✅ Public | Signature abstraction, key management, PQ crypto |
| **Rsrp.Enterprise.HSM** | `crypto-core::hsm` | 🔒 Private | PKCS#11, Thales/Luna connectors |
| **Rsrp.Sovereign.Deployment** | `services/*` | 🔒 Private | mTLS mesh, attestation hooks |

---

## Package 1: Rsrp.ProofEngine

**Purpose**: Core deterministic decision engine for critical systems.

### Contents

```text
crates/crue-engine/    → Proof engine core
crates/crue-dsl/       → Policy DSL parser & compiler
```

### Public API

```rust
// Core types (public interface)
pub trait IProofEngine {
    async fn evaluate(&self, policy: &Policy, input: &EvaluationInput) -> Result<IDecisionResult, Error>;
}

pub trait IDecisionResult {
    fn decision(&self) -> Decision;
    fn generate_proof(&self) -> Result<IProof, Error>;
    fn to_json(&self) -> String;
}

pub trait IProof {
    fn verify(&self) -> bool;
    fn hash(&self) -> &str;
    fn signature(&self) -> Option<&Signature>;
}
```

### Dependencies

- `serde` (serialization)
- `chrono` (timestamps)
- `uuid` (request tracing)
- `tracing` (observability)

### Example Usage

```rust
use crue_engine::{ProofEngine, Policy, EvaluationInput};

let engine = ProofEngine::new();
let decision = engine.evaluate(policy, input).await?;
let proof = decision.generate_proof()?;

assert!(proof.verify());
```

---

## Package 2: Rsrp.ImmutableLedger

**Purpose**: Cryptographically secured append-only audit trail.

### Contents

```text
crates/immutable-logging/  → Immutable ledger, Merkle trees, publication
```

### Public API

```rust
pub trait IImmutableLedger {
    async fn append(&self, entry: LogEntry) -> Result<LogEntry, Error>;
    async fn verify(&self) -> Result<bool, Error>;
    async fn get_merkle_root(&self, hour: DateTime<hour>) -> Result<MerkleRoot, Error>;
    fn export(&self, format: ExportFormat) -> Result<String, Error>;
}

pub trait IProof {
    fn verify(&self) -> bool;
    fn to_canonical_hash(&self) -> String;
}
```

### Dependencies

- `sha2` / `blake3` (hashing)
- `chrono` (time)
- `serde_json` (export)

### Example Usage

```rust
use immutable_logging::{ImmutableLedger, LogEntry};

let ledger = ImmutableLedger::new();
ledger.append(entry).await?;

let valid = ledger.verify().await?;
let export = ledger.export(ExportFormat::Json)?;
```

---

## Package 3: Rsrp.Security.Core

**Purpose**: Cryptographic primitives and post-quantum extensions.

### Contents

```text
crates/pqcrypto/        → Post-quantum signatures (Dilithium, Falcon) + KEM (Kyber)
crates/crypto-core/     → Hash functions, basic signatures, Merkle trees
```

### Public API

```rust
pub trait ISignatureProvider {
    fn sign(&self, message: &[u8], key: &PrivateKey) -> Result<Signature, Error>;
    fn verify(&self, message: &[u8], signature: &Signature, key: &PublicKey) -> bool;
}

pub trait IKeyManager {
    fn generate_key(&self, algorithm: Algorithm) -> Result<KeyPair, Error>;
    fn import_key(&self, key: &[u8], key_type: KeyType) -> Result<KeyHandle, Error>;
}

pub trait IPqcProvider {
    fn hybrid_sign(&self, message: &[u8], classical: &PrivateKey, pq: &PrivateKey) -> Result<HybridSignature, Error>;
    fn hybrid_verify(&self, message: &[u8], sig: &HybridSignature) -> bool;
}
```

### Algorithms Supported

- **Classical**: Ed25519, RSA-PSS, ECDSA
- **Post-Quantum**: Dilithium2/3/5, Falcon-512/1024, Kyber512/768/1024
- **Hashing**: SHA-256, SHA-512, BLAKE3

---

## Private Package: Rsrp.Enterprise.HSM

**Purpose**: Hardware Security Module integration for enterprise deployments.

### Contents

```text
crates/crypto-core/src/hsm.rs  → PKCS#11 implementation
```

### Features

- PKCS#11 v3.0 compliance
- Thales Luna HSM support
- AWS CloudHSM compatibility
- Azure Key Vault HSM
- SafeNet KeySecure

---

## Private Package: Rsrp.Sovereign.Deployment

**Purpose**: Air-gapped and classified environment support.

### Contents

```text
services/api-service/   → Deployment templates
kubernetes/            → K8s manifests
terraform/             → IaC for sovereign clouds
```

### Features

- mTLS mesh enforcement
- Runtime attestation (TPM/Intel SGX)
- Air-gapped deployment scripts
- SecNumCloud compatibility preparation
- FIPS 140-2/3 validated module

---

## Open Core Model

### Community (MIT/Apache 2.0)

| Package | License |
|---------|---------|
| Rsrp.ProofEngine | Apache 2.0 |
| Rsrp.ImmutableLedger | Apache 2.0 |
| Rsrp.Security.Core | Apache 2.0 |

### Enterprise (Commercial)

| Package | License |
|---------|---------|
| Rsrp.Enterprise.HSM | Commercial |
| Rsrp.Sovereign.Deployment | Commercial |

---

## API Design Principles

### 1. Simplicity First

A developer should not need to read 50 pages of documentation.

✅ **Good**
```rust
let proof = engine.evaluate(policy, input)
    .generate_proof()?;
```

❌ **Avoid**
```rust
let config = ConfigBuilder::new()
    .with_hash_algo(HashAlgorithm::Sha256)
    .with_sig_algo(SignatureAlgorithm::Ed25519)
    .with_ledger_mode(LedgerMode::AppendOnly)
    .with_merkle_tree(MerkleConfig::default())
    .build()?;
```

### 2. Hide Implementation Details

Do **NOT** expose:
- Internal crypto structures
- Sensitive key materials
- Raw merkle tree nodes
- HSM connection details

### 3. Feature Flags

Use Cargo features for optional capabilities:

```toml
[features]
default = ["std"]
std = []
pqc = ["pqcrypto/dilithium2", "pqcrypto/kyber512"]
hsm = []
```

---

## Migration Plan

### Phase 1: Current State
```
crates/
├── crue-engine/       (becomes Rsrp.ProofEngine core)
├── crue-dsl/          (becomes Rsrp.ProofEngine DSL)
├── immutable-logging/ (becomes Rsrp.ImmutableLedger)
├── crypto-core/       (splits: public → Rsrp.Security.Core, private → HSM)
└── pqcrypto/          (becomes Rsrp.Security.Core PQ)
```

### Phase 2: Refactoring
1. Create `rsrp-proof-engine` crate → move `crue-engine` + `crue-dsl`
2. Rename `immutable-logging` → `rsrp-immutable-ledger`
3. Create `rsrp-security-core` crate → merge `crypto-core` (non-HSM) + `pqcrypto`
4. Mark `crypto-core::hsm` as private

### Phase 3: Publication
1. Publish to crates.io (Rust) with Apache 2.0
2. Document .NET/NuGet wrapper strategy
3. Establish enterprise licensing

---

## Version Strategy

| Component | Version | Release Cycle |
|-----------|---------|---------------|
| Rsrp.ProofEngine | 1.x | Quarterly |
| Rsrp.ImmutableLedger | 1.x | Quarterly |
| Rsrp.Security.Core | 1.x | As needed (security) |
| Enterprise | Custom | Per contract |

---

## Security Model

### Threat Model
- **Tampering**: Hash chaining prevents log modification
- **Repudiation**: Ed25519/PQ signatures prove decision origin
- **Information Disclosure**: Zero-trust, minimal privilege
- **Denial of Service**: Rate limiting, async processing
- **Elevation of Privilege**: Deterministic policy enforcement

### Verification
- All proofs include cryptographic hash of decision + signature
- Merkle tree roots published hourly (verifiable by third parties)
- TSA timestamps for non-repudiation

---

## Quick Start

```rust
// Add to Cargo.toml
// [dependencies]
// rsrp-proof-engine = "1.0"
// rsrp-immutable-ledger = "1.0"

use rsrp_proof_engine::{ProofEngine, Policy};
use rsrp_immutable_ledger::ImmutableLedger;

// Initialize
let engine = ProofEngine::new();
let ledger = ImmutableLedger::new();

// Evaluate and prove
let decision = engine.evaluate(policy, input).await?;
let proof = decision.generate_proof()?;

// Verify
assert!(proof.verify());

// Record in ledger
ledger.append(proof.into()).await?;
```

---

## Contact

- **Community**: https://github.com/rsrp/rsrp
- **Enterprise**: enterprise@rsrp.io
- **Security**: security@rsrp.io
