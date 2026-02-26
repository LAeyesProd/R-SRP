# ProofEnvelope V1 Canonical Specification

Status: `Draft (implementation-backed)`  
Scope: `rsrp-proof-engine` proof attestation envelope format for deterministic verification and ledger embedding.

## 1. Purpose

`ProofEnvelopeV1` defines a stable, canonical proof attestation payload with:

- fixed-width header fields for deterministic hashing/verifier implementations,
- explicit decision coding,
- typed signature metadata,
- canonical binary encoding suitable for ledger commitments and export.

This format is designed to reduce ambiguity before `v1.0.0` API freeze.

## 2. Canonical Data Model

Conceptual structure:

```rust
struct ProofEnvelopeV1 {
    version: u8,
    encoding_version: u8,
    runtime_version: u16,
    policy_hash: [u8; 32],
    bytecode_hash: [u8; 32],
    input_hash: [u8; 32],
    state_hash: [u8; 32],
    decision_code: u8,
    signature: SignatureV1,
}
```

## 3. Field Semantics

- `version`: schema major version (`1`)
- `encoding_version`: canonical binary encoding revision (`1`)
- `runtime_version`: packed runtime semver `(major << 8) | minor`
  - example: `0.9.1` -> `0x0009`
- `policy_hash`: SHA-256 of canonical serialized policy representation
  - current engine compiled path uses canonical serialized AST hash
- `bytecode_hash`: SHA-256 of canonical serialized compiled bytecode (including action bytecode)
- `input_hash`: SHA-256 of canonical serialized evaluation request
- `state_hash`: SHA-256 of canonical serialized evaluation context snapshot (sorted fields)
- `decision_code`: deterministic decision enum encoding
- `signature`: typed signature metadata + signature bytes

## 4. Decision Codes

- `1` = `ALLOW`
- `2` = `BLOCK`
- `3` = `WARN`
- `4` = `APPROVAL_REQUIRED`

## 5. SignatureV1 Variants

### 5.1 `Ed25519`

Metadata:

- `algorithm_code = 1`
- `key_id_hash: [u8; 32]` = `SHA-256(signer_key_id UTF-8 bytes)`

Signature bytes:

- raw Ed25519 signature bytes (`64` bytes)

### 5.2 `HybridEd25519+ML-DSA` (feature-gated)

Metadata:

- `algorithm_code = 2`
- `key_id_hash: [u8; 32]`
- `backend_id_hash: [u8; 32]` = `SHA-256(pq_backend_id UTF-8 bytes)` (e.g. `mock-crypto`, `oqs`)
- `level_code: u8`:
  - `2` = `Dilithium2 / ML-DSA-44`
  - `3` = `Dilithium3 / ML-DSA-65`
  - `5` = `Dilithium5 / ML-DSA-87`

Signature bytes:

- packed hybrid signature bytes using current `rsrp-pqcrypto::HybridSignature::to_bytes()`
  - format: `[classical_len:u16][classical_sig][quantum_sig]`

## 6. Signing Payload (Canonical, Unsigned Portion)

The signature MUST be computed over `signing_bytes`, which is the canonical binary encoding of:

- fixed header fields (`version` .. `decision_code`)
- signature metadata only (algorithm + key/level metadata)

The signature bytes themselves are NOT included in the signing payload.

This avoids self-referential encoding and supports deterministic verification.

## 7. Canonical Binary Encoding

### 7.1 `signing_bytes`

Byte order: **big-endian** for integers.

Layout (in order):

1. `version` (`u8`)
2. `encoding_version` (`u8`)
3. `runtime_version` (`u16`)
4. `policy_hash` (`[u8; 32]`)
5. `bytecode_hash` (`[u8; 32]`)
6. `input_hash` (`[u8; 32]`)
7. `state_hash` (`[u8; 32]`)
8. `decision_code` (`u8`)
9. `signature_meta_len` (`u16`)
10. `signature_meta` (`signature_meta_len` bytes)

### 7.2 `canonical_bytes` (full envelope)

`canonical_bytes = signing_bytes || signature_len:u32 || signature_bytes`

Where:

- `signature_len` is the length of the serialized signature bytes payload for the selected signature variant
- integers use **big-endian**

## 8. Verification Procedure (Normative)

Verifier must:

1. Validate `version == 1` and `encoding_version == 1`
2. Validate `decision_code` is known
3. Validate signature variant metadata (algorithm code, key/level compatibility)
4. Recompute `signing_bytes`
5. Verify signature over `signing_bytes`
6. Recompute and compare hashes (`policy_hash`, `bytecode_hash`, `input_hash`, `state_hash`) against claimed execution context

## 9. Compatibility / Migration Rules

- `ProofBinding` (legacy/dynamic) remains supported as an internal bridge
- `ProofEnvelope` / `PqProofEnvelope` remain supported for backward compatibility
- new attestation APIs should prefer `ProofEnvelopeV1`
- future incompatible changes MUST increment `version`
- encoding-only changes MUST increment `encoding_version`

## 10. Current Implementation Coverage (Workspace)

Implemented in `rsrp-proof-engine`:

- `ProofBinding` includes `policy_hash`
- `ProofEnvelopeV1` canonical signing and verification (Ed25519)
- `ProofEnvelopeV1` canonical signing and verification (hybrid, feature-gated)
- engine APIs:
  - `evaluate_with_signed_proof_v1_ed25519(...)`
  - `evaluate_with_signed_proof_v1_hybrid(...)` (`pq-proof`)

## 11. Known Limitations Before v1.0 Freeze

- parser coverage in `rsrp-policy-dsl` still limits some `THEN` syntactic variants
- signature metadata currently hashes signer/backend string IDs rather than embedding a full certificate/KMS identity structure
- runtime version packs only `major.minor` (patch omitted)

## 12. Test Vector (Ed25519, Canonical V1)

Deterministic fixture (implemented in `rsrp-proof-engine` unit tests):

- binding hashes:
  - `policy_hash = 0x11 * 32`
  - `bytecode_hash = 0x22 * 32`
  - `input_hash = 0x33 * 32`
  - `state_hash = 0x44 * 32`
- `runtime_version = "0.9.1"` (packed to `0x0009`)
- `decision_code = BLOCK (2)`
- signer key: `Ed25519KeyPair::derive_from_secret("rsrp-proof-envelope-v1-ed25519-test-vector", "fixture-ed25519-key")`

Machine-readable fixture export:

- `docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json`

Canonical `signing_bytes` hex:

```text
01010009111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444402002101e7e331964026891ae93f6f0d4b20c19f95cf20d6c6ba87fd73e287b081a46201
```

Canonical `canonical_bytes` hex (includes signature length + signature bytes):

```text
01010009111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444402002101e7e331964026891ae93f6f0d4b20c19f95cf20d6c6ba87fd73e287b081a4620100000040ec3e14a8311ebc1d76c65054b7b011cbf9b10d6796417b9e69bc3cb28fd6aab41228c26d034d52b6690680ea27617a35db24993cd24dd296c3905b1338272d05
```
