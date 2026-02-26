# SECURITY_HARDENING_v0.9.4

Date: `2026-02-26`
Scope: `rsrp-pqcrypto`, `rsrp-immutable-ledger`, `rsrp-proof-engine`, `rsrp-policy-dsl`, `rsrp-security-core`

## 1. Security-Critical Fixes

- Hybrid KEM classical branch migrated to real X25519 ECDH (`x25519-dalek`), replacing simulated random classical ciphertext.
- Hybrid KEM now verifies a classical/quantum binding tag before deriving the final secret; tampered classical or quantum components are rejected.
- Hybrid shared secret derivation standardized to HKDF-SHA256 with explicit length-prefixing.
- Secret-bearing key structures were hardened:
  - hybrid keypair secret fields remain private,
  - secret key types no longer derive `Clone`,
  - secret key serialization exposure reduced for PQ secret key structs.
- `LogEntry::new(...)` is now fail-closed and returns `Result<LogEntry, LogError>`; silent fallback/synthetic entries removed.
- `ProofBinding` canonical payload encoding changed from JSON payload serialization to explicit deterministic binary field encoding.
- `ProofEnvelopeV1.runtime_version` migrated from `u16` (major/minor) to `u32` (major/minor/patch packing).
- DSL rule signing pipeline aligned on Ed25519 end-to-end (`Ed25519InMemorySigner`), removing HMAC/BLAKE3 mismatch risk.
- RSA-PSS stubs removed from operational path by implementing RSA-PSS-SHA256 sign/verify using DER key material.
- DSL compiler now supports `IN` and `BETWEEN`; VM execution tests confirm correct behavior.

## 2. Determinism and Interop

- `ProofEnvelopeV1` vectors/spec updated for `runtime_version` packed `u32`.
- Added canonical binary decode path: `ProofEnvelopeV1::from_canonical_bytes(...)`.
- Added round-trip canonical decode test to lock binary compatibility.

## 3. Tests Executed

- `cargo test -p rsrp-pqcrypto --lib`
- `cargo test -p rsrp-policy-dsl --lib`
- `cargo test -p rsrp-immutable-ledger --lib`
- `cargo test -p rsrp-security-core --lib`
- `cargo test -p rsrp-proof-engine --lib`
- `cargo check --workspace`

## 4. Residual Risks (Not Fully Closed)

- `real-crypto` OQS end-to-end validation remains environment-dependent (LLVM/Clang/libclang toolchain).
- Parser coverage for all `THEN` syntactic variants is still partial.
- Formal external crypto review, fuzzing campaign scale-up, and performance benchmark publication remain pending.
