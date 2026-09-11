# Changelog

## 0.10.0 - Unreleased

### Proof verification hardening

- Reject unsupported `ProofEnvelopeV1` schema/encoding versions and decision codes before signature verification.
- Add fail-closed Ed25519 verification bound to the expected `ProofBinding` and signer key ID.
- Strengthen Python, TypeScript and Go interop checks and make all three release-gating.
- Generate the canonical Ed25519 fixture from Rust and reject fixture drift in CI.
- Add portable negative-vector mutations for signature, payload, version, decision and trailing-byte rejection.

## 0.9.4 - 2026-02-26

### Security

- Replaced hybrid KEM simulated classical branch with real X25519 ECDH.
- Added hybrid classical/quantum binding tag validation; tampered ciphertext now fails decapsulation.
- Removed silent `LogEntry::new` fallback path; constructor now returns `Result`.
- Replaced RSA-PSS placeholder functions with real RSA-PSS-SHA256 sign/verify.
- Aligned DSL signing pipeline on Ed25519 (`Ed25519InMemorySigner`).

### Determinism and Proof Format

- Migrated `ProofEnvelopeV1.runtime_version` from packed `u16` to packed `u32` (`major.minor.patch`).
- Replaced `ProofBinding` canonical payload JSON serialization with deterministic binary field encoding.
- Added `ProofEnvelopeV1::from_canonical_bytes` decode path and roundtrip tests.
- Updated `ProofEnvelopeV1` spec and test vectors.

### DSL/VM

- Implemented compiler support for `IN` and `BETWEEN` expressions.
- Added VM tests validating `IN` and `BETWEEN` decision behavior.

### Hardening

- Reduced secret exposure in PQ key structures (private secret fields, reduced secret cloning/serialization surface).
- Added hardening report: `docs/SECURITY_HARDENING_v0.9.4.md`.
