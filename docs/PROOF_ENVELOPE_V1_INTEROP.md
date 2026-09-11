# ProofEnvelopeV1 Interop Notes (Go / TypeScript / Python)

Status: `Utility / CI support`  
Scope: deterministic validation of canonical `ProofEnvelopeV1` fixtures outside Rust.

## Purpose

This document points to cross-language smoke checks for `ProofEnvelopeV1` canonical vectors.

The goal is to validate:

- canonical byte layout stability,
- length-prefix semantics,
- packed runtime version bytes,
- deterministic SHA-256 over `canonical_bytes`.
- independent semantic reconstruction and Ed25519 signature verification.
- portable rejection cases for tampered payloads/signatures and invalid framing.

Ed25519 verification is covered. Hybrid Ed25519 + ML-DSA interoperability is
not yet part of the vector corpus.

## Fixtures

- `docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json`

## Reference Checkers

- Python: `scripts/interop/verify_proof_envelope_v1_vectors.py`
- TypeScript: `scripts/interop/verify_proof_envelope_v1_vectors.ts`
- Go: `scripts/interop/verify_proof_envelope_v1_vectors.go`

## Next Step (Recommended)

Add hybrid Ed25519 + ML-DSA vectors and optional KMS/certificate identity
metadata for a future `v1.1/v2` identity profile.
