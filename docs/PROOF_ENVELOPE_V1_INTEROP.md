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

It is not a full cryptographic interoperability suite yet (signature verification key export is not part of the current vector JSON).

## Fixtures

- `docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json`

## Reference Checkers

- Python: `scripts/interop/verify_proof_envelope_v1_vectors.py`
- TypeScript: `scripts/interop/verify_proof_envelope_v1_vectors.ts`
- Go: `scripts/interop/verify_proof_envelope_v1_vectors.go`

## Next Step (Recommended)

For cross-language signature verification vectors, extend the JSON schema with:

- `ed25519_public_key_hex`
- `signature_bytes_hex` (or structured extraction for `ProofEnvelopeV1`)
- optional KMS/cert identity metadata for future `v1.1/v2`
