# ProofEnvelopeV1 Interop Vector Checks

These scripts validate deterministic encoding invariants using:

- `docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json`

They do not require the Rust crates and are intended for cross-language CI smoke checks.

## What is checked

- hex decode roundtrip for `signing_bytes` and `canonical_bytes`
- declared lengths match actual lengths
- `canonical_bytes = signing_bytes || signature_len:u32 || signature_bytes`
- packed `runtime_version` bytes match fixture metadata
- `decision_code` byte matches fixture metadata
- SHA-256 of canonical bytes matches fixture value

## Run

Python:

```powershell
python scripts/interop/verify_proof_envelope_v1_vectors.py
```

TypeScript (Node + tsx/ts-node):

```powershell
npx tsx scripts/interop/verify_proof_envelope_v1_vectors.ts
```

Go:

```powershell
go run scripts/interop/verify_proof_envelope_v1_vectors.go
```
