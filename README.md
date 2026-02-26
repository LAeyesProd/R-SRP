# RSRP (Risk Secure Runtime Protocol)

Deterministic security runtime for verifiable decisions:

`Policy -> Decision -> Proof -> Ledger -> Verification`

## Status

- Release line: `0.9.4`
- Maturity: pre-1.0 hardened runtime
- Language: Rust workspace (multi-crate)

## Crates

- `rsrp-security-core`
- `rsrp-policy-dsl`
- `rsrp-pqcrypto`
- `rsrp-proof-engine`
- `rsrp-immutable-ledger`

Published on crates.io under `0.9.4`.

## What Was Hardened in 0.9.4

- Hybrid KEM classical branch moved to real X25519 ECDH.
- Hybrid secret derivation normalized via HKDF-SHA256 with strict binding checks.
- `LogEntry::new` made fail-closed (no synthetic fallback entry).
- `ProofBinding` canonical payload switched to deterministic binary field encoding.
- `ProofEnvelopeV1.runtime_version` migrated to packed `u32` (major/minor/patch).
- DSL signing path aligned on Ed25519.
- RSA-PSS stubs replaced by real sign/verify implementation.
- DSL `IN` and `BETWEEN` compiled and VM-tested.

## Quick Start

Requirements:

- Rust stable toolchain

Build and test:

```bash
cargo check --workspace
cargo test -p rsrp-pqcrypto --lib
cargo test -p rsrp-proof-engine --lib
```

ProofEnvelope vector checks:

```bash
python scripts/interop/verify_proof_envelope_v1_vectors.py
node scripts/interop/verify_proof_envelope_v1_vectors.ts
```

## Security and Docs

- Security policy: `SECURITY.md`
- Hardening report: `docs/SECURITY_HARDENING_v0.9.4.md`
- ProofEnvelope v1 spec: `docs/PROOF_ENVELOPE_V1_SPEC.md`
- Changelog: `CHANGELOG.md`
- Audit status: `docs/RSRP_AUDIT_SECURITE_V091_STATUT_CORRECTIFS_WORKSPACE.md`

## License

EUPL-1.2 (`LICENSE`).
