# RSRP (Risk Secure Runtime Protocol)

Deterministic security runtime for verifiable decisions:

`Policy -> Decision -> Proof -> Ledger -> Verification`

## Status

- Development line: `0.10.0`
- Maturity: pre-1.0 hardened runtime
- Language: Rust workspace (multi-crate)

## Crates

- `rsrp-security-core`
- `rsrp-policy-dsl`
- `rsrp-pqcrypto`
- `rsrp-proof-engine`
- `rsrp-immutable-ledger`

The last documented crates.io release is `0.9.4`; the current workspace is the
unreleased `0.10.0` development line.

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
go run scripts/interop/verify_proof_envelope_v1_vectors.go
npx --yes tsx scripts/interop/verify_proof_envelope_v1_vectors.ts
```

## Release validation

`production-gate.yml` orders the blocking checks as follows:

`fmt/Clippy/check -> workspace tests -> real crypto -> API integration -> Docker smoke -> ELF hardening -> audit/deny/SBOM/provenance/signatures -> negative tests/fuzz -> reproducibility`.

- The default, mock, real and production feature configurations are tested separately.
  `--all-features` cannot compile by design: mock and real crypto are mutually
  exclusive, and production freezes ML-KEM-768 / ML-DSA-65. Compilation guards
  are tested rather than weakened.
- The API integration suite starts real listeners and generates temporary JWT
  secrets and TLS certificates. The Docker suite tests the actual distroless
  image; ELF checks inspect its extracted executable, not a separate host build.
- SoftHSM2/PKCS#11 checks exercise an external token module. They do **not**
  certify an API PKCS#11 backend: the open-source API only has software signing
  and a non-production HSM simulation.
- Audit exceptions remain in `.cargo/audit.toml`; `cargo deny` rejects yanked
  dependencies. The evidence includes the Cargo CycloneDX SBOM, tested image
  digest and SLSA-format provenance. This is not a claim of a SLSA assurance level.
- Two fresh Docker builds must reproduce the tested ELF and canonical Cargo
  SBOM. Only SBOM document UUID/time and provenance invocation metadata are
  excluded from comparison; Docker archive bytes and OS-package SBOM coverage
  are not certified by this check.
- Pull requests run validation without signing. Trusted push/dispatch runs sign
  and verify evidence with Sigstore. The final aggregate check fails on failed,
  skipped or cancelled prerequisites and never publishes a tag or release.

Require the `Release closure (no automatic publication)` check in repository
protection settings and use a successful trusted run before release approval.
Warnings that fail strict Clippy must be fixed; later stages never bypass them.

## Security and Docs

- Security policy: `SECURITY.md`
- Hardening report: `docs/SECURITY_HARDENING_v0.9.4.md`
- ProofEnvelope v1 spec: `docs/PROOF_ENVELOPE_V1_SPEC.md`
- Changelog: `CHANGELOG.md`
- Audit status: `docs/RSRP_AUDIT_SECURITE_V091_STATUT_CORRECTIFS_WORKSPACE.md`

## License

EUPL-1.2 (`LICENSE`).
