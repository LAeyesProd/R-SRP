# R-SRP Security Target

Version: 0.9.8
Date: 2026-02-27
Owner: Security Engineering

## 1. Scope

Target of Evaluation (TOE):
- `rsrp-security-core`
- `rsrp-proof-engine`
- `rsrp-policy-dsl`
- `rsrp-immutable-ledger`
- `rsrp-pqcrypto`
- `rsrp-demo` (reference integration profile)

Security baseline for production profile:
- ML-KEM-768
- ML-DSA-65
- Hybrid signature required
- Mock crypto forbidden in release/production

## 2. Security Boundary

Trusted boundary includes:
- Rust code in the crates listed above
- Build pipeline controls in `.github/workflows`
- Cryptographic dependencies pinned by `Cargo.lock`

Out of boundary:
- External HSM/KMS hardware implementation details
- External TSA trust anchors
- Host OS hardening outside project guidance

## 3. Assets

Protected assets:
- Private keys (classical and post-quantum)
- Policy decision evidence and signed proof envelopes
- Immutable audit log entries and publication roots
- Build artifacts and SBOM/provenance metadata

## 4. Assumptions

- Production deploys with trusted entropy source and FIPS-compatible runtime where required.
- Secrets and signing identities are managed by approved operators.
- CI runners and release credentials are controlled and monitored.

## 5. Threats

- T1: Signature forgery against decision proofs.
- T2: Temporal access bypass (requests outside mission window).
- T3: Audit log tampering and second-preimage attempts.
- T4: Secret retention in process memory after key lifecycle events.
- T5: Supply-chain compromise through dependency or artifact substitution.

## 6. Security Objectives

- O1: Enforce hybrid verification (classical plus PQ) for signed evidence.
- O2: Enforce fail-closed temporal authorization checks.
- O3: Provide tamper-evident immutable logging with compact inclusion proof.
- O4: Ensure private key material is zeroized on drop and in failure paths.
- O5: Enforce production-only cryptographic profile in CI/CD.
- O6: Provide verifiable supply-chain integrity (SBOM, signing, provenance).

## 7. Functional Security Requirements

- FSR-01 Hybrid signature validation: both Ed25519 and ML-DSA signatures must verify.
- FSR-02 Temporal RBAC: deny outside mission schedule and deny when schedule data unavailable.
- FSR-03 Immutable logging: hash-linked entries plus Merkle domain separation.
- FSR-04 Compact inclusion proof: O(log n) membership proof for chain evidence.
- FSR-05 Zeroization: private key memory cleared at lifecycle termination.
- FSR-06 FIPS posture: fail on unsupported RNG/config in strict mode.
- FSR-07 CI gating: production profile build mandatory; mock backend rejected.
- FSR-08 Supply chain: lockfile, audit, deny policy, SBOM, signatures, provenance.

## 8. Assurance Evidence

Implementation and controls:
- `docs/CRYPTO_ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/THREAT_MODEL_STRIDE.md`
- `docs/KEY_LIFECYCLE_POLICY.md`
- `docs/SUPPLY_CHAIN_POLICY.md`
- `docs/MERKLE_SECURITY_MODEL.md`

Pipeline evidence:
- `.github/workflows/production-gate.yml`
- `.github/workflows/sbom.yml`
- `.github/workflows/reproducible-build.yml`
- `.github/workflows/signing.yml`

## 9. Residual Risks

- External PKI/HSM trust and operational controls remain deployment responsibilities.
- Third-party advisory latency remains possible between disclosure and patch.
- Runtime side-channel resistance depends on platform hardening and hardware profile.

## 10. Certification Intent

Target posture:
- External audit readiness for product-grade security review.
- Preparation for CSPN-like evaluation and EUCC substantial profile planning.
