# R-SRP Security Target

Version: 0.9.9
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
- SPIFFE/SVID-specific identity verification (TOE currently enforces mTLS X.509 validation, not SPIFFE URI-SAN policy enforcement)

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
- FSR-06 FIPS posture and entropy runtime checks: fail on unsupported RNG/config in strict mode and expose fail-closed readiness status for entropy degradation.
- FSR-07 CI gating: production profile build mandatory; mock backend rejected.
- FSR-08 Supply chain: lockfile, audit, deny policy, SBOM, signatures, provenance.

## 8. Assurance Evidence

Implementation and controls:
- `docs/CRYPTO_ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/THREAT_MODEL_STRIDE.md`
- `docs/KEY_LIFECYCLE_POLICY.md`
- `docs/HSM_IMPLEMENTATION_STATUS.md`
- `docs/NETWORK_IDENTITY_STATUS.md`
- `docs/INCIDENT_RESPONSE_PLAN.md`
- `docs/SUPPLY_CHAIN_POLICY.md`
- `docs/MERKLE_SECURITY_MODEL.md`

Pipeline evidence:
- `.github/workflows/production-gate.yml`
- `.github/workflows/sbom.yml`
- `.github/workflows/reproducible-build.yml`
- `.github/workflows/signing.yml`
- `.github/workflows/fuzz-evidence.yml`

## 9. Residual Risks

- External PKI/HSM trust and operational controls remain deployment responsibilities.
- Third-party advisory latency remains possible between disclosure and patch.
- Runtime side-channel resistance depends on platform hardening and hardware profile.
- In-memory per-process rate limiting is not globally consistent in multi-replica deployments; production requires an external distributed limiter or ingress-level limiting policy.

## 10. Certification Intent

Target posture:
- External audit readiness for product-grade security review.
- Preparation for CSPN-like evaluation and EUCC substantial profile planning.

## 11. TOE Summary Specification (TSS)

This section describes how each FSR is implemented in the TOE, and how implementation is verified.

| FSR | Mechanism | Main Modules | Verification Evidence |
|---|---|---|---|
| FSR-01 Hybrid signature validation | Dual verification is required: Ed25519 and ML-DSA must both succeed for a valid result. | `crates/pqcrypto/src/hybrid.rs` | `cargo test -p rsrp-pqcrypto --locked` (hybrid tamper tests) |
| FSR-02 Temporal RBAC | Mission schedule is evaluated at runtime; unknown/absent schedule context is denied (fail-closed). | `services/api-service/src/mission_schedule.rs`, `services/api-service/src/handlers.rs` | `cargo test -p api-service --locked` (mission schedule tests) |
| FSR-03 Immutable logging | Append-only chain with hash-linked entries and Merkle leaf/node domain separation. | `crates/immutable-logging/src/chain.rs`, `crates/immutable-logging/src/merkle_service.rs`, `crates/crypto-core/src/merkle.rs` | `cargo test -p rsrp-immutable-ledger --locked`, `cargo test -p rsrp-security-core --locked` |
| FSR-04 Compact inclusion proof | Chain proof uses compact membership paths (`O(log n)`) bound to chain root and head hash. | `crates/immutable-logging/src/chain.rs` | `test_chain_proof_is_compact_logarithmic` |
| FSR-05 Zeroization | Key material uses explicit zeroization in cryptographic key structures and lifecycle paths. | `crates/crypto-core/src/signature.rs`, `crates/pqcrypto/src/*` | `cargo test -p rsrp-security-core --locked` (zeroization tests) |
| FSR-06 FIPS/entropy runtime controls | Entropy self-test at startup and periodic runtime check; fail-closed readiness when configured; default key generation mode is `FipsMode::Enabled` unless explicitly disabled. | `crates/crypto-core/src/entropy.rs`, `crates/crypto-core/src/signature.rs`, `services/api-service/src/main.rs`, `services/api-service/src/handlers.rs` | `cargo test -p rsrp-security-core --locked entropy::tests::test_entropy_health_check_reports_ok -- --nocapture` |
| FSR-07 CI crypto profile gating | Production feature graph rejects mock backend and enforces hardened profile checks. | `.github/workflows/production-gate.yml`, `crates/pqcrypto/src/lib.rs` | Production Gate workflow artifacts |
| FSR-08 Supply-chain integrity | Locked dependencies, advisory/bans/license/source checks, SBOM/provenance/signing workflows. | `Cargo.lock`, `deny.toml`, `.github/workflows/*.yml` | `cargo deny`, `cargo audit`, SBOM and provenance artifacts |

### 11.1 Formal Mapping (FSR to Threats and Assumptions)

| FSR | Mitigated Threats | Required Assumptions |
|---|---|---|
| FSR-01 | T1 | A2 (key custody), A3 (CI/release integrity) |
| FSR-02 | T2 | A6 (deployment network controls) |
| FSR-03 | T3 | A4 (append-only storage/WAL integrity) |
| FSR-04 | T3 | A4 (append-only storage/WAL integrity) |
| FSR-05 | T4 | A1 (approved runtime profile), A2 (key custody) |
| FSR-06 | T4, T5 | A1 (entropy source trust), A3 (pipeline integrity) |
| FSR-07 | T5 | A3 (branch/runner/credential controls) |
| FSR-08 | T5 | A3 (CI/release control), A5 (external trust anchors governance) |

Assumption identifiers are maintained in `docs/ASSUMPTIONS_REGISTER.md`.

## 12. Configuration Management Process

Configuration management controls for TOE artifacts:

- Versioning model:
  - Workspace version is controlled from `Cargo.toml` (`[workspace.package].version`).
  - Release tags follow `v<semver>` and are published on `origin`.
- Change control:
  - All security-relevant changes require traceability update in `docs/TRACEABILITY_MATRIX.md`.
  - Security documents updated in the same change set as code when claims are impacted.
- Release integrity:
  - CI enforces `clippy -D warnings`, production profile checks, and supply-chain gates.
  - SBOM and signed provenance artifacts are generated by dedicated workflows.
- Reproducible build controls:
  - reproducibility workflow compares binary hashes across independent build environments.
  - mismatch is a release blocker.
- Artifact archive requirements:
  - release bundle includes docs, CI evidence, test evidence, SBOM, signatures, and provenance.
  - archive format and naming are defined in `docs/CERTIFICATION_BUNDLE.md`.

## 13. Vulnerability Management Process

Vulnerability lifecycle for TOE and dependency stack:

1. Intake:
   - sources: internal reports, external disclosures, `cargo audit`, `cargo deny`, platform alerts.
2. Triage:
   - classify by impact on confidentiality/integrity/availability and exposure path.
   - map each vulnerability to affected TOE component(s) and threat(s).
3. Containment:
   - apply temporary mitigation or risk acceptance with explicit rationale and review date.
   - accepted risks must be recorded in `docs/DEPENDENCY_RISK_ASSESSMENT.md`.
4. Remediation:
   - implement patch or dependency upgrade with tests and traceability updates.
   - enforce CI pass on security gates before merge/release.
5. Disclosure:
   - publish release notes/advisory with impacted versions, remediation version, and migration guidance.
6. Closure:
   - verify fix in CI artifacts and update risk register status.

## 14. Attack Potential Mapping

This mapping provides a pre-certification estimate of attacker effort and feasibility.

| Threat | Required Skill | Required Time | Required Equipment | Feasibility (Current Controls) |
|---|---|---|---|---|
| T1 Signature forgery against decision proofs | Advanced cryptography and implementation knowledge | High | Specialized compute and signing attack tooling | Low (hybrid verification + key custody assumptions) |
| T2 Temporal access bypass | Intermediate API abuse and auth understanding | Medium | Standard offensive tooling | Low to Medium (depends on deployment enforcement and schedule governance) |
| T3 Audit log tampering / second preimage | Advanced integrity/proof manipulation expertise | High | Storage access + custom tamper tooling | Low (hash-chain + compact proof + domain separation) |
| T4 Secret retention in memory | Advanced runtime exploitation and memory forensics | Medium to High | Debug/memory extraction capabilities | Medium (reduced by zeroization; host hardening remains external) |
| T5 Supply-chain compromise | Advanced CI/release compromise capability | Medium to High | Credential theft path, artifact substitution infra | Medium (reduced by lockfile, deny/audit, SBOM, provenance, signing) |

These estimates are reviewed against deployment model assumptions and hostile-host scenarios in `docs/ASSUMPTIONS_REGISTER.md` and `docs/THREAT_MODEL_STRIDE.md`.
