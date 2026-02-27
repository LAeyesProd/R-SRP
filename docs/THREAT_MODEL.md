# R-SRP Threat Model

Version: 0.9.9
Date: 2026-02-27
Owner: Security Engineering
Classification: Internal

## 1. Purpose and Method

This document defines the formal threat model used for pre-certification and external audit readiness.

Method:
- STRIDE for threat classification.
- Attack-potential estimation (skill, time, equipment, opportunity).
- Fail-closed design verification for production profile controls.

This document is normative with:
- `docs/SECURITY_TARGET.md`
- `docs/THREAT_MODEL_STRIDE.md`
- `docs/ASSUMPTIONS_REGISTER.md`
- `docs/ATTACK_SCENARIOS.md`
- `docs/TRACEABILITY_MATRIX.md`

## 2. Scope and Boundaries

In scope (TOE-aligned):
- `rsrp-security-core`
- `rsrp-proof-engine`
- `rsrp-policy-dsl`
- `rsrp-immutable-ledger`
- `rsrp-pqcrypto`
- `services/api-service`

Out of scope:
- Kernel and hypervisor integrity.
- Physical datacenter controls.
- External HSM/TSA implementation internals.

## 3. Trust Boundaries

| ID | Boundary | Security Property | Primary Controls |
|---|---|---|---|
| B-01 | External client -> API ingress | Authenticated entry only | TLS, JWT EdDSA-only, strict `iss` and `aud` |
| B-02 | API handlers -> policy/proof path | Input and context integrity | Typed validation, fail-closed parsing |
| B-03 | Proof/engine -> crypto providers | Algorithm and key policy integrity | Production profile, hybrid required |
| B-04 | Engine -> ledger append path | Tamper evidence and continuity | Hash chain, Merkle domain separation, compact proof |
| B-05 | Runtime -> entropy and key lifecycle | Secret handling safety | startup/runtime entropy checks, zeroization |
| B-06 | CI/release -> public artifacts | Supply-chain integrity | lockfile, deny/audit, SBOM, provenance, signature |

## 4. Protected Assets

| Asset ID | Asset | Security Need |
|---|---|---|
| AS-01 | Ed25519 and ML-DSA private keys | Confidentiality, lifecycle control |
| AS-02 | KEM secrets and shared secret material | Confidentiality, integrity |
| AS-03 | Canonical proof envelopes and signatures | Integrity, authenticity |
| AS-04 | Ledger entries, chain roots, inclusion proofs | Integrity, non-repudiation |
| AS-05 | Build outputs, SBOM, attestations | Integrity, provenance |
| AS-06 | Mission schedule and temporal policy state | Integrity, availability |

## 5. Attacker Models

| ID | Model | Capabilities | Objective |
|---|---|---|---|
| AM-01 | Remote unauthenticated attacker | Network access, malformed requests, replay attempts | Unauthorized access, DoS, fingerprinting |
| AM-02 | Authenticated malicious tenant | Valid token and API usage rights | Privilege escalation and policy bypass |
| AM-03 | Insider with limited platform access | Service credentials or log access | Evidence tampering or misuse |
| AM-04 | Supply-chain adversary | Dependency or artifact substitution path | Build/release compromise |
| AM-05 | Hostile host (container or VM compromise) | Runtime memory/process control on host | Secret extraction and trust erosion |

Hostile-host policy:
- AM-05 is treated as an operational resilience scenario, not a cryptographic correctness guarantee.
- Required compensating controls are defined in `docs/ASSUMPTIONS_REGISTER.md` and `docs/KEY_LIFECYCLE_POLICY.md`.

## 6. Threat Catalog (STRIDE)

| Threat ID | STRIDE | Threat | Preconditions | Primary Mitigations | Key Evidence |
|---|---|---|---|---|---|
| T1 | Spoofing | Signature forgery against proof/publication data | Attacker can alter payload or one signature branch | Mandatory dual verification (Ed25519 plus ML-DSA), strict algorithm binding | `rsrp-pqcrypto` hybrid forge tests |
| T2 | Elevation of Privilege | Temporal authorization bypass | Valid identity but out-of-window or missing schedule | Mission schedule persistence and fail-closed authorization | `api-service` mission schedule tests |
| T3 | Tampering and Repudiation | Ledger or Merkle proof manipulation | Storage or proof data tampering opportunity | Hash chain continuity, leaf/node domain separation, compact proof verification | `rsrp-immutable-ledger` and `rsrp-security-core` Merkle tests |
| T4 | Information Disclosure | Secret retention in memory after lifecycle events | Memory inspection capability | Zeroization on drop and lifecycle transitions, controlled logging | zeroization tests and key lifecycle evidence |
| T5 | Tampering | Supply-chain substitution of deps/artifacts | CI or distribution path interference | lockfile enforcement, deny/audit gates, SBOM, provenance and signing | workflow artifacts from production gates |
| T6 | Information Disclosure | Operational fingerprinting via health and readiness | Access to public endpoint exposure | production defaults deny public diagnostics unless explicitly allowed | startup config and endpoint policy checks |
| T7 | Denial of Service | Resource exhaustion through request floods or regex abuse | High request volume or expensive payloads | bounded rate limiting policy, external backend requirement in prod, parser constraints | middleware tests and runtime fail-closed checks |

## 7. Attack Potential Mapping

| Threat | Skill | Time | Equipment | Opportunity | Feasibility after Controls |
|---|---|---|---|---|---|
| T1 | Advanced | High | Specialized crypto tooling | Medium | Low |
| T2 | Intermediate | Medium | Standard API tooling | Medium | Low to Medium |
| T3 | Advanced | High | Storage access and custom proof tooling | Low to Medium | Low |
| T4 | Advanced | Medium to High | Memory extraction and debugging tools | Medium (if host compromised) | Medium |
| T5 | Advanced | Medium to High | CI credential theft and artifact substitution path | Medium | Medium |
| T6 | Basic to Intermediate | Low | Recon tooling | High if exposed | Low when hardened defaults applied |
| T7 | Intermediate | Low to Medium | Botnet or request automation | High | Medium |

## 8. Control Mapping to Code and Tests

| Control | Code Anchors | Test Anchors | CI/Gate |
|---|---|---|---|
| Hybrid signature enforcement | `crates/pqcrypto/src/hybrid.rs` | `rsrp-pqcrypto` hybrid tamper tests | production gate |
| Temporal RBAC fail-closed | `services/api-service/src/mission_schedule.rs`, `services/api-service/src/handlers.rs` | `api-service` mission schedule tests | workspace tests |
| Merkle and chain integrity | `crates/immutable-logging/src/chain.rs`, `crates/immutable-logging/src/merkle_service.rs`, `crates/crypto-core/src/merkle.rs` | compact-proof and domain-separation tests | workspace tests |
| Zeroization and key lifecycle | `crates/crypto-core/src/signature.rs`, `crates/pqcrypto/src/*` | zeroization tests | security-core tests |
| Entropy and FIPS posture | `crates/crypto-core/src/entropy.rs`, `services/api-service/src/main.rs` | entropy health tests | production gate |
| Supply-chain integrity | `Cargo.lock`, `deny.toml`, `.github/workflows/*.yml` | `cargo deny`, `cargo audit` | production gate, SBOM, signing, reproducible build |

## 9. Residual Risks

Residual risks remain and require governance controls:
- External trust anchors (HSM/TSA/PKI) and operator process quality.
- Host-level side channels and runtime introspection under AM-05.
- Multi-replica operational controls when external rate-limit backend is misconfigured.
- Vulnerability disclosure lag between upstream publication and patch release.

Tracked in:
- `docs/RISK_REGISTER.md`
- `docs/DEPENDENCY_RISK_ASSESSMENT.md`

## 10. Review and Change Control

This threat model must be reviewed when one of the following changes occurs:
- crypto backend, key policy, or algorithm profile changes.
- proof envelope, ledger, or Merkle verification changes.
- CI signing, provenance, or SBOM workflow changes.
- new deployment model including hostile-host assumptions.

Mandatory update rule:
1. Update this file.
2. Update `docs/SECURITY_TARGET.md` when claims change.
3. Update `docs/TRACEABILITY_MATRIX.md` with new anchors.
4. Update `docs/ASSUMPTIONS_REGISTER.md` for any new trust dependency.
