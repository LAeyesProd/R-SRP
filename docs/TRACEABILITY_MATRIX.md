# R-SRP Traceability Matrix

Version: 0.9.9  
Date: 2026-02-27  
Owner: Security Engineering

## 1. Purpose

This matrix prevents audit failures caused by divergence between:
- security claims in documentation,
- implemented controls in code,
- executed controls in CI,
- archived evidence in release bundles.

Rule: a PR that changes any code anchor below must update this matrix and the referenced control document.

## 2. Control Traceability

| Control ID | Security Claim | Code Anchors | Test Anchors | CI / Gate | Evidence Artifact |
|---|---|---|---|---|---|
| C-CRYPTO-001 | Production crypto profile is frozen (`ML-KEM-768`, `ML-DSA-65`) and mock backend is forbidden in production/release. | `crates/pqcrypto/src/lib.rs` | `cargo test -p rsrp-pqcrypto --no-default-features --features production --tests --no-run` | `.github/workflows/production-gate.yml` | Production gate logs + feature tree artifact |
| C-CRYPTO-002 | JWT validation is EdDSA-only, with strict `iss`/`aud` validation. | `services/api-service/src/auth.rs` | `auth::tests::test_parse_jwt_algorithm_rejects_hs256_and_rs256` | `cargo test -p api-service --locked` | Test logs in CI evidence pack |
| C-ACCESS-001 | Temporal RBAC is fail-closed when mission schedule is missing/unknown/out-of-window. | `services/api-service/src/mission_schedule.rs`, `services/api-service/src/handlers.rs` | `mission_schedule::tests::*` | `cargo test -p api-service --locked` | API test logs + runtime config snapshot (`MISSION_SCHEDULE_PATH`) |
| C-HSM-001 | SoftHSM verification uses public-key verification, not sign-then-compare. | `crates/crypto-core/src/hsm.rs` | `hsm::tests::test_soft_hsm*` | `cargo test -p rsrp-security-core --locked` | Security-core test logs |
| C-LEDGER-001 | Chain proof is compact and verifiable in `O(log n)`. | `crates/immutable-logging/src/chain.rs` | `chain::tests::test_chain_proof_is_compact_logarithmic` | `cargo test -p rsrp-immutable-ledger --locked` | Immutable-ledger test logs |
| C-LEDGER-002 | Merkle hashing uses leaf/node domain separation prefixes. | `crates/immutable-logging/src/merkle_service.rs`, `crates/crypto-core/src/merkle.rs` | `test_leaf_and_node_hash_domain_separation`, `test_merkle_domain_separation_leaf_vs_node` | `cargo test -p rsrp-security-core --locked`, `cargo test -p rsrp-immutable-ledger --locked` | Dual-crate test logs |
| C-API-001 | Public health endpoints are disabled by default in production unless explicitly opted in. | `services/api-service/src/main.rs` | `cargo check -p api-service --locked` | Runtime policy check at boot | Startup logs with effective config |
| C-API-002 | In-memory local rate limiting is forbidden in production; external backend required. | `services/api-service/src/main.rs`, `services/api-service/src/middleware.rs` | `middleware::tests::*` | Runtime fail-closed check at boot | Startup logs + deployment manifest |
| C-ENTROPY-001 | Entropy health is checked at startup and continuously at runtime; readiness is fail-closed when configured. | `crates/crypto-core/src/entropy.rs`, `services/api-service/src/main.rs`, `services/api-service/src/handlers.rs` | `entropy::tests::test_entropy_health_check_reports_ok` | `.github/workflows/production-gate.yml` | startup/readiness logs + entropy self-test CI logs |
| C-PUB-001 | Daily publication date is derived from logged hourly roots, not directly from wall clock for publication decision. | `services/api-service/src/handlers.rs`, `crates/immutable-logging/src/publication.rs` | `handlers::tests::test_latest_hourly_root_date_uses_logged_hour_prefix` | `cargo test -p api-service --locked` | API test logs + publication JSON sample |
| C-SC-001 | Any accepted supply-chain exception is explicitly justified and review-dated. | `deny.toml`, `docs/DEPENDENCY_RISK_ASSESSMENT.md` | `cargo deny check advisories bans licenses sources` | `.github/workflows/production-gate.yml` | `cargo deny` output + risk acceptance record |

## 3. Verification Command Pack

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check --workspace --locked
cargo test -p rsrp-security-core --locked
cargo test -p rsrp-immutable-ledger --locked
cargo test -p api-service --locked
```

For production controls:

```bash
cargo build -p rsrp-pqcrypto --release --locked --no-default-features --features production
cargo test -p rsrp-pqcrypto --locked --no-default-features --features production --tests --no-run
```
