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
| C-HSM-002 | SoftHSM is fail-closed in production and requires explicit non-production opt-in outside tests. | `crates/crypto-core/src/hsm.rs` | `cargo test -p rsrp-security-core --locked` | runtime profile checks at boot/session creation | startup/session error logs + deployment env snapshot |
| C-LEDGER-001 | Chain proof is compact and verifiable in `O(log n)`. | `crates/immutable-logging/src/chain.rs` | `chain::tests::test_chain_proof_is_compact_logarithmic` | `cargo test -p rsrp-immutable-ledger --locked` | Immutable-ledger test logs |
| C-LEDGER-002 | Merkle hashing uses leaf/node domain separation prefixes. | `crates/immutable-logging/src/merkle_service.rs`, `crates/crypto-core/src/merkle.rs` | `test_leaf_and_node_hash_domain_separation`, `test_merkle_domain_separation_leaf_vs_node` | `cargo test -p rsrp-security-core --locked`, `cargo test -p rsrp-immutable-ledger --locked` | Dual-crate test logs |
| C-API-001 | Public health endpoints are disabled by default in production unless explicitly opted in, and health payload version stays redacted unless explicit override is set. | `services/api-service/src/main.rs`, `services/api-service/src/handlers.rs` | `main::tests::test_production_profile_disables_public_health_and_ready_routes`, `main::tests::test_production_health_opt_in_still_redacts_version` | `cargo test -p api-service --locked` | API test logs + startup logs with effective config |
| C-API-002 | In-memory local rate limiting is forbidden in production; external backend required. | `services/api-service/src/main.rs`, `services/api-service/src/middleware.rs` | `middleware::tests::*` | Runtime fail-closed check at boot | Startup logs + deployment manifest |
| C-PUB-001 | Daily publication date is derived from logged hourly roots, not directly from wall clock for publication decision. | `services/api-service/src/handlers.rs`, `crates/immutable-logging/src/publication.rs` | `handlers::tests::test_latest_hourly_root_date_uses_logged_hour_prefix` | `cargo test -p api-service --locked` | API test logs + publication JSON sample |
| C-SC-001 | Any accepted supply-chain exception is explicitly justified and review-dated. | `deny.toml`, `docs/DEPENDENCY_RISK_ASSESSMENT.md` | `cargo deny check advisories bans licenses sources` | `.github/workflows/production-gate.yml` | `cargo deny` output + risk acceptance record |
| C-TEST-001 | Fuzzing evidence is reproducible and archived with target-level duration/corpus/crash metrics. | `scripts/run_fuzz_evidence.sh`, `fuzz/fuzz_targets/*.rs` | `bash scripts/run_fuzz_evidence.sh` | `.github/workflows/fuzz-evidence.yml`, `.github/workflows/formal-verification.yml` | `fuzz-evidence.json` + campaign logs artifact |
| C-TEST-002 | Non-production crypto vectors (Kyber512/Dilithium2) are explicitly labeled and segregated from production-profile tests. | `crates/pqcrypto/src/kem.rs`, `crates/pqcrypto/src/signature.rs`, `crates/pqcrypto/src/hybrid.rs` | `*_non_production_profile_*`, `*_production_profile_*` tests | `cargo test -p rsrp-pqcrypto --locked` | PQCrypto test logs and coverage labels |

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

