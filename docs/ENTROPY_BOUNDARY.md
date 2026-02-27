# R-SRP Entropy Boundary

Version: 0.9.8  
Date: 2026-02-27  
Owner: Security Engineering

## 1. Scope

This document defines:
- where entropy enters the system,
- which code paths are allowed in production,
- fail-closed behavior when entropy or crypto runtime requirements are not met.

## 2. Boundary Definition

Entropy boundary includes:
- OS-provided CSPRNG (`OsRng`) access from runtime process context.
- Production crypto key generation paths in `rsrp-security-core` and `rsrp-pqcrypto`.

Out of entropy boundary:
- user-provided secrets used for deterministic derivation (`derive_from_secret`),
- mock crypto randomness (`thread_rng`) used in non-production feature sets,
- external HSM entropy internals (treated as external trusted service).

## 3. Source-to-Control Mapping

| Component | Entropy Source | Production Status | Fail-Closed Behavior |
|---|---|---|---|
| `crates/crypto-core/src/signature.rs` (`Ed25519KeyPair::generate*`) | `OsRng` primary, fallback only when FIPS disabled | Allowed | `FipsMode::Enabled` and `FipsMode::Strict` return error when OS entropy is unavailable |
| `crates/pqcrypto/src/hybrid.rs` (Ed25519/X25519 generation) | `OsRng` | Allowed (`real-crypto` / `production`) | Build/profile gates forbid mock-only production |
| `crates/pqcrypto/src/kem.rs`, `crates/pqcrypto/src/signature.rs` mock paths | `thread_rng` | Forbidden in production/release | Compile-time guards reject mock in release/production |
| `crates/crypto-core/src/hsm.rs` (`SoftHSM`) | `OsRng` for test-key generation | Forbidden in production | Runtime boot fails in production for `SoftHSM` |
| `services/api-service` publication software signer | Deterministic `derive_from_secret` from externally managed secret | Forbidden in production | Boot fails in production if software signer is selected |

## 4. Operational Requirements

- Production deployments must use:
  - `rsrp-pqcrypto` with `production` feature,
  - HSM-backed or equivalent approved signing custody for long-lived keys,
  - documented secret provenance for any deterministic derivation inputs.
- Any entropy degradation event must be logged and treated as security-significant.

## 5. Evidence Requirements

Mandatory evidence for release/certification package:
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo check --workspace --locked`
- `cargo test -p rsrp-security-core --locked` (FIPS/zeroization relevant tests)
- `cargo build -p rsrp-pqcrypto --release --locked --no-default-features --features production`
- startup logs proving production reject behavior for disallowed runtime profiles.

## 6. Audit Notes

This boundary must be reviewed whenever:
- RNG primitives change,
- production feature policy changes,
- key custody model changes (software signer/HSM/KMS),
- deployment architecture changes (container, VM, hostile-host assumptions).

