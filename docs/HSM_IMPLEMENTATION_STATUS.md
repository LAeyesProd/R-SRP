# R-SRP HSM Implementation Status

Version: 0.9.9  
Date: 2026-02-27  
Owner: Security Engineering

## 1. Purpose

This document prevents claim drift between documentation and implementation for signer custody.

## 2. Current TOE Status

- Implemented and available:
  - `HsmType::SoftHSM` test/non-production backend in `crates/crypto-core/src/hsm.rs`.
  - Ed25519 signing and verification through `HsmSigner` with key-handle abstraction.
- Not implemented in this open-source TOE build:
  - `HsmType::ThalesLuna`
  - `HsmType::Utimaco`
  - `HsmType::AwsCloudHsm`
  - `HsmType::AzureKeyVault`

Session creation for non-implemented backend types returns an explicit error.

## 3. Runtime Guardrails

- `SoftHSM` is rejected in production profile (`ENV`/`APP_ENV`/`RUST_ENV`/`RSRP_DEPLOYMENT_PROFILE` set to production values).
- Outside tests, `SoftHSM` requires explicit opt-in:
  - `RSRP_ALLOW_SOFT_HSM=1`
- Fail-closed behavior:
  - no implicit fallback from declared hardware backend type to `SoftHSM`.

## 4. Certification Position

- Hardware HSM integration is outside the current TOE implementation boundary.
- Deployments requiring certified hardware custody must provide external signer/KMS controls and evidence at deployment level.
- Security claims in certification documents must reference this status file.

## 5. Evidence

- Code anchor: `crates/crypto-core/src/hsm.rs`
- Test anchor: `hsm::tests::test_soft_hsm*`
- Traceability: `docs/TRACEABILITY_MATRIX.md` (`C-HSM-001`, `C-HSM-002`)
