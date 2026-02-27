# RSRP Key Lifecycle Policy

Date: 2026-02-27  
Owner: Security Operations

## 1. Scope

This policy applies to:

- ML-DSA signing keys
- ML-KEM key encapsulation keys
- Hybrid classical+PQ key material

## 2. Generation

- Production keys MUST be generated in approved cryptographic runtime (`real-crypto`).
- Non-production keys may use mock backend only for tests and local development.
- Key generation events must be logged with immutable audit evidence.

## 3. Storage

- Private keys are never persisted in plaintext.
- Memory containing secrets must be zeroized after use.
- Long-lived keys must be stored in HSM/KMS where available.

## 4. Rotation

- Standard rotation interval: 12 months maximum.
- Emergency rotation must complete within 24h after compromise suspicion.
- Rotation requires dual-control approval and ticket traceability.

## 5. Revocation

- Compromised keys are revoked immediately.
- Revocation records are immutable and linked to incident IDs.
- Services must reject revoked key IDs at verification time.

## 6. Destruction

- Destroy retired key material using secure erase procedures.
- Maintain destruction attestations for audit.

## 7. Separation of Duties

- Key generation, approval, and deployment cannot be performed by one person alone.
- Break-glass operations require post-incident review.

## 8. Operational Demonstration Requirements

The following evidence is required for external audit review:

| Lifecycle Phase | Required Evidence | Verification Command / Source |
|---|---|---|
| Generation | proof of approved crypto profile and generation path | `cargo build -p rsrp-pqcrypto --release --locked --no-default-features --features production` |
| Activation | configuration evidence showing production-safe signer selection | API startup logs + deployment env (`AUDIT_PUBLICATION_SIGNING_PROVIDER`, runtime checks) |
| Use | signature verification evidence from automated tests | `cargo test -p rsrp-security-core --locked` and `cargo test -p api-service --locked` |
| Rotation | traceable change request + new key_id + rollout evidence | change ticket, release notes, immutable audit entries |
| Revocation | incident-linked revocation record and enforcement evidence | incident record + verifier rejection logs/tests |
| Destruction | destruction attestation and post-destruction verification | key custody attestation + operational runbook records |

## 9. Current Implementation Status

- Implemented in code:
  - key generation and signing primitives,
  - zeroization checks,
  - production profile gating and runtime fail-closed checks.
- Operationally required outside crate code:
  - key ceremony records,
  - revocation workflow execution proof,
  - destruction attestations from HSM/KMS or approved operator process.

## 10. Audit Packaging

Attach the following to the certification bundle:
- command outputs listed in section 8,
- immutable audit excerpts for key lifecycle events,
- signed runbook execution logs for rotation/revocation exercises.
