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
