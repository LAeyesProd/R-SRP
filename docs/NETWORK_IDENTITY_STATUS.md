# R-SRP Network Identity Status

Version: 0.9.9  
Date: 2026-02-27  
Owner: Security Engineering

## Current TOE Implementation

- Service-to-service identity enforcement is implemented via mTLS with X.509 validation.
- TLS enforcement and certificate checks are implemented in `services/api-service/src/tls.rs`.
- SPIFFE/SVID URI-SAN policy validation is not implemented in the current TOE.

## Certification Claim Boundary

- Do not claim SPIFFE/SVID enforcement for v0.9.9 TOE evidence.
- Zero-Trust claim for this version must be limited to:
  - mTLS X.509 enforcement,
  - JWT EdDSA validation with strict claim checks,
  - fail-closed runtime controls documented in the Security Target.

## Evidence

- Code anchors:
  - `services/api-service/src/tls.rs`
  - `services/api-service/src/auth.rs`
  - `services/api-service/src/main.rs`
- Documentation anchors:
  - `docs/SECURITY_TARGET.md`
  - `docs/THREAT_MODEL.md`
