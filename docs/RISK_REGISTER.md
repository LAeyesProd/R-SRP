# RSRP Risk Register

Date: 2026-02-27  
Owner: Security + Platform

## Current Risks

| ID | Risk | Area | Likelihood | Impact | Treatment | Owner | Status |
|---|---|---|---|---|---|---|---|
| R-001 | Mock backend accidentally deployed in production | Crypto | Medium | Critical | Feature-gate hardening + release compile errors | Crypto Team | Mitigated |
| R-002 | Algorithm drift from approved baseline | Crypto governance | Medium | High | Freeze baseline to ML-KEM-768 / ML-DSA-65 via `production` feature | Crypto Team | Mitigated |
| R-003 | Verbose logging leaks operational metadata | Observability | Medium | High | Reject debug/trace in production-hardening | Platform | Mitigated |
| R-004 | Runtime config weakens hybrid guarantees | Runtime configuration | Medium | High | Reject `RSRP_HYBRID_REQUIRED=false` under production profile | Platform | Mitigated |
| R-005 | OQS toolchain inconsistency across environments | Build pipeline | High | High | Standardized Linux container build with external `liboqs` | DevSecOps | Mitigated |
| R-006 | Transitive dependency compromise | Supply chain | Medium | Critical | SBOM/signing/reproducible build controls | DevSecOps | Active |
| R-007 | Key lifecycle non-conformance | Key management | Low | Critical | Enforce lifecycle policy and rotation evidence | Security Ops | Active |

## Risk Acceptance Rules

- No acceptance for Critical risks without CISO sign-off.
- High risks require documented compensating controls and due date.
- All production crypto exceptions are time-boxed and ticketed.
