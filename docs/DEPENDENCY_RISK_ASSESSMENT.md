# Dependency Risk Assessment
Date: `2026-02-27`  
Scope: `RSRP workspace dependency posture before external audit`

## 1. Context
This note documents the remaining dependency risk that is currently accepted with controls, after pre-audit hardening.

## 2. Active Risk Item
### DR-001: `rustls-pemfile` unmaintained (transitive)
- Advisory: `RUSTSEC-2025-0134`
- Package: `rustls-pemfile 2.2.0`
- Exposure path: transitive via `axum-server` in `services/api-service`
- Mandatory review deadline: `2026-03-31` (tracked in `deny.toml` exception)
- Current status:
  - direct usages removed from codebase (`api-service` now uses `rustls::pki_types::pem::PemObject`)
  - no direct import of `rustls-pemfile` remains in workspace manifests

## 3. Impact Assessment
- Confidentiality: `Low`
- Integrity: `Low`
- Availability: `Low`
- Rationale:
  - advisory category is `unmaintained`, not a known exploitable vulnerability with published patch
  - affected crate is transitively pulled by server stack; functional path in RSRP no longer depends on its API directly

## 4. Compensating Controls
1. Supply-chain gates active in CI:
   - `cargo audit`
   - `cargo deny`
   - strict `clippy` + tests
2. Runtime controls:
   - TLS config path in `api-service` migrated away from direct `rustls-pemfile` use.
3. Release controls:
   - SBOM generated and signed (Cosign keyless) for traceability.

## 5. Decision
- Decision: `Temporary risk acceptance with monitoring`
- Acceptance window: until upstream dependency graph no longer includes `rustls-pemfile`
- Escalation trigger:
  - new CVE/RUSTSEC with exploitable impact on the transitive path
  - available stable migration path in `axum-server`/dependency chain
  - review deadline reached without re-assessment

## 6. Remediation Plan
1. Track upstream migration away from `rustls-pemfile` in `axum-server` stack.
2. Re-run `cargo tree -i rustls-pemfile -e normal` at each release candidate.
3. Remove risk acceptance once transitive dependency is eliminated.

## 7. Verification Commands
```bash
cargo audit --json
cargo deny check advisories
cargo tree -i rustls-pemfile -e normal
```

## 8. Ownership
- Technical owner: `RSRP maintainers`
- Review cadence: each release and quarterly security review.
