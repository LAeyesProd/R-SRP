# R-SRP Release Notes

Version: `v1.1.0-hardened`  
Date: `2026-02-27`  
Type: Security hardening release

## Summary

This release closes remaining hard-audit hardening items and strengthens production fail-closed controls across API, crypto, WAL integrity, and CI evidence.

## Key Changes

### 1) Runtime hardening (fail-closed)
- CRUE evaluation now fails closed when no active rules are loaded.
- CRUE responses now fail closed when no matching rule is found.
- Daily publication path now uses a mutex lock to avoid concurrent publication races.
- Production startup now requires an audit publication signer.

### 2) Auth and policy enforcement
- JWT now enforces `nbf` validation and maximum token lifetime (`JWT_MAX_EXPIRY_SECONDS`, default `3600`).
- `legal_basis` is now mandatory for GET and POST validation requests.

### 3) Sensitive data protection
- SoftHSM key handling now explicitly zeroizes seed and in-memory key buffers during replacement and shutdown.

### 4) WAL tamper evidence hardening
- Optional WAL entry signing added via `IMMUTABLE_LOG_WAL_SIGNING_SECRET`.
- WAL replay now verifies signed records and rejects invalid signatures.
- Signed mode rejects unsigned WAL lines.

### 5) Abuse resistance and response hardening
- Per-identity rate limiting added server-side.
- Client-supplied request counters were removed from API request models.
- Security response headers added globally (`nosniff`, `DENY`, CSP, no-store, etc.).

### 6) Audit evidence and CI
- Non-production PQ tests now explicitly labeled (`*_non_production_profile_*`).
- Production-profile PQ tests added (`*_production_profile_*`).
- Fuzz evidence pipeline added with structured campaign output (`fuzz-evidence.json`).
- Production gate now enforces health/readiness leak controls.

## Verification Performed

- `cargo fmt --all`
- `cargo check --workspace --locked`
- `cargo test -p api-service --locked`
- `cargo test -p rsrp-security-core --locked`
- `cargo test -p rsrp-immutable-ledger --locked`
- `cargo test -p rsrp-pqcrypto --locked`

## Certification Artifacts

- Main compliance dossier: `docs/CERTIFICATION_BUNDLE.md`
- Security target: `docs/SECURITY_TARGET.md`
- Traceability matrix: `docs/TRACEABILITY_MATRIX.md`

For GitHub release publication, attach:
- `docs/CERTIFICATION_BUNDLE.md`
- `docs/RELEASE_NOTES_v1.1.0-hardened.md`

