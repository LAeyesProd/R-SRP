# RSRP Supply Chain Policy

Date: 2026-02-27
Owner: DevSecOps

## 1. Policy Goal

This policy enforces verifiable software integrity from source to released artifact.

## 2. Trust Boundaries

- Trusted source registry: `https://github.com/rust-lang/crates.io-index` only.
- Untrusted sources: ad-hoc git dependencies, unsigned artifacts, mutable lockfiles.
- CI is the authoritative build path for releasable artifacts.

## 3. Mandatory Dependency Controls

- `Cargo.lock` is required and must be used with `--locked` in CI.
- `cargo deny` gates are blocking for advisories, bans, licenses, and sources.
- `cargo audit` is blocking except documented, dated exceptions.
- Wildcard dependency requirements are forbidden.
- New dependency introduction requires security review and owner approval.

## 4. Production-Only Cryptography Gate

- Production builds must use the `production` feature profile.
- `mock-crypto` is forbidden in production dependency graph and release build.
- `rsrp-demo` and `rsrp-pqcrypto` production builds are mandatory CI gates.

## 5. Build Integrity and Reproducibility

- Release builds must be deterministic (`SOURCE_DATE_EPOCH`, `--locked`).
- Cross-runner reproducibility checks are required before release promotion.
- Any reproducibility hash mismatch blocks release.

## 6. Artifact Integrity

- Release artifacts require cryptographic signature before publication.
- SBOM generation is mandatory for release candidates.
- Provenance metadata (SLSA/in-toto compatible) must be attached to release pipeline outputs.
- Deployment gates must verify checksum and signature prior to promotion.

## 7. Operational Controls

- Two-person review required for dependency policy exceptions.
- Exception entries must include:
  - risk statement,
  - ticket/issue link,
  - expiration date,
  - compensating controls.
- Emergency exceptions are temporary and reviewed within one business day.

## 8. Monitoring and Review Cadence

- Advisory review: daily automated, weekly human review.
- SBOM refresh: every release and at least monthly for long-lived branches.
- Policy review: quarterly or after major supply-chain incident.

## 9. Incident Response for Supply-Chain Events

- Immediate actions: freeze release promotion, identify affected artifacts, revoke trust on impacted signatures.
- Containment: lock dependency graph, pin safe versions, regenerate SBOM and attestations.
- Recovery: rebuild from trusted commit and publish signed remediation artifacts.

## 10. Evidence Locations

- Policy config: `deny.toml`
- CI gates: `.github/workflows/production-gate.yml`, `.github/workflows/reproducible-build.yml`, `.github/workflows/sbom.yml`, `.github/workflows/signing.yml`
- Certification mapping: `docs/CERTIFICATION_BUNDLE.md`
