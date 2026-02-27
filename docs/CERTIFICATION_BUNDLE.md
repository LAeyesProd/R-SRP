# R-SRP Certification Bundle

Version: 0.9.9
Date: 2026-02-27
Owner: Security Engineering

## 1. Purpose

This document defines the mandatory evidence package for pre-certification and external audit hand-off.
A release is non-compliant if one required artifact is missing, unverifiable, or inconsistent with code and CI evidence.

## 2. Bundle Scope

Certification bundle coverage:
- Security claims and threat model consistency.
- Control implementation evidence in code and tests.
- Supply-chain integrity evidence (SBOM, provenance, signatures).
- Operational evidence for fail-closed production posture.

## 3. Mandatory Document Set

The following files are required and traceability-aligned to the release baseline:
- `docs/SECURITY_TARGET.md`
- `docs/THREAT_MODEL.md`
- `docs/THREAT_MODEL_STRIDE.md`
- `docs/ASSUMPTIONS_REGISTER.md`
- `docs/ATTACK_SCENARIOS.md`
- `docs/TRACEABILITY_MATRIX.md`
- `docs/CRYPTO_ARCHITECTURE.md`
- `docs/ENTROPY_BOUNDARY.md`
- `docs/KEY_LIFECYCLE_POLICY.md`
- `docs/MERKLE_SECURITY_MODEL.md`
- `docs/SUPPLY_CHAIN_POLICY.md`
- `docs/RISK_REGISTER.md`
- `docs/DEPENDENCY_RISK_ASSESSMENT.md`

## 4. Mandatory Technical Evidence

### 4.1 Code and Test Evidence

Required passing evidence:
- Hybrid signature forge-rejection tests.
- Temporal RBAC mission-window fail-closed tests.
- Compact chain proof `O(log n)` verification tests.
- Merkle domain-separation and second-preimage-resistance tests.
- Zeroization tests for key lifecycle paths.
- Entropy startup and runtime health-check tests.

Minimum command pack:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check --workspace --locked
cargo test -p rsrp-policy-dsl --locked
cargo test -p rsrp-security-core --locked
cargo test -p rsrp-pqcrypto --locked
cargo test -p rsrp-immutable-ledger --locked
cargo test -p rsrp-proof-engine --locked
cargo test -p api-service --locked
```

## 4.3 Required Technical Evidence

Code and tests:
- Hybrid signature verification tests
- Temporal RBAC tests
- Immutable log compact proof tests (`O(log n)`)
- Merkle second-preimage/domain-separation tests
- Zeroization tests and key lifecycle checks
- Entropy runtime self-test coverage and fail-closed readiness behavior

Pipeline evidence:
- Production-only gate workflow run logs
- `cargo audit` and `cargo deny` reports
- SBOM artifacts and checksums
- Signature and provenance attestations
- Reproducible build comparison report
- Fuzz campaign artifact (`fuzz-evidence.json` + per-target logs)

## 4. Control-to-Evidence Mapping

```bash
cargo build -p rsrp-pqcrypto --release --locked --no-default-features --features production
cargo test -p rsrp-pqcrypto --locked --no-default-features --features production --tests --no-run
```

### 4.2 CI and Supply-Chain Evidence

Required workflow evidence:
- `.github/workflows/production-gate.yml`
- `.github/workflows/sbom.yml`
- `.github/workflows/signing.yml`
- `.github/workflows/reproducible-build.yml`

Required outputs:
- `cargo deny` and `cargo audit` reports.
- SBOM artifact and checksum.
- provenance attestation.
- signed release artifact metadata.
- reproducible build comparison result.

## 5. Evidence Integrity Requirements

Bundle integrity constraints:
- every artifact must include release version and git commit SHA.
- all checksums must be listed in `MANIFEST.sha256`.
- bundle metadata must be signed (cosign or equivalent approved signer).
- provenance subject digest must match release artifacts and SBOM digest.

Mismatch in any digest or signature is a release blocker.

## 6. Packaging Layout

Required archive layout:

```text
certification-bundle/
  docs/
  ci-evidence/
  test-evidence/
  sbom/
  signatures/
  provenance/
  manifests/
    MANIFEST.sha256
    RELEASE_METADATA.json
```

Required archive naming:
- `rsrp-certification-bundle-v<version>-<git-sha>.tar.gz`

## 7. Hostile-Host Evidence Addendum

For attacker model `AM-05` (container or VM compromise), include:
- key rotation and revocation runbook execution proof.
- incident containment and re-establishment checklist.
- off-host evidence export confirmation.
- post-incident trust-anchor revalidation record.

Reference:
- `docs/ASSUMPTIONS_REGISTER.md`
- `docs/KEY_LIFECYCLE_POLICY.md`

## 8. Release Rejection Criteria (Fail-Closed)

Reject release if any condition is true:
- production build does not pass.
- mock backend appears in production feature graph.
- one required test class is missing or failing.
- `cargo deny` or `cargo audit` policy gates fail without approved exception record.
- SBOM, provenance, or signature artifact is missing or invalid.
- traceability links are stale against changed code anchors.
- document versions are inconsistent across the bundle.

## 9. Auditor Hand-off Checklist

- [ ] Full document set exported at released commit SHA.
- [ ] CI run IDs recorded for all required workflows.
- [ ] Test command outputs archived.
- [ ] SBOM/provenance/signature artifacts verified against manifest.
- [ ] Risk acceptances reviewed, justified, and dated.
- [ ] Final compliance sign-off recorded by security owner.

## 10. Governance Rule

Any release-criterion or evidence change requires updates in:
- this file,
- `docs/TRACEABILITY_MATRIX.md`,
- `docs/SECURITY_TARGET.md` if security claims are affected.
