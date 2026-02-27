# R-SRP Certification Bundle

Version: 0.9.8
Date: 2026-02-27

## 1. Bundle Purpose

This bundle defines the minimum evidence set for external security review and certification-preparation assessments.

## 2. Required Documents

Core documents:
- `docs/SECURITY_TARGET.md`
- `docs/ATTACK_SCENARIOS.md`
- `docs/CRYPTO_ARCHITECTURE.md`
- `docs/TRACEABILITY_MATRIX.md`
- `docs/ENTROPY_BOUNDARY.md`
- `docs/ASSUMPTIONS_REGISTER.md`
- `docs/THREAT_MODEL.md`
- `docs/THREAT_MODEL_STRIDE.md`
- `docs/KEY_LIFECYCLE_POLICY.md`
- `docs/RISK_REGISTER.md`
- `docs/SUPPLY_CHAIN_POLICY.md`
- `docs/MERKLE_SECURITY_MODEL.md`

## 3. Required Technical Evidence

Code and tests:
- Hybrid signature verification tests
- Temporal RBAC tests
- Immutable log compact proof tests (`O(log n)`)
- Merkle second-preimage/domain-separation tests
- Zeroization tests and key lifecycle checks

Pipeline evidence:
- Production-only gate workflow run logs
- `cargo audit` and `cargo deny` reports
- SBOM artifacts and checksums
- Signature and provenance attestations
- Reproducible build comparison report

Risk acceptance evidence (when applicable):
- `docs/DEPENDENCY_RISK_ASSESSMENT.md` (explicit accepted-risk record, owner, review date, compensating controls)
- `deny.toml` justification entry referencing the accepted-risk record

## 4. Control-to-Evidence Mapping

- Cryptographic integrity:
  - code: `crates/pqcrypto`, `crates/immutable-logging`
  - docs: `CRYPTO_ARCHITECTURE.md`, `MERKLE_SECURITY_MODEL.md`
  - pipeline: `production-gate.yml`

- Access control and authorization:
  - code: `crates/crypto-core`, `crates/proof-engine`
  - docs: `THREAT_MODEL*.md`
  - tests: temporal mission-window enforcement

- Supply chain:
  - policy: `deny.toml`, `SUPPLY_CHAIN_POLICY.md`
  - pipeline: `production-gate.yml`, `sbom.yml`, `signing.yml`, `reproducible-build.yml`

## 5. Release Exit Criteria

All conditions must be true:
- Production profile builds pass (`rsrp-pqcrypto` with `production` feature).
- No mock crypto in production dependency graph.
- `cargo audit` and `cargo deny` gates pass according to policy.
- Public health endpoints policy enforced in production (`PUBLIC_HEALTH_ENDPOINTS` explicit opt-in only).
- Production deployment uses external shared rate limiting (`RATE_LIMIT_BACKEND=external`).
- SBOM generated and signed.
- Release artifacts signed and provenance attached.
- Compact chain proof verification tests pass.

## 6. Auditor Hand-off Checklist

- [ ] Security Target delivered
- [ ] Threat model and attack scenarios delivered
- [ ] Risk register updated with open items and owners
- [ ] CI evidence (run IDs, logs, artifacts) exported
- [ ] Supply-chain policy exceptions reviewed and dated
- [ ] Final compliance statement approved by security owner

## 7. Packaging Guidance

Recommended archive layout:

```text
certification-bundle/
  docs/
  ci-evidence/
  test-evidence/
  sbom/
  signatures/
  provenance/
```

Use immutable archive naming:
- `rsrp-certification-bundle-v<version>-<git-sha>.tar.gz`
