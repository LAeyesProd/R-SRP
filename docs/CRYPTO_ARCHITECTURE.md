# RSRP Crypto Architecture

Date: 2026-02-27  
Owner: Security Engineering

## 1. Baseline Decisions

- Default KEM profile for production: `ML-KEM-768`
- Default signature profile for production: `ML-DSA-65`
- Hybrid mode is mandatory in production (classical + PQ)
- Mock backend is development-only

## 2. Feature-Gate Policy

`rsrp-pqcrypto` exposes:

- `mock-crypto`: deterministic non-production backend
- `real-crypto`: liboqs-backed backend
- `production`: hardened profile

`production` expands to:

```toml
production = ["real-crypto", "kyber768", "dilithium3"]
```

The crate enforces:

- no `production + mock-crypto`
- no `production` without `real-crypto`
- no release build with mock backend
- no non-frozen algorithm set under `production`

## 3. Runtime Security Controls

When `production` is enabled:

- `RUST_LOG=debug|trace` is rejected
- `RSRP_HYBRID_REQUIRED=false|0|off` is rejected
- KEM level is frozen to `Kyber768`
- Signature level is frozen to `Dilithium3`

## 4. Integration Contract

For application crates (example `rsrp-demo`):

- expose local feature `production = ["real-crypto", "rsrp-pqcrypto/production"]`
- do not hardwire `mock-crypto` in transitive features for production paths
- validate runtime security config at process startup

## 5. Compliance Notes

- Aligns with FIPS 203/204 NIST PQ standards
- Supports deterministic gating for audit evidence
- Designed for SOC2/ISO 27001 control mapping:
  - cryptographic policy freezing
  - runtime hardening
  - secure defaults

## 6. Mandatory Companion Documents

To avoid documentation/code divergence, this document is normative together with:
- `docs/TRACEABILITY_MATRIX.md`
- `docs/ENTROPY_BOUNDARY.md`
- `docs/ASSUMPTIONS_REGISTER.md`
- `docs/KEY_LIFECYCLE_POLICY.md`

Any security-relevant code change affecting crypto behavior must update this set in the same PR.
