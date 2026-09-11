# PR #20 Audit

- Repository: `LAeyesProd/R-SRP`
- Pull request: `#20`
- URL: `https://github.com/LAeyesProd/R-SRP/pull/20`
- Auditor: `Copilot Task Agent`
- Date: `2026-09-11`

## Summary

The review found 3 actionable issues in the merged changeset.

## Findings

### 1. High — Reproducibility gate does not bind to the released TOE artifact

- Affected files:
  - `/home/runner/work/R-SRP/R-SRP/scripts/certification-gate.sh`
  - `/home/runner/work/R-SRP/R-SRP/scripts/verify-reproducibility.sh`
  - `/home/runner/work/R-SRP/R-SRP/.github/workflows/certification-gate.yml`
- Evidence:
  - `scripts/certification-gate.sh` reads `certification/evidence/toe/rsrp-demo.sha256` but only calls `verify-reproducibility.sh` with `build-a.json` and `build-b.json`.
  - `scripts/verify-reproducibility.sh` compares build A and build B digests to each other, but never checks either digest against the TOE artifact digest.
- Impact:
  - Certification can pass even when the published TOE artifact differs from both reproducibility builds.
- Recommendation:
  - Require the reproducibility gate to compare the TOE digest against both reproducibility metadata digests, not only A vs B.

### 2. High — Security-sensitive workflows use a mutable GitHub Action reference

- Affected files:
  - `/home/runner/work/R-SRP/R-SRP/.github/workflows/build-toe.yml`
  - `/home/runner/work/R-SRP/R-SRP/.github/workflows/reproducible-build.yml`
  - `/home/runner/work/R-SRP/R-SRP/.github/workflows/provenance.yml`
  - `/home/runner/work/R-SRP/R-SRP/.github/workflows/certification-gate.yml`
- Evidence:
  - Multiple jobs use `dtolnay/rust-toolchain@master`.
- Impact:
  - The build and certification pipeline depends on a mutable branch and can change without a repository change, weakening reproducibility and supply-chain integrity.
- Recommendation:
  - Pin the action to an immutable release or commit SHA.

### 3. Medium — Certification gate does not enforce all documented sign-off fields

- Affected files:
  - `/home/runner/work/R-SRP/R-SRP/certification/SECURITY_OWNER_SIGNOFF.md`
  - `/home/runner/work/R-SRP/R-SRP/scripts/certification-gate.sh`
- Evidence:
  - The policy requires `artifact_name`, `sbom_archive`, `provenance_file`, `generated_at`, and `workflow_run_id`.
  - The gate validates only `status`, `commit_sha`, `artifact_sha256`, `approved_by`, `approval_environment`, and `approval_enforced`.
- Impact:
  - An incomplete or weakly bound sign-off statement can still satisfy the gate.
- Recommendation:
  - Fail closed when any required field is missing or inconsistent with the expected artifact, provenance, or workflow run metadata.

## Verdict

PR #20 should be considered to have introduced material audit gaps in certification and supply-chain assurance, even though the new controls improve documentation and artifact generation coverage.
