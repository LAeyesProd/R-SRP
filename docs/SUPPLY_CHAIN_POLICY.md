# RSRP Supply Chain Policy

Date: 2026-02-27  
Owner: DevSecOps

## 1. Objectives

- Prevent introduction of malicious dependencies
- Ensure build provenance and reproducibility
- Maintain auditable artifact integrity

## 2. Dependency Controls

- All Rust dependencies are lockfile-pinned (`Cargo.lock` committed).
- Security scanning is mandatory (`cargo audit`, deny policy, advisories review).
- Unmaintained/critical dependency findings require tracked remediation.

## 3. Build Provenance

- Production artifacts must be built in controlled Linux containers.
- Builds must emit SBOM and signed attestations.
- Build jobs for `real-crypto` must validate liboqs/libclang toolchain.

## 4. Artifact Integrity

- Release artifacts are signed before publication.
- Signatures and checksums are verified during deployment.
- Promotion between environments requires signature verification gates.

## 5. Reproducibility

- Reproducible build checks are mandatory for release candidates.
- Any hash mismatch across trusted build environments blocks release.

## 6. Exception Management

- Exceptions require documented risk acceptance and expiration date.
- Emergency exceptions must be reviewed within one business day.
