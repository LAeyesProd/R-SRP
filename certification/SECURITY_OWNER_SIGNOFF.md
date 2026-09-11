# SECURITY OWNER SIGNOFF

This template defines the minimum approval payload for P1 certification evidence.

The sign-off job must run in the protected GitHub environment `security-owner-signoff`.
That environment must require independent reviewers and expose an environment-scoped
secret named `SECURITY_SIGNOFF_SENTINEL` so the workflow fails closed if the protected
approval context is missing.

Required fields in the generated sign-off statement:
- `status`: must be `APPROVED`
- `commit_sha`: Git commit bound to the certification run
- `artifact_name`: TOE binary identifier
- `artifact_sha256`: SHA-256 of the exact TOE artifact covered by provenance
- `sbom_archive`: signed SBOM bundle name
- `provenance_file`: in-toto provenance statement name
- `approved_by`: security owner role or group
- `approval_environment`: must be `security-owner-signoff`
- `approval_enforced`: must be `true`
- `generated_at`: UTC timestamp of the approval record
- `workflow_run_id`: GitHub Actions run identifier

The certification gate must fail closed if the sign-off statement is missing, unsigned, or references a different commit or artifact digest.
