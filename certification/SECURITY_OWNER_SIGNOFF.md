# SECURITY OWNER SIGNOFF

This template defines the minimum approval payload for P1 certification evidence.

Required fields in the generated sign-off statement:
- `status`: must be `APPROVED`
- `commit_sha`: Git commit bound to the certification run
- `artifact_name`: TOE binary identifier
- `artifact_sha256`: SHA-256 of the exact TOE artifact covered by provenance
- `sbom_archive`: signed SBOM bundle name
- `provenance_file`: in-toto provenance statement name
- `approved_by`: security owner role or group
- `generated_at`: UTC timestamp of the approval record
- `workflow_run_id`: GitHub Actions run identifier

The certification gate must fail closed if the sign-off statement is missing, unsigned, or references a different commit or artifact digest.
