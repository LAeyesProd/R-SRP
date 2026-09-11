#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <evidence-root> <github-repository> <expected-commit>" >&2
  exit 64
fi

EVIDENCE_ROOT="$1"
GITHUB_REPOSITORY="$2"
EXPECTED_COMMIT="$3"
IDENTITY_REGEXP="^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/certification-gate.yml@.*$"

TOE_DIGEST_FILE="$EVIDENCE_ROOT/toe/rsrp-demo.sha256"
SBOM_JSON="$EVIDENCE_ROOT/sbom/rsrp.cdx.json"
SBOM_ARCHIVE="$EVIDENCE_ROOT/sbom/rsrp-sbom-${EXPECTED_COMMIT}.tar.gz"
SBOM_CHECKSUM="$SBOM_ARCHIVE.sha256"
SBOM_SIG="$SBOM_ARCHIVE.sig"
SBOM_CERT="$SBOM_ARCHIVE.pem"
PROVENANCE_FILE="$EVIDENCE_ROOT/provenance/provenance.intoto.jsonl"
PROVENANCE_SIG="$PROVENANCE_FILE.sig"
PROVENANCE_CERT="$PROVENANCE_FILE.pem"
BUILD_A_JSON="$EVIDENCE_ROOT/reproducibility/build-a.json"
BUILD_B_JSON="$EVIDENCE_ROOT/reproducibility/build-b.json"
SIGNOFF_JSON="$EVIDENCE_ROOT/signoff/SECURITY_OWNER_SIGNOFF.json"
SIGNOFF_SIG="$SIGNOFF_JSON.sig"
SIGNOFF_CERT="$SIGNOFF_JSON.pem"

for path in "$TOE_DIGEST_FILE" "$SIGNOFF_JSON" "$SIGNOFF_SIG" "$SIGNOFF_CERT"; do
  [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
done

TOE_DIGEST="$(awk '{print $1}' "$TOE_DIGEST_FILE")"
[ -n "$TOE_DIGEST" ] || { echo "empty TOE digest" >&2; exit 1; }

"$(dirname "$0")/verify-sbom.sh" \
  "$SBOM_JSON" \
  "$SBOM_ARCHIVE" \
  "$SBOM_CHECKSUM" \
  "$SBOM_SIG" \
  "$SBOM_CERT" \
  "$IDENTITY_REGEXP"

"$(dirname "$0")/verify-provenance.sh" \
  "$PROVENANCE_FILE" \
  "$TOE_DIGEST" \
  "$EXPECTED_COMMIT" \
  "$PROVENANCE_SIG" \
  "$PROVENANCE_CERT" \
  "$IDENTITY_REGEXP"

"$(dirname "$0")/verify-reproducibility.sh" "$BUILD_A_JSON" "$BUILD_B_JSON"

SIGNOFF_STATUS="$(jq -r '.status // empty' "$SIGNOFF_JSON")"
SIGNOFF_COMMIT="$(jq -r '.commit_sha // empty' "$SIGNOFF_JSON")"
SIGNOFF_DIGEST="$(jq -r '.artifact_sha256 // empty' "$SIGNOFF_JSON")"
SIGNOFF_OWNER="$(jq -r '.approved_by // empty' "$SIGNOFF_JSON")"

[ "$SIGNOFF_STATUS" = "APPROVED" ] || { echo "security owner sign-off is not approved" >&2; exit 1; }
[ "$SIGNOFF_COMMIT" = "$EXPECTED_COMMIT" ] || { echo "sign-off commit mismatch" >&2; exit 1; }
[ "$SIGNOFF_DIGEST" = "$TOE_DIGEST" ] || { echo "sign-off artifact digest mismatch" >&2; exit 1; }
[ -n "$SIGNOFF_OWNER" ] || { echo "missing sign-off owner" >&2; exit 1; }

cosign verify-blob \
  --certificate "$SIGNOFF_CERT" \
  --signature "$SIGNOFF_SIG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  "$SIGNOFF_JSON" >/dev/null

echo "P1 certification gate PASS"
