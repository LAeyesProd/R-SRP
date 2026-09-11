#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ] && [ "$#" -ne 6 ]; then
  echo "usage: $0 <provenance-jsonl> <expected-subject-sha256> <expected-commit> [<signature> <certificate> <identity-regexp>]" >&2
  exit 64
fi

PROVENANCE_FILE="$1"
EXPECTED_SUBJECT_SHA="$2"
EXPECTED_COMMIT="$3"
SIGNATURE_FILE="${4:-}"
CERTIFICATE_FILE="${5:-}"
IDENTITY_REGEXP="${6:-}"

[ -f "$PROVENANCE_FILE" ] || { echo "missing file: $PROVENANCE_FILE" >&2; exit 1; }

PREDICATE_TYPE="$(jq -r '.predicateType // empty' "$PROVENANCE_FILE")"
SUBJECT_SHA="$(jq -r '.subject[0].digest.sha256 // empty' "$PROVENANCE_FILE")"
SUBJECT_NAME="$(jq -r '.subject[0].name // empty' "$PROVENANCE_FILE")"
BUILDER_ID="$(jq -r '.predicate.builder.id // empty' "$PROVENANCE_FILE")"
MATERIAL_COUNT="$(jq '.predicate.materials | length' "$PROVENANCE_FILE")"
COMMIT_SHA="$(jq -r '.predicate.invocation.configSource.digest.sha1 // empty' "$PROVENANCE_FILE")"
SOURCE_URI="$(jq -r '.predicate.invocation.configSource.uri // empty' "$PROVENANCE_FILE")"

[ "$PREDICATE_TYPE" = "https://slsa.dev/provenance/v0.2" ] || { echo "unexpected predicate type: $PREDICATE_TYPE" >&2; exit 1; }
[ -n "$SUBJECT_NAME" ] || { echo "missing provenance subject name" >&2; exit 1; }
[ -n "$BUILDER_ID" ] || { echo "missing builder id" >&2; exit 1; }
[ "$MATERIAL_COUNT" -gt 0 ] || { echo "provenance materials are missing" >&2; exit 1; }
[ "$SUBJECT_SHA" = "$EXPECTED_SUBJECT_SHA" ] || {
  echo "provenance subject digest mismatch" >&2
  echo "expected=$EXPECTED_SUBJECT_SHA actual=$SUBJECT_SHA" >&2
  exit 1
}
[ "$COMMIT_SHA" = "$EXPECTED_COMMIT" ] || {
  echo "provenance commit mismatch" >&2
  echo "expected=$EXPECTED_COMMIT actual=$COMMIT_SHA" >&2
  exit 1
}
case "$SOURCE_URI" in
  *"$EXPECTED_COMMIT"*) ;;
  *)
    echo "provenance source URI does not reference expected commit" >&2
    exit 1
    ;;
esac

if [ -n "$SIGNATURE_FILE" ] || [ -n "$CERTIFICATE_FILE" ] || [ -n "$IDENTITY_REGEXP" ]; then
  for path in "$SIGNATURE_FILE" "$CERTIFICATE_FILE"; do
    [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
  done
  cosign verify-blob \
    --certificate "$CERTIFICATE_FILE" \
    --signature "$SIGNATURE_FILE" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    "$PROVENANCE_FILE" >/dev/null
fi

echo "Provenance verification passed"
