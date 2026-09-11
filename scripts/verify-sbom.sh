#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ] && [ "$#" -ne 6 ]; then
  echo "usage: $0 <sbom-json> <archive> <archive.sha256> [<signature> <certificate> <identity-regexp>]" >&2
  exit 64
fi

SBOM_JSON="$1"
ARCHIVE="$2"
CHECKSUM_FILE="$3"
SIGNATURE_FILE="${4:-}"
CERTIFICATE_FILE="${5:-}"
IDENTITY_REGEXP="${6:-}"

for path in "$SBOM_JSON" "$ARCHIVE" "$CHECKSUM_FILE"; do
  [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
done

COMPONENT_COUNT="$(jq 'if has("components") then (.components | length) elif has("packages") then (.packages | length) else 0 end' "$SBOM_JSON")"
[ "$COMPONENT_COUNT" -gt 0 ] || { echo "SBOM contains no components" >&2; exit 1; }

COMPUTED_DIGEST="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
EXPECTED_DIGEST="$(awk '{print $1}' "$CHECKSUM_FILE")"
[ -n "$COMPUTED_DIGEST" ] || { echo "empty SBOM digest" >&2; exit 1; }
[ "$COMPUTED_DIGEST" = "$EXPECTED_DIGEST" ] || {
  echo "SBOM archive digest mismatch" >&2
  echo "expected=$EXPECTED_DIGEST actual=$COMPUTED_DIGEST" >&2
  exit 1
}

if [ -n "$SIGNATURE_FILE" ] || [ -n "$CERTIFICATE_FILE" ] || [ -n "$IDENTITY_REGEXP" ]; then
  for path in "$SIGNATURE_FILE" "$CERTIFICATE_FILE"; do
    [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
  done
  cosign verify-blob \
    --certificate "$CERTIFICATE_FILE" \
    --signature "$SIGNATURE_FILE" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    "$ARCHIVE" >/dev/null
fi

echo "SBOM verification passed"
