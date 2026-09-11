#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <build-a.json> <build-b.json>" >&2
  exit 64
fi

BUILD_A="$1"
BUILD_B="$2"

for path in "$BUILD_A" "$BUILD_B"; do
  [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
done

artifact_sha() {
  jq -r '.artifact_sha256 // empty' "$1"
}

cargo_lock_sha() {
  jq -r '.cargo_lock_sha256 // empty' "$1"
}

rustc_version() {
  jq -r '.rustc_version // empty' "$1"
}

toe_binary() {
  jq -r '.toe_binary // empty' "$1"
}

ARTIFACT_SHA_A="$(artifact_sha "$BUILD_A")"
ARTIFACT_SHA_B="$(artifact_sha "$BUILD_B")"
LOCK_SHA_A="$(cargo_lock_sha "$BUILD_A")"
LOCK_SHA_B="$(cargo_lock_sha "$BUILD_B")"
RUSTC_A="$(rustc_version "$BUILD_A")"
RUSTC_B="$(rustc_version "$BUILD_B")"
TOE_A="$(toe_binary "$BUILD_A")"
TOE_B="$(toe_binary "$BUILD_B")"

[ -n "$ARTIFACT_SHA_A" ] && [ -n "$ARTIFACT_SHA_B" ] || { echo "missing artifact digest" >&2; exit 1; }
[ "$ARTIFACT_SHA_A" = "$ARTIFACT_SHA_B" ] || {
  echo "artifact digests differ" >&2
  echo "build-a=$ARTIFACT_SHA_A build-b=$ARTIFACT_SHA_B" >&2
  exit 1
}
[ "$LOCK_SHA_A" = "$LOCK_SHA_B" ] || { echo "Cargo.lock digests differ" >&2; exit 1; }
[ -n "$RUSTC_A" ] && [ "$RUSTC_A" = "$RUSTC_B" ] || { echo "toolchain differs across builds" >&2; exit 1; }
[ -n "$TOE_A" ] && [ "$TOE_A" = "$TOE_B" ] || { echo "TOE binary differs across builds" >&2; exit 1; }

echo "Reproducibility verification passed for $TOE_A"
