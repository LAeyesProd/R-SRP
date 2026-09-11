#!/usr/bin/env bash
# External SoftHSM2 module integration ONLY; the application has no PKCS#11 backend.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in softhsm2-util pkcs11-tool openssl python3; do
    command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done

module=""
for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/softhsm/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then module="$candidate"; break; fi
done
[[ -n "$module" ]] || { echo "SoftHSM2 module not installed" >&2; exit 1; }

mkdir -p target
work="$PWD/target/pkcs11-check-$$-$RANDOM"
mkdir "$work"
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/tokens"
export SOFTHSM2_CONF="$work/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$work/tokens" > "$SOFTHSM2_CONF"
# Fresh random credentials protect only this disposable, isolated software token.
export PKCS11_TEST_PIN
PKCS11_TEST_PIN="$(openssl rand -hex 12)"
so_pin="$(openssl rand -hex 12)"
softhsm2-util --init-token --free --label rsrp-release-test --so-pin "$so_pin" --pin "$PKCS11_TEST_PIN"

p11=(pkcs11-tool --module "$module" --token-label rsrp-release-test)
"${p11[@]}" --login --pin env:PKCS11_TEST_PIN --keypairgen --key-type rsa:2048 --id 01 --label release-signing-key --usage-sign
printf 'R-SRP external PKCS11 release evidence\n' > "$work/message"
"${p11[@]}" --login --pin env:PKCS11_TEST_PIN --sign --mechanism SHA256-RSA-PKCS --id 01 --input-file "$work/message" --output-file "$work/signature"
verified=$("${p11[@]}" --verify --mechanism SHA256-RSA-PKCS --id 01 --input-file "$work/message" --signature-file "$work/signature" 2>&1)
printf '%s\n' "$verified"
grep -Fxq 'Signature is valid' <<< "$verified" || { echo "ERROR: module did not verify signature" >&2; exit 1; }

assert_signature_rejected() {
    local output
    # OpenSC versions may return zero even after CKR_SIGNATURE_INVALID.
    # Require explicit cryptographic rejection, not merely a tool/login error.
    output=$("${p11[@]}" --verify --mechanism SHA256-RSA-PKCS --id 01 --input-file "$1" --signature-file "$2" 2>&1) || true
    printf '%s\n' "$output"
    if ! grep -Fxq 'Invalid signature' <<< "$output"; then
        echo "ERROR: module did not explicitly reject tampered input" >&2
        exit 1
    fi
}

printf 'tampered release evidence\n' > "$work/tampered-message"
assert_signature_rejected "$work/tampered-message" "$work/signature"
python3 - "$work/signature" "$work/tampered-signature" <<'PY'
import pathlib
import sys
signature = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
signature[0] ^= 1
pathlib.Path(sys.argv[2]).write_bytes(signature)
PY
assert_signature_rejected "$work/message" "$work/tampered-signature"
echo "PASS: external SoftHSM2 PKCS#11 key generation/sign/verify/tamper rejection."
echo "NOT application PKCS#11 backend coverage; NOT physical HSM validation."
