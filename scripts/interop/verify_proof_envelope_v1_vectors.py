import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)


def verify_vector(v: dict) -> None:
    signing = hex_to_bytes(v["signing_bytes_hex"])
    canonical = hex_to_bytes(v["canonical_bytes_hex"])

    key_hash = hashlib.sha256(v["signer_key_id"].encode("utf-8")).digest()
    metadata = bytes([v["signature_algorithm_code"]]) + key_hash
    reconstructed = b"".join(
        [
            bytes([v["proof_envelope_version"], v["encoding_version"]]),
            hex_to_bytes(v["runtime_version_packed_u32_be_hex"]),
            hex_to_bytes(v["policy_hash_hex"]),
            hex_to_bytes(v["bytecode_hash_hex"]),
            hex_to_bytes(v["input_hash_hex"]),
            hex_to_bytes(v["state_hash_hex"]),
            bytes([v["decision_code"]]),
            len(metadata).to_bytes(2, "big"),
            metadata,
        ]
    )
    assert reconstructed == signing, f"{v['id']}: semantic reconstruction mismatch"

    assert len(signing) == v["signing_bytes_len"], f"{v['id']}: signing len mismatch"
    assert len(canonical) == v["canonical_bytes_len"], f"{v['id']}: canonical len mismatch"
    assert len(signing) >= 138, f"{v['id']}: signing bytes too short"
    assert len(canonical) >= len(signing) + 4, f"{v['id']}: canonical bytes too short"
    assert canonical.startswith(signing), f"{v['id']}: canonical does not start with signing bytes"

    sig_len = int.from_bytes(canonical[len(signing):len(signing) + 4], "big")
    sig = canonical[len(signing) + 4:]
    assert len(sig) == sig_len, f"{v['id']}: signature length suffix mismatch"

    runtime_packed = signing[2:6].hex()
    assert runtime_packed == v["runtime_version_packed_u32_be_hex"], f"{v['id']}: runtime pack mismatch"

    decision_code = signing[134]
    assert decision_code == v["decision_code"], f"{v['id']}: decision code mismatch"
    assert signing[0] == v["proof_envelope_version"] == 1, f"{v['id']}: envelope version mismatch"
    assert signing[1] == v["encoding_version"] == 1, f"{v['id']}: encoding version mismatch"
    assert decision_code in (1, 2, 3, 4), f"{v['id']}: unknown decision code"

    meta_len = int.from_bytes(signing[135:137], "big")
    meta = signing[137:]
    assert len(meta) == meta_len, f"{v['id']}: signature metadata length mismatch"
    assert meta[0] == v["signature_algorithm_code"], f"{v['id']}: algorithm code mismatch"
    if v["kind"] == "ed25519":
        assert meta_len == 33, f"{v['id']}: invalid Ed25519 metadata length"
        assert meta[1:] == key_hash, f"{v['id']}: signer key id hash mismatch"
        assert sig_len == 64, f"{v['id']}: invalid Ed25519 signature length"
        assert sig.hex() == v["signature_bytes_hex"], f"{v['id']}: signature bytes mismatch"
        public_key = Ed25519PublicKey.from_public_bytes(hex_to_bytes(v["ed25519_public_key_hex"]))
        public_key.verify(sig, signing)
        tampered = bytearray(signing)
        tampered[6] ^= 1
        try:
            public_key.verify(sig, tampered)
        except InvalidSignature:
            pass
        else:
            raise AssertionError(f"{v['id']}: tampered payload signature accepted")

    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == v["canonical_bytes_sha256_hex"], f"{v['id']}: sha256 mismatch"


def verify_negative_case(case: dict, vectors_by_id: dict) -> None:
    source = vectors_by_id[case["source_vector"]]
    signing = bytearray(hex_to_bytes(source["signing_bytes_hex"]))
    canonical = bytearray(hex_to_bytes(source["canonical_bytes_hex"]))
    mutation = case["mutation"]
    if mutation == "flip_signing_byte_6":
        signing[6] ^= 1
        canonical[6] ^= 1
    elif mutation == "flip_last_signature_byte":
        canonical[-1] ^= 1
    elif mutation == "set_version_2":
        signing[0] = canonical[0] = 2
    elif mutation == "set_decision_0":
        signing[134] = canonical[134] = 0
    elif mutation == "append_zero_byte":
        canonical.append(0)
    else:
        raise AssertionError(f"{case['id']}: unknown mutation {mutation}")

    if canonical[0] != 1:
        actual_error = "UNSUPPORTED_VERSION"
    elif canonical[134] not in (1, 2, 3, 4):
        actual_error = "UNKNOWN_DECISION"
    elif len(canonical) != len(signing) + 4 + int.from_bytes(canonical[len(signing):len(signing) + 4], "big"):
        actual_error = "TRAILING_BYTES"
    else:
        public_key = Ed25519PublicKey.from_public_bytes(hex_to_bytes(source["ed25519_public_key_hex"]))
        try:
            public_key.verify(bytes(canonical[-64:]), bytes(signing))
        except InvalidSignature:
            actual_error = "INVALID_SIGNATURE"
        else:
            actual_error = "VALID"
    assert actual_error == case["expected_error"], (
        f"{case['id']}: expected {case['expected_error']}, got {actual_error}"
    )


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    vectors_path = repo_root / "docs" / "PROOF_ENVELOPE_V1_TEST_VECTORS.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))

    assert data["schema"] == "rsrp.proof-envelope-v1.test-vectors"
    assert data["version"] == 1

    vectors = data.get("vectors", [])
    assert vectors, "vector corpus must not be empty"
    for v in vectors:
        verify_vector(v)

    negative_cases = data.get("negative_cases", [])
    assert negative_cases, "negative vector corpus must not be empty"
    vectors_by_id = {vector["id"]: vector for vector in vectors}
    for case in negative_cases:
        verify_negative_case(case, vectors_by_id)

    print(f"ok: {len(vectors)} positive and {len(negative_cases)} negative ProofEnvelopeV1 vector(s) verified")


if __name__ == "__main__":
    main()
