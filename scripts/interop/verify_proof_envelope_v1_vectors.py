import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)


class ParseError(ValueError):
    pass


def parse_envelope(canonical: bytes) -> dict:
    cursor = 0

    def read(length: int) -> bytes:
        nonlocal cursor
        if len(canonical) - cursor < length:
            raise ParseError("TRUNCATED")
        value = canonical[cursor:cursor + length]
        cursor += length
        return value

    version = read(1)[0]
    encoding = read(1)[0]
    runtime = read(4)
    hashes = [read(32) for _ in range(4)]
    decision_offset = cursor
    decision = read(1)[0]
    metadata_length_offset = cursor
    metadata_len = int.from_bytes(read(2), "big")
    metadata = read(metadata_len)
    if len(metadata) != 65 or metadata[0] != 1:
        raise ParseError("INVALID_METADATA")
    signing = canonical[:cursor]
    signature_len = int.from_bytes(read(4), "big")
    signature = read(signature_len)
    if signature_len != 64:
        raise ParseError("INVALID_SIGNATURE_LENGTH")
    if cursor != len(canonical):
        raise ParseError("TRAILING_BYTES")
    if version != 1 or encoding != 2:
        raise ParseError("UNSUPPORTED_VERSION")
    if decision not in (1, 2, 3, 4):
        raise ParseError("UNKNOWN_DECISION")
    if metadata[1:33] == bytes(32) or metadata[33:] == bytes(32):
        raise ParseError("INVALID_METADATA")
    return dict(signing=signing, signature=signature, runtime=runtime, hashes=hashes,
                version=version, encoding=encoding, decision=decision, metadata=metadata,
                decision_offset=decision_offset, metadata_length_offset=metadata_length_offset)


def verify_vector(v: dict) -> None:
    assert v["kind"] == "ed25519", f"{v['id']}: unsupported signature kind"
    signing = hex_to_bytes(v["signing_bytes_hex"])
    canonical = hex_to_bytes(v["canonical_bytes_hex"])

    key_hash = hashlib.sha256(v["signer_key_id"].encode("utf-8")).digest()
    binding_hash = hex_to_bytes(v["binding_hash_hex"])
    assert len(binding_hash) == 32
    metadata = bytes([v["signature_algorithm_code"]]) + key_hash + binding_hash
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
    parsed = parse_envelope(bytes(canonical))
    assert parsed["signing"] == signing
    assert parsed["runtime"].hex() == v["runtime_version_packed_u32_be_hex"]
    assert [h.hex() for h in parsed["hashes"]] == [v[f"{name}_hash_hex"] for name in ("policy", "bytecode", "input", "state")]
    assert parsed["decision"] == v["decision_code"]
    assert parsed["version"] == v["proof_envelope_version"]
    assert parsed["encoding"] == v["encoding_version"]
    assert parsed["metadata"] == metadata
    if v["kind"] == "ed25519":
        assert parsed["signature"].hex() == v["signature_bytes_hex"]
        public_key = Ed25519PublicKey.from_public_bytes(hex_to_bytes(v["ed25519_public_key_hex"]))
        public_key.verify(parsed["signature"], parsed["signing"])
        tampered = bytearray(signing)
        tampered[2 + len(parsed["runtime"])] ^= 1
        try:
            public_key.verify(parsed["signature"], bytes(tampered))
        except InvalidSignature:
            pass
        else:
            raise AssertionError(f"{v['id']}: tampered payload signature accepted")

    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == v["canonical_bytes_sha256_hex"], f"{v['id']}: sha256 mismatch"


def verify_negative_case(case: dict, vectors_by_id: dict) -> None:
    source = vectors_by_id[case["source_vector"]]
    canonical = bytearray(hex_to_bytes(source["canonical_bytes_hex"]))
    parsed = parse_envelope(bytes(canonical))
    mutation = case["mutation"]
    if mutation == "flip_signing_byte_6":
        canonical[2 + len(parsed["runtime"])] ^= 1
    elif mutation == "flip_last_signature_byte":
        canonical[-1] ^= 1
    elif mutation == "set_version_2":
        canonical[0] = 2
    elif mutation == "set_decision_0":
        canonical[parsed["decision_offset"]] = 0
    elif mutation == "append_zero_byte":
        canonical.append(0)
    elif mutation == "truncate_last_byte":
        canonical.pop()
    elif mutation == "set_metadata_length_zero":
        canonical[parsed["metadata_length_offset"]:parsed["metadata_length_offset"] + 2] = b"\0\0"
    elif mutation == "set_signature_length_63":
        canonical[len(parsed["signing"]):len(parsed["signing"]) + 4] = (63).to_bytes(4, "big")
    else:
        raise AssertionError(f"{case['id']}: unknown mutation {mutation}")

    try:
        parsed = parse_envelope(bytes(canonical))
    except ParseError as error:
        actual_error = str(error)
    else:
        public_key = Ed25519PublicKey.from_public_bytes(hex_to_bytes(source["ed25519_public_key_hex"]))
        try:
            public_key.verify(parsed["signature"], parsed["signing"])
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
