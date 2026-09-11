import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)


def verify_vector(v: dict) -> None:
    signing = hex_to_bytes(v["signing_bytes_hex"])
    canonical = hex_to_bytes(v["canonical_bytes_hex"])

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
        expected_key_hash = hashlib.sha256(v["signer_key_id"].encode("utf-8")).digest()
        assert meta[1:] == expected_key_hash, f"{v['id']}: signer key id hash mismatch"
        assert sig_len == 64, f"{v['id']}: invalid Ed25519 signature length"
        assert sig.hex() == v["signature_bytes_hex"], f"{v['id']}: signature bytes mismatch"
        public_key = Ed25519PublicKey.from_public_bytes(hex_to_bytes(v["ed25519_public_key_hex"]))
        public_key.verify(sig, signing)

    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == v["canonical_bytes_sha256_hex"], f"{v['id']}: sha256 mismatch"


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

    print(f"ok: {len(vectors)} ProofEnvelopeV1 vector(s) verified")


if __name__ == "__main__":
    main()
