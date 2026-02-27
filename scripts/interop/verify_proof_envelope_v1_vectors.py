import hashlib
import json
from pathlib import Path


def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)


def verify_vector(v: dict) -> None:
    signing = hex_to_bytes(v["signing_bytes_hex"])
    canonical = hex_to_bytes(v["canonical_bytes_hex"])

    assert len(signing) == v["signing_bytes_len"], f"{v['id']}: signing len mismatch"
    assert len(canonical) == v["canonical_bytes_len"], f"{v['id']}: canonical len mismatch"
    assert canonical.startswith(signing), f"{v['id']}: canonical does not start with signing bytes"

    sig_len = int.from_bytes(canonical[len(signing):len(signing) + 4], "big")
    sig = canonical[len(signing) + 4:]
    assert len(sig) == sig_len, f"{v['id']}: signature length suffix mismatch"

    runtime_packed = signing[2:6].hex()
    assert runtime_packed == v["runtime_version_packed_u32_be_hex"], f"{v['id']}: runtime pack mismatch"

    decision_code = signing[134]
    assert decision_code == v["decision_code"], f"{v['id']}: decision code mismatch"

    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == v["canonical_bytes_sha256_hex"], f"{v['id']}: sha256 mismatch"


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    vectors_path = repo_root / "docs" / "PROOF_ENVELOPE_V1_TEST_VECTORS.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))

    assert data["schema"] == "rsrp.proof-envelope-v1.test-vectors"
    assert data["version"] == 1

    vectors = data.get("vectors", [])
    for v in vectors:
        verify_vector(v)

    print(f"ok: {len(vectors)} ProofEnvelopeV1 vector(s) verified")


if __name__ == "__main__":
    main()
