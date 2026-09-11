use crue_engine::decision::Decision;
use crue_engine::proof::{ProofBinding, ProofEnvelopeV1, SignatureV1};
use serde::Serialize;
use std::path::PathBuf;

const SIGNER_KEY_ID: &str = "fixture-ed25519-key";
const DERIVATION_SECRET: &str = "rsrp-proof-envelope-v1-ed25519-test-vector";

#[derive(Serialize)]
struct VectorDocument {
    schema: &'static str,
    version: u8,
    generated_from: &'static str,
    vectors: Vec<Ed25519Vector>,
    negative_cases: Vec<NegativeCase>,
}

#[derive(Serialize)]
struct NegativeCase {
    id: &'static str,
    source_vector: &'static str,
    mutation: &'static str,
    expected_error: &'static str,
}

#[derive(Serialize)]
struct Ed25519Vector {
    id: &'static str,
    kind: &'static str,
    proof_envelope_version: u8,
    encoding_version: u8,
    runtime_version_string: &'static str,
    runtime_version_packed_u32_be_hex: String,
    decision_code: u8,
    decision_label: &'static str,
    signature_algorithm_code: u8,
    signature_algorithm_label: &'static str,
    signer_key_id: &'static str,
    signer_key_derivation_secret_utf8: &'static str,
    ed25519_public_key_hex: String,
    policy_hash_hex: String,
    bytecode_hash_hex: String,
    input_hash_hex: String,
    state_hash_hex: String,
    signing_bytes_len: usize,
    signing_bytes_hex: String,
    canonical_bytes_len: usize,
    signature_bytes_hex: String,
    canonical_bytes_hex: String,
    canonical_bytes_sha256_hex: String,
}

fn fixed_hash_hex(byte: u8) -> String {
    crypto_core::hash::hex_encode(&[byte; 32])
}

fn main() -> Result<(), String> {
    let binding = ProofBinding {
        serialization_version: 1,
        schema_id: "rsrp.proof.binding.v1".to_string(),
        runtime_version: "0.9.1".to_string(),
        crypto_backend_id: "mock-crypto".to_string(),
        policy_hash: fixed_hash_hex(0x11),
        bytecode_hash: fixed_hash_hex(0x22),
        input_hash: fixed_hash_hex(0x33),
        state_hash: fixed_hash_hex(0x44),
        decision: Decision::Block,
    };
    let key_pair = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
        DERIVATION_SECRET.as_bytes(),
        Some(SIGNER_KEY_ID.to_string()),
    );
    let envelope = ProofEnvelopeV1::sign_ed25519(&binding, SIGNER_KEY_ID, &key_pair)?;
    let signing_bytes = envelope.signing_bytes()?;
    let canonical_bytes = envelope.canonical_bytes()?;
    #[cfg(feature = "pq-proof")]
    let signature_bytes = match &envelope.signature {
        SignatureV1::Ed25519(signature) => signature.signature.clone(),
        SignatureV1::Hybrid(_) => return Err("unexpected hybrid fixture".to_string()),
    };
    #[cfg(not(feature = "pq-proof"))]
    let SignatureV1::Ed25519(signature) = &envelope.signature;
    #[cfg(not(feature = "pq-proof"))]
    let signature_bytes = signature.signature.clone();

    let document = VectorDocument {
        schema: "rsrp.proof-envelope-v1.test-vectors",
        version: 1,
        generated_from: "crates/crue-engine/examples/generate_proof_envelope_vectors.rs",
        vectors: vec![Ed25519Vector {
            id: "ed25519_fixture_v1_block_00090001",
            kind: "ed25519",
            proof_envelope_version: envelope.version,
            encoding_version: envelope.encoding_version,
            runtime_version_string: "0.9.1",
            runtime_version_packed_u32_be_hex: crypto_core::hash::hex_encode(&signing_bytes[2..6]),
            decision_code: envelope.decision_code,
            decision_label: "BLOCK",
            signature_algorithm_code: 1,
            signature_algorithm_label: "ED25519",
            signer_key_id: SIGNER_KEY_ID,
            signer_key_derivation_secret_utf8: DERIVATION_SECRET,
            ed25519_public_key_hex: crypto_core::hash::hex_encode(&key_pair.verifying_key()),
            policy_hash_hex: binding.policy_hash,
            bytecode_hash_hex: binding.bytecode_hash,
            input_hash_hex: binding.input_hash,
            state_hash_hex: binding.state_hash,
            signing_bytes_len: signing_bytes.len(),
            signing_bytes_hex: crypto_core::hash::hex_encode(&signing_bytes),
            canonical_bytes_len: canonical_bytes.len(),
            signature_bytes_hex: crypto_core::hash::hex_encode(&signature_bytes),
            canonical_bytes_hex: crypto_core::hash::hex_encode(&canonical_bytes),
            canonical_bytes_sha256_hex: crypto_core::hash::hex_encode(&crypto_core::hash::sha256(
                &canonical_bytes,
            )),
        }],
        negative_cases: vec![
            NegativeCase {
                id: "reject_tampered_signing_payload",
                source_vector: "ed25519_fixture_v1_block_00090001",
                mutation: "flip_signing_byte_6",
                expected_error: "INVALID_SIGNATURE",
            },
            NegativeCase {
                id: "reject_tampered_signature",
                source_vector: "ed25519_fixture_v1_block_00090001",
                mutation: "flip_last_signature_byte",
                expected_error: "INVALID_SIGNATURE",
            },
            NegativeCase {
                id: "reject_unsupported_version",
                source_vector: "ed25519_fixture_v1_block_00090001",
                mutation: "set_version_2",
                expected_error: "UNSUPPORTED_VERSION",
            },
            NegativeCase {
                id: "reject_unknown_decision",
                source_vector: "ed25519_fixture_v1_block_00090001",
                mutation: "set_decision_0",
                expected_error: "UNKNOWN_DECISION",
            },
            NegativeCase {
                id: "reject_trailing_bytes",
                source_vector: "ed25519_fixture_v1_block_00090001",
                mutation: "append_zero_byte",
                expected_error: "TRAILING_BYTES",
            },
        ],
    };

    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/PROOF_ENVELOPE_V1_TEST_VECTORS.json");
    let json = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())? + "\n";
    std::fs::write(&output, json).map_err(|error| error.to_string())?;
    println!("wrote {}", output.display());
    Ok(())
}
