//! Strict proof binding primitives (Phase 2 bootstrap).

use crate::context::{EvaluationContext, FieldValue};
use crate::decision::Decision;
use crate::EvaluationRequest;
use crue_dsl::compiler::{ActionDecision, ActionInstruction, Bytecode, Constant};
use serde::Serialize;

const PROOF_BINDING_SERIALIZATION_VERSION: u8 = 1;
const PROOF_BINDING_SCHEMA_ID: &str = "rsrp.proof.binding.v1";
const PROOF_ENVELOPE_SERIALIZATION_VERSION: u8 = 1;
const PROOF_ENVELOPE_SCHEMA_ID: &str = "rsrp.proof.envelope.v1";
pub const PROOF_ENVELOPE_V1_VERSION: u8 = 1;
pub const PROOF_ENVELOPE_V1_ENCODING_VERSION: u8 = 1;
#[cfg(feature = "pq-proof")]
const PQ_PROOF_ENVELOPE_SERIALIZATION_VERSION: u8 = 1;
#[cfg(feature = "pq-proof")]
const PQ_PROOF_ENVELOPE_SCHEMA_ID: &str = "rsrp.proof.envelope.pq-hybrid.v1";

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProofBinding {
    pub serialization_version: u8,
    pub schema_id: String,
    pub runtime_version: String,
    pub crypto_backend_id: String,
    pub policy_hash: String,
    pub bytecode_hash: String,
    pub input_hash: String,
    pub state_hash: String,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProofEnvelope {
    pub serialization_version: u8,
    pub schema_id: String,
    pub signature_algorithm: String,
    pub signer_key_id: String,
    pub binding: ProofBinding,
    pub signature: Vec<u8>,
}

#[cfg(feature = "pq-proof")]
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct PqProofEnvelope {
    pub serialization_version: u8,
    pub schema_id: String,
    pub signature_algorithm: String,
    pub signer_key_id: String,
    pub pq_backend_id: String,
    pub level: pqcrypto::DilithiumLevel,
    pub binding: ProofBinding,
    pub signature: pqcrypto::hybrid::HybridSignature,
}

/// Decision code for canonical proof envelope v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DecisionCodeV1 {
    Allow = 1,
    Block = 2,
    Warn = 3,
    ApprovalRequired = 4,
}

/// Signature algorithm code for canonical proof envelope v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum SignatureAlgorithmCodeV1 {
    Ed25519 = 1,
    #[cfg(feature = "pq-proof")]
    HybridEd25519Mldsa = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Ed25519SignatureV1 {
    pub key_id_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[cfg(feature = "pq-proof")]
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct HybridSignatureV1 {
    pub key_id_hash: [u8; 32],
    pub backend_id_hash: [u8; 32],
    pub level_code: u8,
    pub signature: pqcrypto::hybrid::HybridSignature,
}

#[derive(Clone, Serialize, serde::Deserialize)]
pub enum SignatureV1 {
    Ed25519(Ed25519SignatureV1),
    #[cfg(feature = "pq-proof")]
    Hybrid(HybridSignatureV1),
}

/// Canonical proof envelope v1: fixed header + typed signature payload.
#[derive(Clone, Serialize, serde::Deserialize)]
pub struct ProofEnvelopeV1 {
    pub version: u8,
    pub encoding_version: u8,
    pub runtime_version: u32,
    pub policy_hash: [u8; 32],
    pub bytecode_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub state_hash: [u8; 32],
    pub decision_code: u8,
    pub signature: SignatureV1,
}

impl ProofBinding {
    pub fn create(
        bytecode: &Bytecode,
        request: &EvaluationRequest,
        ctx: &EvaluationContext,
        decision: Decision,
        crypto_backend_id: &str,
    ) -> Result<Self, String> {
        Self::create_with_policy_hash(bytecode, request, ctx, decision, crypto_backend_id, None)
    }

    pub fn create_with_policy_hash(
        bytecode: &Bytecode,
        request: &EvaluationRequest,
        ctx: &EvaluationContext,
        decision: Decision,
        crypto_backend_id: &str,
        policy_hash_hex: Option<&str>,
    ) -> Result<Self, String> {
        let bytecode_hash = sha256_hex(&canonical_bytecode_bytes(bytecode)?);
        let policy_hash = policy_hash_hex.unwrap_or(&bytecode_hash).to_string();
        Ok(Self {
            serialization_version: PROOF_BINDING_SERIALIZATION_VERSION,
            schema_id: PROOF_BINDING_SCHEMA_ID.to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            crypto_backend_id: crypto_backend_id.to_string(),
            policy_hash,
            bytecode_hash,
            input_hash: sha256_hex(&canonical_request_bytes(request)?),
            state_hash: sha256_hex(&canonical_state_bytes(&state_snapshot(ctx))?),
            decision,
        })
    }

    pub fn verify_recompute(
        &self,
        bytecode: &Bytecode,
        request: &EvaluationRequest,
        ctx: &EvaluationContext,
        decision: Decision,
        crypto_backend_id: &str,
    ) -> Result<bool, String> {
        let recomputed = Self::create_with_policy_hash(
            bytecode,
            request,
            ctx,
            decision,
            crypto_backend_id,
            Some(&self.policy_hash),
        )?;
        Ok(
            self.serialization_version == PROOF_BINDING_SERIALIZATION_VERSION
                && self.schema_id == PROOF_BINDING_SCHEMA_ID
                && self == &recomputed,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let payload = self.canonical_payload_bytes()?;
        let schema_len: u16 = self
            .schema_id
            .len()
            .try_into()
            .map_err(|_| "schema_id too long".to_string())?;
        let payload_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| "payload too long".to_string())?;
        let mut out = Vec::with_capacity(1 + 2 + self.schema_id.len() + 4 + payload.len());
        out.push(self.serialization_version);
        out.extend_from_slice(&schema_len.to_be_bytes());
        out.extend_from_slice(self.schema_id.as_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    fn canonical_payload_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(
            1 + 2 + self.runtime_version.len() + 2 + self.crypto_backend_id.len() + (32 * 4) + 1,
        );
        encode_len_prefixed_str(&mut out, &self.runtime_version)?;
        encode_len_prefixed_str(&mut out, &self.crypto_backend_id)?;
        out.extend_from_slice(&hex32(&self.policy_hash)?);
        out.extend_from_slice(&hex32(&self.bytecode_hash)?);
        out.extend_from_slice(&hex32(&self.input_hash)?);
        out.extend_from_slice(&hex32(&self.state_hash)?);
        out.push(decision_to_code(self.decision) as u8);
        Ok(out)
    }
}

impl PartialEq for ProofBinding {
    fn eq(&self, other: &Self) -> bool {
        self.serialization_version == other.serialization_version
            && self.schema_id == other.schema_id
            && self.runtime_version == other.runtime_version
            && self.crypto_backend_id == other.crypto_backend_id
            && self.policy_hash == other.policy_hash
            && self.bytecode_hash == other.bytecode_hash
            && self.input_hash == other.input_hash
            && self.state_hash == other.state_hash
            && self.decision == other.decision
    }
}

impl Eq for ProofBinding {}

impl ProofEnvelope {
    pub fn sign_ed25519(
        binding: ProofBinding,
        signer_key_id: impl Into<String>,
        key_pair: &crypto_core::signature::Ed25519KeyPair,
    ) -> Result<Self, String> {
        let payload = binding.canonical_bytes()?;
        let signature = key_pair.sign(&payload);
        Ok(Self {
            serialization_version: PROOF_ENVELOPE_SERIALIZATION_VERSION,
            schema_id: PROOF_ENVELOPE_SCHEMA_ID.to_string(),
            signature_algorithm: "ED25519".to_string(),
            signer_key_id: signer_key_id.into(),
            binding,
            signature,
        })
    }

    pub fn verify_ed25519(&self, public_key: &[u8]) -> Result<bool, String> {
        if self.serialization_version != PROOF_ENVELOPE_SERIALIZATION_VERSION
            || self.schema_id != PROOF_ENVELOPE_SCHEMA_ID
            || self.signature_algorithm != "ED25519"
        {
            return Ok(false);
        }
        let payload = self.binding.canonical_bytes()?;
        crypto_core::signature::verify(
            &payload,
            &self.signature,
            public_key,
            crypto_core::SignatureAlgorithm::Ed25519,
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(feature = "pq-proof")]
impl PqProofEnvelope {
    pub fn sign_hybrid(
        binding: ProofBinding,
        signer_key_id: impl Into<String>,
        signer: &pqcrypto::hybrid::HybridSigner,
        keypair: &pqcrypto::hybrid::HybridKeyPair,
    ) -> Result<Self, String> {
        let payload = binding.canonical_bytes()?;
        let signature = signer.sign(keypair, &payload).map_err(|e| e.to_string())?;

        Ok(Self {
            serialization_version: PQ_PROOF_ENVELOPE_SERIALIZATION_VERSION,
            schema_id: PQ_PROOF_ENVELOPE_SCHEMA_ID.to_string(),
            signature_algorithm: "HYBRID-ED25519+ML-DSA".to_string(),
            signer_key_id: signer_key_id.into(),
            pq_backend_id: signer.backend_id().to_string(),
            level: keypair.level,
            binding,
            signature,
        })
    }

    pub fn verify_hybrid(
        &self,
        public_key: &pqcrypto::hybrid::HybridPublicKey,
    ) -> Result<bool, String> {
        if self.serialization_version != PQ_PROOF_ENVELOPE_SERIALIZATION_VERSION
            || self.schema_id != PQ_PROOF_ENVELOPE_SCHEMA_ID
            || self.signature_algorithm != "HYBRID-ED25519+ML-DSA"
            || self.level != public_key.level
            || self.signature.quantum.level != self.level
        {
            return Ok(false);
        }

        let payload = self.binding.canonical_bytes()?;
        let verifier = pqcrypto::hybrid::HybridVerifier::new(self.level);
        verifier
            .verify_public(public_key, &payload, &self.signature)
            .map_err(|e| e.to_string())
    }
}

impl ProofEnvelopeV1 {
    pub fn sign_ed25519(
        binding: &ProofBinding,
        signer_key_id: impl AsRef<str>,
        key_pair: &crypto_core::signature::Ed25519KeyPair,
    ) -> Result<Self, String> {
        let mut envelope = Self::unsigned_from_binding(
            binding,
            SignatureV1::Ed25519(Ed25519SignatureV1 {
                key_id_hash: sha256_fixed(signer_key_id.as_ref().as_bytes()),
                signature: Vec::new(),
            }),
        )?;
        let payload = envelope.signing_bytes()?;
        match &mut envelope.signature {
            SignatureV1::Ed25519(sig) => sig.signature = key_pair.sign(&payload),
            #[cfg(feature = "pq-proof")]
            SignatureV1::Hybrid(_) => {
                return Err("invalid signature variant for ed25519 signing".to_string())
            }
        }
        Ok(envelope)
    }

    #[cfg(feature = "pq-proof")]
    pub fn sign_hybrid(
        binding: &ProofBinding,
        signer_key_id: impl AsRef<str>,
        signer: &pqcrypto::hybrid::HybridSigner,
        keypair: &pqcrypto::hybrid::HybridKeyPair,
    ) -> Result<Self, String> {
        let mut envelope = Self::unsigned_from_binding(
            binding,
            SignatureV1::Hybrid(HybridSignatureV1 {
                key_id_hash: sha256_fixed(signer_key_id.as_ref().as_bytes()),
                backend_id_hash: sha256_fixed(signer.backend_id().as_bytes()),
                level_code: dilithium_level_code(keypair.level),
                signature: pqcrypto::hybrid::HybridSignature::new(
                    Vec::new(),
                    pqcrypto::signature::DilithiumSignature {
                        level: keypair.level,
                        signature: Vec::new(),
                    },
                ),
            }),
        )?;
        let payload = envelope.signing_bytes()?;
        let sig = signer.sign(keypair, &payload).map_err(|e| e.to_string())?;
        if let SignatureV1::Hybrid(h) = &mut envelope.signature {
            h.signature = sig;
        }
        Ok(envelope)
    }

    pub fn verify_ed25519(&self, public_key: &[u8]) -> Result<bool, String> {
        #[cfg(feature = "pq-proof")]
        let sig = match &self.signature {
            SignatureV1::Ed25519(sig) => sig,
            SignatureV1::Hybrid(_) => return Ok(false),
        };
        #[cfg(not(feature = "pq-proof"))]
        let SignatureV1::Ed25519(sig) = &self.signature;
        let payload = self.signing_bytes()?;
        crypto_core::signature::verify(
            &payload,
            &sig.signature,
            public_key,
            crypto_core::SignatureAlgorithm::Ed25519,
        )
        .map_err(|e| e.to_string())
    }

    #[cfg(feature = "pq-proof")]
    pub fn verify_hybrid(
        &self,
        public_key: &pqcrypto::hybrid::HybridPublicKey,
    ) -> Result<bool, String> {
        let SignatureV1::Hybrid(sig) = &self.signature else {
            return Ok(false);
        };
        if sig.level_code != dilithium_level_code(public_key.level) {
            return Ok(false);
        }
        if sig.backend_id_hash == [0u8; 32] {
            return Ok(false);
        }
        let payload = self.signing_bytes()?;
        let verifier = pqcrypto::hybrid::HybridVerifier::new(public_key.level);
        verifier
            .verify_public(public_key, &payload, &sig.signature)
            .map_err(|e| e.to_string())
    }

    /// Canonical bytes excluding signature material (signing payload).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(1 + 1 + 4 + (32 * 4) + 1);
        out.push(self.version);
        out.push(self.encoding_version);
        out.extend_from_slice(&self.runtime_version.to_be_bytes());
        out.extend_from_slice(&self.policy_hash);
        out.extend_from_slice(&self.bytecode_hash);
        out.extend_from_slice(&self.input_hash);
        out.extend_from_slice(&self.state_hash);
        out.push(self.decision_code);
        let sig_meta = self.signature.meta_bytes()?;
        let sig_meta_len: u16 = sig_meta
            .len()
            .try_into()
            .map_err(|_| "signature metadata too large".to_string())?;
        out.extend_from_slice(&sig_meta_len.to_be_bytes());
        out.extend_from_slice(&sig_meta);
        Ok(out)
    }

    /// Canonical bytes including signature bytes (stable serialization for ledger embedding/export).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = self.signing_bytes()?;
        let sig_bytes = self.signature.signature_owned_bytes();
        let sig_len: u32 = sig_bytes
            .len()
            .try_into()
            .map_err(|_| "signature too large".to_string())?;
        out.extend_from_slice(&sig_len.to_be_bytes());
        out.extend_from_slice(&sig_bytes);
        Ok(out)
    }

    /// Decode canonical bytes produced by `canonical_bytes`.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        let encoding_version = read_u8(bytes, &mut cursor)?;
        let runtime_version = read_u32_be(bytes, &mut cursor)?;
        let policy_hash = read_fixed_32(bytes, &mut cursor)?;
        let bytecode_hash = read_fixed_32(bytes, &mut cursor)?;
        let input_hash = read_fixed_32(bytes, &mut cursor)?;
        let state_hash = read_fixed_32(bytes, &mut cursor)?;
        let decision_code = read_u8(bytes, &mut cursor)?;

        let sig_meta_len = read_u16_be(bytes, &mut cursor)? as usize;
        let sig_meta = read_slice(bytes, &mut cursor, sig_meta_len)?;
        let mut signature = SignatureV1::from_meta_bytes(sig_meta)?;

        let sig_len = read_u32_be(bytes, &mut cursor)? as usize;
        let sig_bytes = read_slice(bytes, &mut cursor, sig_len)?;
        signature.attach_signature_bytes(sig_bytes)?;

        if cursor != bytes.len() {
            return Err("unexpected trailing bytes in ProofEnvelopeV1".to_string());
        }

        Ok(Self {
            version,
            encoding_version,
            runtime_version,
            policy_hash,
            bytecode_hash,
            input_hash,
            state_hash,
            decision_code,
            signature,
        })
    }

    pub fn decision(&self) -> Result<Decision, String> {
        decision_from_code(self.decision_code)
    }

    fn unsigned_from_binding(
        binding: &ProofBinding,
        signature: SignatureV1,
    ) -> Result<Self, String> {
        Ok(Self {
            version: PROOF_ENVELOPE_V1_VERSION,
            encoding_version: PROOF_ENVELOPE_V1_ENCODING_VERSION,
            runtime_version: pack_runtime_version_u32(&binding.runtime_version)?,
            policy_hash: hex32(&binding.policy_hash)?,
            bytecode_hash: hex32(&binding.bytecode_hash)?,
            input_hash: hex32(&binding.input_hash)?,
            state_hash: hex32(&binding.state_hash)?,
            decision_code: decision_to_code(binding.decision) as u8,
            signature,
        })
    }
}

impl SignatureV1 {
    fn meta_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            SignatureV1::Ed25519(sig) => {
                let mut out = Vec::with_capacity(1 + 32);
                out.push(SignatureAlgorithmCodeV1::Ed25519 as u8);
                out.extend_from_slice(&sig.key_id_hash);
                Ok(out)
            }
            #[cfg(feature = "pq-proof")]
            SignatureV1::Hybrid(sig) => {
                let mut out = Vec::with_capacity(1 + 32 + 32 + 1);
                out.push(SignatureAlgorithmCodeV1::HybridEd25519Mldsa as u8);
                out.extend_from_slice(&sig.key_id_hash);
                out.extend_from_slice(&sig.backend_id_hash);
                out.push(sig.level_code);
                Ok(out)
            }
        }
    }

    fn signature_owned_bytes(&self) -> Vec<u8> {
        match self {
            SignatureV1::Ed25519(sig) => sig.signature.clone(),
            #[cfg(feature = "pq-proof")]
            SignatureV1::Hybrid(sig) => sig.signature.to_bytes(),
        }
    }

    fn from_meta_bytes(meta: &[u8]) -> Result<Self, String> {
        if meta.is_empty() {
            return Err("missing signature metadata".to_string());
        }
        match meta[0] {
            x if x == SignatureAlgorithmCodeV1::Ed25519 as u8 => {
                if meta.len() != 1 + 32 {
                    return Err("invalid Ed25519 signature metadata length".to_string());
                }
                let mut key_id_hash = [0u8; 32];
                key_id_hash.copy_from_slice(&meta[1..33]);
                Ok(SignatureV1::Ed25519(Ed25519SignatureV1 {
                    key_id_hash,
                    signature: Vec::new(),
                }))
            }
            #[cfg(feature = "pq-proof")]
            x if x == SignatureAlgorithmCodeV1::HybridEd25519Mldsa as u8 => {
                if meta.len() != 1 + 32 + 32 + 1 {
                    return Err("invalid Hybrid signature metadata length".to_string());
                }
                let mut key_id_hash = [0u8; 32];
                key_id_hash.copy_from_slice(&meta[1..33]);
                let mut backend_id_hash = [0u8; 32];
                backend_id_hash.copy_from_slice(&meta[33..65]);
                let level_code = meta[65];
                let level = dilithium_level_from_code(level_code)?;
                Ok(SignatureV1::Hybrid(HybridSignatureV1 {
                    key_id_hash,
                    backend_id_hash,
                    level_code,
                    signature: pqcrypto::hybrid::HybridSignature::new(
                        Vec::new(),
                        pqcrypto::signature::DilithiumSignature {
                            level,
                            signature: Vec::new(),
                        },
                    ),
                }))
            }
            _ => Err(format!("unknown signature algorithm code {}", meta[0])),
        }
    }

    fn attach_signature_bytes(&mut self, signature_bytes: &[u8]) -> Result<(), String> {
        match self {
            SignatureV1::Ed25519(sig) => {
                if signature_bytes.len() != 64 {
                    return Err("invalid Ed25519 signature length".to_string());
                }
                sig.signature = signature_bytes.to_vec();
                Ok(())
            }
            #[cfg(feature = "pq-proof")]
            SignatureV1::Hybrid(sig) => {
                let level = dilithium_level_from_code(sig.level_code)?;
                sig.signature =
                    pqcrypto::hybrid::HybridSignature::from_bytes(level, signature_bytes)
                        .map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }
}

#[derive(Serialize)]
struct StateField<'a> {
    key: &'a str,
    value: &'a FieldValue,
}

fn state_snapshot(ctx: &EvaluationContext) -> Vec<StateField<'_>> {
    let mut items: Vec<_> = ctx.fields().iter().collect();
    items.sort_by(|(ka, _), (kb, _)| ka.cmp(kb));
    items
        .into_iter()
        .map(|(key, value)| StateField {
            key: key.as_str(),
            value,
        })
        .collect()
}

fn canonical_bytecode_bytes(bytecode: &Bytecode) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rsrp.bytecode.v1");

    encode_len_prefixed_bytes(&mut out, &bytecode.instructions)?;

    encode_u32(
        &mut out,
        bytecode
            .constants
            .len()
            .try_into()
            .map_err(|_| "too many constants".to_string())?,
    );
    for c in &bytecode.constants {
        match c {
            Constant::Number(n) => {
                out.push(1);
                out.extend_from_slice(&n.to_be_bytes());
            }
            Constant::String(s) => {
                out.push(2);
                encode_len_prefixed_bytes(&mut out, s.as_bytes())?;
            }
            Constant::Boolean(b) => {
                out.push(3);
                out.push(u8::from(*b));
            }
        }
    }

    encode_u32(
        &mut out,
        bytecode
            .fields
            .len()
            .try_into()
            .map_err(|_| "too many fields".to_string())?,
    );
    for field in &bytecode.fields {
        encode_len_prefixed_bytes(&mut out, field.as_bytes())?;
    }

    encode_u32(
        &mut out,
        bytecode
            .action_instructions
            .len()
            .try_into()
            .map_err(|_| "too many action instructions".to_string())?,
    );
    for instruction in &bytecode.action_instructions {
        encode_action_instruction(&mut out, instruction)?;
    }

    Ok(out)
}

fn canonical_request_bytes(request: &EvaluationRequest) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rsrp.request.v1");
    encode_len_prefixed_bytes(&mut out, request.request_id.as_bytes())?;
    encode_len_prefixed_bytes(&mut out, request.agent_id.as_bytes())?;
    encode_len_prefixed_bytes(&mut out, request.agent_org.as_bytes())?;
    encode_len_prefixed_bytes(&mut out, request.agent_level.as_bytes())?;
    encode_opt_str(&mut out, request.mission_id.as_deref())?;
    encode_opt_str(&mut out, request.mission_type.as_deref())?;
    encode_opt_str(&mut out, request.query_type.as_deref())?;
    encode_opt_str(&mut out, request.justification.as_deref())?;
    encode_opt_str(&mut out, request.export_format.as_deref())?;
    encode_opt_u32(&mut out, request.result_limit);
    encode_u32(&mut out, request.requests_last_hour);
    encode_u32(&mut out, request.requests_last_24h);
    encode_u32(&mut out, request.results_last_query);
    encode_opt_str(&mut out, request.account_department.as_deref())?;
    encode_u32(
        &mut out,
        request
            .allowed_departments
            .len()
            .try_into()
            .map_err(|_| "too many departments".to_string())?,
    );
    for dept in &request.allowed_departments {
        encode_u32(&mut out, *dept);
    }
    encode_u32(&mut out, request.request_hour);
    out.push(u8::from(request.is_within_mission_hours));
    Ok(out)
}

fn canonical_state_bytes(fields: &[StateField<'_>]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rsrp.state.v1");
    encode_u32(
        &mut out,
        fields
            .len()
            .try_into()
            .map_err(|_| "too many state fields".to_string())?,
    );
    for field in fields {
        encode_len_prefixed_bytes(&mut out, field.key.as_bytes())?;
        encode_field_value(&mut out, field.value)?;
    }
    Ok(out)
}

fn encode_action_instruction(
    out: &mut Vec<u8>,
    instruction: &ActionInstruction,
) -> Result<(), String> {
    match instruction {
        ActionInstruction::SetDecision(d) => {
            out.push(1);
            let code = match d {
                ActionDecision::Allow => 1,
                ActionDecision::Block => 2,
                ActionDecision::Warn => 3,
                ActionDecision::ApprovalRequired => 4,
            };
            out.push(code);
        }
        ActionInstruction::SetErrorCode(v) => {
            out.push(2);
            encode_len_prefixed_bytes(out, v.as_bytes())?;
        }
        ActionInstruction::SetMessage(v) => {
            out.push(3);
            encode_len_prefixed_bytes(out, v.as_bytes())?;
        }
        ActionInstruction::SetApprovalTimeout(v) => {
            out.push(4);
            encode_u32(out, *v);
        }
        ActionInstruction::SetAlertSoc(v) => {
            out.push(5);
            out.push(u8::from(*v));
        }
        ActionInstruction::Halt => out.push(6),
    }
    Ok(())
}

fn encode_field_value(out: &mut Vec<u8>, value: &FieldValue) -> Result<(), String> {
    match value {
        FieldValue::Number(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::Float(f) => {
            out.push(2);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        FieldValue::String(s) => {
            out.push(3);
            encode_len_prefixed_bytes(out, s.as_bytes())?;
        }
        FieldValue::Boolean(b) => {
            out.push(4);
            out.push(u8::from(*b));
        }
    }
    Ok(())
}

fn encode_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_opt_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(v) => {
            out.push(1);
            encode_u32(out, v);
        }
        None => out.push(0),
    }
}

fn encode_opt_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(v) => {
            out.push(1);
            encode_len_prefixed_bytes(out, v.as_bytes())?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn encode_len_prefixed_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let len: u32 = value
        .len()
        .try_into()
        .map_err(|_| "field too large".to_string())?;
    encode_u32(out, len);
    out.extend_from_slice(value);
    Ok(())
}

fn encode_len_prefixed_str(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len: u16 = value
        .len()
        .try_into()
        .map_err(|_| "string field too long".to_string())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    use crypto_core::hash::{hex_encode, sha256};
    hex_encode(&sha256(data))
}

fn sha256_fixed(data: &[u8]) -> [u8; 32] {
    let digest = crypto_core::hash::sha256(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn hex32(hex: &str) -> Result<[u8; 32], String> {
    let decoded = crypto_core::hash::hex_decode(hex).map_err(|e| e.to_string())?;
    if decoded.len() != 32 {
        return Err(format!("expected 32-byte hash, got {}", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn pack_runtime_version_u32(runtime_version: &str) -> Result<u32, String> {
    // Packs semver major.minor.patch as (major << 24) | (minor << 16) | patch.
    let mut parts = runtime_version.split('.');
    let major: u32 = parts
        .next()
        .ok_or_else(|| "missing major runtime version".to_string())?
        .parse()
        .map_err(|_| "invalid major runtime version".to_string())?;
    let minor: u32 = parts
        .next()
        .ok_or_else(|| "missing minor runtime version".to_string())?
        .parse()
        .map_err(|_| "invalid minor runtime version".to_string())?;
    let patch: u32 = match parts.next() {
        Some(p) if !p.is_empty() => p
            .parse()
            .map_err(|_| "invalid patch runtime version".to_string())?,
        _ => 0,
    };
    if major > 0xFF || minor > 0xFF || patch > 0xFFFF {
        return Err("runtime_version component exceeds u32 packing limits".to_string());
    }
    Ok((major << 24) | (minor << 16) | patch)
}

fn decision_to_code(decision: Decision) -> DecisionCodeV1 {
    match decision {
        Decision::Allow => DecisionCodeV1::Allow,
        Decision::Block => DecisionCodeV1::Block,
        Decision::Warn => DecisionCodeV1::Warn,
        Decision::ApprovalRequired => DecisionCodeV1::ApprovalRequired,
    }
}

fn decision_from_code(code: u8) -> Result<Decision, String> {
    match code {
        x if x == DecisionCodeV1::Allow as u8 => Ok(Decision::Allow),
        x if x == DecisionCodeV1::Block as u8 => Ok(Decision::Block),
        x if x == DecisionCodeV1::Warn as u8 => Ok(Decision::Warn),
        x if x == DecisionCodeV1::ApprovalRequired as u8 => Ok(Decision::ApprovalRequired),
        _ => Err(format!("invalid decision code {}", code)),
    }
}

#[cfg(feature = "pq-proof")]
fn dilithium_level_code(level: pqcrypto::DilithiumLevel) -> u8 {
    match level {
        pqcrypto::DilithiumLevel::Dilithium2 => 2,
        pqcrypto::DilithiumLevel::Dilithium3 => 3,
        pqcrypto::DilithiumLevel::Dilithium5 => 5,
    }
}

#[cfg(feature = "pq-proof")]
fn dilithium_level_from_code(code: u8) -> Result<pqcrypto::DilithiumLevel, String> {
    match code {
        2 => Ok(pqcrypto::DilithiumLevel::Dilithium2),
        3 => Ok(pqcrypto::DilithiumLevel::Dilithium3),
        5 => Ok(pqcrypto::DilithiumLevel::Dilithium5),
        _ => Err(format!("invalid Dilithium level code {}", code)),
    }
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, String> {
    if *cursor >= data.len() {
        return Err("unexpected EOF reading u8".to_string());
    }
    let v = data[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16_be(data: &[u8], cursor: &mut usize) -> Result<u16, String> {
    let slice = read_slice(data, cursor, 2)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32_be(data: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let slice = read_slice(data, cursor, 4)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_fixed_32(data: &[u8], cursor: &mut usize) -> Result<[u8; 32], String> {
    let slice = read_slice(data, cursor, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_slice<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], String> {
    if data.len().saturating_sub(*cursor) < len {
        return Err("unexpected EOF reading bytes".to_string());
    }
    let start = *cursor;
    *cursor += len;
    Ok(&data[start..start + len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::EvaluationContext;

    fn fixed_hash_hex(byte: u8) -> String {
        crypto_core::hash::hex_encode(&[byte; 32])
    }

    #[test]
    fn test_proof_binding_recompute_detects_bytecode_change() {
        let src = r#"
RULE CRUE_001 VERSION 1.0
WHEN
    agent.requests_last_hour >= 50
THEN
    BLOCK WITH CODE "VOLUME_EXCEEDED"
"#;
        let ast = crue_dsl::parser::parse(src).unwrap();
        let mut bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();

        let req = crate::EvaluationRequest {
            request_id: "r".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "l".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 60,
            requests_last_24h: 10,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 9,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        let proof =
            ProofBinding::create(&bytecode, &req, &ctx, Decision::Block, "mock-crypto").unwrap();
        assert!(proof
            .verify_recompute(&bytecode, &req, &ctx, Decision::Block, "mock-crypto")
            .unwrap());

        bytecode.instructions.push(0x00);
        assert!(!proof
            .verify_recompute(&bytecode, &req, &ctx, Decision::Block, "mock-crypto")
            .unwrap());
    }

    #[test]
    fn test_proof_envelope_ed25519_sign_verify() {
        let src = r#"
RULE CRUE_002 VERSION 1.0
WHEN
    agent.requests_last_hour >= 10
THEN
    BLOCK WITH CODE "TEST"
"#;
        let ast = crue_dsl::parser::parse(src).unwrap();
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();
        let req = crate::EvaluationRequest {
            request_id: "r".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "l".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 12,
            requests_last_24h: 10,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 9,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        let binding =
            ProofBinding::create(&bytecode, &req, &ctx, Decision::Block, "mock-crypto").unwrap();
        let kp = crypto_core::signature::Ed25519KeyPair::generate().unwrap();
        let envelope = ProofEnvelope::sign_ed25519(binding, "proof-key-1", &kp).unwrap();
        let pk = kp.verifying_key();
        assert!(envelope.verify_ed25519(&pk).unwrap());
    }

    #[test]
    fn test_proof_envelope_v1_ed25519_vector_fixture() {
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
        let kp = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
            b"rsrp-proof-envelope-v1-ed25519-test-vector",
            Some("fixture-ed25519-key".into()),
        );
        let pk = kp.verifying_key();
        let env = ProofEnvelopeV1::sign_ed25519(&binding, "fixture-ed25519-key", &kp).unwrap();
        assert_eq!(env.decision().unwrap(), Decision::Block);
        assert!(env.verify_ed25519(&pk).unwrap());

        let signing_hex = crypto_core::hash::hex_encode(&env.signing_bytes().unwrap());
        let canonical_hex = crypto_core::hash::hex_encode(&env.canonical_bytes().unwrap());

        assert_eq!(
            signing_hex,
            "010100090001111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444402002101e7e331964026891ae93f6f0d4b20c19f95cf20d6c6ba87fd73e287b081a46201"
        );
        assert_eq!(
            canonical_hex,
            "010100090001111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444402002101e7e331964026891ae93f6f0d4b20c19f95cf20d6c6ba87fd73e287b081a46201000000406dfc53cce34237ad8fdd62a3fc35b1221d18d7503971bdf73ec1f37d0cacfe002cc3405dfa2c046b66a68760c29c55a2fb8c130cc3d926a54645c771989dc000"
        );
    }

    #[test]
    fn test_proof_envelope_v1_canonical_decode_roundtrip() {
        let binding = ProofBinding {
            serialization_version: 1,
            schema_id: "rsrp.proof.binding.v1".to_string(),
            runtime_version: "0.9.3".to_string(),
            crypto_backend_id: "mock-crypto".to_string(),
            policy_hash: fixed_hash_hex(0xAA),
            bytecode_hash: fixed_hash_hex(0xBB),
            input_hash: fixed_hash_hex(0xCC),
            state_hash: fixed_hash_hex(0xDD),
            decision: Decision::Allow,
        };
        let kp = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
            b"rsrp-proof-envelope-v1-roundtrip",
            Some("fixture-ed25519-key".into()),
        );
        let pk = kp.verifying_key();
        let env = ProofEnvelopeV1::sign_ed25519(&binding, "fixture-ed25519-key", &kp).unwrap();
        let bytes = env.canonical_bytes().unwrap();
        let decoded = ProofEnvelopeV1::from_canonical_bytes(&bytes).unwrap();

        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        assert_eq!(decoded.decision().unwrap(), Decision::Allow);
        assert!(decoded.verify_ed25519(&pk).unwrap());
    }

    #[test]
    fn test_pack_runtime_version_u32_includes_patch() {
        assert_ne!(
            pack_runtime_version_u32("0.9.4").unwrap(),
            pack_runtime_version_u32("0.9.99").unwrap()
        );
        assert_eq!(pack_runtime_version_u32("1.2.3").unwrap(), 0x01020003);
    }

    #[cfg(feature = "pq-proof")]
    #[test]
    fn test_pq_proof_envelope_hybrid_sign_verify() {
        let src = r#"
RULE CRUE_003 VERSION 1.0
WHEN
    agent.requests_last_hour >= 10
THEN
    BLOCK WITH CODE "TEST"
"#;
        let ast = crue_dsl::parser::parse(src).unwrap();
        let bytecode = crue_dsl::compiler::Compiler::compile(&ast).unwrap();
        let req = crate::EvaluationRequest {
            request_id: "r".into(),
            agent_id: "a".into(),
            agent_org: "o".into(),
            agent_level: "l".into(),
            mission_id: None,
            mission_type: None,
            query_type: None,
            justification: None,
            export_format: None,
            result_limit: None,
            requests_last_hour: 12,
            requests_last_24h: 10,
            results_last_query: 1,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 9,
            is_within_mission_hours: true,
        };
        let ctx = EvaluationContext::from_request(&req);
        let binding =
            ProofBinding::create(&bytecode, &req, &ctx, Decision::Block, "mock-crypto").unwrap();

        let signer = pqcrypto::hybrid::HybridSigner::new(pqcrypto::DilithiumLevel::Dilithium2);
        let kp = signer.generate_keypair().unwrap();
        let pk = kp.public_key();
        let envelope =
            PqProofEnvelope::sign_hybrid(binding, "pq-proof-key-1", &signer, &kp).unwrap();
        assert_eq!(envelope.pq_backend_id, signer.backend_id());
        assert!(envelope.verify_hybrid(&pk).unwrap());
    }
}
