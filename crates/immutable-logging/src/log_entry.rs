//! Log Entry - Structure of immutable audit log entries

use crate::error::LogError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CANONICAL_ENCODING_VERSION: u8 = 1;
const CONTENT_SCHEMA_ID: &str = "rsrp.ledger.log_entry.content.v1";
const ENTRY_SCHEMA_ID: &str = "rsrp.ledger.log_entry.full.v1";
const COMMIT_SCHEMA_ID: &str = "rsrp.ledger.log_entry.commit.v1";

/// Event types for audit logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EventType {
    AccountQuery,
    AuthSuccess,
    AuthFailure,
    SessionStart,
    SessionEnd,
    RuleViolation,
    AnomalyDetected,
    TokenRevoked,
    MissionCreated,
    MissionExpired,
    ExportRequested,
    DataAccess,
}

impl Default for EventType {
    fn default() -> Self {
        EventType::DataAccess
    }
}

/// Actor (user/system) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub agent_id: String,
    pub agent_org: String,
    pub mission_id: Option<String>,
    pub mission_type: Option<String>,
}

/// Request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub query_type: Option<String>,
    pub justification: Option<String>,
    pub result_count: Option<u32>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Compliance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compliance {
    pub legal_basis: String,
    pub retention_years: u32,
}

/// Integrity metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    content_hash: String,
    previous_entry_hash: String,
}

impl Integrity {
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    pub fn previous_entry_hash(&self) -> &str {
        &self.previous_entry_hash
    }
}

/// Access decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Block,
    Warn,
    ApprovalRequired,
}

impl Default for Decision {
    fn default() -> Self {
        Decision::Allow
    }
}

/// Log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    entry_id: String,
    version: String,
    timestamp_unix: i64,
    timestamp_iso: String,
    event_type: EventType,
    actor: Actor,
    request: Option<RequestContext>,
    compliance: Option<Compliance>,
    proof_envelope_v1_b64: Option<String>,
    integrity: Integrity,
    decision: Decision,
    rule_id: Option<String>,
}

/// Immutable builder for `LogEntry`.
#[derive(Debug, Clone)]
pub struct LogEntryBuilder {
    event_type: EventType,
    actor: Actor,
    request: Option<RequestContext>,
    compliance: Option<Compliance>,
    proof_envelope_v1_b64: Option<String>,
    decision: Decision,
    rule_id: Option<String>,
}

#[derive(Serialize)]
struct CanonicalLogEntryContent<'a> {
    entry_id: &'a str,
    version: &'a str,
    timestamp_unix: i64,
    timestamp_iso: &'a str,
    event_type: EventType,
    actor: &'a Actor,
    request: &'a Option<RequestContext>,
    compliance: &'a Option<Compliance>,
    proof_envelope_v1_b64: &'a Option<String>,
    decision: Decision,
    rule_id: &'a Option<String>,
}

#[derive(Serialize)]
struct CanonicalLogEntryFull<'a> {
    content: CanonicalLogEntryContent<'a>,
    integrity: &'a Integrity,
}

#[derive(Serialize)]
struct CanonicalLogEntryCommit<'a> {
    entry_id: &'a str,
    content_hash: &'a str,
    previous_entry_hash: &'a str,
}

impl LogEntryBuilder {
    pub fn mission(mut self, mission_id: Option<String>, mission_type: Option<String>) -> Self {
        self.actor.mission_id = mission_id;
        self.actor.mission_type = mission_type;
        self
    }

    pub fn request(mut self, request: RequestContext) -> Self {
        self.request = Some(request);
        self
    }

    pub fn compliance(mut self, compliance: Compliance) -> Self {
        self.compliance = Some(compliance);
        self
    }

    pub fn decision(mut self, decision: Decision) -> Self {
        self.decision = decision;
        self
    }

    /// Attach a canonical ProofEnvelopeV1 payload (base64-encoded for JSON storage).
    pub fn proof_envelope_v1_bytes(mut self, bytes: &[u8]) -> Self {
        use base64::Engine as _;
        self.proof_envelope_v1_b64 = Some(base64::engine::general_purpose::STANDARD.encode(bytes));
        self
    }

    pub fn rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn build(self) -> Result<LogEntry, LogError> {
        let timestamp = Utc::now();
        let timestamp_unix = timestamp.timestamp();
        let timestamp_iso = timestamp.to_rfc3339();
        let entry_id = format!(
            "le_{}_{}",
            timestamp_unix,
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("unknown")
        );

        let mut entry = LogEntry {
            entry_id,
            version: "1.0".to_string(),
            timestamp_unix,
            timestamp_iso,
            event_type: self.event_type,
            actor: self.actor,
            request: self.request,
            compliance: self.compliance,
            proof_envelope_v1_b64: self.proof_envelope_v1_b64,
            integrity: Integrity {
                content_hash: String::new(),
                previous_entry_hash: String::new(),
            },
            decision: self.decision,
            rule_id: self.rule_id,
        };
        entry.recompute_content_hash()?;
        Ok(entry)
    }
}

impl LogEntry {
    /// Create a builder for a new log entry.
    pub fn builder(event_type: EventType, agent_id: String, agent_org: String) -> LogEntryBuilder {
        LogEntryBuilder {
            event_type,
            actor: Actor {
                agent_id,
                agent_org,
                mission_id: None,
                mission_type: None,
            },
            request: None,
            compliance: None,
            proof_envelope_v1_b64: None,
            decision: Decision::Allow,
            rule_id: None,
        }
    }

    /// Backward-compatible constructor using default builder values.
    pub fn new(event_type: EventType, agent_id: String, agent_org: String) -> Self {
        Self::builder(event_type, agent_id, agent_org)
            .build()
            .unwrap_or_else(|_| Self {
                entry_id: "le_invalid".to_string(),
                version: "1.0".to_string(),
                timestamp_unix: 0,
                timestamp_iso: "1970-01-01T00:00:00+00:00".to_string(),
                event_type,
                actor: Actor {
                    agent_id: "invalid".to_string(),
                    agent_org: "invalid".to_string(),
                    mission_id: None,
                    mission_type: None,
                },
                request: None,
                compliance: None,
                proof_envelope_v1_b64: None,
                integrity: Integrity {
                    content_hash: "0".repeat(64),
                    previous_entry_hash: String::new(),
                },
                decision: Decision::Allow,
                rule_id: None,
            })
    }

    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    pub fn decision(&self) -> Decision {
        self.decision
    }

    pub fn proof_envelope_v1_b64(&self) -> Option<&str> {
        self.proof_envelope_v1_b64.as_deref()
    }

    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }

    pub fn timestamp_iso(&self) -> &str {
        &self.timestamp_iso
    }

    pub(crate) fn previous_entry_hash(&self) -> &str {
        self.integrity.previous_entry_hash()
    }

    pub(crate) fn verify_content_hash(&self) -> bool {
        match self.compute_content_hash() {
            Ok(v) => v == self.integrity.content_hash,
            Err(_) => false,
        }
    }

    pub(crate) fn commit_with_previous_hash(mut self, previous_hash: &str) -> Result<Self, LogError> {
        self.integrity.previous_entry_hash = previous_hash.to_string();
        self.recompute_content_hash()?;
        Ok(self)
    }

    pub(crate) fn canonical_entry_bytes(&self) -> Result<Vec<u8>, LogError> {
        let full = CanonicalLogEntryFull {
            content: self.canonical_content_payload(),
            integrity: &self.integrity,
        };
        encode_canonical(ENTRY_SCHEMA_ID, &full)
    }

    /// Compute full hash including previous entry hash using canonical encoding.
    pub fn compute_hash(&self, previous_hash: &str) -> Result<String, LogError> {
        let commit = CanonicalLogEntryCommit {
            entry_id: &self.entry_id,
            content_hash: &self.integrity.content_hash,
            previous_entry_hash: previous_hash,
        };
        let bytes = encode_canonical(COMMIT_SCHEMA_ID, &commit)?;
        Ok(sha256_hex(&bytes))
    }

    fn canonical_content_payload(&self) -> CanonicalLogEntryContent<'_> {
        CanonicalLogEntryContent {
            entry_id: &self.entry_id,
            version: &self.version,
            timestamp_unix: self.timestamp_unix,
            timestamp_iso: &self.timestamp_iso,
            event_type: self.event_type,
            actor: &self.actor,
            request: &self.request,
            compliance: &self.compliance,
            proof_envelope_v1_b64: &self.proof_envelope_v1_b64,
            decision: self.decision,
            rule_id: &self.rule_id,
        }
    }

    fn compute_content_hash(&self) -> Result<String, LogError> {
        let content = self.canonical_content_payload();
        let bytes = encode_canonical(CONTENT_SCHEMA_ID, &content)?;
        Ok(sha256_hex(&bytes))
    }

    fn recompute_content_hash(&mut self) -> Result<(), LogError> {
        self.integrity.content_hash = self.compute_content_hash()?;
        Ok(())
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn encode_canonical<T: Serialize>(schema_id: &str, payload: &T) -> Result<Vec<u8>, LogError> {
    let json = serde_json::to_vec(payload)
        .map_err(|e| LogError::SerializationError(e.to_string()))?;
    let schema_len: u16 = schema_id
        .len()
        .try_into()
        .map_err(|_| LogError::SerializationError("schema_id too long".to_string()))?;
    let json_len: u32 = json
        .len()
        .try_into()
        .map_err(|_| LogError::SerializationError("payload too long".to_string()))?;

    let mut out = Vec::with_capacity(1 + 2 + schema_id.len() + 4 + json.len());
    out.push(CANONICAL_ENCODING_VERSION);
    out.extend_from_slice(&schema_len.to_be_bytes());
    out.extend_from_slice(schema_id.as_bytes());
    out.extend_from_slice(&json_len.to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_entry() {
        let entry = LogEntry::new(
            EventType::AccountQuery,
            "AGENT_001".to_string(),
            "FISCALITE_DGFiP".to_string(),
        );

        assert!(entry.entry_id().starts_with("le_"));
        assert_eq!(entry.event_type(), EventType::AccountQuery);
        assert!(entry.verify_content_hash());
    }

    #[test]
    fn test_compute_hash() {
        let entry = LogEntry::new(
            EventType::AuthSuccess,
            "AGENT_001".to_string(),
            "GENDARMERIE".to_string(),
        )
        .commit_with_previous_hash("previous_hash_123")
        .unwrap();

        let hash = entry.compute_hash("previous_hash_123").unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_tamper_invalidates_content_hash() {
        let mut entry = LogEntry::new(
            EventType::RuleViolation,
            "AGENT_001".to_string(),
            "DGFiP".to_string(),
        );
        assert!(entry.verify_content_hash());

        entry.decision = Decision::Block;
        assert!(!entry.verify_content_hash());
    }

    #[test]
    fn test_canonical_entry_bytes_have_version_and_schema_prefix() {
        let entry = LogEntry::new(
            EventType::DataAccess,
            "AGENT_001".to_string(),
            "ORG".to_string(),
        );
        let bytes = entry.canonical_entry_bytes().unwrap();
        assert_eq!(bytes[0], CANONICAL_ENCODING_VERSION);
        let schema_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        let schema = std::str::from_utf8(&bytes[3..3 + schema_len]).unwrap();
        assert_eq!(schema, ENTRY_SCHEMA_ID);
    }

    #[test]
    fn test_proof_envelope_attachment_is_hashed() {
        let base = LogEntry::builder(
            EventType::RuleViolation,
            "AGENT_001".to_string(),
            "ORG".to_string(),
        )
        .decision(Decision::Block)
        .build()
        .unwrap();

        let with_proof = LogEntry::builder(
            EventType::RuleViolation,
            "AGENT_001".to_string(),
            "ORG".to_string(),
        )
        .decision(Decision::Block)
        .proof_envelope_v1_bytes(&[1, 2, 3, 4])
        .build()
        .unwrap();

        assert_ne!(
            base.integrity().content_hash(),
            with_proof.integrity().content_hash()
        );
        assert!(with_proof.proof_envelope_v1_b64().is_some());
    }
}
