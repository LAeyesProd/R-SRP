//! Log Entry - Structure of immutable audit log entries

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};

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
    pub content_hash: String,
    pub previous_entry_hash: String,
}

/// Log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique entry ID (format: le_{timestamp}_{uuid})
    pub entry_id: String,
    /// Schema version
    pub version: String,
    /// Unix timestamp
    pub timestamp_unix: i64,
    /// ISO 8601 timestamp
    pub timestamp_iso: String,
    /// Event type
    pub event_type: EventType,
    /// Actor information
    pub actor: Actor,
    /// Request context
    pub request: Option<RequestContext>,
    /// Compliance metadata
    pub compliance: Option<Compliance>,
    /// Integrity metadata
    pub integrity: Integrity,
    /// Decision made
    pub decision: Decision,
    /// Rule ID that triggered decision (if any)
    pub rule_id: Option<String>,
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

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        event_type: EventType,
        agent_id: String,
        agent_org: String,
    ) -> Self {
        let timestamp = Utc::now();
        let timestamp_unix = timestamp.timestamp();
        let timestamp_iso = timestamp.to_rfc3339();
        
        let entry_id = format!(
            "le_{}_{}",
            timestamp_unix,
            uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
        );
        
        let content_hash = Self::compute_content_hash(&entry_id, &timestamp_iso, event_type, &agent_id, &agent_org);
        
        LogEntry {
            entry_id,
            version: "1.0".to_string(),
            timestamp_unix,
            timestamp_iso,
            event_type,
            actor: Actor {
                agent_id,
                agent_org,
                mission_id: None,
                mission_type: None,
            },
            request: None,
            compliance: None,
            integrity: Integrity {
                content_hash: content_hash.clone(),
                previous_entry_hash: String::new(), // Will be set by chain
            },
            decision: Decision::Allow,
            rule_id: None,
        }
    }
    
    /// Compute content hash
    fn compute_content_hash(
        entry_id: &str,
        timestamp: &str,
        event_type: EventType,
        agent_id: &str,
        agent_org: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry_id.as_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(format!("{:?}", event_type).as_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(agent_org.as_bytes());
        
        format!("{:x}", hasher.finalize())
    }
    
    /// Compute full hash including previous entry
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.timestamp_iso.as_bytes());
        hasher.update(self.integrity.content_hash.as_bytes());
        hasher.update(previous_hash.as_bytes());
        
        format!("{:x}", hasher.finalize())
    }
    
    /// Update previous hash (called when appending to chain)
    pub fn update_previous_hash(&mut self, previous_hash: &str) {
        self.integrity.previous_entry_hash = previous_hash.to_string();
    }
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
        
        assert!(entry.entry_id.starts_with("le_"));
        assert_eq!(entry.event_type, EventType::AccountQuery);
    }
    
    #[test]
    fn test_compute_hash() {
        let mut entry = LogEntry::new(
            EventType::AuthSuccess,
            "AGENT_001".to_string(),
            "GENDARMERIE".to_string(),
        );
        
        entry.update_previous_hash("previous_hash_123");
        let hash = entry.compute_hash("previous_hash_123");
        
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
}
