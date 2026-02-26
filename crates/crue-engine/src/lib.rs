//! CRUE Engine - Deterministic Rule Execution Engine
//! 
//! This is the core of the Zero-Trust access control system.
//! Rules are immutable, versioned, signed, and cannot be bypassed.

pub mod engine;
pub mod context;
pub mod decision;
pub mod rules;
pub mod error;
pub mod vm;
pub mod proof;
pub mod ir;

use serde::{Deserialize, Serialize};

/// Rule evaluation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// Request ID for tracing
    pub request_id: String,
    /// Agent information
    pub agent_id: String,
    pub agent_org: String,
    pub agent_level: String,
    /// Mission context
    pub mission_id: Option<String>,
    pub mission_type: Option<String>,
    /// Request details
    pub query_type: Option<String>,
    pub justification: Option<String>,
    pub export_format: Option<String>,
    pub result_limit: Option<u32>,
    /// Real-time metrics
    pub requests_last_hour: u32,
    pub requests_last_24h: u32,
    pub results_last_query: u32,
    /// Geographic context
    pub account_department: Option<String>,
    pub allowed_departments: Vec<u32>,
    /// Time context
    pub request_hour: u32,
    pub is_within_mission_hours: bool,
}

/// Rule evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Request ID
    pub request_id: String,
    /// Decision
    pub decision: decision::Decision,
    /// Error code (if blocked)
    pub error_code: Option<String>,
    /// Error message
    pub message: Option<String>,
    /// Rule ID that triggered
    pub rule_id: Option<String>,
    /// Rule version
    pub rule_version: Option<String>,
    /// Timestamp
    pub evaluated_at: String,
    /// Evaluation time in ms
    pub evaluation_time_ms: u64,
}

impl Default for EvaluationResult {
    fn default() -> Self {
        EvaluationResult {
            request_id: String::new(),
            decision: decision::Decision::Allow,
            error_code: None,
            message: None,
            rule_id: None,
            rule_version: None,
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            evaluation_time_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_result() {
        let result = EvaluationResult::default();
        assert_eq!(result.decision, decision::Decision::Allow);
    }
    
    #[test]
    fn test_evaluation_request_serialization() {
        let request = EvaluationRequest {
            request_id: "req_001".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: Some("MIS_001".to_string()),
            mission_type: Some("FISCAL".to_string()),
            query_type: Some("SEARCH_BY_NAME".to_string()),
            justification: Some("Enquête".to_string()),
            export_format: None,
            result_limit: Some(50),
            requests_last_hour: 10,
            requests_last_24h: 100,
            results_last_query: 5,
            account_department: Some("75".to_string()),
            allowed_departments: vec![75, 92, 93],
            request_hour: 14,
            is_within_mission_hours: true,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("AGENT_001"));
    }
}
