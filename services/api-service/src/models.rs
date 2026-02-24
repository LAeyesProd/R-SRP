//! API Models

use serde::{Deserialize, Serialize};

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: String,
}

/// Component status for readiness check
#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    pub engine: String,
}

/// Readiness check response
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub components: ComponentStatus,
    pub timestamp: String,
}

/// Validation parameters (GET)
#[derive(Debug, Deserialize)]
pub struct ValidateParams {
    pub agent_id: String,
    pub agent_org: String,
    #[serde(default)]
    pub agent_level: Option<String>,
    #[serde(default)]
    pub mission_id: Option<String>,
    #[serde(default)]
    pub mission_type: Option<String>,
    #[serde(default)]
    pub query_type: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub export_format: Option<String>,
    #[serde(default)]
    pub result_limit: Option<u32>,
    #[serde(default)]
    pub requests_last_hour: Option<u32>,
    #[serde(default)]
    pub requests_last_24h: Option<u32>,
    #[serde(default)]
    pub results_last_query: Option<u32>,
    #[serde(default)]
    pub account_department: Option<String>,
    #[serde(default)]
    pub allowed_departments: Option<Vec<u32>>,
}

/// Validation request (POST)
#[derive(Debug, Deserialize)]
pub struct ValidationRequest {
    pub agent_id: String,
    pub agent_org: String,
    #[serde(default)]
    pub agent_level: Option<String>,
    #[serde(default)]
    pub mission_id: Option<String>,
    #[serde(default)]
    pub mission_type: Option<String>,
    #[serde(default)]
    pub query_type: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub export_format: Option<String>,
    #[serde(default)]
    pub result_limit: Option<u32>,
    #[serde(default)]
    pub requests_last_hour: Option<u32>,
    #[serde(default)]
    pub requests_last_24h: Option<u32>,
    #[serde(default)]
    pub results_last_query: Option<u32>,
    #[serde(default)]
    pub account_department: Option<String>,
    #[serde(default)]
    pub allowed_departments: Option<Vec<u32>>,
}

/// Validation response
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    pub request_id: String,
    pub decision: String,
    pub error_code: Option<String>,
    pub message: Option<String>,
    pub rule_id: Option<String>,
    pub rule_version: Option<String>,
    pub evaluated_at: String,
    pub evaluation_time_ms: u64,
}

/// Chain verification response
#[derive(Debug, Serialize)]
pub struct ChainVerifyResponse {
    pub valid: bool,
    pub entry_count: u64,
    pub current_hash: String,
    pub verified_at: String,
}

/// Daily root response
#[derive(Debug, Serialize)]
pub struct DailyRootResponse {
    pub date: String,
    pub root_hash: String,
    pub entry_count: u64,
    pub previous_day_root: String,
    pub published_at: String,
}

/// Metrics response
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub warnings: u64,
    pub avg_evaluation_time_ms: f64,
}
