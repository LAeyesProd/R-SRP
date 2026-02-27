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
    #[serde(default)]
    pub legal_basis: Option<String>,
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
    pub legal_basis: String,
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

/// Daily publication verification response
#[derive(Debug, Serialize)]
pub struct DailyPublicationVerifyResponse {
    pub date: String,
    pub root_hash: String,
    pub hourly_root_count: usize,
    pub recomputed_root_hash: String,
    pub root_hash_verified: bool,
    pub previous_day_link_verified: Option<bool>,
    pub previous_day_link_status: String,
    pub previous_publication_date: Option<String>,
    pub previous_publication_root_hash: Option<String>,
    pub signature_present: bool,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signature_verified: Option<bool>,
    pub signature_public_key_hex: Option<String>,
    pub tsa_present: bool,
    pub tsa_url: Option<String>,
    pub tsa_verified: Option<bool>,
    pub tsa_status: Option<String>,
    pub verified_at: String,
}

/// Daily publication response (creation + persistence info)
#[derive(Debug, Serialize)]
pub struct DailyPublishResponse {
    pub date: String,
    pub root_hash: String,
    pub entry_count: u64,
    pub previous_day_root: String,
    pub published_at: String,
    pub json_path: String,
    pub gzip_path: Option<String>,
    pub signature_algorithm: Option<String>,
    pub signature_key_id: Option<String>,
    pub signature_public_key_hex: Option<String>,
    pub signature_verified: Option<bool>,
    pub tsa_url: Option<String>,
    pub tsa_timestamp: Option<String>,
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
