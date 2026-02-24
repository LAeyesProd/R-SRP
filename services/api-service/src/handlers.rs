//! API Handlers

use axum::{
    extract::{State, Path, Query},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;
use crate::models::*;
use crate::error::ApiError;

/// Health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: "1.0.0".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Readiness check endpoint - confirms service can handle requests
pub async fn ready_check(
    State(state): State<Arc<AppState>>,
) -> Json<ReadyResponse> {
    // Check if CRUE engine is initialized
    let engine_ready = state.engine.rule_count() >= 0;
    
    Json(ReadyResponse {
        ready: engine_ready,
        components: ComponentStatus {
            engine: if engine_ready { "ready".to_string() } else { "not_ready".to_string() },
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Validate access (GET)
pub async fn validate_access(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ValidateParams>,
) -> Result<Json<ValidationResponse>, ApiError> {
    tracing::debug!("Validating access for agent: {}", params.agent_id);
    
    let request = crue_engine::EvaluationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        agent_id: params.agent_id,
        agent_org: params.agent_org,
        agent_level: params.agent_level.unwrap_or_else(|| "standard".to_string()),
        mission_id: params.mission_id,
        mission_type: params.mission_type,
        query_type: params.query_type,
        justification: params.justification,
        export_format: params.export_format,
        result_limit: params.result_limit,
        requests_last_hour: params.requests_last_hour.unwrap_or(0),
        requests_last_24h: params.requests_last_24h.unwrap_or(0),
        results_last_query: params.results_last_query.unwrap_or(0),
        account_department: params.account_department,
        allowed_departments: params.allowed_departments.unwrap_or_default(),
        request_hour: chrono::Utc::now().hour(),
        is_within_mission_hours: true,
    };
    
    let result = state.engine.evaluate(&request);
    
    Ok(Json(ValidationResponse {
        request_id: result.request_id,
        decision: format!("{:?}", result.decision),
        error_code: result.error_code,
        message: result.message,
        rule_id: result.rule_id,
        rule_version: result.rule_version,
        evaluated_at: result.evaluated_at,
        evaluation_time_ms: result.evaluation_time_ms,
    }))
}

/// Validate access (POST)
pub async fn validate_access_post(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ValidationRequest>,
) -> Result<Json<ValidationResponse>, ApiError> {
    tracing::debug!("Validating access for agent: {}", payload.agent_id);
    
    let request = crue_engine::EvaluationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        agent_id: payload.agent_id,
        agent_org: payload.agent_org,
        agent_level: payload.agent_level.unwrap_or_else(|| "standard".to_string()),
        mission_id: payload.mission_id,
        mission_type: payload.mission_type,
        query_type: payload.query_type,
        justification: payload.justification,
        export_format: payload.export_format,
        result_limit: payload.result_limit,
        requests_last_hour: payload.requests_last_hour.unwrap_or(0),
        requests_last_24h: payload.requests_last_24h.unwrap_or(0),
        results_last_query: payload.results_last_query.unwrap_or(0),
        account_department: payload.account_department,
        allowed_departments: payload.allowed_departments.unwrap_or_default(),
        request_hour: chrono::Utc::now().hour(),
        is_within_mission_hours: true,
    };
    
    let result = state.engine.evaluate(&request);
    
    Ok(Json(ValidationResponse {
        request_id: result.request_id,
        decision: format!("{:?}", result.decision),
        error_code: result.error_code,
        message: result.message,
        rule_id: result.rule_id,
        rule_version: result.rule_version,
        evaluated_at: result.evaluated_at,
        evaluation_time_ms: result.evaluation_time_ms,
    }))
}

/// Verify chain integrity
pub async fn verify_chain() -> Result<Json<ChainVerifyResponse>, ApiError> {
    // Simplified - would check actual chain
    Ok(Json(ChainVerifyResponse {
        valid: true,
        entry_count: 0,
        current_hash: "genesis".to_string(),
        verified_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Get daily root
pub async fn get_daily_root(
    Path(date): Path<String>,
) -> Result<Json<DailyRootResponse>, ApiError> {
    Ok(Json(DailyRootResponse {
        date,
        root_hash: "placeholder".to_string(),
        entry_count: 0,
        previous_day_root: "genesis".to_string(),
        published_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Metrics endpoint
pub async fn metrics() -> Result<Json<MetricsResponse>, ApiError> {
    Ok(Json(MetricsResponse {
        total_requests: 0,
        allowed_requests: 0,
        blocked_requests: 0,
        warnings: 0,
        avg_evaluation_time_ms: 0.0,
    }))
}
