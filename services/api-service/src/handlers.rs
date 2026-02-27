//! API Handlers

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::USER_AGENT, HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::Timelike;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;

use crate::error::ApiError;
use crate::middleware;
use crate::models::*;
use crate::AppState;
use immutable_logging::log_entry::{
    Compliance, Decision as AuditDecision, EventType, LogEntry,
    RequestContext as AuditRequestContext,
};
use immutable_logging::merkle_service::HourlyRoot;
use immutable_logging::publication::{DailyPublication, TsaCmsVerifyError};

/// Health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    let expose_version = cfg!(debug_assertions)
        || std::env::var("HEALTH_EXPOSE_VERSION")
            .ok()
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: if expose_version {
            "1.0.0".to_string()
        } else {
            "redacted".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Readiness check endpoint - confirms service can handle requests
pub async fn ready_check(State(state): State<Arc<AppState>>) -> Json<ReadyResponse> {
    // Check if CRUE engine is initialized
    let rule_count = state.engine.rule_count();
    let engine_ready = rule_count > 0;

    Json(ReadyResponse {
        ready: engine_ready,
        components: ComponentStatus {
            engine: if engine_ready {
                "ready".to_string()
            } else {
                "not_ready".to_string()
            },
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Validate access (GET)
pub async fn validate_access(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ValidateParams>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<ValidationResponse>, ApiError> {
    validate_get_request(&params)?;
    tracing::debug!("Validating access for agent: {}", params.agent_id);
    let ip_address = middleware::resolve_client_ip(
        &headers,
        connect_info.as_ref().map(|ci| ci.0.ip()),
        &state.trusted_proxies,
    );
    let legal_basis = derive_legal_basis(
        params.legal_basis.as_deref(),
        params.query_type.as_deref(),
        params.mission_type.as_deref(),
        Some(params.agent_org.as_str()),
    )?;
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

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
    state.record_validation_metrics(result.decision, result.evaluation_time_ms);
    record_validation_decision_audit(
        &state,
        &request,
        &result,
        ip_address,
        user_agent,
        legal_basis,
    )
    .await;

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
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(payload): Json<ValidationRequest>,
) -> Result<Json<ValidationResponse>, ApiError> {
    validate_post_request(&payload)?;
    tracing::debug!("Validating access for agent: {}", payload.agent_id);
    let ip_address = middleware::resolve_client_ip(
        &headers,
        connect_info.as_ref().map(|ci| ci.0.ip()),
        &state.trusted_proxies,
    );
    let legal_basis = derive_legal_basis(
        Some(payload.legal_basis.as_str()),
        payload.query_type.as_deref(),
        payload.mission_type.as_deref(),
        Some(payload.agent_org.as_str()),
    )?;
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    let request = crue_engine::EvaluationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        agent_id: payload.agent_id,
        agent_org: payload.agent_org,
        agent_level: payload
            .agent_level
            .unwrap_or_else(|| "standard".to_string()),
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
    state.record_validation_metrics(result.decision, result.evaluation_time_ms);
    record_validation_decision_audit(
        &state,
        &request,
        &result,
        ip_address,
        user_agent,
        legal_basis,
    )
    .await;

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
pub async fn verify_chain(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChainVerifyResponse>, ApiError> {
    let valid = state.logging.verify().await?;
    let entry_count = state.logging.entry_count().await as u64;
    let current_hash = state.logging.current_hash().await;

    Ok(Json(ChainVerifyResponse {
        valid,
        entry_count,
        current_hash,
        verified_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Get daily root
pub async fn get_daily_root(
    State(state): State<Arc<AppState>>,
    Path(date): Path<String>,
) -> Result<Json<DailyRootResponse>, ApiError> {
    let dir = state.audit_publications_dir.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Audit publication store is not configured (AUDIT_PUBLICATIONS_DIR)",
        )
    })?;

    let publication = load_daily_publication_from_dir(dir, &date).map_err(|e| {
        ApiError::new(
            match e {
                LoadPublicationError::NotFound(_) => StatusCode::NOT_FOUND,
                LoadPublicationError::Io(_) | LoadPublicationError::Parse(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            e.to_string(),
        )
    })?;

    Ok(Json(DailyRootResponse {
        date: publication.date,
        root_hash: publication.root_hash,
        entry_count: publication.entry_count,
        previous_day_root: publication.previous_day_root,
        published_at: publication.created_at,
    }))
}

/// Verify a stored daily publication (signature + TSA metadata presence/status)
pub async fn verify_daily_publication(
    State(state): State<Arc<AppState>>,
    Path(date): Path<String>,
) -> Result<Json<DailyPublicationVerifyResponse>, ApiError> {
    let dir = state.audit_publications_dir.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Audit publication store is not configured (AUDIT_PUBLICATIONS_DIR)",
        )
    })?;

    let publication = load_daily_publication_from_dir(dir, &date).map_err(|e| {
        ApiError::new(
            match e {
                LoadPublicationError::NotFound(_) => StatusCode::NOT_FOUND,
                LoadPublicationError::Io(_) | LoadPublicationError::Parse(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            e.to_string(),
        )
    })?;

    let recomputed_root_hash = publication.recompute_root_hash();
    let root_hash_verified = publication.root_hash == recomputed_root_hash;
    let (
        previous_day_link_verified,
        previous_day_link_status,
        previous_publication_date,
        previous_publication_root_hash,
    ) = verify_previous_day_link(dir, &publication);

    let mut signature_verified = None;
    let mut signature_public_key_hex = None;
    if let Some(signature) = publication.signature.as_ref() {
        let payload = publication_signed_payload(&publication)?;
        let signature_bytes = BASE64_STANDARD
            .decode(signature.value.as_bytes())
            .map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Invalid publication signature encoding: {e}"),
                )
            })?;
        if let Some(signer) = state.audit_publication_signer.as_ref() {
            let mut signer = signer.lock().await;
            let verified = signer
                .verify_publication_signature(
                    &payload,
                    &signature_bytes,
                    &signature.algorithm,
                    &signature.key_id,
                )
                .map_err(|e| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to verify publication signature: {e}"),
                    )
                })?;
            signature_public_key_hex = signer.verification_public_key_hex();
            signature_verified = Some(verified);
        }
    }

    let (tsa_present, tsa_url, mut tsa_verified, mut tsa_status) =
        tsa_verification_status(&publication);
    if let (Some(tsa), Some(trust_store_path)) = (
        publication.tsa_timestamp.as_ref(),
        state.audit_tsa_trust_store_pem.as_ref(),
    ) {
        if !tsa.tsa_url.starts_with("mock://") {
            match std::fs::read(trust_store_path) {
                Ok(pem) => match tsa.verify_cms_signature_with_pem_roots(&pem) {
                    Ok(cms) => {
                        let timestamp_matches = cms
                            .extracted_timestamp
                            .as_deref()
                            .map(|v| v == tsa.timestamp)
                            .unwrap_or(true);
                        tsa_verified = Some(cms.verified && timestamp_matches);
                        tsa_status = Some(if timestamp_matches {
                            "cms-signature-verified".to_string()
                        } else {
                            "cms-signature-verified-timestamp-mismatch".to_string()
                        });
                    }
                    Err(err) => {
                        tsa_verified = if matches!(err, TsaCmsVerifyError::BackendUnavailable(_)) {
                            None
                        } else {
                            Some(false)
                        };
                        tsa_status = Some(tsa_cms_verify_error_status(&err));
                    }
                },
                Err(_) => {
                    tsa_status = Some("tsa-trust-store-read-error".to_string());
                }
            }
        }
    }

    Ok(Json(DailyPublicationVerifyResponse {
        date: publication.date,
        root_hash: publication.root_hash,
        hourly_root_count: publication.hourly_roots.len(),
        recomputed_root_hash,
        root_hash_verified,
        previous_day_link_verified,
        previous_day_link_status,
        previous_publication_date,
        previous_publication_root_hash,
        signature_present: publication.signature.is_some(),
        signature_algorithm: publication.signature.as_ref().map(|s| s.algorithm.clone()),
        signature_key_id: publication.signature.as_ref().map(|s| s.key_id.clone()),
        signature_verified,
        signature_public_key_hex,
        tsa_present,
        tsa_url,
        tsa_verified,
        tsa_status,
        verified_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Publish daily root/publication to filesystem backend
pub async fn publish_daily(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DailyPublishResponse>, ApiError> {
    let dir = state.audit_publications_dir.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Audit publication store is not configured (AUDIT_PUBLICATIONS_DIR)",
        )
    })?;

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    match load_daily_publication_from_dir(dir, &date) {
        Ok(_) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("Daily publication already exists for date {date}"),
            ));
        }
        Err(LoadPublicationError::NotFound(_)) => {}
        Err(LoadPublicationError::Io(e)) | Err(LoadPublicationError::Parse(e)) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to check existing publication for {date}: {e}"),
            ));
        }
    }

    let hourly_roots = state.logging.hourly_roots_snapshot().await;
    let filtered = hourly_root_hashes_for_date(&hourly_roots, &date);
    if filtered.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("No hourly roots available to publish for date {date}"),
        ));
    }

    let entry_count = state.logging.entry_count().await as u64;
    let mut publisher = state.publication_service.lock().await;
    let mut publication = publisher.create_daily_publication(&filtered, entry_count);

    let mut signature_public_key_hex = None;
    let mut signature_verified = None;
    if let Some(signer) = state.audit_publication_signer.as_ref() {
        let mut signer = signer.lock().await;
        let signed_payload = publication.to_canonical_json_bytes()?;
        let signed = signer
            .sign_publication_payload(&signed_payload)
            .map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to sign daily publication: {e}"),
                )
            })?;
        publisher.sign_publication_with_metadata(
            &mut publication,
            &signed.signature,
            &signed.algorithm,
            &signed.key_id,
        );
        signature_public_key_hex = signed.public_key_hex;
        signature_verified = signed.verified;
    }

    if let Some(tsa_url) = state.audit_tsa_url.as_deref() {
        publisher
            .add_tsa_timestamp(&mut publication, tsa_url)
            .await
            .map_err(|e| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to timestamp publication with TSA: {e}"),
                )
            })?;
    }

    let written = publisher.publish_to_filesystem(&publication, dir, true)?;
    let signature_algorithm = publication.signature.as_ref().map(|s| s.algorithm.clone());
    let signature_key_id = publication.signature.as_ref().map(|s| s.key_id.clone());
    let tsa_url = publication
        .tsa_timestamp
        .as_ref()
        .map(|t| t.tsa_url.clone());
    let tsa_timestamp = publication
        .tsa_timestamp
        .as_ref()
        .map(|t| t.timestamp.clone());

    Ok(Json(DailyPublishResponse {
        date: publication.date,
        root_hash: publication.root_hash,
        entry_count: publication.entry_count,
        previous_day_root: publication.previous_day_root,
        published_at: publication.created_at,
        json_path: written.json_path.display().to_string(),
        gzip_path: written.gzip_path.map(|p| p.display().to_string()),
        signature_algorithm,
        signature_key_id,
        signature_public_key_hex,
        signature_verified,
        tsa_url,
        tsa_timestamp,
    }))
}

/// Metrics endpoint
pub async fn metrics(
    State(state): State<Arc<AppState>>,
) -> Result<Json<MetricsResponse>, ApiError> {
    let (total_requests, allowed_requests, blocked_requests, warnings, avg_evaluation_time_ms) =
        state.metrics_snapshot();
    Ok(Json(MetricsResponse {
        total_requests,
        allowed_requests,
        blocked_requests,
        warnings,
        avg_evaluation_time_ms,
    }))
}

#[derive(Debug, thiserror::Error)]
enum LoadPublicationError {
    #[error("Daily publication not found for date {0}")]
    NotFound(String),
    #[error("Publication store I/O error: {0}")]
    Io(String),
    #[error("Publication parse error: {0}")]
    Parse(String),
}

fn load_daily_publication_from_dir(
    dir: &FsPath,
    date: &str,
) -> Result<DailyPublication, LoadPublicationError> {
    let entries = std::fs::read_dir(dir).map_err(|e| LoadPublicationError::Io(e.to_string()))?;
    let prefix = format!("daily-publication-{date}-");

    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| LoadPublicationError::Io(e.to_string()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(v) => v,
            None => continue,
        };
        if name.starts_with(&prefix) && name.ends_with(".json") {
            candidates.push(path);
        }
    }

    candidates.sort();
    let path = candidates
        .into_iter()
        .next()
        .ok_or_else(|| LoadPublicationError::NotFound(date.to_string()))?;

    let bytes = std::fs::read(&path).map_err(|e| LoadPublicationError::Io(e.to_string()))?;
    serde_json::from_slice::<DailyPublication>(&bytes)
        .map_err(|e| LoadPublicationError::Parse(format!("{} ({})", path.display(), e)))
}

fn hourly_root_hashes_for_date(roots: &[HourlyRoot], date: &str) -> Vec<String> {
    let prefix = format!("{date}T");
    let mut filtered: Vec<&HourlyRoot> = roots
        .iter()
        .filter(|r| r.hour.starts_with(&prefix))
        .collect();
    filtered.sort_by(|a, b| a.hour.cmp(&b.hour));
    filtered.into_iter().map(|r| r.root_hash.clone()).collect()
}

fn publication_signed_payload(publication: &DailyPublication) -> Result<Vec<u8>, ApiError> {
    let mut unsigned = publication.clone();
    unsigned.signature = None;
    unsigned.tsa_timestamp = None;
    Ok(unsigned.to_canonical_json_bytes()?)
}

fn tsa_verification_status(
    publication: &DailyPublication,
) -> (bool, Option<String>, Option<bool>, Option<String>) {
    match publication.tsa_timestamp.as_ref() {
        None => (false, None, None, None),
        Some(tsa) if tsa.tsa_url.starts_with("mock://") => {
            if tsa.token.starts_with("mock-sha256=") {
                (
                    true,
                    Some(tsa.tsa_url.clone()),
                    None,
                    Some("mock-token-format-ok".to_string()),
                )
            } else {
                (
                    true,
                    Some(tsa.tsa_url.clone()),
                    Some(false),
                    Some("mock-token-format-invalid".to_string()),
                )
            }
        }
        Some(tsa) => {
            let inspected = tsa.inspect_token();
            let status = if !inspected.token_present {
                "token-missing".to_string()
            } else if !inspected.token_base64_valid {
                "token-base64-invalid".to_string()
            } else if !inspected.token_der_nonempty {
                "token-der-empty".to_string()
            } else if let Some(extracted) = &inspected.extracted_timestamp {
                let ts_matches = tsa.timestamp == *extracted;
                if ts_matches {
                    "token-parse-ok-timestamp-match".to_string()
                } else {
                    "token-parse-ok-timestamp-mismatch".to_string()
                }
            } else {
                "token-parse-partial-no-time".to_string()
            };

            let tsa_verified = if !inspected.token_base64_valid || !inspected.token_der_nonempty {
                Some(false)
            } else {
                None
            };

            (true, Some(tsa.tsa_url.clone()), tsa_verified, Some(status))
        }
    }
}

fn verify_previous_day_link(
    dir: &FsPath,
    publication: &DailyPublication,
) -> (Option<bool>, String, Option<String>, Option<String>) {
    let zero_root = "0".repeat(64);
    let prev_date = match previous_date(&publication.date) {
        Some(d) => d,
        None => {
            return (None, "date-parse-error".to_string(), None, None);
        }
    };

    if publication.previous_day_root == zero_root {
        return (None, "genesis-link".to_string(), Some(prev_date), None);
    }

    match load_daily_publication_from_dir(dir, &prev_date) {
        Ok(prev) => {
            let matches = prev.root_hash == publication.previous_day_root;
            (
                Some(matches),
                if matches {
                    "previous-day-match".to_string()
                } else {
                    "previous-day-mismatch".to_string()
                },
                Some(prev_date),
                Some(prev.root_hash),
            )
        }
        Err(LoadPublicationError::NotFound(_)) => (
            None,
            "previous-day-not-found".to_string(),
            Some(prev_date),
            None,
        ),
        Err(LoadPublicationError::Io(_)) => (
            None,
            "previous-day-store-io-error".to_string(),
            Some(prev_date),
            None,
        ),
        Err(LoadPublicationError::Parse(_)) => (
            None,
            "previous-day-parse-error".to_string(),
            Some(prev_date),
            None,
        ),
    }
}

fn previous_date(date: &str) -> Option<String> {
    let d = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    d.pred_opt().map(|v| v.format("%Y-%m-%d").to_string())
}

fn tsa_cms_verify_error_status(err: &TsaCmsVerifyError) -> String {
    match err {
        TsaCmsVerifyError::BackendUnavailable(_) => "cms-backend-unavailable".to_string(),
        TsaCmsVerifyError::TokenMissing => "cms-token-missing".to_string(),
        TsaCmsVerifyError::TokenBase64(_) => "cms-token-base64-invalid".to_string(),
        TsaCmsVerifyError::Pkcs7Parse(_) => "cms-token-pkcs7-parse-failed".to_string(),
        TsaCmsVerifyError::TrustStore(_) => "cms-trust-store-invalid".to_string(),
        TsaCmsVerifyError::Verify(_) => "cms-signature-invalid".to_string(),
    }
}

const MAX_AGENT_ID_LEN: usize = 256;
const MAX_AGENT_ORG_LEN: usize = 256;
const MAX_AGENT_LEVEL_LEN: usize = 64;
const MAX_MISSION_ID_LEN: usize = 256;
const MAX_MISSION_TYPE_LEN: usize = 128;
const MAX_QUERY_TYPE_LEN: usize = 128;
const MAX_JUSTIFICATION_LEN: usize = 4096;
const MAX_EXPORT_FORMAT_LEN: usize = 64;
const MAX_ACCOUNT_DEPARTMENT_LEN: usize = 64;
const MAX_ALLOWED_DEPARTMENTS: usize = 256;
const MAX_LEGAL_BASIS_LEN: usize = 64;
const LEGAL_BASIS_ALLOWED: [&str; 3] = ["LEGITIMATE_INTEREST", "PUBLIC_TASK", "LEGAL_OBLIGATION"];

fn validate_required_field_len(name: &str, value: &str, max_len: usize) -> Result<(), ApiError> {
    let len = value.chars().count();
    if len == 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{name} cannot be empty"),
        ));
    }
    if len > max_len {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{name} exceeds maximum length ({max_len})"),
        ));
    }
    Ok(())
}

fn validate_optional_field_len(
    name: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<(), ApiError> {
    if let Some(value) = value {
        let len = value.chars().count();
        if len > max_len {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{name} exceeds maximum length ({max_len})"),
            ));
        }
    }
    Ok(())
}

fn validate_allowed_departments_len(allowed_departments: Option<&[u32]>) -> Result<(), ApiError> {
    if let Some(departments) = allowed_departments {
        if departments.len() > MAX_ALLOWED_DEPARTMENTS {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("allowed_departments exceeds maximum size ({MAX_ALLOWED_DEPARTMENTS})"),
            ));
        }
    }
    Ok(())
}

fn validate_get_request(params: &ValidateParams) -> Result<(), ApiError> {
    validate_required_field_len("agent_id", &params.agent_id, MAX_AGENT_ID_LEN)?;
    validate_required_field_len("agent_org", &params.agent_org, MAX_AGENT_ORG_LEN)?;
    validate_optional_field_len(
        "agent_level",
        params.agent_level.as_deref(),
        MAX_AGENT_LEVEL_LEN,
    )?;
    validate_optional_field_len(
        "mission_id",
        params.mission_id.as_deref(),
        MAX_MISSION_ID_LEN,
    )?;
    validate_optional_field_len(
        "mission_type",
        params.mission_type.as_deref(),
        MAX_MISSION_TYPE_LEN,
    )?;
    validate_optional_field_len(
        "query_type",
        params.query_type.as_deref(),
        MAX_QUERY_TYPE_LEN,
    )?;
    validate_optional_field_len(
        "justification",
        params.justification.as_deref(),
        MAX_JUSTIFICATION_LEN,
    )?;
    validate_optional_field_len(
        "export_format",
        params.export_format.as_deref(),
        MAX_EXPORT_FORMAT_LEN,
    )?;
    validate_optional_field_len(
        "account_department",
        params.account_department.as_deref(),
        MAX_ACCOUNT_DEPARTMENT_LEN,
    )?;
    validate_optional_field_len(
        "legal_basis",
        params.legal_basis.as_deref(),
        MAX_LEGAL_BASIS_LEN,
    )?;
    validate_allowed_departments_len(params.allowed_departments.as_deref())?;
    Ok(())
}

fn validate_post_request(payload: &ValidationRequest) -> Result<(), ApiError> {
    validate_required_field_len("agent_id", &payload.agent_id, MAX_AGENT_ID_LEN)?;
    validate_required_field_len("agent_org", &payload.agent_org, MAX_AGENT_ORG_LEN)?;
    validate_optional_field_len(
        "agent_level",
        payload.agent_level.as_deref(),
        MAX_AGENT_LEVEL_LEN,
    )?;
    validate_optional_field_len(
        "mission_id",
        payload.mission_id.as_deref(),
        MAX_MISSION_ID_LEN,
    )?;
    validate_optional_field_len(
        "mission_type",
        payload.mission_type.as_deref(),
        MAX_MISSION_TYPE_LEN,
    )?;
    validate_optional_field_len(
        "query_type",
        payload.query_type.as_deref(),
        MAX_QUERY_TYPE_LEN,
    )?;
    validate_optional_field_len(
        "justification",
        payload.justification.as_deref(),
        MAX_JUSTIFICATION_LEN,
    )?;
    validate_optional_field_len(
        "export_format",
        payload.export_format.as_deref(),
        MAX_EXPORT_FORMAT_LEN,
    )?;
    validate_optional_field_len(
        "account_department",
        payload.account_department.as_deref(),
        MAX_ACCOUNT_DEPARTMENT_LEN,
    )?;
    validate_required_field_len("legal_basis", &payload.legal_basis, MAX_LEGAL_BASIS_LEN)?;
    validate_allowed_departments_len(payload.allowed_departments.as_deref())?;
    Ok(())
}

fn normalize_legal_basis(value: &str) -> Result<String, ApiError> {
    let normalized = value.trim().to_ascii_uppercase();
    if LEGAL_BASIS_ALLOWED.contains(&normalized.as_str()) {
        return Ok(normalized);
    }
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "legal_basis must be one of: LEGITIMATE_INTEREST, PUBLIC_TASK, LEGAL_OBLIGATION",
    ))
}

fn derive_legal_basis(
    provided: Option<&str>,
    query_type: Option<&str>,
    mission_type: Option<&str>,
    agent_org: Option<&str>,
) -> Result<String, ApiError> {
    if let Some(basis) = provided {
        if !basis.trim().is_empty() {
            return normalize_legal_basis(basis);
        }
    }

    let query_type = query_type.unwrap_or_default().to_ascii_uppercase();
    if query_type.contains("EXPORT") {
        return Ok("LEGAL_OBLIGATION".to_string());
    }

    let mission_type = mission_type.unwrap_or_default().to_ascii_uppercase();
    if mission_type.contains("PUBLIC")
        || mission_type.contains("GOV")
        || mission_type.contains("FISCAL")
    {
        return Ok("PUBLIC_TASK".to_string());
    }

    let agent_org = agent_org.unwrap_or_default().to_ascii_uppercase();
    if agent_org.contains("DGFIP") || agent_org.contains("MINIST") || agent_org.contains("STATE") {
        return Ok("PUBLIC_TASK".to_string());
    }

    Ok("LEGITIMATE_INTEREST".to_string())
}

async fn record_validation_decision_audit(
    state: &Arc<AppState>,
    request: &crue_engine::EvaluationRequest,
    result: &crue_engine::EvaluationResult,
    ip_address: Option<String>,
    user_agent: Option<String>,
    legal_basis: String,
) {
    let entry = match build_audit_log_entry(request, result, ip_address, user_agent, &legal_basis) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(
                "Failed to build immutable audit log entry for request {}: {}",
                request.request_id,
                err
            );
            return;
        }
    };
    if let Err(err) = state.logging.append(entry).await {
        tracing::warn!(
            "Failed to append immutable audit log for request {}: {}",
            request.request_id,
            err
        );
    }
}

fn build_audit_log_entry(
    request: &crue_engine::EvaluationRequest,
    result: &crue_engine::EvaluationResult,
    ip_address: Option<String>,
    user_agent: Option<String>,
    legal_basis: &str,
) -> Result<LogEntry, immutable_logging::error::LogError> {
    let event_type = match result.decision {
        crue_engine::decision::Decision::Allow => {
            if request.export_format.is_some() {
                EventType::ExportRequested
            } else {
                EventType::AccountQuery
            }
        }
        crue_engine::decision::Decision::Block
        | crue_engine::decision::Decision::Warn
        | crue_engine::decision::Decision::ApprovalRequired => EventType::RuleViolation,
    };

    let decision = match result.decision {
        crue_engine::decision::Decision::Allow => AuditDecision::Allow,
        crue_engine::decision::Decision::Block => AuditDecision::Block,
        crue_engine::decision::Decision::Warn => AuditDecision::Warn,
        crue_engine::decision::Decision::ApprovalRequired => AuditDecision::ApprovalRequired,
    };
    let mut builder = LogEntry::builder(
        event_type,
        request.agent_id.clone(),
        request.agent_org.clone(),
    )
    .mission(request.mission_id.clone(), request.mission_type.clone())
    .request(AuditRequestContext {
        query_type: request.query_type.clone(),
        justification: request.justification.clone(),
        result_count: Some(request.results_last_query),
        ip_address,
        user_agent,
    })
    .compliance(Compliance {
        legal_basis: legal_basis.to_string(),
        retention_years: 10,
    })
    .decision(decision);
    if let Some(rule_id) = &result.rule_id {
        builder = builder.rule_id(rule_id.clone());
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use immutable_logging::publication::{PublicationService, TsaTimestamp};

    #[test]
    fn test_load_daily_publication_from_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["ab".repeat(32)], 5);
        service
            .publish_to_filesystem(&publication, tmp.path(), true)
            .expect("publish");

        let loaded = load_daily_publication_from_dir(tmp.path(), &publication.date).expect("load");
        assert_eq!(loaded.date, publication.date);
        assert_eq!(loaded.root_hash, publication.root_hash);
        assert_eq!(loaded.entry_count, 5);
    }

    #[test]
    fn test_hourly_root_hashes_for_date_filters_and_sorts() {
        let roots = vec![
            HourlyRoot {
                hour: "2026-02-26T12:00:00Z".to_string(),
                root_hash: "h12".to_string(),
                entry_count: 1,
                generated_at: 0,
            },
            HourlyRoot {
                hour: "2026-02-25T23:00:00Z".to_string(),
                root_hash: "h23".to_string(),
                entry_count: 1,
                generated_at: 0,
            },
            HourlyRoot {
                hour: "2026-02-26T09:00:00Z".to_string(),
                root_hash: "h09".to_string(),
                entry_count: 1,
                generated_at: 0,
            },
        ];

        let hashes = hourly_root_hashes_for_date(&roots, "2026-02-26");
        assert_eq!(hashes, vec!["h09".to_string(), "h12".to_string()]);
    }

    #[test]
    fn test_build_audit_log_entry_maps_block_to_rule_violation() {
        let request = crue_engine::EvaluationRequest {
            request_id: "req-1".to_string(),
            agent_id: "AGENT_001".to_string(),
            agent_org: "DGFiP".to_string(),
            agent_level: "standard".to_string(),
            mission_id: Some("MIS_001".to_string()),
            mission_type: Some("FISCAL".to_string()),
            query_type: Some("SEARCH".to_string()),
            justification: Some("test".to_string()),
            export_format: None,
            result_limit: Some(10),
            requests_last_hour: 1,
            requests_last_24h: 2,
            results_last_query: 3,
            account_department: None,
            allowed_departments: vec![],
            request_hour: 12,
            is_within_mission_hours: true,
        };
        let result = crue_engine::EvaluationResult {
            request_id: request.request_id.clone(),
            decision: crue_engine::decision::Decision::Block,
            error_code: Some("X".to_string()),
            message: Some("blocked".to_string()),
            rule_id: Some("CRUE_001".to_string()),
            rule_version: Some("1.0.0".to_string()),
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            evaluation_time_ms: 1,
        };

        let entry = build_audit_log_entry(
            &request,
            &result,
            Some("203.0.113.10".to_string()),
            Some("rsrp-test".to_string()),
            "PUBLIC_TASK",
        )
        .unwrap();
        assert_eq!(entry.event_type(), EventType::RuleViolation);
        assert_eq!(entry.decision(), AuditDecision::Block);
        assert_eq!(entry.rule_id(), Some("CRUE_001"));
        let entry_json = serde_json::to_value(&entry).expect("serialize entry");
        assert_eq!(
            entry_json["request"]["ip_address"].as_str(),
            Some("203.0.113.10")
        );
        assert_eq!(
            entry_json["request"]["user_agent"].as_str(),
            Some("rsrp-test")
        );
        assert_eq!(
            entry_json["compliance"]["legal_basis"].as_str(),
            Some("PUBLIC_TASK")
        );
    }

    #[test]
    fn test_derive_legal_basis_mapping_and_validation() {
        let derived = derive_legal_basis(None, Some("EXPORT_CSV"), Some("fiscal"), Some("DGFIP"))
            .expect("derived");
        assert_eq!(derived, "LEGAL_OBLIGATION");

        let explicit =
            derive_legal_basis(Some("public_task"), Some("QUERY"), Some("ops"), Some("org"))
                .expect("explicit");
        assert_eq!(explicit, "PUBLIC_TASK");

        let err = derive_legal_basis(
            Some("UNKNOWN_BASIS"),
            Some("QUERY"),
            Some("ops"),
            Some("org"),
        )
        .expect_err("invalid basis");
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn test_crypto_core_ed25519_signature_verify_roundtrip() {
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["aa".repeat(32)], 1);
        let payload = publication.to_canonical_json_bytes().expect("payload");
        let key = crypto_core::signature::Ed25519KeyPair::derive_from_secret(
            b"secret",
            Some("test-key".to_string()),
        );
        let sig = crypto_core::signature::sign(&payload, &key).expect("sign");
        let verified = crypto_core::signature::verify(
            &payload,
            &sig,
            &key.verifying_key(),
            crypto_core::SignatureAlgorithm::Ed25519,
        )
        .expect("verify");

        assert!(verified);
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_publication_signed_payload_strips_signature_and_tsa() {
        let mut service = PublicationService::new();
        let mut publication = service.create_daily_publication(&["bb".repeat(32)], 2);
        let expected = publication
            .to_canonical_json_bytes()
            .expect("expected payload");

        service.sign_publication_with_metadata(&mut publication, b"sig", "ED25519", "k1");
        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: "mock://tsa".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            token: "mock-token".to_string(),
        });

        let rebuilt = publication_signed_payload(&publication).expect("rebuilt payload");
        assert_eq!(rebuilt, expected);
    }

    #[test]
    fn test_tsa_verification_status_classifies_mock_and_real() {
        let service = PublicationService::new();
        let mut publication = service.create_daily_publication(&["cc".repeat(32)], 1);

        let status_none = tsa_verification_status(&publication);
        assert_eq!(status_none, (false, None, None, None));

        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: "mock://tsa".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: "mock-sha256=abc".to_string(),
        });
        let status_mock = tsa_verification_status(&publication);
        assert_eq!(
            status_mock,
            (
                true,
                Some("mock://tsa".to_string()),
                None,
                Some("mock-token-format-ok".to_string())
            )
        );

        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: "t".to_string(),
        });
        let status_real = tsa_verification_status(&publication);
        assert_eq!(
            status_real,
            (
                true,
                Some("https://tsa.example".to_string()),
                Some(false),
                Some("token-base64-invalid".to_string())
            )
        );
    }

    #[test]
    fn test_tsa_verification_status_parsed_token_timestamp_match() {
        let service = PublicationService::new();
        let mut publication = service.create_daily_publication(&["dd".repeat(32)], 1);
        let token_der = [
            0x18, 0x0f, b'2', b'0', b'2', b'6', b'0', b'2', b'2', b'6', b'0', b'8', b'3', b'0',
            b'4', b'5', b'Z',
        ];
        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T08:30:45+00:00".to_string(),
            token: BASE64_STANDARD.encode(token_der),
        });

        let status = tsa_verification_status(&publication);
        assert_eq!(
            status,
            (
                true,
                Some("https://tsa.example".to_string()),
                None,
                Some("token-parse-ok-timestamp-match".to_string())
            )
        );
    }

    #[test]
    fn test_verify_previous_day_link_statuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service = PublicationService::new();

        let mut prev = service.create_daily_publication(&["11".repeat(32)], 1);
        prev.date = "2026-02-25".to_string();
        prev.previous_day_root = "0".repeat(64);
        service
            .publish_to_filesystem(&prev, tmp.path(), false)
            .expect("publish prev");

        let mut curr = service.create_daily_publication(&["22".repeat(32)], 2);
        curr.date = "2026-02-26".to_string();
        curr.previous_day_root = prev.root_hash.clone();
        let ok = verify_previous_day_link(tmp.path(), &curr);
        assert_eq!(ok.0, Some(true));
        assert_eq!(ok.1, "previous-day-match");
        assert_eq!(ok.2.as_deref(), Some("2026-02-25"));
        assert_eq!(ok.3.as_deref(), Some(prev.root_hash.as_str()));

        curr.previous_day_root = "ff".repeat(32);
        let mismatch = verify_previous_day_link(tmp.path(), &curr);
        assert_eq!(mismatch.0, Some(false));
        assert_eq!(mismatch.1, "previous-day-mismatch");

        curr.previous_day_root = "0".repeat(64);
        let genesis = verify_previous_day_link(tmp.path(), &curr);
        assert_eq!(genesis.0, None);
        assert_eq!(genesis.1, "genesis-link");
    }

    #[test]
    fn test_previous_date_parsing() {
        assert_eq!(previous_date("2026-03-01").as_deref(), Some("2026-02-28"));
        assert_eq!(previous_date("invalid"), None);
    }

    #[test]
    fn test_tsa_cms_verify_error_status_mapping() {
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::BackendUnavailable("x".to_string())),
            "cms-backend-unavailable"
        );
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::TokenMissing),
            "cms-token-missing"
        );
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::TokenBase64("x".to_string())),
            "cms-token-base64-invalid"
        );
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::Pkcs7Parse("x".to_string())),
            "cms-token-pkcs7-parse-failed"
        );
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::TrustStore("x".to_string())),
            "cms-trust-store-invalid"
        );
        assert_eq!(
            tsa_cms_verify_error_status(&TsaCmsVerifyError::Verify("x".to_string())),
            "cms-signature-invalid"
        );
    }
}
