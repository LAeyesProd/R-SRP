//! JWT authentication and role-based authorization middleware.

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct JwtAuthConfig {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtAuthConfig {
    pub fn from_secret(secret: &str) -> Result<Arc<Self>, String> {
        if secret.trim().is_empty() {
            return Err("JWT_SECRET is empty".to_string());
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.insert("exp".to_string());

        Ok(Arc::new(Self {
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        }))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredRole {
    Agent,
    Auditor,
    Admin,
}

fn role_rank(role: &str) -> Option<u8> {
    match role.to_ascii_uppercase().as_str() {
        "AGENT" => Some(1),
        "AUDITOR" => Some(2),
        "ADMIN" => Some(3),
        _ => None,
    }
}

fn authorized(claims: &JwtClaims, required: RequiredRole) -> bool {
    let required_rank = match required {
        RequiredRole::Agent => 1,
        RequiredRole::Auditor => 2,
        RequiredRole::Admin => 3,
    };
    role_rank(&claims.role)
        .map(|actual| actual >= required_rank)
        .unwrap_or(false)
}

fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
}

fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn decode_claims(config: &JwtAuthConfig, token: &str) -> Result<JwtClaims, String> {
    decode::<JwtClaims>(token, &config.decoding_key, &config.validation)
        .map(|d| d.claims)
        .map_err(|e| e.to_string())
}

async fn enforce_role(
    State(config): State<Arc<JwtAuthConfig>>,
    mut request: axum::extract::Request,
    next: Next,
    required: RequiredRole,
) -> Response {
    let token = match bearer_token(request.headers()) {
        Some(t) => t,
        None => return unauthorized("missing bearer token"),
    };

    let claims = match decode_claims(&config, token) {
        Ok(c) => c,
        Err(_) => return unauthorized("invalid token"),
    };

    if !authorized(&claims, required) {
        return forbidden("insufficient role");
    }

    request.extensions_mut().insert(claims);
    next.run(request).await
}

pub async fn require_agent(
    state: State<Arc<JwtAuthConfig>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    enforce_role(state, request, next, RequiredRole::Agent).await
}

pub async fn require_auditor(
    state: State<Arc<JwtAuthConfig>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    enforce_role(state, request, next, RequiredRole::Auditor).await
}

pub async fn require_admin(
    state: State<Arc<JwtAuthConfig>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    enforce_role(state, request, next, RequiredRole::Admin).await
}
