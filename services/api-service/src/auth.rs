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
use std::{env, fs, sync::Arc};

#[derive(Clone)]
pub struct JwtAuthConfig {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtAuthConfig {
    pub fn from_env() -> Result<Arc<Self>, String> {
        let issuer = required_env("JWT_ISSUER")?;
        let audience = required_env("JWT_AUDIENCE")?;
        let algorithm = parse_jwt_algorithm(
            &env::var("JWT_ALGORITHM").unwrap_or_else(|_| "EdDSA".to_string()),
        )?;

        let decoding_key = match algorithm {
            Algorithm::HS256 => {
                let secret = required_env("JWT_SECRET")?;
                tracing::warn!(
                    "JWT_ALGORITHM=HS256 configured. Prefer EdDSA/RS256 for zero-trust deployments."
                );
                DecodingKey::from_secret(secret.as_bytes())
            }
            Algorithm::RS256 => {
                let pem = read_public_key_pem()?;
                DecodingKey::from_rsa_pem(&pem).map_err(|e| e.to_string())?
            }
            Algorithm::EdDSA => {
                let pem = read_public_key_pem()?;
                DecodingKey::from_ed_pem(&pem).map_err(|e| e.to_string())?
            }
            other => {
                return Err(format!(
                    "Unsupported JWT_ALGORITHM={other:?}. Allowed: HS256, RS256, EdDSA"
                ));
            }
        };

        Ok(Arc::new(Self {
            decoding_key,
            validation: build_validation(algorithm, &issuer, &audience),
        }))
    }
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(value)
}

fn parse_jwt_algorithm(raw: &str) -> Result<Algorithm, String> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "RS256" => Ok(Algorithm::RS256),
        "EDDSA" => Ok(Algorithm::EdDSA),
        other => Err(format!("Unsupported JWT_ALGORITHM value: {other}")),
    }
}

fn read_public_key_pem() -> Result<Vec<u8>, String> {
    if let Ok(pem) = env::var("JWT_PUBLIC_KEY_PEM") {
        if !pem.trim().is_empty() {
            return Ok(pem.into_bytes());
        }
    }

    let path = required_env("JWT_PUBLIC_KEY_PATH")?;
    fs::read(&path).map_err(|e| format!("Failed to read JWT public key from {path}: {e}"))
}

fn build_validation(algorithm: Algorithm, issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("iss".to_string());
    validation.required_spec_claims.insert("aud".to_string());
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JwtAudience {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<JwtAudience>,
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
