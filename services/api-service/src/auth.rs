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
        let audiences = csv_env("JWT_AUDIENCE").unwrap_or_else(|| vec!["rsrp-api".to_string()]);
        let issuers = csv_env("JWT_ISSUER").unwrap_or_else(|| vec!["rsrp-auth".to_string()]);
        Self::from_secret_with_claim_constraints(secret, Some(audiences), Some(issuers))
    }

    fn from_secret_with_claim_constraints(
        secret: &str,
        audiences: Option<Vec<String>>,
        issuers: Option<Vec<String>>,
    ) -> Result<Arc<Self>, String> {
        if secret.trim().is_empty() {
            return Err("JWT_SECRET is empty".to_string());
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("nbf".to_string());
        if let Some(values) = audiences.as_ref() {
            validation.set_audience(values);
        }
        if let Some(values) = issuers.as_ref() {
            validation.set_issuer(values);
        }

        Ok(Arc::new(Self {
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        }))
    }
}

fn csv_env(name: &str) -> Option<Vec<String>> {
    let value = std::env::var(name).ok()?;
    let items: Vec<String> = value
        .split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect();
    (!items.is_empty()).then_some(items)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtClaims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub nbf: Option<usize>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn jwt_rejects_token_without_nbf() {
        #[derive(Serialize)]
        struct ClaimsNoNbf {
            sub: String,
            role: String,
            exp: usize,
            iss: String,
            aud: String,
        }

        let secret = "test-secret";
        let config = JwtAuthConfig::from_secret_with_claim_constraints(
            secret,
            Some(vec!["rsrp-api".to_string()]),
            Some(vec!["rsrp-auth".to_string()]),
        )
        .expect("config");
        let claims = ClaimsNoNbf {
            sub: "u1".to_string(),
            role: "ADMIN".to_string(),
            exp: 2_000_000_000,
            iss: "rsrp-auth".to_string(),
            aud: "rsrp-api".to_string(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token");

        assert!(decode_claims(&config, &token).is_err());
    }

    #[test]
    fn jwt_rejects_wrong_issuer_and_audience() {
        let secret = "test-secret";
        let config = JwtAuthConfig::from_secret_with_claim_constraints(
            secret,
            Some(vec!["rsrp-api".to_string()]),
            Some(vec!["rsrp-auth".to_string()]),
        )
        .expect("config");
        let claims = JwtClaims {
            sub: "u1".to_string(),
            role: "ADMIN".to_string(),
            exp: 2_000_000_000,
            nbf: Some(1),
            iat: Some(1),
            iss: Some("other-issuer".to_string()),
            aud: Some("other-audience".to_string()),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token");

        assert!(decode_claims(&config, &token).is_err());
    }
}
