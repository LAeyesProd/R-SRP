//! JWT authentication and role-based authorization middleware.

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, env, fs, sync::Arc};

#[derive(Clone)]
pub struct JwtAuthConfig {
    decoding_keys: Arc<HashMap<String, DecodingKey>>,
    default_kid: String,
    validation: Validation,
}

impl JwtAuthConfig {
    pub fn from_env() -> Result<Arc<Self>, String> {
        let issuer = required_env("JWT_ISSUER")?;
        let audience = required_env("JWT_AUDIENCE")?;
        let algorithm = parse_jwt_algorithm(
            &env::var("JWT_ALGORITHM").unwrap_or_else(|_| "EdDSA".to_string()),
        )?;
        if algorithm != Algorithm::EdDSA {
            return Err(
                "JWT_ALGORITHM must be EdDSA (HS256/RS256 are forbidden in zero-trust mode)"
                    .to_string(),
            );
        }

        let (default_kid, decoding_keys) = read_decoding_keys()?;

        Ok(Arc::new(Self {
            decoding_keys: Arc::new(decoding_keys),
            default_kid,
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
        "EDDSA" => Ok(Algorithm::EdDSA),
        "HS256" | "RS256" => {
            Err("JWT_ALGORITHM must be EdDSA. HS256/RS256 are forbidden by policy".to_string())
        }
        other => Err(format!(
            "Unsupported JWT_ALGORITHM value: {other}. Use EdDSA"
        )),
    }
}

fn read_public_key_pem() -> Result<(String, Vec<u8>), String> {
    if let Ok(pem) = env::var("JWT_PUBLIC_KEY_PEM") {
        if !pem.trim().is_empty() {
            let kid = env::var("JWT_KEY_ID").unwrap_or_else(|_| "default".to_string());
            return Ok((kid, pem.into_bytes()));
        }
    }

    let path = required_env("JWT_PUBLIC_KEY_PATH")?;
    let kid = env::var("JWT_KEY_ID").unwrap_or_else(|_| "default".to_string());
    let pem =
        fs::read(&path).map_err(|e| format!("Failed to read JWT public key from {path}: {e}"))?;
    Ok((kid, pem))
}

fn read_decoding_keys() -> Result<(String, HashMap<String, DecodingKey>), String> {
    let mut keys = HashMap::new();
    let mut default_kid = String::new();

    if let Ok(list) = env::var("JWT_PUBLIC_KEY_PATHS") {
        for (idx, pair) in list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .enumerate()
        {
            let (kid, path) = pair.split_once('=').ok_or_else(|| {
                format!("Invalid JWT_PUBLIC_KEY_PATHS item `{pair}`. Expected `kid=/path/key.pem`")
            })?;
            let pem = fs::read(path.trim()).map_err(|e| {
                format!("Failed to read JWT public key from {}: {}", path.trim(), e)
            })?;
            let key = DecodingKey::from_ed_pem(&pem)
                .map_err(|e| format!("Invalid EdDSA public key {}: {}", path.trim(), e))?;
            let kid = kid.trim().to_string();
            if idx == 0 {
                default_kid = kid.clone();
            }
            keys.insert(kid, key);
        }
    }

    if keys.is_empty() {
        let (kid, pem) = read_public_key_pem()?;
        let key = DecodingKey::from_ed_pem(&pem).map_err(|e| e.to_string())?;
        default_kid = kid.clone();
        keys.insert(kid, key);
    }

    if keys.is_empty() {
        return Err("No JWT public verification keys configured".to_string());
    }

    Ok((default_kid, keys))
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
    let header = decode_header(token).map_err(|e| format!("invalid token header: {e}"))?;
    if header.alg != Algorithm::EdDSA {
        return Err("JWT alg must be EdDSA".to_string());
    }
    let kid = header.kid.unwrap_or_else(|| config.default_kid.clone());
    let key = config
        .decoding_keys
        .get(&kid)
        .ok_or_else(|| format!("unknown JWT kid `{kid}`"))?;

    decode::<JwtClaims>(token, key, &config.validation)
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

    #[test]
    fn test_parse_jwt_algorithm_rejects_hs256_and_rs256() {
        assert!(parse_jwt_algorithm("HS256").is_err());
        assert!(parse_jwt_algorithm("RS256").is_err());
        assert_eq!(parse_jwt_algorithm("EdDSA").unwrap(), Algorithm::EdDSA);
    }

    #[test]
    fn test_validation_requires_iss_and_aud() {
        let v = build_validation(Algorithm::EdDSA, "issuer-a", "audience-a");
        assert!(v.required_spec_claims.contains("iss"));
        assert!(v.required_spec_claims.contains("aud"));
    }
}
