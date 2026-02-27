//! Publication - Daily audit publication

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Daily audit publication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyPublication {
    /// Publication date
    pub date: String,
    /// Root hash of all hourly roots
    pub root_hash: String,
    /// Total entry count
    pub entry_count: u64,
    /// Hourly root hashes
    pub hourly_roots: Vec<String>,
    /// Previous day root (for chaining)
    pub previous_day_root: String,
    /// Creation timestamp
    pub created_at: String,
    /// Signature
    pub signature: Option<PublicationSignature>,
    /// TSA timestamp
    pub tsa_timestamp: Option<TsaTimestamp>,
}

impl DailyPublication {
    /// Export as canonical deterministic JSON bytes.
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, crate::error::LogError> {
        let canonical = canonical_publication_json_value(self)?;
        canonical_json_bytes(&canonical)
    }

    /// Export as compact deterministic JSON string.
    pub fn to_canonical_json(&self) -> Result<String, crate::error::LogError> {
        let bytes = self.to_canonical_json_bytes()?;
        String::from_utf8(bytes)
            .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))
    }

    /// Export as gzip-compressed canonical JSON.
    pub fn to_canonical_json_gzip(&self) -> Result<Vec<u8>, crate::error::LogError> {
        let json = self.to_canonical_json_bytes()?;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&json)
            .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))
    }

    /// Build a deterministic basename suitable for filesystem/object publication backends.
    pub fn publication_basename(&self) -> String {
        let root_prefix = self.root_hash.get(..16).unwrap_or(&self.root_hash);
        format!("daily-publication-{}-{}", self.date, root_prefix)
    }

    /// Recompute the publication root from `hourly_roots`.
    pub fn recompute_root_hash(&self) -> String {
        PublicationService::compute_merkle_root(&self.hourly_roots)
    }

    /// Check whether the stored `root_hash` matches the recomputed value.
    pub fn verify_root_hash(&self) -> bool {
        self.root_hash == self.recompute_root_hash()
    }

    /// Write canonical JSON to a file path.
    pub fn write_canonical_json_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), crate::error::LogError> {
        let bytes = self.to_canonical_json_bytes()?;
        std::fs::write(path, bytes)
            .map_err(|e| crate::error::LogError::PublicationError(e.to_string()))
    }

    /// Write gzip-compressed canonical JSON to a file path.
    pub fn write_canonical_json_gzip_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), crate::error::LogError> {
        let bytes = self.to_canonical_json_gzip()?;
        std::fs::write(path, bytes)
            .map_err(|e| crate::error::LogError::PublicationError(e.to_string()))
    }
}

/// Publication signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationSignature {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

/// TSA timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaTimestamp {
    pub tsa_url: String,
    pub timestamp: String,
    pub token: String,
}

/// Best-effort inspection result for a stored TSA token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaTokenInspection {
    pub token_present: bool,
    pub token_base64_valid: bool,
    pub token_der_nonempty: bool,
    pub extracted_timestamp: Option<String>,
}

/// Cryptographic CMS/PKCS#7 verification result for a TSA token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaCmsVerification {
    pub verified: bool,
    pub extracted_timestamp: Option<String>,
}

/// TSA token CMS verification error.
#[derive(Debug, thiserror::Error)]
pub enum TsaCmsVerifyError {
    #[error("TSA CMS verification backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("TSA token missing")]
    TokenMissing,
    #[error("TSA token base64 decode failed: {0}")]
    TokenBase64(String),
    #[error("TSA token PKCS#7 parse failed: {0}")]
    Pkcs7Parse(String),
    #[error("TSA trust store error: {0}")]
    TrustStore(String),
    #[error("TSA CMS verification failed: {0}")]
    Verify(String),
}

/// Publication service
pub struct PublicationService {
    /// Previous day root
    previous_day_root: Option<String>,
}

impl Default for PublicationService {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicationService {
    /// Create new publication service
    pub fn new() -> Self {
        PublicationService {
            previous_day_root: None,
        }
    }

    /// Create daily publication
    pub fn create_daily_publication(
        &self,
        hourly_roots: &[String],
        entry_count: u64,
    ) -> DailyPublication {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let previous = self.previous_day_root.clone().unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });

        // Compute root hash of all hourly roots
        let root_hash = Self::compute_merkle_root(hourly_roots);

        DailyPublication {
            date,
            root_hash,
            entry_count,
            hourly_roots: hourly_roots.to_vec(),
            previous_day_root: previous,
            created_at: Utc::now().to_rfc3339(),
            signature: None,
            tsa_timestamp: None,
        }
    }

    /// Compute merkle root from list of hashes
    fn compute_merkle_root(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }

        use sha2::{Digest, Sha256};

        let mut current: Vec<Vec<u8>> = hashes.iter().map(|h| merkle_leaf_hash(h)).collect();

        while current.len() > 1 {
            let mut next = Vec::new();

            for chunk in current.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() == 2 {
                    &chunk[1]
                } else {
                    &chunk[0]
                };
                let mut hasher = Sha256::new();
                hasher.update([0x01]);
                hasher.update(left);
                hasher.update(right);
                next.push(hasher.finalize().to_vec());
            }

            current = next;
        }

        hex_encode(&current[0])
    }

    /// Sign publication
    pub fn sign_publication(&mut self, publication: &mut DailyPublication, signature: &[u8]) {
        self.sign_publication_with_metadata(
            publication,
            signature,
            "RSA-PSS-SHA256",
            "rnbc-audit-sig-2026",
        );
    }

    /// Sign publication with explicit metadata (useful for API-driven integrations).
    pub fn sign_publication_with_metadata(
        &mut self,
        publication: &mut DailyPublication,
        signature: &[u8],
        algorithm: &str,
        key_id: &str,
    ) {
        publication.signature = Some(PublicationSignature {
            algorithm: algorithm.to_string(),
            key_id: key_id.to_string(),
            value: base64_encode(signature),
        });

        // Store previous day root for chaining
        self.previous_day_root = Some(publication.root_hash.clone());
    }

    /// Publish to a local filesystem directory (precursor to WORM/object storage backends).
    pub fn publish_to_filesystem<P: AsRef<Path>>(
        &self,
        publication: &DailyPublication,
        directory: P,
        write_gzip: bool,
    ) -> Result<FilesystemPublication, crate::error::LogError> {
        let dir = directory.as_ref();
        std::fs::create_dir_all(dir)
            .map_err(|e| crate::error::LogError::PublicationError(e.to_string()))?;

        let basename = publication.publication_basename();
        let json_path = dir.join(format!("{basename}.json"));
        publication.write_canonical_json_file(&json_path)?;

        let gzip_path = if write_gzip {
            let path = dir.join(format!("{basename}.json.gz"));
            publication.write_canonical_json_gzip_file(&path)?;
            Some(path)
        } else {
            None
        };

        Ok(FilesystemPublication {
            json_path,
            gzip_path,
        })
    }

    /// Add TSA timestamp metadata.
    ///
    /// `mock://` URLs are supported for local testing.
    ///
    /// `http(s)://` URLs use an experimental RFC 3161 request path that retrieves
    /// and stores the TSA token, but does not yet perform full CMS/token validation.
    pub async fn add_tsa_timestamp(
        &mut self,
        publication: &mut DailyPublication,
        tsa_url: &str,
    ) -> Result<(), TsaError> {
        // Serialize publication hash for TSA request
        let hash_to_timestamp = &publication.root_hash;

        // In production, this would be a proper RFC 3161 request
        // For now, we'll implement a basic timestamp request structure
        let timestamp_request = TsaRequest {
            hash: hash_to_timestamp.clone(),
            algorithm: "SHA256".to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
        };

        // Make request to TSA (in production, use actual TSA server)
        let response = self.request_timestamp(tsa_url, &timestamp_request).await?;

        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: tsa_url.to_string(),
            timestamp: response.timestamp,
            token: response.token,
        });

        tracing::info!(
            "TSA timestamp added for publication {} at {}",
            publication.date,
            publication
                .tsa_timestamp
                .as_ref()
                .map(|t| t.timestamp.as_str())
                .map_or("unknown", |v| v)
        );

        Ok(())
    }

    /// Request timestamp from TSA server.
    ///
    /// Supports:
    /// - `mock://...` for tests
    /// - `http(s)://...` experimental RFC 3161 transport (token retrieval only)
    async fn request_timestamp(
        &self,
        tsa_url: &str,
        request: &TsaRequest,
    ) -> Result<TsaResponse, TsaError> {
        if tsa_url.starts_with("mock://") {
            tracing::warn!("Using mock TSA timestamp provider: {}", tsa_url);
            return Ok(TsaResponse {
                timestamp: chrono::Utc::now().to_rfc3339(),
                token: format!("mock-sha256={}", request.hash),
                tsa_certificate: "placeholder".to_string(),
            });
        }

        if !(tsa_url.starts_with("https://") || tsa_url.starts_with("http://")) {
            return Err(TsaError::UnsupportedScheme(tsa_url.to_string()));
        }

        let digest_bytes = hex_decode(&request.hash).map_err(TsaError::Encoding)?;
        let body = build_rfc3161_timestamp_query(&digest_bytes, &request.nonce)?;

        tracing::info!("Requesting TSA token from {}", tsa_url);
        let client = reqwest::Client::new();
        let resp = client
            .post(tsa_url)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(body)
            .send()
            .await?;

        let status_code = resp.status();
        if !status_code.is_success() {
            return Err(TsaError::Server(format!(
                "HTTP {} from TSA endpoint",
                status_code
            )));
        }

        let date_header = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = resp.bytes().await?;

        let tsa_reply = parse_timestamp_response(&bytes)?;
        if tsa_reply.status != 0 && tsa_reply.status != 1 {
            return Err(TsaError::Server(format!(
                "TSA rejected request with status {}",
                tsa_reply.status
            )));
        }

        let token_der = tsa_reply
            .time_stamp_token_der
            .ok_or(TsaError::InvalidResponse)?;

        // Best-effort timestamp extraction from token bytes (GeneralizedTime scan).
        // Full CMS/ESS validation is pending.
        let timestamp = extract_generalized_time_rfc3339(&token_der)
            .or_else(|| date_header.and_then(parse_http_date_to_rfc3339))
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        Ok(TsaResponse {
            timestamp,
            token: base64_encode(&token_der),
            tsa_certificate: "unparsed".to_string(),
        })
    }
}

impl TsaTimestamp {
    /// Best-effort validation/inspection of stored TSA token encoding and timestamp extraction.
    ///
    /// This does not perform CMS/PKCS#7 signature validation.
    pub fn inspect_token(&self) -> TsaTokenInspection {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        if self.token.is_empty() {
            return TsaTokenInspection {
                token_present: false,
                token_base64_valid: false,
                token_der_nonempty: false,
                extracted_timestamp: None,
            };
        }

        let der = match STANDARD.decode(self.token.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                return TsaTokenInspection {
                    token_present: true,
                    token_base64_valid: false,
                    token_der_nonempty: false,
                    extracted_timestamp: None,
                };
            }
        };

        let extracted_timestamp = extract_generalized_time_rfc3339(&der);
        TsaTokenInspection {
            token_present: true,
            token_base64_valid: true,
            token_der_nonempty: !der.is_empty(),
            extracted_timestamp,
        }
    }

    /// Verify the `timeStampToken` CMS/PKCS#7 signature against trusted PEM certificates.
    ///
    /// This validates CMS signature and certificate chain. RFC3161-specific TSTInfo checks
    /// (message imprint, policy, nonce) are not yet enforced here.
    #[cfg(feature = "tsa-cms-openssl")]
    pub fn verify_cms_signature_with_pem_roots(
        &self,
        trust_store_pem: &[u8],
    ) -> Result<TsaCmsVerification, TsaCmsVerifyError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
        use openssl::stack::Stack;
        use openssl::x509::{store::X509StoreBuilder, X509};

        if self.token.is_empty() {
            return Err(TsaCmsVerifyError::TokenMissing);
        }

        let der = STANDARD
            .decode(self.token.as_bytes())
            .map_err(|e| TsaCmsVerifyError::TokenBase64(e.to_string()))?;
        let extracted_timestamp = extract_generalized_time_rfc3339(&der);

        let pkcs7 =
            Pkcs7::from_der(&der).map_err(|e| TsaCmsVerifyError::Pkcs7Parse(e.to_string()))?;

        let certs = X509::stack_from_pem(trust_store_pem)
            .map_err(|e| TsaCmsVerifyError::TrustStore(e.to_string()))?;
        let mut store_builder =
            X509StoreBuilder::new().map_err(|e| TsaCmsVerifyError::TrustStore(e.to_string()))?;
        for cert in certs {
            store_builder
                .add_cert(cert)
                .map_err(|e| TsaCmsVerifyError::TrustStore(e.to_string()))?;
        }
        let store = store_builder.build();

        let cert_stack: Stack<X509> =
            Stack::new().map_err(|e| TsaCmsVerifyError::TrustStore(e.to_string()))?;
        let mut out = Vec::<u8>::new();
        pkcs7
            .verify(
                &cert_stack,
                &store,
                None,
                Some(&mut out),
                Pkcs7Flags::empty(),
            )
            .map_err(|e| TsaCmsVerifyError::Verify(e.to_string()))?;

        Ok(TsaCmsVerification {
            verified: true,
            extracted_timestamp,
        })
    }

    #[cfg(not(feature = "tsa-cms-openssl"))]
    pub fn verify_cms_signature_with_pem_roots(
        &self,
        _trust_store_pem: &[u8],
    ) -> Result<TsaCmsVerification, TsaCmsVerifyError> {
        Err(TsaCmsVerifyError::BackendUnavailable(
            "immutable-logging compiled without feature `tsa-cms-openssl`".to_string(),
        ))
    }
}

/// Files created by a filesystem publication backend.
#[derive(Debug, Clone)]
pub struct FilesystemPublication {
    pub json_path: PathBuf,
    pub gzip_path: Option<PathBuf>,
}

/// TSA Request structure (RFC 3161 subset)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TsaRequest {
    hash: String,
    algorithm: String,
    nonce: String,
}

/// TSA Response structure (RFC 3161 subset)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TsaResponse {
    timestamp: String,
    token: String,
    tsa_certificate: String,
}

/// TSA Error type
#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("TSA server error: {0}")]
    Server(String),

    #[error("Unsupported TSA URL scheme: {0}")]
    UnsupportedScheme(String),

    #[error("Invalid response from TSA")]
    InvalidResponse,
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(data)
}

fn canonical_publication_json_value(
    publication: &DailyPublication,
) -> Result<Value, crate::error::LogError> {
    let signature = match publication.signature.as_ref() {
        Some(sig) => serde_json::json!({
            "algorithm": sig.algorithm,
            "key_id": sig.key_id,
            "value": sig.value,
        }),
        None => Value::Null,
    };

    let tsa_timestamp = match publication.tsa_timestamp.as_ref() {
        Some(tsa) => serde_json::json!({
            "timestamp": tsa.timestamp,
            "token": tsa.token,
            "tsa_url": tsa.tsa_url,
        }),
        None => Value::Null,
    };

    serde_json::from_value::<Value>(serde_json::json!({
        "schema_version": "rsrp-daily-publication-v1",
        "created_at": publication.created_at,
        "date": publication.date,
        "entry_count": publication.entry_count,
        "hourly_roots": publication.hourly_roots,
        "previous_day_root": publication.previous_day_root,
        "root_hash": publication.root_hash,
        "signature": signature,
        "tsa_timestamp": tsa_timestamp,
    }))
    .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, crate::error::LogError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), crate::error::LogError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(v) => out.push_str(&v.to_string()),
        Value::String(v) => {
            let encoded = serde_json::to_string(v)
                .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))?;
            out.push_str(&encoded);
        }
        Value::Array(values) => {
            out.push('[');
            for (i, entry) in values.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(entry, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let encoded_key = serde_json::to_string(key)
                    .map_err(|e| crate::error::LogError::SerializationError(e.to_string()))?;
                out.push_str(&encoded_key);
                out.push(':');
                let value = map.get(*key).ok_or_else(|| {
                    crate::error::LogError::SerializationError(
                        "Missing canonical JSON key".to_string(),
                    )
                })?;
                write_canonical_json(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn merkle_leaf_hash(input: &str) -> Vec<u8> {
    let bytes = hex_decode(input).unwrap_or_else(|_| input.as_bytes().to_vec());
    let mut hasher = sha2::Sha256::new();
    hasher.update([0x00]);
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Invalid hex length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex".to_string()))
        .collect()
}

fn build_rfc3161_timestamp_query(
    message_digest: &[u8],
    nonce_text: &str,
) -> Result<Vec<u8>, TsaError> {
    // We support SHA-256 only in this implementation path.
    if message_digest.len() != 32 {
        return Err(TsaError::Encoding(format!(
            "expected SHA-256 digest (32 bytes), got {}",
            message_digest.len()
        )));
    }

    let nonce_hash = sha2::Sha256::digest(nonce_text.as_bytes());
    let nonce = der_integer_positive(&nonce_hash[..16]);

    let algorithm_identifier = der_sequence(&[
        der_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]), // sha256
        der_null(),
    ]);
    let message_imprint = der_sequence(&[algorithm_identifier, der_octet_string(message_digest)]);

    Ok(der_sequence(&[
        der_integer_u64(1), // version v1
        message_imprint,
        nonce,             // nonce
        der_boolean(true), // certReq = TRUE
    ]))
}

struct ParsedTsaResponse {
    status: i64,
    time_stamp_token_der: Option<Vec<u8>>,
}

fn parse_timestamp_response(bytes: &[u8]) -> Result<ParsedTsaResponse, TsaError> {
    let (outer_tag, outer_len, outer_hdr) = der_read_tlv(bytes, 0)?;
    if outer_tag != 0x30 || outer_hdr + outer_len > bytes.len() {
        return Err(TsaError::InvalidResponse);
    }
    let outer = &bytes[outer_hdr..outer_hdr + outer_len];

    let (status_tag, status_len, status_hdr) = der_read_tlv(outer, 0)?;
    if status_tag != 0x30 || status_hdr + status_len > outer.len() {
        return Err(TsaError::InvalidResponse);
    }
    let status_seq = &outer[status_hdr..status_hdr + status_len];
    let (int_tag, int_len, int_hdr) = der_read_tlv(status_seq, 0)?;
    if int_tag != 0x02 || int_hdr + int_len > status_seq.len() {
        return Err(TsaError::InvalidResponse);
    }
    let status = der_parse_integer_i64(&status_seq[int_hdr..int_hdr + int_len])?;

    let next = status_hdr + status_len;
    let time_stamp_token_der = if next < outer.len() {
        let (_tag, len, hdr) = der_read_tlv(outer, next)?;
        Some(outer[next..next + hdr + len].to_vec())
    } else {
        None
    };

    Ok(ParsedTsaResponse {
        status,
        time_stamp_token_der,
    })
}

fn extract_generalized_time_rfc3339(bytes: &[u8]) -> Option<String> {
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        if bytes[i] == 0x18 {
            let (tag, len, hdr) = der_read_tlv(bytes, i).ok()?;
            if tag != 0x18 || i + hdr + len > bytes.len() {
                return None;
            }
            let s = std::str::from_utf8(&bytes[i + hdr..i + hdr + len]).ok()?;
            if let Some(trimmed) = s.strip_suffix('Z') {
                if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y%m%d%H%M%S") {
                    let dt = chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
                    return Some(dt.to_rfc3339());
                }
            }
        }
        i += 1;
    }
    None
}

fn parse_http_date_to_rfc3339(value: String) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc2822(&value).ok()?;
    Some(dt.with_timezone(&Utc).to_rfc3339())
}

fn der_read_tlv(input: &[u8], offset: usize) -> Result<(u8, usize, usize), TsaError> {
    if offset + 2 > input.len() {
        return Err(TsaError::InvalidResponse);
    }
    let tag = input[offset];
    let first_len = input[offset + 1];
    if first_len & 0x80 == 0 {
        let len = first_len as usize;
        Ok((tag, len, 2))
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || n > 4 || offset + 2 + n > input.len() {
            return Err(TsaError::InvalidResponse);
        }
        let mut len = 0usize;
        for b in &input[offset + 2..offset + 2 + n] {
            len = (len << 8) | (*b as usize);
        }
        Ok((tag, len, 2 + n))
    }
}

fn der_parse_integer_i64(bytes: &[u8]) -> Result<i64, TsaError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(TsaError::InvalidResponse);
    }
    let mut v: i64 = 0;
    for b in bytes {
        v = (v << 8) | (*b as i64);
    }
    Ok(v)
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let mut tmp = Vec::new();
    let mut n = len;
    while n > 0 {
        tmp.push((n & 0xff) as u8);
        n >>= 8;
    }
    tmp.reverse();
    let mut out = vec![0x80 | (tmp.len() as u8)];
    out.extend(tmp);
    out
}

fn der_wrap(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend(part);
    }
    der_wrap(0x30, &content)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_boolean(v: bool) -> Vec<u8> {
    vec![0x01, 0x01, if v { 0xff } else { 0x00 }]
}

fn der_integer_u64(v: u64) -> Vec<u8> {
    let mut bytes = if v == 0 {
        vec![0]
    } else {
        let mut tmp = Vec::new();
        let mut n = v;
        while n > 0 {
            tmp.push((n & 0xff) as u8);
            n >>= 8;
        }
        tmp.reverse();
        tmp
    };
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der_wrap(0x02, &bytes)
}

fn der_integer_positive(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    while v.first() == Some(&0) && v.len() > 1 {
        v.remove(0);
    }
    if v.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        v.insert(0, 0);
    }
    der_wrap(0x02, &v)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_wrap(0x04, bytes)
}

fn der_oid(oid: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if oid.len() < 2 {
        return der_wrap(0x06, &out);
    }
    out.push((oid[0] * 40 + oid[1]) as u8);
    for &arc in &oid[2..] {
        let mut stack = [0u8; 5];
        let mut idx = stack.len();
        let mut n = arc;
        stack[idx - 1] = (n & 0x7f) as u8;
        idx -= 1;
        n >>= 7;
        while n > 0 {
            stack[idx - 1] = 0x80 | ((n & 0x7f) as u8);
            idx -= 1;
            n >>= 7;
        }
        out.extend(&stack[idx..]);
    }
    der_wrap(0x06, &out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::io::Read;
    use tempfile::tempdir;

    #[test]
    fn test_daily_publication_and_signature_chain() {
        let mut service = PublicationService::new();
        let hourly_roots = vec!["a".repeat(64), "b".repeat(64)];

        let mut day1 = service.create_daily_publication(&hourly_roots, 42);
        assert_eq!(day1.entry_count, 42);
        assert_eq!(day1.hourly_roots.len(), 2);
        assert_eq!(day1.previous_day_root, "0".repeat(64));
        assert!(day1.signature.is_none());

        service.sign_publication(&mut day1, b"sig");
        let sig = day1.signature.as_ref().expect("signature set");
        assert_eq!(sig.algorithm, "RSA-PSS-SHA256");
        assert_eq!(sig.value, STANDARD.encode(b"sig"));

        let day2 = service.create_daily_publication(&hourly_roots, 1);
        assert_eq!(day2.previous_day_root, day1.root_hash);
    }

    #[test]
    fn test_add_tsa_timestamp_mock_only() {
        let mut service = PublicationService::new();
        let hourly_roots = vec!["c".repeat(64)];
        let mut publication = service.create_daily_publication(&hourly_roots, 1);

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");

        rt.block_on(async {
            service
                .add_tsa_timestamp(&mut publication, "mock://tsa")
                .await
                .expect("mock TSA works");
        });

        let tsa = publication
            .tsa_timestamp
            .as_ref()
            .expect("tsa timestamp set");
        assert_eq!(tsa.tsa_url, "mock://tsa");
        assert!(tsa.token.starts_with("mock-sha256="));
    }

    #[test]
    fn test_add_tsa_timestamp_rejects_non_mock() {
        let mut service = PublicationService::new();
        let hourly_roots = vec!["d".repeat(64)];
        let mut publication = service.create_daily_publication(&hourly_roots, 1);

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");

        let err = rt.block_on(async {
            service
                .add_tsa_timestamp(&mut publication, "https://tsa.example")
                .await
                .expect_err("network call should fail for placeholder endpoint")
        });

        match err {
            TsaError::Server(_) | TsaError::Network(_) => {}
            other => panic!("unexpected error: {other}"),
        }
        assert!(publication.tsa_timestamp.is_none());
    }

    #[test]
    fn test_build_rfc3161_query_der_contains_sha256_oid() {
        let digest = [0x11u8; 32];
        let req = build_rfc3161_timestamp_query(&digest, "nonce").expect("query");
        // sha256 OID bytes: 06 09 60 86 48 01 65 03 04 02 01
        let oid = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        assert!(req.windows(oid.len()).any(|w| w == oid));
    }

    #[test]
    fn test_parse_timestamp_response_status_only() {
        // TimeStampResp ::= SEQUENCE { status PKIStatusInfo }
        let resp = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        let parsed = parse_timestamp_response(&resp).expect("parse");
        assert_eq!(parsed.status, 0);
        assert!(parsed.time_stamp_token_der.is_none());
    }

    #[test]
    fn test_extract_generalized_time_best_effort() {
        // DER GeneralizedTime: "20260226083045Z"
        let mut bytes = vec![0x18, 0x0f];
        bytes.extend_from_slice(b"20260226083045Z");
        let ts = extract_generalized_time_rfc3339(&bytes).expect("timestamp");
        assert!(ts.starts_with("2026-02-26T08:30:45"));
    }

    #[test]
    fn test_canonical_json_export_is_deterministic() {
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["e".repeat(64)], 7);

        let json1 = publication.to_canonical_json().expect("json1");
        let json2 = publication.to_canonical_json().expect("json2");

        assert_eq!(json1, json2);
        assert!(!json1.contains('\n'));
        assert!(json1.contains("\"entry_count\":7"));
        assert!(json1.contains("\"hourly_roots\""));
    }

    #[test]
    fn test_canonical_json_gzip_roundtrip() {
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["f".repeat(64)], 3);

        let original = publication.to_canonical_json_bytes().expect("original");
        let compressed = publication.to_canonical_json_gzip().expect("gzip");
        assert!(!compressed.is_empty());

        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).expect("decompress");

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_publication_basename_is_stable() {
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["bb".repeat(32)], 1);
        let base = publication.publication_basename();

        assert!(base.starts_with("daily-publication-"));
        assert!(base.contains(&publication.date));
        assert!(base.ends_with(&publication.root_hash[..16]));
    }

    #[test]
    fn test_verify_root_hash_detects_tamper() {
        let service = PublicationService::new();
        let mut publication =
            service.create_daily_publication(&["aa".repeat(32), "bb".repeat(32)], 2);
        assert!(publication.verify_root_hash());

        publication.hourly_roots.push("cc".repeat(32));
        assert!(!publication.verify_root_hash());
    }

    #[test]
    fn test_tsa_token_inspection() {
        let tsa = TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: base64_encode(&[
                0x18, 0x0f, b'2', b'0', b'2', b'6', b'0', b'2', b'2', b'6', b'0', b'8', b'3', b'0',
                b'4', b'5', b'Z',
            ]),
        };
        let inspected = tsa.inspect_token();
        assert!(inspected.token_present);
        assert!(inspected.token_base64_valid);
        assert!(inspected.token_der_nonempty);
        assert!(inspected.extracted_timestamp.is_some());

        let bad = TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: "%%%".to_string(),
        };
        let bad_inspected = bad.inspect_token();
        assert!(bad_inspected.token_present);
        assert!(!bad_inspected.token_base64_valid);
    }

    #[cfg(feature = "tsa-cms-openssl")]
    #[test]
    fn test_tsa_cms_verify_rejects_invalid_base64() {
        let tsa = TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: "%%%".to_string(),
        };

        let err = tsa
            .verify_cms_signature_with_pem_roots(b"")
            .expect_err("invalid base64 must fail");
        match err {
            TsaCmsVerifyError::TokenBase64(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(feature = "tsa-cms-openssl")]
    #[test]
    fn test_tsa_cms_verify_rejects_non_pkcs7_der() {
        let tsa = TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: base64_encode(&[0x30, 0x03, 0x02, 0x01, 0x00]),
        };

        let err = tsa
            .verify_cms_signature_with_pem_roots(b"")
            .expect_err("non-pkcs7 der must fail");
        match err {
            TsaCmsVerifyError::Pkcs7Parse(_) | TsaCmsVerifyError::TrustStore(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(not(feature = "tsa-cms-openssl"))]
    #[test]
    fn test_tsa_cms_verify_reports_backend_unavailable_without_feature() {
        let tsa = TsaTimestamp {
            tsa_url: "https://tsa.example".to_string(),
            timestamp: "2026-02-26T00:00:00Z".to_string(),
            token: "%%%".to_string(),
        };

        let err = tsa
            .verify_cms_signature_with_pem_roots(b"")
            .expect_err("backend should be unavailable without feature");
        match err {
            TsaCmsVerifyError::BackendUnavailable(_) => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_publish_to_filesystem_writes_json_and_gzip() {
        let tmp = tempdir().expect("tempdir");
        let service = PublicationService::new();
        let publication = service.create_daily_publication(&["aa".repeat(32)], 11);

        let written = service
            .publish_to_filesystem(&publication, tmp.path(), true)
            .expect("publish");

        assert!(written.json_path.exists());
        let gzip_path = written.gzip_path.as_ref().expect("gzip path");
        assert!(gzip_path.exists());

        let json_bytes = std::fs::read(&written.json_path).expect("json bytes");
        assert_eq!(
            json_bytes,
            publication
                .to_canonical_json_bytes()
                .expect("canonical json")
        );

        let gz_bytes = std::fs::read(gzip_path).expect("gzip bytes");
        let mut decoder = flate2::read::GzDecoder::new(gz_bytes.as_slice());
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("decompress");
        assert_eq!(out, json_bytes);
    }
}
