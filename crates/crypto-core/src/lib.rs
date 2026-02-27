//! Crypto Core - Cryptographic Primitives for R-SRP Ultra
//!
//! Provides SHA-256/SHA-512, BLAKE3, Ed25519, and RSA-PSS implementations
//! with HSM integration support.

pub mod error;
pub mod hash;
pub mod hsm;
pub mod merkle;
pub mod signature;

use serde::{Deserialize, Serialize};

/// Hash algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    /// SHA-256 (default)
    Sha256,
    /// SHA-512
    Sha512,
    /// BLAKE3 (high performance)
    Blake3,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha256
    }
}

/// Signature algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SignatureAlgorithm {
    /// RSA-PSS 2048
    RsaPss2048,
    /// RSA-PSS 4096
    RsaPss4096,
    /// Ed25519
    Ed25519,
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::Ed25519
    }
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key ID
    pub key_id: String,
    /// Algorithm
    pub algorithm: SignatureAlgorithm,
    /// Created at
    pub created_at: i64,
    /// Key type
    pub key_type: KeyType,
    /// HSM slot (if applicable)
    pub hsm_slot: Option<String>,
}

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Signing key
    Signing,
    /// Verification key
    Verification,
    /// Encryption key
    Encryption,
    /// HSM-backed key
    HsmBacked,
}

/// Cryptographic service error
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Hash error: {0}")]
    HashError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Key error: {0}")]
    KeyError(String),

    #[error("HSM error: {0}")]
    HsmError(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Invalid key")]
    InvalidKey,
}

impl serde::Serialize for CryptoError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_hash_algorithm() {
        let algo: HashAlgorithm = serde_json::from_str("\"SHA256\"").unwrap();
        assert_eq!(algo, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_default_signature_algorithm() {
        let algo: SignatureAlgorithm = serde_json::from_str("\"ED25519\"").unwrap();
        assert_eq!(algo, SignatureAlgorithm::Ed25519);
    }
}
