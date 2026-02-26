//! CRUE Rule Signature Module
//! 
//! Handles RSA-PSS signing and verification of compiled rules

use crate::error::Result;
use crate::error::DslError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Sha256, Digest};

/// Rule signature metadata
#[derive(Debug, Clone)]
pub struct SignatureMetadata {
    /// Key ID used for signing
    pub key_id: String,
    /// Algorithm used
    pub algorithm: String,
    /// Timestamp of signing
    pub signed_at: i64,
}

/// Signer interface for rule signatures
pub trait RuleSigner {
    /// Sign rule bytecode
    fn sign(&self, bytecode: &[u8]) -> Result<Vec<u8>>;
    
    /// Get key ID
    fn key_id(&self) -> &str;
}

/// Verifier interface for rule signatures
pub trait RuleVerifier {
    /// Verify signature
    fn verify(&self, bytecode: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
}

/// In-memory signer for testing
pub struct InMemorySigner {
    key_id: String,
    private_key: Vec<u8>,
}

impl InMemorySigner {
    pub fn new(key_id: String, private_key: Vec<u8>) -> Self {
        InMemorySigner { key_id, private_key }
    }
}

impl RuleSigner for InMemorySigner {
    fn sign(&self, bytecode: &[u8]) -> Result<Vec<u8>> {
        // In production, this would use RSA-PSS via rsa crate
        // For now, create a simple HMAC signature
        use blake3::Hasher;
        
        let key = blake3::hash(&self.private_key);
        let mut hasher = Hasher::new_keyed(key.as_bytes());
        hasher.update(bytecode);
        let result = hasher.finalize();
        
        Ok(result.as_bytes().to_vec())
    }
    
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Verify rule signature (simplified)
pub fn verify_signature(
    bytecode: &[u8],
    signature: &[u8],
    _key_id: &str,
    public_key: &[u8],
) -> Result<bool> {
    // Fail-closed verification path: require strict Ed25519 key/signature sizes.
    if public_key.len() != 32 || signature.len() != 64 {
        return Ok(false);
    }

    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| DslError::SignatureError("Invalid Ed25519 public key length".to_string()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| DslError::SignatureError("Invalid Ed25519 signature length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| DslError::SignatureError(format!("Invalid Ed25519 public key: {}", e)))?;
    let parsed_sig = Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(bytecode, &parsed_sig).is_ok())
}

/// Generate rule source hash for signing
pub fn hash_source(source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify source hash matches
pub fn verify_source_hash(source: &str, expected_hash: &str) -> bool {
    hash_source(source) == expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    
    #[test]
    fn test_source_hash() {
        let source = "RULE CRUE_001 VERSION 1.0";
        let hash = hash_source(source);
        assert_eq!(hash.len(), 64);
    }
    
    #[test]
    fn test_verify_source_hash() {
        let source = "RULE CRUE_001 VERSION 1.0";
        let hash = hash_source(source);
        assert!(verify_source_hash(source, &hash));
        assert!(!verify_source_hash(source, "invalid"));
    }
    
    #[test]
    fn test_signer() {
        let key = b"test_key_32_bytes_for_signing!";
        let signer = InMemorySigner::new("test-key-001".to_string(), key.to_vec());
        
        let bytecode = b"test bytecode";
        let signature = signer.sign(bytecode).unwrap();
        
        assert!(!signature.is_empty());
        assert_eq!(signer.key_id(), "test-key-001");
    }

    #[test]
    fn test_verify_signature_ed25519_valid_and_invalid() {
        let secret = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let bytecode = b"compiled-rule-bytecode";
        let sig = signing_key.sign(bytecode);

        assert!(verify_signature(bytecode, &sig.to_bytes(), "k1", &verifying_key.to_bytes()).unwrap());
        assert!(!verify_signature(b"tampered", &sig.to_bytes(), "k1", &verifying_key.to_bytes()).unwrap());
    }
}
