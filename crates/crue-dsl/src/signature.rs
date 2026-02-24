//! CRUE Rule Signature Module
//! 
//! Handles RSA-PSS signing and verification of compiled rules

use crate::error::{DslError, Result};
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
        
        let mut hasher = Hasher::new_keyed(&self.private_key);
        hasher.update(bytecode);
        let mut result = hasher.finalize();
        
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
    // In production, use RSA-PSS verification
    // This is a placeholder verification
    
    // For now, just check signature length
    if signature.len() < 32 {
        return Ok(false);
    }
    
    // Compute expected hash
    let mut hasher = Sha256::new();
    hasher.update(bytecode);
    let hash = hasher.finalize();
    
    // Compare (simplified - real impl would use RSA-PSS)
    Ok(signature.starts_with(hash.as_ref()))
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
}
