//! Signature primitives - Ed25519, RSA-PSS, ECDSA

use crate::{SignatureAlgorithm, Result, CryptoError, KeyMetadata};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as Ed25519Signature};
use signature::{Signature, Signer as SigSigner};

/// Ed25519 key pair
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    metadata: KeyMetadata,
}

impl Ed25519KeyPair {
    /// Generate new Ed25519 key pair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        Ed25519KeyPair {
            signing_key,
            verifying_key,
            metadata: KeyMetadata {
                key_id: format!("ed25519-{}", uuid::Uuid::new_v4()),
                algorithm: SignatureAlgorithm::Ed25519,
                created_at: chrono::Utc::now().timestamp(),
                key_type: crate::KeyType::Signing,
                hsm_slot: None,
            },
        }
    }
    
    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }
    
    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        
        let sig_array: [u8; 64] = signature.try_into().unwrap();
        let ed25519_sig = Ed25519Signature::from_bytes(&sig_array);
        
        self.verifying_key.verify(data, &ed25519_sig).is_ok()
    }
    
    /// Get verifying key (public)
    pub fn verifying_key(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
    
    /// Get metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }
}

/// RSA key pair (placeholder - full implementation would use rsa crate)
pub struct RsaKeyPair {
    key_id: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl RsaKeyPair {
    /// Generate new RSA-PSS 4096 key pair
    #[allow(dead_code)]
    pub fn generate() -> Self {
        // In production, use rsa::RsaPrivateKey::new
        RsaKeyPair {
            key_id: format!("rsa-pss-4096-{}", uuid::Uuid::new_v4()),
            public_key: vec![],
            private_key: vec![],
        }
    }
    
    /// Get key ID
    #[allow(dead_code)]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Sign data with specified algorithm
pub fn sign(data: &[u8], key: &Ed25519KeyPair) -> Result<Vec<u8>> {
    Ok(key.sign(data))
}

/// Verify signature with specified algorithm
pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8], algorithm: SignatureAlgorithm) -> Result<bool> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            // Reconstruct verifying key and verify
            if public_key.len() != 32 {
                return Err(CryptoError::InvalidKey);
            }
            
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(public_key);
            let verifying_key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| CryptoError::InvalidKey)?;
            
            if signature.len() != 64 {
                return Ok(false);
            }
            
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(signature);
            let ed25519_sig = Ed25519Signature::from_bytes(&sig_bytes);
            
            Ok(verifying_key.verify(data, &ed25519_sig).is_ok())
        }
        _ => Err(CryptoError::SignatureError("Algorithm not implemented".to_string())),
    }
}

/// Sign with RSA-PSS (placeholder)
#[allow(dead_code)]
pub fn sign_rsa_pss(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Placeholder - full implementation would use rsa crate
    Err(CryptoError::SignatureError("RSA-PSS not implemented".to_string()))
}

/// Verify RSA-PSS signature (placeholder)
#[allow(dead_code)]
pub fn verify_rsa_pss(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Placeholder - full implementation would use rsa crate
    Err(CryptoError::SignatureError("RSA-PSS not implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let key_pair = Ed25519KeyPair::generate();
        
        let data = b"Test message for signing";
        let signature = key_pair.sign(data);
        
        assert!(key_pair.verify(data, &signature));
        assert!(!key_pair.verify(b"Wrong data", &signature));
    }
    
    #[test]
    fn test_verify_with_public_key() {
        let key_pair = Ed25519KeyPair::generate();
        
        let data = b"Test message";
        let signature = key_pair.sign(data);
        let public_key = key_pair.verifying_key();
        
        let result = verify(data, &signature, &public_key, SignatureAlgorithm::Ed25519).unwrap();
        assert!(result);
    }
}
