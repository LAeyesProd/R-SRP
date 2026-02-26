//! Signature primitives - Ed25519, RSA-PSS, ECDSA

use crate::{SignatureAlgorithm, Result, CryptoError, KeyMetadata};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as Ed25519Signature};
use rand::{rngs::OsRng, rngs::StdRng, SeedableRng};
use sha2::Digest as _;
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Error type for key generation
#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to gather entropy: {0}")]
    EntropyError(String),
    
    #[error("Key generation failed: {0}")]
    GenerationError(String),
}

/// FIPS mode configuration
#[derive(Debug, Clone)]
pub enum FipsMode {
    /// FIPS 140-2/3 compliant mode - requires OS entropy
    Enabled,
    /// Non-FIPS mode - allows fallback to deterministic RNG
    Disabled,
    /// Strict FIPS mode - fails if entropy is insufficient
    Strict,
}

impl Default for FipsMode {
    fn default() -> Self {
        // Check environment for FIPS mode
        match std::env::var("RUST_FIPS").unwrap_or_default().as_str() {
            "1" | "strict" => FipsMode::Strict,
            "true" | "enabled" => FipsMode::Enabled,
            _ => FipsMode::Disabled,
        }
    }
}

/// Ed25519 key pair with secure memory handling
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    #[zeroize(skip)]
    signing_key: SigningKey,
    #[zeroize(skip)]
    verifying_key: VerifyingKey,
    #[zeroize(skip)]
    metadata: KeyMetadata,
}

impl Ed25519KeyPair {
    /// Create an Ed25519 key pair from an explicit 32-byte seed.
    ///
    /// This is primarily intended for deterministic service integrations and tests.
    pub fn from_seed(seed: [u8; 32], key_id: Option<String>) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Ed25519KeyPair {
            signing_key,
            verifying_key,
            metadata: KeyMetadata {
                key_id: key_id.unwrap_or_else(|| format!("ed25519-{}", uuid::Uuid::new_v4())),
                algorithm: SignatureAlgorithm::Ed25519,
                created_at: chrono::Utc::now().timestamp(),
                key_type: crate::KeyType::Signing,
                hsm_slot: None,
            },
        }
    }

    /// Deterministically derive a key pair from secret material (SHA-256(secret)).
    ///
    /// This is useful for service bootstrapping in environments where a proper key
    /// management integration is not yet available. Prefer HSM/KMS in production.
    pub fn derive_from_secret(secret: &[u8], key_id: Option<String>) -> Self {
        let digest = sha2::Sha256::digest(secret);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        Self::from_seed(seed, key_id)
    }

    /// Generate new Ed25519 key pair with FIPS-compliant entropy
    /// 
    /// In FIPS mode (RUST_FIPS=1), this requires OS-level entropy.
    /// In non-FIPS mode, falls back to deterministic RNG if OsRng fails.
    ///
    /// Returns Result to allow error handling in strict mode
    pub fn generate() -> std::result::Result<Self, KeyGenerationError> {
        let fips_mode = FipsMode::default();
        Self::generate_with_mode(fips_mode)
    }
    
    /// Generate key pair with specific FIPS mode
    pub fn generate_with_mode(
        fips_mode: FipsMode,
    ) -> std::result::Result<Self, KeyGenerationError> {
        // Try OS entropy first (FIPS-compliant)
        let signing_key = match Self::generate_with_os_rng() {
            Ok(key) => key,
            Err(e) => {
                // Handle entropy failure based on mode
                match fips_mode {
                    FipsMode::Strict => {
                        // In strict mode, return error - don't panic
                        return Err(KeyGenerationError::EntropyError(
                            format!("FIPS strict mode: OS entropy unavailable: {}", e)
                        ));
                    },
                    FipsMode::Enabled => {
                        // Log warning but try fallback
                        eprintln!("WARNING: OS entropy unavailable, using fallback RNG (non-FIPS): {}", e);
                        Self::generate_fallback()
                    },
                    FipsMode::Disabled => {
                        // Use fallback silently
                        Self::generate_fallback()
                    }
                }
            }
        };
        let verifying_key = signing_key.verifying_key();
        
        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
            metadata: KeyMetadata {
                key_id: format!("ed25519-{}", uuid::Uuid::new_v4()),
                algorithm: SignatureAlgorithm::Ed25519,
                created_at: chrono::Utc::now().timestamp(),
                key_type: crate::KeyType::Signing,
                hsm_slot: None,
            },
        })
    }
    
    /// Generate key using OS entropy (FIPS-compliant)
    fn generate_with_os_rng() -> std::result::Result<SigningKey, KeyGenerationError> {
        let mut os_rng = OsRng;
        Ok(SigningKey::generate(&mut os_rng))
    }
    
    /// Fallback RNG for when OS entropy is unavailable
    /// WARNING: This is NOT cryptographically secure for production!
    /// Use only as last resort or in development.
    ///
    /// Uses StdRng::from_entropy() which seeds from OS entropy,
    /// providing better security than deterministic seeding.
    fn generate_fallback() -> SigningKey {
        // Use OS-entropy-seeded StdRng for fallback
        // This is better than deterministic seeding
        let mut rng = StdRng::from_entropy();
        SigningKey::generate(&mut rng)
    }
    
    /// Generate key with explicit HSM (Hardware Security Module)
    /// Returns error if HSM is not available
    #[allow(dead_code)]
    pub fn generate_with_hsm(_slot: u32) -> Result<Self> {
        // HSM integration would go here
        // For now, return error indicating HSM not implemented
        Err(CryptoError::KeyError("HSM integration not implemented".to_string()))
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
#[allow(dead_code)]
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
pub fn sign_rsa_pss(_data: &[u8], _private_key: &[u8]) -> Result<Vec<u8>> {
    // Placeholder - full implementation would use rsa crate
    Err(CryptoError::SignatureError("RSA-PSS not implemented".to_string()))
}

/// Verify RSA-PSS signature (placeholder)
#[allow(dead_code)]
pub fn verify_rsa_pss(_data: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool> {
    // Placeholder - full implementation would use rsa crate
    Err(CryptoError::SignatureError("RSA-PSS not implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        
        let data = b"Test message for signing";
        let signature = key_pair.sign(data);
        
        assert!(key_pair.verify(data, &signature));
        assert!(!key_pair.verify(b"Wrong data", &signature));
    }
    
    #[test]
    fn test_verify_with_public_key() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        
        let data = b"Test message";
        let signature = key_pair.sign(data);
        let public_key = key_pair.verifying_key();
        
        let result = verify(data, &signature, &public_key, SignatureAlgorithm::Ed25519).unwrap();
        assert!(result);
    }

    #[test]
    fn test_ed25519_derive_from_secret_is_deterministic() {
        let k1 = Ed25519KeyPair::derive_from_secret(b"secret-material", Some("k1".to_string()));
        let k2 = Ed25519KeyPair::derive_from_secret(b"secret-material", Some("k2".to_string()));
        let k3 = Ed25519KeyPair::derive_from_secret(b"other-secret", None);

        assert_eq!(k1.verifying_key(), k2.verifying_key());
        assert_ne!(k1.verifying_key(), k3.verifying_key());

        let msg = b"publication payload";
        let sig = k1.sign(msg);
        assert!(k2.verify(msg, &sig));
    }
}
