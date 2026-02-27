//! Signature primitives - Ed25519 (RSA-PSS legacy path disabled)

use crate::{CryptoError, KeyMetadata, Result, SignatureAlgorithm};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, rngs::StdRng, SeedableRng};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    // 32-byte Ed25519 private seed (zeroized on drop).
    secret_seed: [u8; 32],
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
            secret_seed: seed,
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

    /// Deterministically derive a key pair from secret material (HKDF-SHA256).
    ///
    /// This is useful for service bootstrapping in environments where a proper key
    /// management integration is not yet available. Prefer HSM/KMS in production.
    pub fn derive_from_secret(secret: &[u8], key_id: Option<String>) -> Self {
        // Context-bound HKDF derivation to avoid raw hash-as-key constructions.
        let hk = Hkdf::<sha2::Sha256>::new(Some(b"rsrp-security-core-ed25519-v1"), secret);
        let mut seed = [0u8; 32];
        hk.expand(b"signing-seed", &mut seed)
            .expect("HKDF expand to 32 bytes should never fail");
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
        let secret_seed = match Self::generate_with_os_rng() {
            Ok(seed) => seed,
            Err(e) => {
                // Handle entropy failure based on mode
                match fips_mode {
                    FipsMode::Strict => {
                        // In strict mode, return error - don't panic
                        return Err(KeyGenerationError::EntropyError(format!(
                            "FIPS strict mode: OS entropy unavailable: {}",
                            e
                        )));
                    }
                    FipsMode::Enabled => {
                        tracing::warn!(
                            event = "crypto.fips_fallback",
                            error = %e,
                            "OS entropy unavailable, using fallback RNG (non-FIPS)"
                        );
                        return Err(KeyGenerationError::EntropyError(format!(
                            "FIPS enabled mode: OS entropy unavailable: {}",
                            e
                        )));
                    }
                    FipsMode::Disabled => {
                        // Use fallback silently
                        Self::generate_fallback()
                    }
                }
            }
        };
        let signing_key = SigningKey::from_bytes(&secret_seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            secret_seed,
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
    fn generate_with_os_rng() -> std::result::Result<[u8; 32], KeyGenerationError> {
        let mut os_rng = OsRng;
        Ok(SigningKey::generate(&mut os_rng).to_bytes())
    }

    /// Fallback RNG for when OS entropy is unavailable
    /// WARNING: This is NOT cryptographically secure for production!
    /// Use only as last resort or in development.
    ///
    /// Uses StdRng::from_entropy() which seeds from OS entropy,
    /// providing better security than deterministic seeding.
    fn generate_fallback() -> [u8; 32] {
        // Use OS-entropy-seeded StdRng for fallback
        // This is better than deterministic seeding
        let mut rng = StdRng::from_entropy();
        SigningKey::generate(&mut rng).to_bytes()
    }

    /// Generate key with explicit HSM (Hardware Security Module)
    /// Returns error if HSM is not available
    #[allow(dead_code)]
    pub fn generate_with_hsm(_slot: u32) -> Result<Self> {
        // HSM integration would go here
        // For now, return error indicating HSM not implemented
        Err(CryptoError::KeyError(
            "HSM integration not implemented".to_string(),
        ))
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&self.secret_seed);
        let signature = signing_key.sign(data);
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

/// Legacy RSA key pair support (disabled).
#[allow(dead_code)]
pub struct RsaKeyPair {
    key_id: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl RsaKeyPair {
    /// Generate new RSA-PSS 4096 key pair
    #[allow(dead_code)]
    pub fn generate() -> Result<Self> {
        Self::generate_with_bits(4096)
    }

    /// Generate RSA-PSS key pair with explicit key size.
    #[allow(dead_code)]
    pub fn generate_with_bits(bits: usize) -> Result<Self> {
        let _ = bits;
        Err(CryptoError::SignatureError(
            "RSA-PSS support disabled in rsrp-security-core (legacy path removed)".to_string(),
        ))
    }

    /// Get key ID
    #[allow(dead_code)]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[allow(dead_code)]
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key
    }

    #[allow(dead_code)]
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key
    }
}

/// Sign data with specified algorithm
pub fn sign(data: &[u8], key: &Ed25519KeyPair) -> Result<Vec<u8>> {
    Ok(key.sign(data))
}

/// Verify signature with specified algorithm
pub fn verify(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<bool> {
    match algorithm {
        SignatureAlgorithm::RsaPss2048 | SignatureAlgorithm::RsaPss4096 => {
            verify_rsa_pss(data, signature, public_key)
        }
        SignatureAlgorithm::Ed25519 => {
            // Reconstruct verifying key and verify
            if public_key.len() != 32 {
                return Err(CryptoError::InvalidKey);
            }

            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(public_key);
            let verifying_key =
                VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidKey)?;

            if signature.len() != 64 {
                return Ok(false);
            }

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(signature);
            let ed25519_sig = Ed25519Signature::from_bytes(&sig_bytes);

            Ok(verifying_key.verify(data, &ed25519_sig).is_ok())
        }
        _ => Err(CryptoError::SignatureError(
            "Algorithm not implemented".to_string(),
        )),
    }
}

/// Sign with RSA-PSS-SHA256 using PKCS#8 DER private key bytes.
#[allow(dead_code)]
pub fn sign_rsa_pss(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    let _ = (data, private_key);
    Err(CryptoError::SignatureError(
        "RSA-PSS support disabled in rsrp-security-core (legacy path removed)".to_string(),
    ))
}

/// Verify RSA-PSS-SHA256 using SubjectPublicKeyInfo DER public key bytes.
#[allow(dead_code)]
pub fn verify_rsa_pss(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let _ = (data, signature, public_key);
    Err(CryptoError::SignatureError(
        "RSA-PSS support disabled in rsrp-security-core (legacy path removed)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

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

    #[test]
    fn test_rsa_pss_disabled_by_default() {
        let msg = b"rsa-pss-message";
        let err = sign_rsa_pss(msg, b"not-a-real-key")
            .unwrap_err()
            .to_string();
        assert!(err.contains("disabled"));
    }

    #[test]
    fn test_ed25519_private_seed_zeroize() {
        let mut key_pair =
            Ed25519KeyPair::derive_from_secret(b"seed-material", Some("z".to_string()));
        assert_ne!(key_pair.secret_seed, [0u8; 32]);
        key_pair.zeroize();
        assert_eq!(key_pair.secret_seed, [0u8; 32]);
    }
}
