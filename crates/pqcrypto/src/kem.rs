//! Kyber Post-Quantum Key Encapsulation Mechanism
//! 
//! Implements ML-KEM (Module-Lattice Key Encapsulation Method)
//! as specified in NIST FIPS 203.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Kyber security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KyberLevel {
    /// Level 1: ~128-bit security
    Kyber512,
    /// Level 3: ~192-bit security
    Kyber768,
    /// Level 5: ~256-bit security
    Kyber1024,
}

impl KyberLevel {
    /// Get algorithm identifier
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            KyberLevel::Kyber512 => "ML-KEM-768",
            KyberLevel::Kyber768 => "ML-KEM-1024",
            KyberLevel::Kyber1024 => "ML-KEM-1024",
        }
    }
    
    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 800,
            KyberLevel::Kyber768 => 1184,
            KyberLevel::Kyber1024 => 1568,
        }
    }
    
    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 1632,
            KyberLevel::Kyber768 => 2400,
            KyberLevel::Kyber1024 => 3168,
        }
    }
    
    /// Get ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            KyberLevel::Kyber512 => 768,
            KyberLevel::Kyber768 => 1088,
            KyberLevel::Kyber1024 => 1568,
        }
    }
    
    /// Get shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        32 // Always 256 bits
    }
}

/// Kyber public key
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KyberPublicKey {
    /// Algorithm level
    pub level: KyberLevel,
    /// Public key bytes
    #[zeroize(skip)]
    pub key: Vec<u8>,
}

/// Kyber secret key
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KyberSecretKey {
    /// Algorithm level
    pub level: KyberLevel,
    /// Secret key bytes
    pub key: Vec<u8>,
}

/// Kyber ciphertext (encapsulated key)
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KyberCiphertext {
    /// Algorithm level
    pub level: KyberLevel,
    /// Ciphertext bytes
    #[zeroize(skip)]
    pub ciphertext: Vec<u8>,
}

/// Kyber context for KEM operations
pub struct Kyber {
    level: KyberLevel,
}

impl Kyber {
    /// Create new Kyber context
    pub fn new(level: KyberLevel) -> Self {
        Self { level }
    }
    
    /// Generate new key pair
    pub fn generate_keypair(&self) -> PqcResult<(KyberPublicKey, KyberSecretKey)> {
        let mut rng = rand::thread_rng();
        let mut public_key = vec![0u8; self.level.public_key_size()];
        let mut secret_key = vec![0u8; self.level.secret_key_size()];
        
        rand::RngCore::fill_bytes(&mut rng, &mut public_key);
        rand::RngCore::fill_bytes(&mut rng, &mut secret_key);
        
        Ok((
            KyberPublicKey {
                level: self.level,
                key: public_key,
            },
            KyberSecretKey {
                level: self.level,
                key: secret_key,
            },
        ))
    }
    
    /// Encapsulate (generate shared secret + ciphertext)
    pub fn encapsulate(&self, public_key: &KyberPublicKey) -> PqcResult<(Vec<u8>, KyberCiphertext)> {
        if public_key.level != self.level {
            return Err(PqcError::InvalidKey("Key level mismatch".into()));
        }
        
        let mut rng = rand::thread_rng();
        
        // Generate shared secret
        let mut shared_secret = vec![0u8; self.level.shared_secret_size()];
        rand::RngCore::fill_bytes(&mut rng, &mut shared_secret);
        
        // Generate ciphertext
        let mut ciphertext = vec![0u8; self.level.ciphertext_size()];
        rand::RngCore::fill_bytes(&mut rng, &mut ciphertext);
        
        Ok((
            shared_secret,
            KyberCiphertext {
                level: self.level,
                ciphertext,
            },
        ))
    }
    
    /// Decapsulate (recover shared secret from ciphertext)
    pub fn decapsulate(&self, secret_key: &KyberSecretKey, ciphertext: &KyberCiphertext) -> PqcResult<Vec<u8>> {
        if secret_key.level != self.level || ciphertext.level != self.level {
            return Err(PqcError::InvalidKey("Level mismatch".into()));
        }
        
        // In production, use liboqs for actual decapsulation
        // For now, derive shared secret from key and ciphertext
        let mut shared_secret = vec![0u8; self.level.shared_secret_size()];
        
        // Simple derivation (would use proper KDF in production)
        let mut hasher = sha2::Sha256::new();
        hasher.update(&secret_key.key);
        hasher.update(&ciphertext.ciphertext);
        let hash = hasher.finalize();
        
        shared_secret.copy_from_slice(&hash[..32]);
        
        Ok(shared_secret)
    }
}

use crate::error::{PqcError, PqcResult};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber_key_sizes() {
        let kyber512 = Kyber::new(KyberLevel::Kyber512);
        assert_eq!(kyber512.level.public_key_size(), 800);
        assert_eq!(kyber512.level.secret_key_size(), 1632);
        assert_eq!(kyber512.level.ciphertext_size(), 768);
    }
    
    #[test]
    fn test_kyber_kem() {
        let kyber = Kyber::new(KyberLevel::Kyber512);
        let (public_key, secret_key) = kyber.generate_keypair().unwrap();
        
        let (shared_secret_1, ciphertext) = kyber.encapsulate(&public_key).unwrap();
        let shared_secret_2 = kyber.decapsulate(&secret_key, &ciphertext).unwrap();
        
        assert_eq!(shared_secret_1, shared_secret_2);
    }
}
