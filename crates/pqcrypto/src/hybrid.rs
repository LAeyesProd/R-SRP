//! Hybrid Cryptographic Primitives
//! 
//! Combines classical cryptography with post-quantum algorithms
//! to provide security against both classical and quantum attackers.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

use crate::error::{PqcError, PqcResult};
use crate::signature::{Dilithium, DilithiumLevel, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
use crate::kem::{Kyber, KyberLevel, KyberPublicKey, KyberSecretKey, KyberCiphertext};

/// Hybrid signature scheme: Ed25519 + Dilithium
/// 
/// Security: Both classical (Ed25519) and quantum (Dilithium) must be broken
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical signature (Ed25519)
    pub classical: Vec<u8>,
    /// Post-quantum signature (Dilithium)
    pub quantum: DilithiumSignature,
}

impl HybridSignature {
    /// Create a new hybrid signature from classical and quantum parts
    pub fn new(classical: Vec<u8>, quantum: DilithiumSignature) -> Self {
        Self { classical, quantum }
    }
    
    /// Get total size of the hybrid signature
    pub fn total_size(&self) -> usize {
        self.classical.len() + self.quantum.signature.len()
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size());
        // Format: [classical_len:2][classical][quantum]
        result.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.classical);
        result.extend_from_slice(&self.quantum.signature);
        result
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(level: DilithiumLevel, data: &[u8]) -> PqcResult<Self> {
        if data.len() < 2 {
            return Err(PqcError::InvalidSignature("Too short".into()));
        }
        
        let classical_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + classical_len {
            return Err(PqcError::InvalidSignature("Invalid length".into()));
        }
        
        let classical = data[2..2 + classical_len].to_vec();
        let quantum_signature = DilithiumSignature {
            level,
            signature: data[2 + classical_len..].to_vec(),
        };
        
        Ok(Self {
            classical,
            quantum: quantum_signature,
        })
    }
}

/// Hybrid key pair for signatures
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct HybridKeyPair {
    /// Classical Ed25519 key pair
    pub classical_public: Vec<u8>,
    #[zeroize(skip)]
    pub classical_secret: Vec<u8>,
    /// Post-quantum Dilithium key pair
    pub quantum_public: DilithiumPublicKey,
    pub quantum_secret: DilithiumSecretKey,
    /// Security level
    #[zeroize(skip)]
    pub level: DilithiumLevel,
}

/// Public-only hybrid verification key (safe to share with verifiers).
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// Classical Ed25519 public component (mock representation in current implementation)
    pub classical_public: Vec<u8>,
    /// Post-quantum ML-DSA public key
    pub quantum_public: DilithiumPublicKey,
    /// Security level
    pub level: DilithiumLevel,
}

impl HybridKeyPair {
    /// Extract a public-only verification key from a hybrid signing key pair.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical_public: self.classical_public.clone(),
            quantum_public: self.quantum_public.clone(),
            level: self.level,
        }
    }
}

/// Hybrid KEM: X25519 + Kyber
/// 
/// Security: Both classical (X25519) and quantum (Kyber) must be broken
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridKEM {
    /// Classical ciphertext (X25519)
    pub classical: Vec<u8>,
    /// Post-quantum ciphertext (Kyber)
    pub quantum: KyberCiphertext,
}

impl HybridKEM {
    /// Create new hybrid KEM ciphertext
    pub fn new(classical: Vec<u8>, quantum: KyberCiphertext) -> Self {
        Self { classical, quantum }
    }
    
    /// Get total size of the hybrid ciphertext
    pub fn total_size(&self) -> usize {
        self.classical.len() + self.quantum.ciphertext.len()
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size());
        result.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.classical);
        result.extend_from_slice(&self.quantum.ciphertext);
        result
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(level: KyberLevel, data: &[u8]) -> PqcResult<Self> {
        if data.len() < 2 {
            return Err(PqcError::InvalidSignature("Too short".into()));
        }
        
        let classical_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + classical_len {
            return Err(PqcError::InvalidSignature("Invalid length".into()));
        }
        
        let classical = data[2..2 + classical_len].to_vec();
        let quantum_ct = KyberCiphertext {
            level,
            ciphertext: data[2 + classical_len..].to_vec(),
        };
        
        Ok(Self {
            classical,
            quantum: quantum_ct,
        })
    }
}

/// Hybrid key pair for KEM
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct HybridKEMKeyPair {
    /// Classical X25519 public key
    #[zeroize(skip)]
    pub classical_public: Vec<u8>,
    /// Classical X25519 secret key
    pub classical_secret: Vec<u8>,
    /// Post-quantum Kyber public key
    pub quantum_public: KyberPublicKey,
    /// Post-quantum Kyber secret key
    pub quantum_secret: KyberSecretKey,
    /// Security level
    #[zeroize(skip)]
    pub level: KyberLevel,
}

/// Hybrid signer that creates dual signatures
pub struct HybridSigner {
    dilithium: Dilithium,
    level: DilithiumLevel,
}

impl HybridSigner {
    /// Create new hybrid signer
    pub fn new(level: DilithiumLevel) -> Self {
        Self {
            dilithium: Dilithium::new(level),
            level,
        }
    }

    pub fn backend_id(&self) -> &'static str {
        self.dilithium.backend_id()
    }
    
    /// Generate hybrid key pair
    pub fn generate_keypair(&self) -> PqcResult<HybridKeyPair> {
        // Generate classical key pair (mock, deterministic verification path)
        let mut rng = rand::thread_rng();
        let mut classical_secret = vec![0u8; 64];
        rand::RngCore::fill_bytes(&mut rng, &mut classical_secret);
        let classical_public = mock_classical_public(&classical_secret);
        
        // Generate quantum Dilithium key pair
        let (quantum_public, quantum_secret) = self.dilithium.generate_keypair()?;
        
        Ok(HybridKeyPair {
            classical_public,
            classical_secret,
            quantum_public,
            quantum_secret,
            level: self.level,
        })
    }
    
    /// Sign with both classical and quantum algorithms
    pub fn sign(&self, keypair: &HybridKeyPair, message: &[u8]) -> PqcResult<HybridSignature> {
        // Classical signature (mock but deterministic and verifiable)
        let classical_sig = mock_classical_signature(&keypair.classical_public, message);
        
        // Quantum signature (Dilithium)
        let quantum_sig = self.dilithium.sign(&keypair.quantum_secret, message)?;
        
        Ok(HybridSignature::new(classical_sig, quantum_sig))
    }
}

/// Hybrid verifier for dual signatures
pub struct HybridVerifier {
    dilithium: Dilithium,
    #[allow(dead_code)]
    level: DilithiumLevel,
}

impl HybridVerifier {
    /// Create new hybrid verifier
    pub fn new(level: DilithiumLevel) -> Self {
        Self {
            dilithium: Dilithium::new(level),
            level,
        }
    }
    
    /// Verify hybrid signature
    /// 
    /// Note: Both classical AND quantum must verify successfully
    pub fn verify(&self, keypair: &HybridKeyPair, message: &[u8], signature: &HybridSignature) -> PqcResult<bool> {
        self.verify_public(&keypair.public_key(), message, signature)
    }

    /// Verify hybrid signature using a public-only key.
    ///
    /// This is the production-oriented verification path (no secret key material required).
    pub fn verify_public(
        &self,
        public_key: &HybridPublicKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> PqcResult<bool> {
        if public_key.level != self.level || public_key.quantum_public.level != self.level {
            return Err(PqcError::InvalidKey("Hybrid public key level mismatch".into()));
        }
        if signature.quantum.level != self.level {
            return Err(PqcError::InvalidSignature("Hybrid signature level mismatch".into()));
        }

        // Verify classical signature (mock deterministic backend)
        if signature.classical.len() != 64 {
            return Err(PqcError::InvalidSignature("Invalid classical sig".into()));
        }
        let expected_classical = mock_classical_signature(&public_key.classical_public, message);
        let classical_valid = signature.classical == expected_classical;
        
        // Verify quantum signature
        let quantum_valid = self.dilithium.verify(&public_key.quantum_public, message, &signature.quantum)?;
        
        // Both must be valid
        Ok(classical_valid && quantum_valid)
    }
}

/// Hybrid KEM encapsulator
pub struct HybridKEMEncapsulator {
    kyber: Kyber,
    level: KyberLevel,
}

impl HybridKEMEncapsulator {
    /// Create new hybrid KEM encapsulator
    pub fn new(level: KyberLevel) -> Self {
        Self {
            kyber: Kyber::new(level),
            level,
        }
    }

    pub fn backend_id(&self) -> &'static str {
        self.kyber.backend_id()
    }
    
    /// Generate hybrid KEM key pair
    pub fn generate_keypair(&self) -> PqcResult<HybridKEMKeyPair> {
        // Generate classical X25519 key pair (simulated)
        let mut rng = rand::thread_rng();
        let mut classical_public = vec![0u8; 32];
        let mut classical_secret = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut classical_public);
        rand::RngCore::fill_bytes(&mut rng, &mut classical_secret);
        
        // Generate quantum Kyber key pair
        let (quantum_public, quantum_secret) = self.kyber.generate_keypair()?;
        
        Ok(HybridKEMKeyPair {
            classical_public,
            classical_secret,
            quantum_public,
            quantum_secret,
            level: self.level,
        })
    }
    
    /// Encapsulate shared secret for recipient's public key
    pub fn encapsulate(&self, recipient: &HybridKEMKeyPair) -> PqcResult<(Vec<u8>, HybridKEM)> {
        let mut rng = rand::thread_rng();
        
        // Classical encapsulation (simulated X25519)
        let mut classical_ct = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut classical_ct);
        
        // Quantum encapsulation (Kyber)
        let (shared_quantum, quantum_ct) = self.kyber.encapsulate(&recipient.quantum_public)?;
        
        // Combine shared secrets
        let mut combined_secret = vec![0u8; 32];
        // Simple combination (XOR) - in production use proper KDF
        for i in 0..32 {
            combined_secret[i] = classical_ct[i] ^ shared_quantum[i];
        }
        
        Ok((
            combined_secret,
            HybridKEM::new(classical_ct, quantum_ct),
        ))
    }
}

/// Hybrid KEM decapsulator
pub struct HybridKEMDecapsulator {
    kyber: Kyber,
    #[allow(dead_code)]
    level: KyberLevel,
}

fn mock_classical_public(secret: &[u8]) -> Vec<u8> {
    let mut h = sha2::Sha256::new();
    h.update(b"rsrp-hybrid-mock-classical-public");
    h.update(secret);
    h.finalize().to_vec()
}

fn mock_classical_signature(public_key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let mut counter = 0u32;
    while out.len() < 64 {
        let mut h = sha2::Sha256::new();
        h.update(b"rsrp-hybrid-mock-classical-signature");
        h.update(counter.to_be_bytes());
        h.update(public_key);
        h.update(message);
        let block = h.finalize();
        let remaining = 64 - out.len();
        out.extend_from_slice(&block[..remaining.min(block.len())]);
        counter = counter.wrapping_add(1);
    }
    out
}

impl HybridKEMDecapsulator {
    /// Create new hybrid KEM decapsulator
    pub fn new(level: KyberLevel) -> Self {
        Self {
            kyber: Kyber::new(level),
            level,
        }
    }

    pub fn backend_id(&self) -> &'static str {
        self.kyber.backend_id()
    }
    
    /// Decapsulate shared secret from ciphertext
    pub fn decapsulate(&self, keypair: &HybridKEMKeyPair, ciphertext: &HybridKEM) -> PqcResult<Vec<u8>> {
        // Quantum decapsulation (Kyber)
        let shared_quantum = self.kyber.decapsulate(&keypair.quantum_secret, &ciphertext.quantum)?;
        
        // Combine with classical part
        let mut combined_secret = vec![0u8; 32];
        for i in 0..32 {
            if i < ciphertext.classical.len() {
                combined_secret[i] = ciphertext.classical[i] ^ shared_quantum[i];
            } else {
                combined_secret[i] = shared_quantum[i];
            }
        }
        
        Ok(combined_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hybrid_signature() {
        let signer = HybridSigner::new(DilithiumLevel::Dilithium2);
        let verifier = HybridVerifier::new(DilithiumLevel::Dilithium2);
        
        let keypair = signer.generate_keypair().unwrap();
        let message = b"R-SRP Ultra test message";
        
        let signature = signer.sign(&keypair, message).unwrap();
        assert_eq!(signature.classical.len(), 64);
        assert_eq!(signature.quantum.signature.len(), 2420);
        
        let result = verifier.verify(&keypair, message, &signature);
        assert!(result.unwrap());
    }

    #[test]
    fn test_hybrid_signature_rejects_tampered_classical_part() {
        let signer = HybridSigner::new(DilithiumLevel::Dilithium2);
        let verifier = HybridVerifier::new(DilithiumLevel::Dilithium2);
        let keypair = signer.generate_keypair().unwrap();
        let mut signature = signer.sign(&keypair, b"m").unwrap();
        signature.classical[0] ^= 0x55;
        assert!(!verifier.verify(&keypair, b"m", &signature).unwrap());
    }

    #[test]
    fn test_hybrid_signature_verify_public_only() {
        let signer = HybridSigner::new(DilithiumLevel::Dilithium2);
        let verifier = HybridVerifier::new(DilithiumLevel::Dilithium2);
        let keypair = signer.generate_keypair().unwrap();
        let public_key = keypair.public_key();
        let signature = signer.sign(&keypair, b"m").unwrap();
        assert!(verifier.verify_public(&public_key, b"m", &signature).unwrap());
    }
    
    #[test]
    fn test_hybrid_kem() {
        let encapsulator = HybridKEMEncapsulator::new(KyberLevel::Kyber512);
        let decapsulator = HybridKEMDecapsulator::new(KyberLevel::Kyber512);
        
        let keypair = encapsulator.generate_keypair().unwrap();
        
        let (shared_1, ciphertext) = encapsulator.encapsulate(&keypair).unwrap();
        let shared_2 = decapsulator.decapsulate(&keypair, &ciphertext).unwrap();
        
        assert_eq!(shared_1, shared_2);
    }
}
