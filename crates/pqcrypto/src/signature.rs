//! Dilithium Post-Quantum Signature Implementation
//! 
//! Implements ML-DSA (Module-Lattice Digital Signature Algorithm)
//! as specified in NIST FIPS 203.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

#[cfg(feature = "real-crypto")]
use oqs::sig;

/// Dilithium security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DilithiumLevel {
    /// Level 2: ~128-bit security
    Dilithium2,
    /// Level 3: ~192-bit security
    Dilithium3,
    /// Level 5: ~256-bit security
    Dilithium5,
}

impl DilithiumLevel {
    /// Get algorithm identifier
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            DilithiumLevel::Dilithium2 => "ML-DSA-44",
            DilithiumLevel::Dilithium3 => "ML-DSA-65",
            DilithiumLevel::Dilithium5 => "ML-DSA-87",
        }
    }
    
    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => 1184,
            DilithiumLevel::Dilithium3 => 1568,
            DilithiumLevel::Dilithium5 => 1952,
        }
    }
    
    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => 2528,
            DilithiumLevel::Dilithium3 => 4000,
            DilithiumLevel::Dilithium5 => 4864,
        }
    }
    
    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            DilithiumLevel::Dilithium2 => 2420,
            DilithiumLevel::Dilithium3 => 3293,
            DilithiumLevel::Dilithium5 => 4595,
        }
    }
}

/// Dilithium public key
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct DilithiumPublicKey {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: DilithiumLevel,
    /// Public key bytes
    #[zeroize(skip)]
    pub key: Vec<u8>,
}

/// Dilithium secret key
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct DilithiumSecretKey {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: DilithiumLevel,
    /// Secret key bytes
    pub key: Vec<u8>,
}

/// Dilithium signature
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct DilithiumSignature {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: DilithiumLevel,
    /// Signature bytes
    #[zeroize(skip)]
    pub signature: Vec<u8>,
}

/// Dilithium context for signature operations
pub struct Dilithium {
    level: DilithiumLevel,
}

/// Signature backend provider abstraction (mock or real implementation).
pub trait SignatureProvider {
    fn backend_id(&self) -> &'static str;
    fn generate_keypair(&self, level: DilithiumLevel) -> PqcResult<(DilithiumPublicKey, DilithiumSecretKey)>;
    fn sign(&self, secret_key: &DilithiumSecretKey, message: &[u8]) -> PqcResult<DilithiumSignature>;
    fn verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> PqcResult<bool>;
}

/// Mock PQ signature provider used for development/tests.
///
/// This provider is deterministic and self-consistent, but it is not a real ML-DSA implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockProvider;

/// Placeholder real-provider integration point (liboqs/OQS-backed).
#[cfg(feature = "real-crypto")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OqsProvider;

impl Dilithium {
    /// Create new Dilithium context
    pub fn new(level: DilithiumLevel) -> Self {
        assert_backend_selected();
        Self { level }
    }

    /// Identifier of the active signature backend.
    pub fn backend_id(&self) -> &'static str {
        active_provider().backend_id()
    }
    
    /// Generate new key pair
    pub fn generate_keypair(&self) -> PqcResult<(DilithiumPublicKey, DilithiumSecretKey)> {
        active_provider().generate_keypair(self.level)
    }
    
    /// Sign a message
    pub fn sign(&self, secret_key: &DilithiumSecretKey, message: &[u8]) -> PqcResult<DilithiumSignature> {
        if secret_key.level != self.level {
            return Err(PqcError::InvalidKey("Key level mismatch".into()));
        }
        active_provider().sign(secret_key, message)
    }
    
    /// Verify a signature
    pub fn verify(&self, public_key: &DilithiumPublicKey, message: &[u8], signature: &DilithiumSignature) -> PqcResult<bool> {
        if public_key.level != self.level || signature.level != self.level {
            return Err(PqcError::InvalidKey("Level mismatch".into()));
        }
        active_provider().verify(public_key, message, signature)
    }
}

use crate::error::{PqcError, PqcResult};

fn assert_backend_selected() {
    #[cfg(not(any(feature = "mock-crypto", feature = "real-crypto")))]
    panic!("rsrp-pqcrypto: no crypto backend selected (enable `mock-crypto` or `real-crypto`)");
}

fn active_provider() -> &'static dyn SignatureProvider {
    #[cfg(feature = "real-crypto")]
    {
        &OQS_PROVIDER
    }
    #[cfg(all(not(feature = "real-crypto"), feature = "mock-crypto"))]
    {
        &MOCK_PROVIDER
    }
    #[cfg(not(any(feature = "mock-crypto", feature = "real-crypto")))]
    {
        panic!("rsrp-pqcrypto: no crypto backend selected (enable `mock-crypto` or `real-crypto`)");
    }
}

#[cfg(feature = "mock-crypto")]
static MOCK_PROVIDER: MockProvider = MockProvider;

#[cfg(feature = "real-crypto")]
static OQS_PROVIDER: OqsProvider = OqsProvider;

impl SignatureProvider for MockProvider {
    fn backend_id(&self) -> &'static str {
        "mock-crypto"
    }

    fn generate_keypair(&self, level: DilithiumLevel) -> PqcResult<(DilithiumPublicKey, DilithiumSecretKey)> {
        let mut rng = rand::thread_rng();
        let mut secret_key = vec![0u8; level.secret_key_size()];
        rand::RngCore::fill_bytes(&mut rng, &mut secret_key);
        let public_key = mock_public_from_secret(level, &secret_key);

        Ok((
            DilithiumPublicKey { level, key: public_key },
            DilithiumSecretKey { level, key: secret_key },
        ))
    }

    fn sign(&self, secret_key: &DilithiumSecretKey, message: &[u8]) -> PqcResult<DilithiumSignature> {
        let public_key = mock_public_from_secret(secret_key.level, &secret_key.key);
        let signature = mock_signature_bytes(secret_key.level, &public_key, message);
        Ok(DilithiumSignature {
            level: secret_key.level,
            signature,
        })
    }

    fn verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> PqcResult<bool> {
        let expected_len = public_key.level.signature_size();
        if signature.signature.len() != expected_len {
            return Err(PqcError::InvalidSignature("Invalid signature length".into()));
        }
        let expected = mock_signature_bytes(public_key.level, &public_key.key, message);
        Ok(signature.signature == expected)
    }
}

#[cfg(feature = "real-crypto")]
impl SignatureProvider for OqsProvider {
    fn backend_id(&self) -> &'static str {
        "oqs"
    }

    fn generate_keypair(&self, _level: DilithiumLevel) -> PqcResult<(DilithiumPublicKey, DilithiumSecretKey)> {
        let level = _level;
        oqs::init();
        let sig = oqs_sig_for_level(level)?;
        let (pk, sk) = sig
            .keypair()
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
        let public_key = pk.into_vec();
        let secret_key = sk.into_vec();
        if public_key.len() != level.public_key_size() || secret_key.len() != level.secret_key_size() {
            return Err(PqcError::KeyGenerationFailed(
                "OQS key sizes do not match expected ML-DSA sizes".into(),
            ));
        }
        Ok((
            DilithiumPublicKey { level, key: public_key },
            DilithiumSecretKey { level, key: secret_key },
        ))
    }

    fn sign(&self, secret_key: &DilithiumSecretKey, message: &[u8]) -> PqcResult<DilithiumSignature> {
        oqs::init();
        let sig = oqs_sig_for_level(secret_key.level)?;
        let sk = sig
            .secret_key_from_bytes(&secret_key.key)
            .ok_or_else(|| PqcError::InvalidKey("Invalid ML-DSA secret key length".into()))?;
        let signature = sig
            .sign(message, sk)
            .map_err(|e| PqcError::SigningFailed(e.to_string()))?
            .into_vec();
        Ok(DilithiumSignature {
            level: secret_key.level,
            signature,
        })
    }

    fn verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> PqcResult<bool> {
        oqs::init();
        let sig = oqs_sig_for_level(public_key.level)?;
        let pk = sig
            .public_key_from_bytes(&public_key.key)
            .ok_or_else(|| PqcError::InvalidKey("Invalid ML-DSA public key length".into()))?;
        let sig_ref = sig
            .signature_from_bytes(&signature.signature)
            .ok_or_else(|| PqcError::InvalidSignature("Invalid ML-DSA signature length".into()))?;
        Ok(sig.verify(message, sig_ref, pk).is_ok())
    }
}

#[cfg(feature = "real-crypto")]
fn oqs_sig_for_level(level: DilithiumLevel) -> PqcResult<sig::Sig> {
    use sig::Algorithm;
    let alg = match level {
        DilithiumLevel::Dilithium2 => Algorithm::MlDsa44,
        DilithiumLevel::Dilithium3 => Algorithm::MlDsa65,
        DilithiumLevel::Dilithium5 => Algorithm::MlDsa87,
    };
    sig::Sig::new(alg).map_err(|e| PqcError::UnsupportedAlgorithm(e.to_string()))
}

fn mock_public_from_secret(level: DilithiumLevel, secret: &[u8]) -> Vec<u8> {
    expand_hash(level, b"rsrp-mock-dilithium-public", &[secret], level.public_key_size())
}

fn mock_signature_bytes(level: DilithiumLevel, public_key: &[u8], message: &[u8]) -> Vec<u8> {
    expand_hash(
        level,
        b"rsrp-mock-dilithium-signature",
        &[public_key, message],
        level.signature_size(),
    )
}

fn expand_hash(level: DilithiumLevel, domain: &[u8], parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0u32;
    while out.len() < out_len {
        let mut h = sha2::Sha256::new();
        h.update(domain);
        h.update(level.algorithm_id().as_bytes());
        h.update(counter.to_be_bytes());
        for part in parts {
            h.update((*part).len().to_be_bytes());
            h.update(*part);
        }
        let block = h.finalize();
        let remaining = out_len - out.len();
        out.extend_from_slice(&block[..remaining.min(block.len())]);
        counter = counter.wrapping_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dilithium_key_sizes() {
        let dilithium2 = Dilithium::new(DilithiumLevel::Dilithium2);
        assert_eq!(dilithium2.level.public_key_size(), 1184);
        assert_eq!(dilithium2.level.secret_key_size(), 2528);
        assert_eq!(dilithium2.level.signature_size(), 2420);
    }
    
    #[test]
    fn test_dilithium_sign_verify() {
        let dilithium = Dilithium::new(DilithiumLevel::Dilithium2);
        let (public_key, secret_key) = dilithium.generate_keypair().unwrap();
        
        let message = b"Test message for R-SRP Ultra";
        let signature = dilithium.sign(&secret_key, message).unwrap();
        
        let result = dilithium.verify(&public_key, message, &signature);
        assert!(result.unwrap());
    }

    #[test]
    fn test_dilithium_verify_rejects_tampered_message() {
        let dilithium = Dilithium::new(DilithiumLevel::Dilithium2);
        let (public_key, secret_key) = dilithium.generate_keypair().unwrap();
        let sig = dilithium.sign(&secret_key, b"alpha").unwrap();
        assert!(!dilithium.verify(&public_key, b"beta", &sig).unwrap());
    }
}
