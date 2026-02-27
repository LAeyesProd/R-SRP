//! Kyber Post-Quantum Key Encapsulation Mechanism
//!
//! Implements ML-KEM (Module-Lattice Key Encapsulation Method)
//! provider abstractions for mock and real backends.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

use crate::error::{PqcError, PqcResult};

#[cfg(feature = "real-crypto")]
use oqs::kem;

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
            KyberLevel::Kyber512 => "ML-KEM-512",
            KyberLevel::Kyber768 => "ML-KEM-768",
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
        32
    }
}

/// Kyber public key
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KyberPublicKey {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: KyberLevel,
    /// Public key bytes
    #[zeroize(skip)]
    pub key: Vec<u8>,
}

/// Kyber secret key
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KyberSecretKey {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: KyberLevel,
    /// Secret key bytes
    key: Vec<u8>,
}

/// Kyber ciphertext (encapsulated key)
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KyberCiphertext {
    /// Algorithm level
    #[zeroize(skip)]
    pub level: KyberLevel,
    /// Ciphertext bytes
    #[zeroize(skip)]
    pub ciphertext: Vec<u8>,
}

/// KEM backend provider abstraction (mock or real implementation).
pub trait KemProvider {
    fn backend_id(&self) -> &'static str;
    fn generate_keypair(&self, level: KyberLevel) -> PqcResult<(KyberPublicKey, KyberSecretKey)>;
    fn encapsulate(
        &self,
        level: KyberLevel,
        public_key: &KyberPublicKey,
    ) -> PqcResult<(Vec<u8>, KyberCiphertext)>;
    fn decapsulate(
        &self,
        level: KyberLevel,
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> PqcResult<Vec<u8>>;
}

/// Mock KEM provider used for development/tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockKemProvider;

/// Placeholder real-provider integration point (liboqs/OQS-backed).
#[cfg(feature = "real-crypto")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OqsKemProvider;

/// Kyber context for KEM operations
pub struct Kyber {
    level: KyberLevel,
}

impl Kyber {
    /// Create new Kyber context
    pub fn new(level: KyberLevel) -> Self {
        assert_backend_selected();
        crate::validate_runtime_security_config()
            .expect("production runtime security configuration validation failed");
        #[cfg(feature = "production")]
        if level != KyberLevel::Kyber768 {
            panic!("production-hardening requires ML-KEM-768 (Kyber768)");
        }
        Self { level }
    }

    pub fn backend_id(&self) -> &'static str {
        active_provider().backend_id()
    }

    /// Generate new key pair
    pub fn generate_keypair(&self) -> PqcResult<(KyberPublicKey, KyberSecretKey)> {
        active_provider().generate_keypair(self.level)
    }

    /// Encapsulate (generate shared secret + ciphertext)
    pub fn encapsulate(
        &self,
        public_key: &KyberPublicKey,
    ) -> PqcResult<(Vec<u8>, KyberCiphertext)> {
        if public_key.level != self.level {
            return Err(PqcError::InvalidKey("Key level mismatch".into()));
        }
        active_provider().encapsulate(self.level, public_key)
    }

    /// Decapsulate (recover shared secret from ciphertext)
    pub fn decapsulate(
        &self,
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> PqcResult<Vec<u8>> {
        if secret_key.level != self.level || ciphertext.level != self.level {
            return Err(PqcError::InvalidKey("Level mismatch".into()));
        }
        active_provider().decapsulate(self.level, secret_key, ciphertext)
    }
}

fn assert_backend_selected() {
    #[cfg(all(not(debug_assertions), feature = "mock-crypto"))]
    panic!("rsrp-pqcrypto: mock backend is forbidden in release builds");
    #[cfg(all(not(any(feature = "mock-crypto", feature = "real-crypto")), not(test)))]
    panic!("rsrp-pqcrypto: no KEM backend selected (enable `mock-crypto` or `real-crypto`)");
}

fn active_provider() -> &'static dyn KemProvider {
    #[cfg(feature = "real-crypto")]
    {
        &OQS_KEM_PROVIDER
    }
    #[cfg(all(not(feature = "real-crypto"), feature = "mock-crypto"))]
    {
        &MOCK_KEM_PROVIDER
    }
    #[cfg(not(any(feature = "mock-crypto", feature = "real-crypto")))]
    #[cfg(test)]
    {
        &TEST_FALLBACK_KEM_PROVIDER
    }
    #[cfg(all(not(any(feature = "mock-crypto", feature = "real-crypto")), not(test)))]
    {
        panic!("rsrp-pqcrypto: no KEM backend selected (enable `mock-crypto` or `real-crypto`)");
    }
}

#[cfg(feature = "mock-crypto")]
static MOCK_KEM_PROVIDER: MockKemProvider = MockKemProvider;

#[cfg(feature = "real-crypto")]
static OQS_KEM_PROVIDER: OqsKemProvider = OqsKemProvider;

#[cfg(all(test, not(any(feature = "mock-crypto", feature = "real-crypto"))))]
static TEST_FALLBACK_KEM_PROVIDER: MockKemProvider = MockKemProvider;

impl KemProvider for MockKemProvider {
    fn backend_id(&self) -> &'static str {
        "mock-crypto"
    }

    fn generate_keypair(&self, level: KyberLevel) -> PqcResult<(KyberPublicKey, KyberSecretKey)> {
        let mut rng = rand::thread_rng();
        let mut secret_key = vec![0u8; level.secret_key_size()];
        rand::RngCore::fill_bytes(&mut rng, &mut secret_key);
        let public_key = derive_mock_public_key(level, &secret_key);

        Ok((
            KyberPublicKey {
                level,
                key: public_key.clone(),
            },
            KyberSecretKey {
                level,
                key: embed_public_component(level, &secret_key, &public_key),
            },
        ))
    }

    fn encapsulate(
        &self,
        level: KyberLevel,
        public_key: &KyberPublicKey,
    ) -> PqcResult<(Vec<u8>, KyberCiphertext)> {
        if public_key.key.len() != level.public_key_size() {
            return Err(PqcError::InvalidKey("Invalid public key length".into()));
        }
        let mut rng = rand::thread_rng();
        let mut ciphertext = vec![0u8; level.ciphertext_size()];
        rand::RngCore::fill_bytes(&mut rng, &mut ciphertext);

        let shared_secret = derive_mock_shared_secret(level, &public_key.key, &ciphertext);
        Ok((shared_secret, KyberCiphertext { level, ciphertext }))
    }

    fn decapsulate(
        &self,
        level: KyberLevel,
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> PqcResult<Vec<u8>> {
        if secret_key.key.len() != level.secret_key_size() {
            return Err(PqcError::InvalidKey("Invalid secret key length".into()));
        }
        if ciphertext.ciphertext.len() != level.ciphertext_size() {
            return Err(PqcError::InvalidParameter(
                "Invalid ciphertext length".into(),
            ));
        }
        let public_len = level.public_key_size();
        let public_part = &secret_key.key[..public_len];
        Ok(derive_mock_shared_secret(
            level,
            public_part,
            &ciphertext.ciphertext,
        ))
    }
}

#[cfg(feature = "real-crypto")]
impl KemProvider for OqsKemProvider {
    fn backend_id(&self) -> &'static str {
        "oqs"
    }

    fn generate_keypair(&self, level: KyberLevel) -> PqcResult<(KyberPublicKey, KyberSecretKey)> {
        oqs::init();
        let kem = oqs_kem_for_level(level)?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
        let public_key = pk.into_vec();
        let secret_key = sk.into_vec();
        if public_key.len() != level.public_key_size()
            || secret_key.len() != level.secret_key_size()
        {
            return Err(PqcError::KeyGenerationFailed(
                "OQS key sizes do not match expected ML-KEM sizes".into(),
            ));
        }
        Ok((
            KyberPublicKey {
                level,
                key: public_key,
            },
            KyberSecretKey {
                level,
                key: secret_key,
            },
        ))
    }

    fn encapsulate(
        &self,
        level: KyberLevel,
        public_key: &KyberPublicKey,
    ) -> PqcResult<(Vec<u8>, KyberCiphertext)> {
        oqs::init();
        let kem = oqs_kem_for_level(level)?;
        let pk = kem
            .public_key_from_bytes(&public_key.key)
            .ok_or_else(|| PqcError::InvalidKey("Invalid ML-KEM public key length".into()))?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|e| PqcError::EncryptionFailed(e.to_string()))?;
        Ok((
            ss.into_vec(),
            KyberCiphertext {
                level,
                ciphertext: ct.into_vec(),
            },
        ))
    }

    fn decapsulate(
        &self,
        level: KyberLevel,
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> PqcResult<Vec<u8>> {
        oqs::init();
        let kem = oqs_kem_for_level(level)?;
        let sk = kem
            .secret_key_from_bytes(&secret_key.key)
            .ok_or_else(|| PqcError::InvalidKey("Invalid ML-KEM secret key length".into()))?;
        let ct = kem
            .ciphertext_from_bytes(&ciphertext.ciphertext)
            .ok_or_else(|| PqcError::InvalidParameter("Invalid ML-KEM ciphertext length".into()))?;
        let ss = kem
            .decapsulate(sk, ct)
            .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;
        Ok(ss.into_vec())
    }
}

#[cfg(feature = "real-crypto")]
fn oqs_kem_for_level(level: KyberLevel) -> PqcResult<kem::Kem> {
    use kem::Algorithm;
    let alg = match level {
        KyberLevel::Kyber512 => Algorithm::MlKem512,
        KyberLevel::Kyber768 => Algorithm::MlKem768,
        KyberLevel::Kyber1024 => Algorithm::MlKem1024,
    };
    kem::Kem::new(alg).map_err(|e| PqcError::UnsupportedAlgorithm(e.to_string()))
}

fn derive_mock_public_key(level: KyberLevel, secret_key: &[u8]) -> Vec<u8> {
    expand_hash(
        level,
        b"rsrp-mock-mlkem-public",
        &[secret_key],
        level.public_key_size(),
    )
}

fn embed_public_component(level: KyberLevel, secret_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut out = secret_key.to_vec();
    out[..level.public_key_size()].copy_from_slice(public_key);
    out
}

fn derive_mock_shared_secret(level: KyberLevel, public_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    expand_hash(
        level,
        b"rsrp-mock-mlkem-shared-secret",
        &[public_key, ciphertext],
        level.shared_secret_size(),
    )
}

fn expand_hash(level: KyberLevel, domain: &[u8], parts: &[&[u8]], out_len: usize) -> Vec<u8> {
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
    fn test_kyber_key_sizes() {
        let kyber512 = Kyber::new(KyberLevel::Kyber512);
        assert_eq!(kyber512.level.public_key_size(), 800);
        assert_eq!(kyber512.level.secret_key_size(), 1632);
        assert_eq!(kyber512.level.ciphertext_size(), 768);
        assert_eq!(KyberLevel::Kyber512.algorithm_id(), "ML-KEM-512");
    }

    #[test]
    fn test_kyber_kem() {
        let kyber = Kyber::new(KyberLevel::Kyber512);
        let (public_key, secret_key) = kyber.generate_keypair().unwrap();

        let (shared_secret_1, ciphertext) = kyber.encapsulate(&public_key).unwrap();
        let shared_secret_2 = kyber.decapsulate(&secret_key, &ciphertext).unwrap();

        assert_eq!(shared_secret_1, shared_secret_2);
    }

    #[test]
    fn test_kyber_decapsulation_rejects_tampered_ciphertext() {
        let kyber = Kyber::new(KyberLevel::Kyber768);
        let (public_key, secret_key) = kyber.generate_keypair().unwrap();
        let (shared_secret, mut ciphertext) = kyber.encapsulate(&public_key).unwrap();
        ciphertext.ciphertext[0] ^= 0x01;
        let tampered = kyber.decapsulate(&secret_key, &ciphertext).unwrap();
        assert_ne!(shared_secret, tampered);
    }
}
