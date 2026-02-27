//! HSM (Hardware Security Module) integration
//!
//! Provides abstraction layer for Thales Luna HSM and other PKCS#11 compatible HSMs

use crate::{CryptoError, KeyMetadata, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM type
    pub hsm_type: HsmType,
    /// Connection string
    pub connection: String,
    /// Slot number
    pub slot: u32,
    /// Key label prefix
    pub key_label_prefix: String,
}

/// HSM type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HsmType {
    /// Thales Luna HSM
    ThalesLuna,
    /// Utimaco HSM
    Utimaco,
    /// AWS CloudHSM
    AwsCloudHsm,
    /// Azure Key Vault HSM
    AzureKeyVault,
    /// Software simulation (testing)
    SoftHSM,
}

impl Default for HsmType {
    fn default() -> Self {
        HsmType::ThalesLuna
    }
}

/// HSM key handle
#[derive(Debug, Clone)]
pub struct HsmKeyHandle {
    pub key_id: String,
    pub slot: u32,
    pub algorithm: String,
}

/// HSM session
pub trait HsmSession: Send {
    /// Sign data with key
    fn sign(&mut self, key_handle: &HsmKeyHandle, data: &[u8]) -> Result<Vec<u8>>;

    /// Verify signature
    fn verify(&mut self, key_handle: &HsmKeyHandle, data: &[u8], signature: &[u8]) -> Result<bool>;

    /// Generate key pair
    fn generate_key_pair(&mut self, algorithm: &str, key_id: &str) -> Result<HsmKeyHandle>;

    /// Import key
    fn import_key(&mut self, key_id: &str, key_data: &[u8]) -> Result<HsmKeyHandle>;

    /// Close session
    fn close(&mut self);
}

/// SoftHSM implementation for testing
pub struct SoftHsm {
    config: HsmConfig,
    keys: std::collections::HashMap<String, Vec<u8>>,
}

impl SoftHsm {
    pub fn new(config: HsmConfig) -> Self {
        SoftHsm {
            config,
            keys: std::collections::HashMap::new(),
        }
    }
}

impl HsmSession for SoftHsm {
    fn sign(&mut self, key_handle: &HsmKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        let key_data = self
            .keys
            .get(&key_handle.key_id)
            .ok_or_else(|| CryptoError::HsmError("Key not found".to_string()))?;
        if key_data.len() != 32 {
            return Err(CryptoError::HsmError(
                "Invalid SoftHSM key size (expected 32-byte Ed25519 seed)".to_string(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(key_data);
        let key =
            crate::signature::Ed25519KeyPair::from_seed(seed, Some(key_handle.key_id.clone()));
        Ok(key.sign(data))
    }

    fn verify(&mut self, key_handle: &HsmKeyHandle, data: &[u8], signature: &[u8]) -> Result<bool> {
        let computed = self.sign(key_handle, data)?;
        Ok(computed == signature)
    }

    fn generate_key_pair(&mut self, algorithm: &str, key_id: &str) -> Result<HsmKeyHandle> {
        let mut key_data = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_data);
        self.keys.insert(key_id.to_string(), key_data);

        Ok(HsmKeyHandle {
            key_id: key_id.to_string(),
            slot: self.config.slot,
            algorithm: algorithm.to_string(),
        })
    }

    fn import_key(&mut self, key_id: &str, key_data: &[u8]) -> Result<HsmKeyHandle> {
        if key_data.len() != 32 {
            return Err(CryptoError::HsmError(
                "SoftHSM import expects a 32-byte Ed25519 seed".to_string(),
            ));
        }
        self.keys.insert(key_id.to_string(), key_data.to_vec());

        Ok(HsmKeyHandle {
            key_id: key_id.to_string(),
            slot: self.config.slot,
            algorithm: "ED25519".to_string(),
        })
    }

    fn close(&mut self) {
        self.keys.clear();
    }
}

/// Create HSM session based on configuration
pub fn create_hsm_session(config: &HsmConfig) -> Result<Box<dyn HsmSession>> {
    if matches!(config.hsm_type, HsmType::SoftHSM) && is_production_environment() {
        return Err(CryptoError::HsmError(
            "SoftHSM is forbidden in production environment".to_string(),
        ));
    }
    match config.hsm_type {
        HsmType::SoftHSM => Ok(Box::new(SoftHsm::new(config.clone()))),
        _ => Err(CryptoError::HsmError(format!(
            "HSM type {:?} not implemented",
            config.hsm_type
        ))),
    }
}

/// HSM-backed signer
pub struct HsmSigner {
    session: Box<dyn HsmSession>,
    key_handle: HsmKeyHandle,
    config: HsmConfig,
}

impl HsmSigner {
    /// Create new HSM signer
    pub fn new(config: HsmConfig, key_id: &str) -> Result<Self> {
        let mut session = create_hsm_session(&config)?;
        let key_handle = session.generate_key_pair("ED25519", key_id)?;

        Ok(HsmSigner {
            session,
            key_handle,
            config,
        })
    }

    /// Sign data
    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.session.sign(&self.key_handle, data)
    }

    /// Verify signature (best-effort depending on HSM backend support)
    pub fn verify(&mut self, data: &[u8], signature: &[u8]) -> Result<bool> {
        self.session.verify(&self.key_handle, data, signature)
    }

    /// Get key metadata
    pub fn metadata(&self) -> KeyMetadata {
        let algorithm = match self.key_handle.algorithm.to_ascii_uppercase().as_str() {
            "ED25519" => crate::SignatureAlgorithm::Ed25519,
            "RSA" | "RSA-PSS" | "RSA-PSS-4096" => crate::SignatureAlgorithm::RsaPss4096,
            _ => crate::SignatureAlgorithm::Ed25519,
        };
        KeyMetadata {
            key_id: self.key_handle.key_id.clone(),
            algorithm,
            created_at: chrono::Utc::now().timestamp(),
            key_type: crate::KeyType::HsmBacked,
            hsm_slot: Some(self.config.slot.to_string()),
        }
    }
}

fn is_production_environment() -> bool {
    [
        std::env::var("ENV").ok(),
        std::env::var("APP_ENV").ok(),
        std::env::var("RUST_ENV").ok(),
    ]
    .into_iter()
    .flatten()
    .any(|v| matches!(v.to_ascii_lowercase().as_str(), "prod" | "production"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soft_hsm() {
        let config = HsmConfig {
            hsm_type: HsmType::SoftHSM,
            connection: "localhost".to_string(),
            slot: 0,
            key_label_prefix: "test".to_string(),
        };

        let mut session = create_hsm_session(&config).unwrap();
        let handle = session.generate_key_pair("RSA", "test-key").unwrap();

        let data = b"test data";
        let signature = session.sign(&handle, data).unwrap();

        assert!(session.verify(&handle, data, &signature).unwrap());
    }

    #[test]
    fn test_hsm_signer_soft_hsm_roundtrip() {
        let config = HsmConfig {
            hsm_type: HsmType::SoftHSM,
            connection: "local://softhsm".to_string(),
            slot: 0,
            key_label_prefix: "audit".to_string(),
        };

        let mut signer = HsmSigner::new(config, "audit-key").unwrap();
        let data = b"daily publication payload";
        let sig = signer.sign(data).unwrap();

        assert!(signer.verify(data, &sig).unwrap());
        assert!(!signer.verify(b"tampered", &sig).unwrap());
    }
}
