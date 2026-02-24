//! PQCrypto Error Types

use thiserror::Error;

/// Result type for PQCrypto operations
pub type PqcResult<T> = Result<T, PqcError>;

/// Error types for post-quantum cryptography
#[derive(Error, Debug)]
pub enum PqcError {
    /// Algorithm not supported
    #[error("Algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),
    
    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    
    /// Invalid signature format
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
    
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    /// Encryption/Encapsulation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),
    
    /// Hybrid composition failed
    #[error("Hybrid composition failed: {0}")]
    HybridFailed(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// liboqs not available
    #[error("liboqs library not available")]
    LiboqsNotAvailable,
    
    /// Random number generation failed
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    
    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

impl serde::Serialize for PqcError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
