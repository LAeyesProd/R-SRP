//! Crypto Core Error Module

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoCoreError {
    #[error("Hash error: {0}")]
    HashError(String),
    
    #[error("Signature error: {0}")]
    SignatureError(String),
    
    #[error("Key error: {0}")]
    KeyError(String),
    
    #[error("HSM error: {0}")]
    HsmError(String),
    
    #[error("Verification failed")]
    VerificationFailed,
    
    #[error("Invalid key")]
    InvalidKey,
}
