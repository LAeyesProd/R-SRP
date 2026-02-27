//! Immutable Logging Error Module

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LogError {
    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Merkle error: {0}")]
    MerkleError(String),

    #[error("Publication error: {0}")]
    PublicationError(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
