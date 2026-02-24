//! PQCrypto - Post-Quantum Cryptography for R-SRP Ultra
//! 
//! Provides hybrid cryptographic primitives combining classical algorithms
//! (RSA, ECDSA) with post-quantum algorithms (Dilithium, Kyber) from NIST 2024.
//! 
//! # Security Model
//! 
//! - **Hybrid Signatures**: Ed25519 + Dilithium2/3/5
//! - **Hybrid KEM**: X25519 + Kyber512/768/1024
//! - Both classical and PQ must be broken to compromise the system
//! 
//! # Standards
//! 
//! - NIST FIPS 203: Dilithium (Digital Signatures)
//! - NIST FIPS 204: Kyber (Key Encapsulation)
//! - NIST FIPS 205: SPHINCS+ (Hash-based signatures)

pub mod error;
pub mod signature;
pub mod kem;
pub mod hybrid;

pub use error::PqcError;
pub use signature::{Dilithium, DilithiumLevel};
pub use kem::{Kyber, KyberLevel};
pub use hybrid::{HybridSignature, HybridKEM};

/// PQC Algorithm identifiers for serialization
pub const ALGORITHM_DILITHIUM2: &str = "ML-DSA-44";
pub const ALGORITHM_DILITHIUM3: &str = "ML-DSA-65";
pub const ALGORITHM_DILITHIUM5: &str = "ML-DSA-87";
pub const ALGORITHM_KYBER512: &str = "ML-KEM-768";
pub const ALGORITHM_KYBER768: &str = "ML-KEM-1024";
pub const ALGORITHM_KYBER1024: &str = "ML-KEM-1024";

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
