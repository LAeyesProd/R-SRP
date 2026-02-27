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

#[cfg(all(feature = "mock-crypto", feature = "real-crypto"))]
compile_error!("Enable exactly one of `mock-crypto` or `real-crypto` for rsrp-pqcrypto.");

#[cfg(all(not(debug_assertions), not(feature = "real-crypto")))]
compile_error!(
    "Release builds require `real-crypto` for rsrp-pqcrypto (mock backend forbidden in release)."
);

pub mod error;
pub mod hybrid;
pub mod kem;
pub mod signature;

pub use error::PqcError;
pub use hybrid::{HybridKEM, HybridSignature};
#[cfg(feature = "real-crypto")]
pub use kem::OqsKemProvider;
pub use kem::{KemProvider, Kyber, KyberLevel, MockKemProvider};
#[cfg(feature = "real-crypto")]
pub use signature::OqsProvider;
pub use signature::{Dilithium, DilithiumLevel, MockProvider, SignatureProvider};

/// PQC Algorithm identifiers for serialization
pub const ALGORITHM_DILITHIUM2: &str = "ML-DSA-44";
pub const ALGORITHM_DILITHIUM3: &str = "ML-DSA-65";
pub const ALGORITHM_DILITHIUM5: &str = "ML-DSA-87";
pub const ALGORITHM_KYBER512: &str = "ML-KEM-512";
pub const ALGORITHM_KYBER768: &str = "ML-KEM-768";
pub const ALGORITHM_KYBER1024: &str = "ML-KEM-1024";

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
