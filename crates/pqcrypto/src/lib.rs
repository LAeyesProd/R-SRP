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
//! - NIST FIPS 203: ML-KEM (Key Encapsulation)
//! - NIST FIPS 204: ML-DSA (Digital Signatures)
//! - NIST FIPS 205: SLH-DSA (Hash-based signatures)

#[cfg(all(feature = "mock-crypto", feature = "real-crypto"))]
compile_error!("Enable exactly one of `mock-crypto` or `real-crypto` for rsrp-pqcrypto.");

#[cfg(all(feature = "production", feature = "mock-crypto"))]
compile_error!("`production` cannot be combined with `mock-crypto` in rsrp-pqcrypto.");

#[cfg(all(feature = "production", not(feature = "real-crypto")))]
compile_error!("`production` requires `real-crypto` in rsrp-pqcrypto.");

#[cfg(all(
    feature = "production",
    any(
        not(feature = "kyber768"),
        not(feature = "dilithium3"),
        feature = "kyber512",
        feature = "kyber1024",
        feature = "dilithium2",
        feature = "dilithium5"
    )
))]
compile_error!(
    "`production` freezes algorithms to ML-KEM-768 and ML-DSA-65 only in rsrp-pqcrypto."
);

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

/// Frozen production default for signatures.
pub const PRODUCTION_DEFAULT_DILITHIUM_LEVEL: DilithiumLevel = DilithiumLevel::Dilithium3;
/// Frozen production default for KEM.
pub const PRODUCTION_DEFAULT_KYBER_LEVEL: KyberLevel = KyberLevel::Kyber768;

/// Runtime hardening checks for production deployments.
///
/// In `production` builds:
/// - debug/trace logging levels are rejected,
/// - disabling hybrid mode via env is rejected.
pub fn validate_runtime_security_config() -> Result<(), PqcError> {
    #[cfg(feature = "production")]
    {
        if let Ok(level) = std::env::var("RUST_LOG") {
            let level = level.to_ascii_lowercase();
            if level.contains("debug") || level.contains("trace") {
                return Err(PqcError::InvalidParameter(
                    "RUST_LOG debug/trace is forbidden in production-hardening mode".into(),
                ));
            }
        }

        if let Ok(flag) = std::env::var("RSRP_HYBRID_REQUIRED") {
            let flag = flag.to_ascii_lowercase();
            if matches!(flag.as_str(), "0" | "false" | "no" | "off") {
                return Err(PqcError::InvalidParameter(
                    "RSRP_HYBRID_REQUIRED cannot be disabled in production-hardening mode".into(),
                ));
            }
        }
    }

    Ok(())
}
