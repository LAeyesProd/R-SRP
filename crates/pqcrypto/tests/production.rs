//! These tests must execute against liboqs, not the unit-test mock fallback.
#![cfg(feature = "production")]

use pqcrypto::{
    Dilithium, DilithiumLevel, Kyber, KyberLevel, PRODUCTION_DEFAULT_DILITHIUM_LEVEL,
    PRODUCTION_DEFAULT_KYBER_LEVEL,
};

#[test]
fn production_uses_oqs_for_frozen_algorithms() {
    let signer = Dilithium::new(PRODUCTION_DEFAULT_DILITHIUM_LEVEL);
    let kem = Kyber::new(PRODUCTION_DEFAULT_KYBER_LEVEL);
    assert_eq!(signer.backend_id(), "oqs");
    assert_eq!(kem.backend_id(), "oqs");

    let (public, secret) = signer.generate_keypair().unwrap();
    assert_eq!(public.level.algorithm_id(), "ML-DSA-65");
    assert_eq!(public.key.len(), 1952);
    let signature = signer.sign(&secret, b"release evidence").unwrap();
    assert_eq!(signature.signature.len(), 3309);
    assert!(signer
        .verify(&public, b"release evidence", &signature)
        .unwrap());
    assert!(!signer
        .verify(&public, b"tampered evidence", &signature)
        .unwrap());
    let (wrong_public, _) = signer.generate_keypair().unwrap();
    assert!(!signer
        .verify(&wrong_public, b"release evidence", &signature)
        .unwrap());
    let mut malformed = signature.clone();
    malformed.signature.clear();
    assert!(!matches!(
        signer.verify(&public, b"release evidence", &malformed),
        Ok(true)
    ));

    let (public, secret) = kem.generate_keypair().unwrap();
    assert_eq!(public.level.algorithm_id(), "ML-KEM-768");
    assert_eq!(public.key.len(), 1184);
    let (shared, mut ciphertext) = kem.encapsulate(&public).unwrap();
    assert_eq!(shared.len(), 32);
    assert_eq!(ciphertext.ciphertext.len(), 1088);
    assert_eq!(shared, kem.decapsulate(&secret, &ciphertext).unwrap());
    let (_, wrong_secret) = kem.generate_keypair().unwrap();
    assert_ne!(shared, kem.decapsulate(&wrong_secret, &ciphertext).unwrap());
    // ML-KEM implicit rejection returns a different secret, not an error.
    ciphertext.ciphertext[0] ^= 1;
    assert_ne!(shared, kem.decapsulate(&secret, &ciphertext).unwrap());
    ciphertext.ciphertext.clear();
    assert!(kem.decapsulate(&secret, &ciphertext).is_err());
}

#[test]
fn production_rejects_non_frozen_levels() {
    for level in [DilithiumLevel::Dilithium2, DilithiumLevel::Dilithium5] {
        assert!(std::panic::catch_unwind(|| Dilithium::new(level)).is_err());
    }
    for level in [KyberLevel::Kyber512, KyberLevel::Kyber1024] {
        assert!(std::panic::catch_unwind(|| Kyber::new(level)).is_err());
    }
}
