//! Hashing primitives - SHA-256, SHA-512, BLAKE3

use crate::{CryptoError, HashAlgorithm, Result};
use digest::Digest;

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-512 hash
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute BLAKE3 hash (high performance)
pub fn blake3(data: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Compute hash using specified algorithm
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(sha256(data)),
        HashAlgorithm::Sha512 => Ok(sha512(data)),
        HashAlgorithm::Blake3 => Ok(blake3(data)),
    }
}

/// Hash data and return hex string
pub fn hash_hex(data: &[u8], algorithm: HashAlgorithm) -> Result<String> {
    let hash = hash(data, algorithm)?;
    Ok(hex_encode(&hash))
}

/// Encode bytes to hex
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex to bytes
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(CryptoError::HashError("Invalid hex string".to_string()));
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| CryptoError::HashError("Invalid hex".to_string()))
        })
        .collect()
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 supports arbitrary key sizes");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compute hash of multiple data chunks (for Merkle tree)
pub fn hash_concat(data: &[&[u8]], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            for d in data {
                h.update(d);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut h = sha2::Sha512::new();
            for d in data {
                h.update(d);
            }
            Ok(h.finalize().to_vec())
        }
        HashAlgorithm::Blake3 => {
            let mut h = blake3::Hasher::new();
            for d in data {
                h.update(d);
            }
            Ok(h.finalize().as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha512() {
        let data = b"hello world";
        let hash = sha512(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake3() {
        let data = b"hello world";
        let hash = blake3(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hex_encode_decode() {
        let original = b"test data";
        let encoded = hex_encode(original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"message";
        let hmac = hmac_sha256(key, data);
        assert_eq!(hmac.len(), 32);
    }
}
