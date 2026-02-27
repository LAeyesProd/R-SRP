//! Merkle Service - Hourly Merkle tree root generation

use crate::error::LogError;
use crate::log_entry::LogEntry;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hourly root hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyRoot {
    /// Hour identifier (e.g., "2026-02-23T14:00:00Z")
    pub hour: String,
    /// Root hash
    pub root_hash: String,
    /// Number of entries
    pub entry_count: u64,
    /// Timestamp when root was generated
    pub generated_at: i64,
}

/// Merkle proof step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub side: String, // "left" or "right"
    pub hash: String,
}

/// Full Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub entry_id: String,
    pub leaf_hash: String,
    pub root_hash: String,
    pub proof: Vec<MerkleProofStep>,
}

/// Merkle tree service
pub struct MerkleService {
    /// Current hour entries (leaf hashes)
    entries: Vec<Vec<u8>>,
    /// Current hour string
    current_hour: String,
    /// Published hourly roots
    published_roots: Vec<HourlyRoot>,
}

impl MerkleService {
    /// Create new Merkle service
    pub fn new() -> Self {
        MerkleService {
            entries: Vec::new(),
            current_hour: Self::get_current_hour(),
            published_roots: Vec::new(),
        }
    }

    /// Get current hour string
    fn get_current_hour() -> String {
        Utc::now().format("%Y-%m-%dT%H:00:00Z").to_string()
    }

    /// Add entry to current hour
    pub async fn add_entry(&mut self, entry: LogEntry) -> Result<(), LogError> {
        let current = Self::get_current_hour();
        if current != self.current_hour {
            self.publish_current_root();
            self.entries.clear();
            self.current_hour = current;
        }

        let bytes = entry.canonical_entry_bytes()?;
        let hash = Self::hash_entry(&bytes);
        self.entries.push(hash);
        Ok(())
    }

    /// Hash entry data
    fn hash_entry(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Get current root
    pub fn get_current_root(&self) -> Option<HourlyRoot> {
        if self.entries.is_empty() {
            return None;
        }

        let root = self.build_tree(&self.entries);

        Some(HourlyRoot {
            hour: self.current_hour.clone(),
            root_hash: Self::hex_encode(&root),
            entry_count: self.entries.len() as u64,
            generated_at: Utc::now().timestamp(),
        })
    }

    /// Publish current root (for hour transition)
    fn publish_current_root(&mut self) {
        if let Some(root) = self.get_current_root() {
            self.published_roots.push(root);
        }
    }

    /// Build Merkle tree root from leaves
    fn build_tree(&self, leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![0u8; 32];
        }
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = Self::next_level(&level);
        }
        level[0].clone()
    }

    fn next_level(level: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() == 2 {
                &chunk[1]
            } else {
                &chunk[0]
            };
            let mut combined = left.clone();
            combined.extend_from_slice(right);
            next.push(Self::hash_entry(&combined));
        }
        next
    }

    /// Generate proof for entry
    pub fn generate_proof(&self, entry_id: &str, entry_data: &LogEntry) -> Option<MerkleProof> {
        let entry_bytes = entry_data.canonical_entry_bytes().ok()?;
        let leaf_hash_bytes = Self::hash_entry(&entry_bytes);
        let leaf_hash = Self::hex_encode(&leaf_hash_bytes);
        let root = self.get_current_root()?;

        let index = self.entries.iter().position(|h| h == &leaf_hash_bytes)?;
        let proof = self.build_proof_path(&self.entries, index)?;

        Some(MerkleProof {
            entry_id: entry_id.to_string(),
            leaf_hash,
            root_hash: root.root_hash,
            proof,
        })
    }

    /// Build proof path for a leaf index
    fn build_proof_path(
        &self,
        entries: &[Vec<u8>],
        mut index: usize,
    ) -> Option<Vec<MerkleProofStep>> {
        if entries.is_empty() || index >= entries.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut level = entries.to_vec();

        while level.len() > 1 {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right {
                index - 1
            } else {
                (index + 1).min(level.len() - 1)
            };
            let sibling_hash = Self::hex_encode(&level[sibling_index]);
            proof.push(MerkleProofStep {
                side: if is_right {
                    "left".to_string()
                } else {
                    "right".to_string()
                },
                hash: sibling_hash,
            });

            level = Self::next_level(&level);
            index /= 2;
        }

        Some(proof)
    }

    /// Hex encode
    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// Get published roots
    pub fn get_published_roots(&self) -> &[HourlyRoot] {
        &self.published_roots
    }
}

impl Default for MerkleService {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a Merkle proof against the declared root.
pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut current = match MerkleService::hex_decode(&proof.leaf_hash) {
        Some(v) => v,
        None => return false,
    };

    for step in &proof.proof {
        let sibling = match MerkleService::hex_decode(&step.hash) {
            Some(v) => v,
            None => return false,
        };
        let mut combined = Vec::with_capacity(current.len() + sibling.len());
        match step.side.as_str() {
            "left" => {
                combined.extend_from_slice(&sibling);
                combined.extend_from_slice(&current);
            }
            "right" => {
                combined.extend_from_slice(&current);
                combined.extend_from_slice(&sibling);
            }
            _ => return false,
        }
        current = MerkleService::hash_entry(&combined);
    }

    MerkleService::hex_encode(&current) == proof.root_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entry::EventType;

    #[test]
    fn test_hourly_root() {
        let service = MerkleService::new();
        let root = service.get_current_root();
        assert!(root.is_none());
    }

    #[test]
    fn test_hex_encode() {
        let data = b"test";
        let encoded = MerkleService::hex_encode(data);
        assert_eq!(encoded.len(), 8);
    }

    #[tokio::test]
    async fn test_merkle_proof_roundtrip() {
        let mut service = MerkleService::new();
        let e1 = LogEntry::new(EventType::AccountQuery, "a".to_string(), "o".to_string()).unwrap();
        let e2 = LogEntry::new(EventType::AuthSuccess, "b".to_string(), "o".to_string()).unwrap();
        service.add_entry(e1.clone()).await.unwrap();
        service.add_entry(e2.clone()).await.unwrap();

        let proof = service.generate_proof(e2.entry_id(), &e2).unwrap();
        assert!(verify_proof(&proof));
    }
}
