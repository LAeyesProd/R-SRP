//! Merkle Service - Hourly Merkle tree root generation

use crate::log_entry::LogEntry;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use chrono::Utc;

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
    pub side: String,  // "left" or "right"
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
    /// Current hour entries
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
    pub async fn add_entry(&mut self, entry: LogEntry) {
        // Check if new hour
        let current = Self::get_current_hour();
        if current != self.current_hour {
            // Publish previous hour root
            self.publish_current_root();
            self.entries.clear();
            self.current_hour = current;
        }
        
        // Hash entry and add to list
        let entry_json = serde_json::to_vec(&entry).unwrap_or_default();
        let hash = Self::hash_entry(&entry_json);
        self.entries.push(hash);
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
    
    /// Build Merkle tree
    fn build_tree(&self, leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![0u8; 32];
        }
        
        if leaves.len() == 1 {
            return leaves[0].clone();
        }
        
        let mut current = leaves.to_vec();
        
        while current.len() > 1 {
            let mut next = Vec::new();
            
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    let mut combined = chunk[0].clone();
                    combined.extend_from_slice(&chunk[1]);
                    let hash = Self::hash_entry(&combined);
                    next.push(hash);
                } else {
                    // Odd element - hash with itself
                    let mut combined = chunk[0].clone();
                    combined.extend_from_slice(&chunk[0]);
                    let hash = Self::hash_entry(&combined);
                    next.push(hash);
                }
            }
            
            current = next;
        }
        
        current[0].clone()
    }
    
    /// Generate proof for entry
    pub fn generate_proof(&self, entry_id: &str, entry_data: &LogEntry) -> Option<MerkleProof> {
        let entry_json = serde_json::to_vec(entry_data).ok()?;
        let leaf_hash = Self::hex_encode(&Self::hash_entry(&entry_json));
        
        let root = self.get_current_root()?;
        
        // Build proof path
        let proof = self.build_proof_path(&self.entries)?;
        
        Some(MerkleProof {
            entry_id: entry_id.to_string(),
            leaf_hash,
            root_hash: root.root_hash,
            proof,
        })
    }
    
    /// Build proof path
    fn build_proof_path(&self, _entries: &[Vec<u8>]) -> Option<Vec<MerkleProofStep>> {
        // Simplified - would need index to build proper path
        Some(Vec::new())
    }
    
    /// Hex encode
    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entry::EventType;
    
    #[test]
    fn test_hourly_root() {
        let mut service = MerkleService::new();
        
        let entry = LogEntry::new(
            EventType::AccountQuery,
            "AGENT_001".to_string(),
            "DGFiP".to_string(),
        );
        
        // Would need runtime to add entry
        let root = service.get_current_root();
        assert!(root.is_none()); // Empty
    }
    
    #[test]
    fn test_hex_encode() {
        let data = b"test";
        let encoded = MerkleService::hex_encode(data);
        assert_eq!(encoded.len(), 8);
    }
}
