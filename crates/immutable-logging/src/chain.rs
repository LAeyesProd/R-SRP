//! Log Chain - Append-only linked list with hash chaining

use crate::error::LogError;
use crate::log_entry::LogEntry;
use crate::merkle_service::{self, MerkleProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Genesis hash (initial chain hash)
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const CHAIN_PROOF_LEAF_PREFIX: u8 = 0x02;
const CHAIN_PROOF_NODE_PREFIX: u8 = 0x03;

/// Chain proof for cryptographic verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProof {
    pub target_entry_id: String,
    pub target_index: usize,
    pub chain_length: usize,
    pub chain_head_hash: String,
    pub target_entry: LogEntry,
    pub target_entry_hash: String,
    pub chain_root_hash: String,
    pub target_membership_proof: Vec<ChainProofPathStep>,
    pub head_membership_proof: Vec<ChainProofPathStep>,
    pub merkle_proof: Option<MerkleProof>,
}

/// Merkle path element for compact chain proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofPathStep {
    pub side: String, // "left" or "right"
    pub hash: String,
}

impl ChainProof {
    pub fn attach_merkle_proof(&mut self, proof: Option<MerkleProof>) {
        self.merkle_proof = proof;
    }
}

/// Log chain state
pub struct LogChain {
    entries: Vec<LogEntry>,
    current_hash: String,
    entry_index: std::collections::HashMap<String, usize>,
}

impl LogChain {
    /// Create new chain with genesis block
    pub fn new() -> Self {
        LogChain {
            entries: Vec::new(),
            current_hash: GENESIS_HASH.to_string(),
            entry_index: std::collections::HashMap::new(),
        }
    }

    /// Append entry to chain
    pub async fn append(&mut self, entry: LogEntry) -> Result<LogEntry, LogError> {
        let entry = entry.commit_with_previous_hash(&self.current_hash)?;
        let new_hash = entry.compute_hash(&self.current_hash)?;

        let index = self.entries.len();
        self.entry_index.insert(entry.entry_id().to_string(), index);
        self.entries.push(entry.clone());
        self.current_hash = new_hash;

        Ok(entry)
    }

    /// Append an already-committed entry (WAL replay path).
    pub async fn append_committed(&mut self, entry: LogEntry) -> Result<(), LogError> {
        if !entry.verify_content_hash() {
            return Err(LogError::ChainError(
                "WAL replay rejected entry with invalid content hash".to_string(),
            ));
        }
        if entry.previous_entry_hash() != self.current_hash {
            return Err(LogError::ChainError(format!(
                "WAL replay previous hash mismatch: expected {}, got {}",
                self.current_hash,
                entry.previous_entry_hash()
            )));
        }

        let new_hash = entry.compute_hash(&self.current_hash)?;
        let index = self.entries.len();
        self.entry_index.insert(entry.entry_id().to_string(), index);
        self.entries.push(entry);
        self.current_hash = new_hash;
        Ok(())
    }

    /// Verify chain integrity
    pub fn verify(&self) -> bool {
        let mut previous_hash = GENESIS_HASH.to_string();
        for entry in &self.entries {
            if !entry.verify_content_hash() {
                return false;
            }
            if entry.previous_entry_hash() != previous_hash {
                return false;
            }

            let computed = match entry.compute_hash(&previous_hash) {
                Ok(v) => v,
                Err(_) => return false,
            };
            previous_hash = computed;
        }

        previous_hash == self.current_hash
    }

    pub fn get_entry(&self, entry_id: &str) -> Option<&LogEntry> {
        self.entry_index
            .get(entry_id)
            .and_then(|idx| self.entries.get(*idx))
    }

    /// Generate a compact inclusion proof for an entry.
    ///
    /// The proof size is O(log n):
    /// - one Merkle path proving target entry hash membership in the chain root
    /// - one Merkle path proving chain head hash membership in the same root
    pub fn generate_proof(&self, entry_id: &str) -> Option<ChainProof> {
        let &target_index = self.entry_index.get(entry_id)?;
        if target_index >= self.entries.len() {
            return None;
        }

        let entry_hashes = self.compute_entry_hashes()?;
        let chain_length = entry_hashes.len();
        if chain_length == 0 {
            return None;
        }

        let target_entry = self.entries.get(target_index)?.clone();
        let target_entry_hash = entry_hashes.get(target_index)?.clone();
        let head_index = chain_length - 1;
        let head_hash = entry_hashes.get(head_index)?;
        if head_hash != &self.current_hash {
            return None;
        }

        let leaves = entry_hashes
            .iter()
            .map(|h| Self::hex_decode(h).map(|bytes| Self::hash_chain_leaf(&bytes)))
            .collect::<Option<Vec<_>>>()?;
        let chain_root_hash = Self::hex_encode(&Self::build_merkle_root(&leaves));
        let target_membership_proof = Self::build_merkle_path(&leaves, target_index)?;
        let head_membership_proof = Self::build_merkle_path(&leaves, head_index)?;

        Some(ChainProof {
            target_entry_id: entry_id.to_string(),
            target_index,
            chain_length,
            chain_head_hash: self.current_hash.clone(),
            target_entry,
            target_entry_hash,
            chain_root_hash,
            target_membership_proof,
            head_membership_proof,
            merkle_proof: None,
        })
    }

    fn compute_entry_hashes(&self) -> Option<Vec<String>> {
        let mut hashes = Vec::with_capacity(self.entries.len());
        let mut previous_hash = GENESIS_HASH.to_string();
        for entry in &self.entries {
            if !entry.verify_content_hash() {
                return None;
            }
            if entry.previous_entry_hash() != previous_hash {
                return None;
            }
            let entry_hash = entry.compute_hash(&previous_hash).ok()?;
            previous_hash = entry_hash.clone();
            hashes.push(entry_hash);
        }

        if previous_hash != self.current_hash {
            return None;
        }

        Some(hashes)
    }

    fn hash_chain_leaf(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update([CHAIN_PROOF_LEAF_PREFIX]);
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn hash_chain_node(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update([CHAIN_PROOF_NODE_PREFIX]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
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
            next.push(Self::hash_chain_node(left, right));
        }
        next
    }

    fn build_merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![0u8; 32];
        }
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = Self::next_level(&level);
        }
        level[0].clone()
    }

    fn build_merkle_path(leaves: &[Vec<u8>], mut index: usize) -> Option<Vec<ChainProofPathStep>> {
        if leaves.is_empty() || index >= leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut level = leaves.to_vec();

        while level.len() > 1 {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right {
                index - 1
            } else {
                (index + 1).min(level.len() - 1)
            };
            path.push(ChainProofPathStep {
                side: if is_right {
                    "left".to_string()
                } else {
                    "right".to_string()
                },
                hash: Self::hex_encode(&level[sibling_index]),
            });
            level = Self::next_level(&level);
            index /= 2;
        }

        Some(path)
    }

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

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get current hash
    pub fn current_hash(&self) -> &str {
        &self.current_hash
    }
}

impl Default for LogChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify chain proof using compact O(log n) membership paths and optional Merkle proof.
pub fn verify_chain_proof(proof: &ChainProof) -> bool {
    if proof.chain_length == 0 || proof.target_index >= proof.chain_length {
        return false;
    }
    if proof.target_entry.entry_id() != proof.target_entry_id {
        return false;
    }
    if proof.chain_head_hash.len() != 64 || proof.target_entry_hash.len() != 64 {
        return false;
    }
    if !proof.target_entry.verify_content_hash() {
        return false;
    }

    let target_entry_hash = match proof
        .target_entry
        .compute_hash(proof.target_entry.previous_entry_hash())
    {
        Ok(v) => v,
        Err(_) => return false,
    };
    if target_entry_hash != proof.target_entry_hash {
        return false;
    }

    if !verify_compact_membership(
        &proof.target_entry_hash,
        &proof.target_membership_proof,
        &proof.chain_root_hash,
    ) {
        return false;
    }

    if !verify_compact_membership(
        &proof.chain_head_hash,
        &proof.head_membership_proof,
        &proof.chain_root_hash,
    ) {
        return false;
    }

    if let Some(merkle) = &proof.merkle_proof {
        if merkle.entry_id != proof.target_entry_id {
            return false;
        }
        if !merkle_service::verify_proof(merkle) {
            return false;
        }
    }

    true
}

fn verify_compact_membership(
    entry_hash_hex: &str,
    path: &[ChainProofPathStep],
    expected_root_hex: &str,
) -> bool {
    let entry_hash = match LogChain::hex_decode(entry_hash_hex) {
        Some(v) => v,
        None => return false,
    };
    let mut current = LogChain::hash_chain_leaf(&entry_hash);

    for step in path {
        let sibling = match LogChain::hex_decode(&step.hash) {
            Some(v) => v,
            None => return false,
        };
        match step.side.as_str() {
            "left" => current = LogChain::hash_chain_node(&sibling, &current),
            "right" => current = LogChain::hash_chain_node(&current, &sibling),
            _ => return false,
        }
    }

    LogChain::hex_encode(&current) == expected_root_hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entry::EventType;

    #[test]
    fn test_genesis_hash() {
        assert_eq!(GENESIS_HASH.len(), 64);
    }

    #[tokio::test]
    async fn test_append_entry() {
        let mut chain = LogChain::new();
        let entry = LogEntry::new(
            EventType::AccountQuery,
            "AGENT_001".to_string(),
            "DGFiP".to_string(),
        )
        .unwrap();

        let result = chain.append(entry).await;
        assert!(result.is_ok());
        assert!(chain.verify());
    }

    #[tokio::test]
    async fn test_chain_proof_detects_tampering() {
        let mut chain = LogChain::new();
        let e1 = chain
            .append(
                LogEntry::new(
                    EventType::AuthSuccess,
                    "AGENT_001".to_string(),
                    "DGFiP".to_string(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let _e2 = chain
            .append(
                LogEntry::new(
                    EventType::DataAccess,
                    "AGENT_002".to_string(),
                    "DGFiP".to_string(),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let mut proof = chain.generate_proof(e1.entry_id()).unwrap();
        assert!(verify_chain_proof(&proof));

        proof.target_entry_hash = "0".repeat(64);
        assert!(!verify_chain_proof(&proof));
    }

    #[tokio::test]
    async fn test_chain_proof_is_compact_logarithmic() {
        let mut chain = LogChain::new();
        let mut target_id = String::new();
        let n = 64usize;

        for i in 0..n {
            let entry = chain
                .append(
                    LogEntry::new(
                        EventType::DataAccess,
                        format!("AGENT_{i:03}"),
                        "DGFiP".to_string(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            if i == 17 {
                target_id = entry.entry_id().to_string();
            }
        }

        let proof = chain.generate_proof(&target_id).unwrap();
        assert!(verify_chain_proof(&proof));

        let max_depth = (usize::BITS - (n - 1).leading_zeros()) as usize;
        assert!(proof.target_membership_proof.len() <= max_depth);
        assert!(proof.head_membership_proof.len() <= max_depth);
    }

    #[tokio::test]
    async fn test_chain_proof_detects_path_tampering() {
        let mut chain = LogChain::new();
        let e1 = chain
            .append(
                LogEntry::new(
                    EventType::AuthSuccess,
                    "AGENT_001".to_string(),
                    "DGFiP".to_string(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let _e2 = chain
            .append(
                LogEntry::new(
                    EventType::DataAccess,
                    "AGENT_002".to_string(),
                    "DGFiP".to_string(),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let mut proof = chain.generate_proof(e1.entry_id()).unwrap();
        assert!(verify_chain_proof(&proof));

        if let Some(first) = proof.target_membership_proof.first_mut() {
            first.hash = "f".repeat(64);
        } else {
            proof.chain_root_hash = "e".repeat(64);
        }
        assert!(!verify_chain_proof(&proof));
    }
}
