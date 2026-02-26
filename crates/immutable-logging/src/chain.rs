//! Log Chain - Append-only linked list with hash chaining

use crate::error::LogError;
use crate::log_entry::LogEntry;
use crate::merkle_service::{self, MerkleProof};
use serde::{Deserialize, Serialize};

/// Genesis hash (initial chain hash)
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Chain proof for cryptographic verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProof {
    pub target_entry_id: String,
    pub target_index: usize,
    pub chain_head_hash: String,
    pub steps: Vec<ChainProofStep>,
    pub merkle_proof: Option<MerkleProof>,
}

/// Single step in chain proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofStep {
    pub entry_hash: String,
    pub entry: LogEntry,
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

    /// Generate proof for entry (includes all steps up to current head).
    pub fn generate_proof(&self, entry_id: &str) -> Option<ChainProof> {
        let &target_index = self.entry_index.get(entry_id)?;
        if target_index >= self.entries.len() {
            return None;
        }

        let mut steps = Vec::with_capacity(self.entries.len());
        let mut previous_hash = GENESIS_HASH.to_string();
        for entry in &self.entries {
            let entry_hash = entry.compute_hash(&previous_hash).ok()?;
            steps.push(ChainProofStep {
                entry_hash: entry_hash.clone(),
                entry: entry.clone(),
            });
            previous_hash = entry_hash;
        }

        Some(ChainProof {
            target_entry_id: entry_id.to_string(),
            target_index,
            chain_head_hash: self.current_hash.clone(),
            steps,
            merkle_proof: None,
        })
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

/// Verify chain proof by recomputing the hash chain and optional Merkle proof.
pub fn verify_chain_proof(proof: &ChainProof) -> bool {
    if proof.steps.is_empty() || proof.target_index >= proof.steps.len() {
        return false;
    }
    if proof.steps[proof.target_index].entry.entry_id() != proof.target_entry_id {
        return false;
    }

    let mut previous_hash = GENESIS_HASH.to_string();
    for step in &proof.steps {
        if !step.entry.verify_content_hash() {
            return false;
        }
        if step.entry.previous_entry_hash() != previous_hash {
            return false;
        }
        let recomputed = match step.entry.compute_hash(&previous_hash) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if recomputed != step.entry_hash {
            return false;
        }
        previous_hash = recomputed;
    }

    if previous_hash != proof.chain_head_hash {
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
        );

        let result = chain.append(entry).await;
        assert!(result.is_ok());
        assert!(chain.verify());
    }

    #[tokio::test]
    async fn test_chain_proof_detects_tampering() {
        let mut chain = LogChain::new();
        let e1 = chain
            .append(LogEntry::new(
                EventType::AuthSuccess,
                "AGENT_001".to_string(),
                "DGFiP".to_string(),
            ))
            .await
            .unwrap();
        let _e2 = chain
            .append(LogEntry::new(
                EventType::DataAccess,
                "AGENT_002".to_string(),
                "DGFiP".to_string(),
            ))
            .await
            .unwrap();

        let mut proof = chain.generate_proof(e1.entry_id()).unwrap();
        assert!(verify_chain_proof(&proof));

        proof.steps[0].entry_hash = "0".repeat(64);
        assert!(!verify_chain_proof(&proof));
    }
}
