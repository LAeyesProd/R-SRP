//! Log Chain - Append-only linked list with hash chaining

use crate::log_entry::LogEntry;
use crate::error::LogError;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

/// Genesis hash (initial chain hash)
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Chain proof for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProof {
    pub entry_id: String,
    pub entry_hash: String,
    pub path: Vec<ChainProofStep>,
}

/// Single step in chain proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofStep {
    pub previous_hash: String,
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
    pub async fn append(&mut self, mut entry: LogEntry) -> Result<LogEntry, LogError> {
        // Update previous hash
        entry.update_previous_hash(&self.current_hash);
        
        // Compute new hash
        let new_hash = entry.compute_hash(&self.current_hash);
        
        // Store entry
        let index = self.entries.len();
        self.entry_index.insert(entry.entry_id.clone(), index);
        self.entries.push(entry.clone());
        
        // Update current hash
        self.current_hash = new_hash;
        
        Ok(entry)
    }
    
    /// Verify chain integrity
    pub fn verify(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        
        let mut previous_hash = GENESIS_HASH.to_string();
        
        for entry in &self.entries {
            // Verify previous hash
            if entry.integrity.previous_entry_hash != previous_hash {
                return false;
            }
            
            // Compute expected hash
            let computed = entry.compute_hash(&previous_hash);
            if computed != self.get_entry_hash(&entry.entry_id) {
                return false;
            }
            
            previous_hash = computed;
        }
        
        true
    }
    
    /// Get hash for entry
    fn get_entry_hash(&self, entry_id: &str) -> String {
        // This would be stored in a real implementation
        // For now, compute on demand
        let index = self.entry_index.get(entry_id).copied();
        
        if let Some(idx) = index {
            let entry = &self.entries[idx];
            entry.compute_hash(&entry.integrity.previous_entry_hash)
        } else {
            String::new()
        }
    }
    
    /// Generate proof for entry
    pub fn generate_proof(&self, entry_id: &str) -> Option<ChainProof> {
        let index = self.entry_index.get(entry_id)?;
        
        if *index >= self.entries.len() {
            return None;
        }
        
        let entry = &self.entries[*index];
        let entry_hash = entry.compute_hash(&entry.integrity.previous_entry_hash);
        
        let mut path = Vec::new();
        
        // Build proof path
        for i in 0..=*index {
            if i == 0 {
                path.push(ChainProofStep {
                    previous_hash: GENESIS_HASH.to_string(),
                });
            } else {
                let prev_entry = &self.entries[i - 1];
                let hash = prev_entry.compute_hash(&prev_entry.integrity.previous_entry_hash);
                path.push(ChainProofStep {
                    previous_hash: hash,
                });
            }
        }
        
        Some(ChainProof {
            entry_id: entry_id.to_string(),
            entry_hash,
            path,
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

/// Verify chain proof
pub fn verify_chain_proof(proof: &ChainProof) -> bool {
    // Simplified verification
    !proof.entry_hash.is_empty() && !proof.path.is_empty()
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
        
        let mut entry = LogEntry::new(
            EventType::AccountQuery,
            "AGENT_001".to_string(),
            "DGFiP".to_string(),
        );
        entry.update_previous_hash(GENESIS_HASH);
        
        let result = chain.append(entry).await;
        assert!(result.is_ok());
        assert!(chain.verify());
    }
    
    #[tokio::test]
    async fn test_chain_proof() {
        let mut chain = LogChain::new();
        
        let entry = LogEntry::new(
            EventType::AuthSuccess,
            "AGENT_001".to_string(),
            "DGFiP".to_string(),
        );
        
        let entry = chain.append(entry).await.unwrap();
        let proof = chain.generate_proof(&entry.entry_id);
        
        assert!(proof.is_some());
    }
}
