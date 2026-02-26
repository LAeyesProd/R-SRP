//! Immutable Logging - Append-only audit logs with cryptographic proof
//! 
//! This module implements the immutable audit layer as specified in SPEC_IMMUTABLE_LOGGING.md
//! Features:
//! - Chained hash verification
//! - Hourly Merkle tree roots
//! - Daily publication
//! - TSA timestamps

pub mod log_entry;
pub mod chain;
pub mod merkle_service;
pub mod publication;
pub mod error;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Immutable log service
pub struct ImmutableLog {
    chain: Arc<RwLock<chain::LogChain>>,
    merkle: Arc<RwLock<merkle_service::MerkleService>>,
}

impl ImmutableLog {
    /// Create new immutable log
    pub fn new() -> Self {
        ImmutableLog {
            chain: Arc::new(RwLock::new(chain::LogChain::new())),
            merkle: Arc::new(RwLock::new(merkle_service::MerkleService::new())),
        }
    }
    
    /// Append a new entry
    pub async fn append(&self, entry: log_entry::LogEntry) -> Result<log_entry::LogEntry, error::LogError> {
        // Get current chain state
        let mut chain = self.chain.write().await;
        let entry = chain.append(entry).await?;
        
        // Add to merkle tree
        let mut merkle = self.merkle.write().await;
        merkle.add_entry(entry.clone()).await?;
        
        Ok(entry)
    }
    
    /// Verify chain integrity
    pub async fn verify(&self) -> Result<bool, error::LogError> {
        let chain = self.chain.read().await;
        Ok(chain.verify())
    }

    /// Get number of entries currently stored in the chain.
    pub async fn entry_count(&self) -> usize {
        let chain = self.chain.read().await;
        chain.len()
    }

    /// Get the current chain hash (or genesis hash if empty).
    pub async fn current_hash(&self) -> String {
        let chain = self.chain.read().await;
        chain.current_hash().to_string()
    }
    
    /// Get current hourly root
    pub async fn get_hourly_root(&self) -> Option<merkle_service::HourlyRoot> {
        let merkle = self.merkle.read().await;
        merkle.get_current_root()
    }

    /// Snapshot hourly roots (published roots + current in-progress hour root if present).
    pub async fn hourly_roots_snapshot(&self) -> Vec<merkle_service::HourlyRoot> {
        let merkle = self.merkle.read().await;
        let mut roots = merkle.get_published_roots().to_vec();
        if let Some(current) = merkle.get_current_root() {
            let exists = roots
                .iter()
                .any(|r| r.hour == current.hour && r.root_hash == current.root_hash);
            if !exists {
                roots.push(current);
            }
        }
        roots
    }
    
    /// Generate chain proof for an entry
    pub async fn get_chain_proof(&self, entry_id: &str) -> Option<chain::ChainProof> {
        let chain = self.chain.read().await;
        let entry = chain.get_entry(entry_id)?.clone();
        let mut proof = chain.generate_proof(entry_id)?;
        drop(chain);

        let merkle = self.merkle.read().await;
        let merkle_proof = merkle.generate_proof(entry_id, &entry);
        proof.attach_merkle_proof(merkle_proof);
        Some(proof)
    }
}

impl Default for ImmutableLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for immutable logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Hash algorithm
    pub hash_algorithm: String,
    /// Hourly publication enabled
    pub hourly_publication: bool,
    /// Daily publication enabled
    pub daily_publication: bool,
    /// TSA server URL
    pub tsa_url: Option<String>,
    /// Blockchain enabled
    pub blockchain_enabled: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            hash_algorithm: "SHA256".to_string(),
            hourly_publication: true,
            daily_publication: true,
            tsa_url: None,
            blockchain_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = LogConfig::default();
        assert_eq!(config.hash_algorithm, "SHA256");
        assert!(config.hourly_publication);
    }
    
    #[tokio::test]
    async fn test_append_entry() {
        let log = ImmutableLog::new();
        
        let entry = log_entry::LogEntry::new(
            log_entry::EventType::AccountQuery,
            "agent-001".to_string(),
            "org-001".to_string(),
        );
        
        let result = log.append(entry).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_chain_stats() {
        let log = ImmutableLog::new();
        assert_eq!(log.entry_count().await, 0);
        assert_eq!(log.current_hash().await.len(), 64);
    }

    #[tokio::test]
    async fn test_hourly_roots_snapshot_includes_current_root() {
        let log = ImmutableLog::new();
        let entry = log_entry::LogEntry::new(
            log_entry::EventType::AccountQuery,
            "agent-001".to_string(),
            "org-001".to_string(),
        );
        log.append(entry).await.expect("append");

        let roots = log.hourly_roots_snapshot().await;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].entry_count, 1);
    }
}
