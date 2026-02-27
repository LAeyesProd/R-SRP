//! Immutable Logging - Append-only audit logs with cryptographic proof
//!
//! This module implements the immutable audit layer as specified in SPEC_IMMUTABLE_LOGGING.md
//! Features:
//! - Chained hash verification
//! - Hourly Merkle tree roots
//! - Daily publication
//! - TSA timestamps

pub mod chain;
pub mod error;
pub mod log_entry;
pub mod merkle_service;
pub mod publication;

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{io::Write, path::Path, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock};

/// Immutable log service
pub struct ImmutableLog {
    chain: Arc<RwLock<chain::LogChain>>,
    merkle: Arc<RwLock<merkle_service::MerkleService>>,
    wal: Option<Arc<Mutex<WalStore>>>,
}

struct WalStore {
    path: PathBuf,
    signing_key: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalRecord {
    entry: log_entry::LogEntry,
    #[serde(default)]
    signature: Option<String>,
}

impl WalStore {
    fn open(path: PathBuf) -> Result<Self, error::LogError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| error::LogError::PublicationError(e.to_string()))?;
        }
        if !path.exists() {
            std::fs::File::create(&path)
                .map_err(|e| error::LogError::PublicationError(e.to_string()))?;
        }
        let signing_key = std::env::var("IMMUTABLE_LOG_WAL_SIGNING_SECRET")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|secret| derive_wal_signing_key(secret.as_bytes()));
        Ok(Self { path, signing_key })
    }

    fn load_entries(&self) -> Result<Vec<log_entry::LogEntry>, error::LogError> {
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| error::LogError::PublicationError(e.to_string()))?;
        let mut out = Vec::new();
        for (line_no, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<WalRecord>(line) {
                if let Some(signing_key) = &self.signing_key {
                    let signature = record.signature.clone().ok_or_else(|| {
                        error::LogError::PublicationError(format!(
                            "WAL signature missing at line {} (signing is required)",
                            line_no + 1
                        ))
                    })?;
                    let canonical = serde_json::to_string(&record.entry).map_err(|e| {
                        error::LogError::SerializationError(format!(
                            "WAL canonicalization error at line {}: {}",
                            line_no + 1,
                            e
                        ))
                    })?;
                    let expected = wal_entry_signature_hex(signing_key, canonical.as_bytes());
                    if signature != expected {
                        return Err(error::LogError::PublicationError(format!(
                            "WAL signature verification failed at line {}",
                            line_no + 1
                        )));
                    }
                }
                out.push(record.entry);
                continue;
            }

            let entry = serde_json::from_str::<log_entry::LogEntry>(line).map_err(|e| {
                error::LogError::PublicationError(format!(
                    "WAL parse error at line {}: {}",
                    line_no + 1,
                    e
                ))
            })?;
            if self.signing_key.is_some() {
                return Err(error::LogError::PublicationError(format!(
                    "Unsigned WAL line {} is rejected when IMMUTABLE_LOG_WAL_SIGNING_SECRET is set",
                    line_no + 1
                )));
            }
            out.push(entry);
        }
        Ok(out)
    }

    fn append_entry(&mut self, entry: &log_entry::LogEntry) -> Result<(), error::LogError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| error::LogError::PublicationError(e.to_string()))?;
        let encoded = serde_json::to_string(entry)
            .map_err(|e| error::LogError::SerializationError(e.to_string()))?;
        let line = if let Some(signing_key) = &self.signing_key {
            let signature = wal_entry_signature_hex(signing_key, encoded.as_bytes());
            let record = WalRecord {
                entry: entry.clone(),
                signature: Some(signature),
            };
            serde_json::to_string(&record)
                .map_err(|e| error::LogError::SerializationError(e.to_string()))?
        } else {
            encoded
        };
        writeln!(file, "{}", line).map_err(|e| error::LogError::PublicationError(e.to_string()))
    }
}

fn derive_wal_signing_key(secret: &[u8]) -> [u8; 32] {
    let digest = sha2::Sha256::digest(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn wal_entry_signature_hex(key: &[u8; 32], entry: &[u8]) -> String {
    blake3::keyed_hash(key, entry).to_hex().to_string()
}

impl ImmutableLog {
    /// Create new immutable log
    pub fn new() -> Self {
        ImmutableLog {
            chain: Arc::new(RwLock::new(chain::LogChain::new())),
            merkle: Arc::new(RwLock::new(merkle_service::MerkleService::new())),
            wal: None,
        }
    }

    /// Create immutable log backed by an append-only WAL file and replay existing entries on boot.
    pub async fn with_wal_path<P: AsRef<Path>>(path: P) -> Result<Self, error::LogError> {
        let wal = WalStore::open(path.as_ref().to_path_buf())?;
        let entries = wal.load_entries()?;
        let log = ImmutableLog {
            chain: Arc::new(RwLock::new(chain::LogChain::new())),
            merkle: Arc::new(RwLock::new(merkle_service::MerkleService::new())),
            wal: Some(Arc::new(Mutex::new(wal))),
        };

        if !entries.is_empty() {
            let mut chain = log.chain.write().await;
            let mut merkle = log.merkle.write().await;
            for entry in entries {
                chain.append_committed(entry.clone()).await?;
                merkle.add_entry(entry).await?;
            }
        }

        Ok(log)
    }

    /// Append a new entry
    pub async fn append(
        &self,
        entry: log_entry::LogEntry,
    ) -> Result<log_entry::LogEntry, error::LogError> {
        // Get current chain state
        let mut chain = self.chain.write().await;
        let entry = chain.append(entry).await?;

        // Add to merkle tree
        let mut merkle = self.merkle.write().await;
        merkle.add_entry(entry.clone()).await?;

        if let Some(wal) = &self.wal {
            let mut wal = wal.lock().await;
            wal.append_entry(&entry)?;
        }

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
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .expect("env lock")
    }

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
        )
        .unwrap();

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
        )
        .unwrap();
        log.append(entry).await.expect("append");

        let roots = log.hourly_roots_snapshot().await;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].entry_count, 1);
    }

    #[tokio::test]
    async fn test_wal_replay_rebuilds_chain() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wal_path = tmp.path().join("log.wal");

        let log = ImmutableLog::with_wal_path(&wal_path)
            .await
            .expect("wal init");
        let entry = log_entry::LogEntry::new(
            log_entry::EventType::AccountQuery,
            "agent-001".to_string(),
            "org-001".to_string(),
        )
        .unwrap();
        log.append(entry).await.expect("append");
        assert_eq!(log.entry_count().await, 1);
        drop(log);

        let reloaded = ImmutableLog::with_wal_path(&wal_path)
            .await
            .expect("wal reload");
        assert_eq!(reloaded.entry_count().await, 1);
        assert!(reloaded.verify().await.expect("verify"));
    }

    #[tokio::test]
    async fn test_wal_signed_replay_rebuilds_chain() {
        let _guard = env_test_lock();
        let previous = std::env::var("IMMUTABLE_LOG_WAL_SIGNING_SECRET").ok();
        std::env::set_var(
            "IMMUTABLE_LOG_WAL_SIGNING_SECRET",
            "wal-signing-test-secret",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let wal_path = tmp.path().join("log-signed.wal");

        let log = ImmutableLog::with_wal_path(&wal_path)
            .await
            .expect("wal init");
        let entry = log_entry::LogEntry::new(
            log_entry::EventType::AccountQuery,
            "agent-001".to_string(),
            "org-001".to_string(),
        )
        .unwrap();
        log.append(entry).await.expect("append");
        drop(log);

        let reloaded = ImmutableLog::with_wal_path(&wal_path)
            .await
            .expect("wal reload");
        assert_eq!(reloaded.entry_count().await, 1);

        match previous {
            Some(value) => std::env::set_var("IMMUTABLE_LOG_WAL_SIGNING_SECRET", value),
            None => std::env::remove_var("IMMUTABLE_LOG_WAL_SIGNING_SECRET"),
        }
    }

    #[tokio::test]
    async fn test_wal_signed_replay_rejects_tampering() {
        let _guard = env_test_lock();
        let previous = std::env::var("IMMUTABLE_LOG_WAL_SIGNING_SECRET").ok();
        std::env::set_var(
            "IMMUTABLE_LOG_WAL_SIGNING_SECRET",
            "wal-signing-test-secret",
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let wal_path = tmp.path().join("log-tampered.wal");

        let log = ImmutableLog::with_wal_path(&wal_path)
            .await
            .expect("wal init");
        let entry = log_entry::LogEntry::new(
            log_entry::EventType::AccountQuery,
            "agent-001".to_string(),
            "org-001".to_string(),
        )
        .unwrap();
        log.append(entry).await.expect("append");
        drop(log);

        let raw = std::fs::read_to_string(&wal_path).expect("read wal");
        let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
        let mut record: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("parse signed wal line");
        record["signature"] = serde_json::Value::String("00deadbeef".to_string());
        lines[0] = serde_json::to_string(&record).expect("serialize tampered wal line");
        std::fs::write(&wal_path, lines.join("\n")).expect("write wal");

        let reload = ImmutableLog::with_wal_path(&wal_path).await;
        assert!(reload.is_err());

        match previous {
            Some(value) => std::env::set_var("IMMUTABLE_LOG_WAL_SIGNING_SECRET", value),
            None => std::env::remove_var("IMMUTABLE_LOG_WAL_SIGNING_SECRET"),
        }
    }
}
