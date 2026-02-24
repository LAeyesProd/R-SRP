//! Publication - Daily audit publication

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Daily audit publication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyPublication {
    /// Publication date
    pub date: String,
    /// Root hash of all hourly roots
    pub root_hash: String,
    /// Total entry count
    pub entry_count: u64,
    /// Hourly root hashes
    pub hourly_roots: Vec<String>,
    /// Previous day root (for chaining)
    pub previous_day_root: String,
    /// Creation timestamp
    pub created_at: String,
    /// Signature
    pub signature: Option<PublicationSignature>,
    /// TSA timestamp
    pub tsa_timestamp: Option<TsaTimestamp>,
}

/// Publication signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationSignature {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

/// TSA timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaTimestamp {
    pub tsa_url: String,
    pub timestamp: String,
    pub token: String,
}

/// Publication service
pub struct PublicationService {
    /// Previous day root
    previous_day_root: Option<String>,
}

impl PublicationService {
    /// Create new publication service
    pub fn new() -> Self {
        PublicationService {
            previous_day_root: None,
        }
    }
    
    /// Create daily publication
    pub fn create_daily_publication(
        &self,
        hourly_roots: &[String],
        entry_count: u64,
    ) -> DailyPublication {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let previous = self.previous_day_root.clone().unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });
        
        // Compute root hash of all hourly roots
        let root_hash = Self::compute_merkle_root(hourly_roots);
        
        DailyPublication {
            date,
            root_hash,
            entry_count,
            hourly_roots: hourly_roots.to_vec(),
            previous_day_root: previous,
            created_at: Utc::now().to_rfc3339(),
            signature: None,
            tsa_timestamp: None,
        }
    }
    
    /// Compute merkle root from list of hashes
    fn compute_merkle_root(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }
        
        use sha2::{Sha256, Digest};
        
        let mut current: Vec<String> = hashes.to_vec();
        
        while current.len() > 1 {
            let mut next = Vec::new();
            
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(chunk[0].as_bytes());
                    hasher.update(chunk[1].as_bytes());
                    next.push(format!("{:x}", hasher.finalize()));
                } else {
                    next.push(chunk[0].clone());
                }
            }
            
            current = next;
        }
        
        current[0].clone()
    }
    
    /// Sign publication
    pub fn sign_publication(&mut self, publication: &mut DailyPublication, signature: &[u8]) {
        publication.signature = Some(PublicationSignature {
            algorithm: "RSA-PSS-SHA256".to_string(),
            key_id: "rnbc-audit-sig-2026".to_string(),
            value: base64_encode(signature),
        });
        
        // Store previous day root for chaining
        self.previous_day_root = Some(publication.root_hash.clone());
    }
    
    /// Add TSA timestamp
    pub fn add_tsa_timestamp(&mut self, publication: &mut DailyPublication, tsa_url: &str) {
        publication.tsa_timestamp = Some(TsaTimestamp {
            tsa_url: tsa_url.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            token: "placeholder".to_string(), // Would be real TSA token
        });
    }
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_daily_publication() {
        let service = PublicationService::new();
        
        let hourly_roots = vec![
            "hash1".to_string