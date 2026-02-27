//! Merkle Tree implementation for hourly audit logs

use crate::hash::hash;
use crate::{CryptoError, HashAlgorithm, Result};
use serde::{Deserialize, Serialize};

const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Merkle tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Node hash
    pub hash: String,
    /// Left child hash (if not leaf)
    pub left: Option<Box<MerkleNode>>,
    /// Right child hash (if not leaf)
    pub right: Option<Box<MerkleNode>>,
    /// Leaf data (if leaf)
    pub leaf: Option<Vec<u8>>,
}

/// Merkle tree root with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleRoot {
    /// Hour identifier (e.g., "2026-02-23T14:00:00Z")
    pub hour: String,
    /// Root hash
    pub root_hash: String,
    /// Number of leaves
    pub leaf_count: u64,
    /// Timestamp of creation
    pub created_at: i64,
    /// Algorithm used
    pub algorithm: HashAlgorithm,
}

/// Merkle tree builder
pub struct MerkleTree {
    algorithm: HashAlgorithm,
    leaves: Vec<Vec<u8>>,
}

impl MerkleTree {
    /// Create new Merkle tree with specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        MerkleTree {
            algorithm,
            leaves: Vec::new(),
        }
    }

    /// Add a leaf
    pub fn add_leaf(&mut self, data: Vec<u8>) {
        let leaf_hash = self.hash_leaf(&data);
        self.leaves.push(leaf_hash);
    }

    /// Build the tree and return root
    pub fn build(&self) -> Option<MerkleRoot> {
        if self.leaves.is_empty() {
            return None;
        }

        let root = self.build_tree(&self.leaves);

        Some(MerkleRoot {
            hour: chrono::Utc::now().format("%Y-%m-%dT%H:00:00Z").to_string(),
            root_hash: hex_encode(&root),
            leaf_count: self.leaves.len() as u64,
            created_at: chrono::Utc::now().timestamp(),
            algorithm: self.algorithm,
        })
    }

    /// Recursively build tree
    fn build_tree(&self, nodes: &[Vec<u8>]) -> Vec<u8> {
        if nodes.is_empty() {
            return vec![0u8; 32]; // Empty hash
        }

        if nodes.len() == 1 {
            return nodes[0].clone();
        }

        let mid = nodes.len().div_ceil(2);
        let left = self.build_tree(&nodes[..mid]);
        let right = self.build_tree(&nodes[mid..]);
        self.hash_node(&left, &right)
    }

    /// Generate proof for a leaf
    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = MerkleProof {
            leaf_index: index,
            leaf_hash: hex_encode(&self.leaves[index]),
            path: Vec::new(),
        };

        self.build_proof(&self.leaves, index, &mut proof.path);

        Some(proof)
    }

    fn build_proof(&self, nodes: &[Vec<u8>], index: usize, path: &mut Vec<MerkleProofStep>) {
        if nodes.len() <= 1 {
            return;
        }

        let mid = nodes.len().div_ceil(2);

        if index < mid {
            // Build leaf-to-root proof ordering: recurse first, then append sibling subtree root.
            self.build_proof(&nodes[..mid], index, path);
            path.push(MerkleProofStep {
                side: "right".to_string(),
                hash: hex_encode(&self.build_tree(&nodes[mid..])),
            });
        } else {
            // Build leaf-to-root proof ordering: recurse first, then append sibling subtree root.
            self.build_proof(&nodes[mid..], index - mid, path);
            path.push(MerkleProofStep {
                side: "left".to_string(),
                hash: hex_encode(&self.build_tree(&nodes[..mid])),
            });
        }
    }

    fn hash_leaf(&self, data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(MERKLE_LEAF_PREFIX);
        payload.extend_from_slice(data);
        hash(&payload, self.algorithm).unwrap_or_default()
    }

    fn hash_node(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + left.len() + right.len());
        payload.push(MERKLE_NODE_PREFIX);
        payload.extend_from_slice(left);
        payload.extend_from_slice(right);
        hash(&payload, self.algorithm).unwrap_or_else(|_| vec![0u8; 32])
    }
}

/// Proof step in Merkle verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub side: String,
    pub hash: String,
}

/// Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: String,
    pub path: Vec<MerkleProofStep>,
}

/// Verify a Merkle proof
pub fn verify_proof(proof: &MerkleProof, root_hash: &str, algorithm: HashAlgorithm) -> bool {
    let mut current_hash = hex_decode(&proof.leaf_hash).unwrap_or_default();

    for step in &proof.path {
        let sibling = hex_decode(&step.hash).unwrap_or_default();

        let mut payload = Vec::with_capacity(1 + sibling.len() + current_hash.len());
        payload.push(MERKLE_NODE_PREFIX);
        if step.side == "left" {
            payload.extend_from_slice(&sibling);
            payload.extend_from_slice(&current_hash);
        } else {
            payload.extend_from_slice(&current_hash);
            payload.extend_from_slice(&sibling);
        }

        current_hash = hash(&payload, algorithm).unwrap_or_default();
    }

    hex_encode(&current_hash) == root_hash
}

/// Encode bytes to hex
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex to bytes
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let mut tree = MerkleTree::new(HashAlgorithm::Sha256);

        tree.add_leaf(b"leaf1".to_vec());
        tree.add_leaf(b"leaf2".to_vec());
        tree.add_leaf(b"leaf3".to_vec());
        tree.add_leaf(b"leaf4".to_vec());

        let root = tree.build().unwrap();
        assert!(!root.root_hash.is_empty());
        assert_eq!(root.leaf_count, 4);
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = MerkleTree::new(HashAlgorithm::Blake3);

        for i in 0..8 {
            tree.add_leaf(format!("data{}", i).as_bytes().to_vec());
        }

        let root = tree.build().unwrap();
        let proof = tree.generate_proof(0).unwrap();

        assert!(verify_proof(&proof, &root.root_hash, HashAlgorithm::Blake3));
    }

    #[test]
    fn test_merkle_domain_separation_leaf_vs_node() {
        let tree = MerkleTree::new(HashAlgorithm::Sha256);
        let left = vec![0xAA; 32];
        let right = vec![0xBB; 32];
        let mut combined = left.clone();
        combined.extend_from_slice(&right);

        let leaf_hash = tree.hash_leaf(&combined);
        let node_hash = tree.hash_node(&left, &right);
        assert_ne!(leaf_hash, node_hash);
    }
}
