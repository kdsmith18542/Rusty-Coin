//! Proof types for state verification
//!
//! This module contains types for merkle proofs and state verification
//! used by light clients and P2P communication.

use crate::Hash;
use serde::{Deserialize, Serialize};

/// State proof request message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofRequest {
    pub proof_type: ProofType,
    pub keys: Vec<Vec<u8>>,
    pub block_height: u64,
}

/// State proof response message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofResponse {
    pub proof_type: ProofType,
    pub proof_data: ProofData,
    pub block_height: u64,
    pub state_root: Hash,
    pub proof_size: usize,
}

/// Types of state proofs that can be requested
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Proof of UTXO existence or non-existence
    UtxoProof,
    /// Proof of ticket existence or non-existence
    TicketProof,
    /// Proof of masternode registration
    MasternodeProof,
    /// Proof of governance proposal state
    GovernanceProof,
    /// Batch proof for multiple items
    BatchProof,
}

/// Different types of proof data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProofData {
    Single(MerkleProof),
    Batch(BatchMerkleProof),
    Range(RangeProof),
}

/// Merkle proof for state verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub proof_nodes: Vec<TrieNode>,
    pub root_hash: Hash,
}

/// Batch merkle proof for multiple keys
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BatchMerkleProof {
    pub proofs: Vec<MerkleProof>,
    pub shared_nodes: std::collections::HashMap<Vec<u8>, TrieNode>,
    pub root_hash: Hash,
}

/// Range proof for a set of keys
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RangeProof {
    pub included_keys: Vec<Vec<u8>>,
    pub proof_nodes: Vec<TrieNode>,
    pub root_hash: Hash,
}

/// Trie node types for merkle proofs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrieNode {
    Empty,
    Leaf { key_end: Vec<u8>, value: Vec<u8> },
    Extension { common_prefix: Vec<u8>, next_hash: Hash },
    Branch { children: [Option<Hash>; 16], value: Option<Vec<u8>> },
}