//! State proof manager for light clients
//! 
//! This module provides high-level APIs for generating and verifying
//! state proofs for light client operations.

use std::collections::HashMap;
use log::{info, warn, error, debug};

use rusty_shared_types::{Hash, OutPoint, Utxo, TicketId};
use crate::consensus::error::ConsensusError;
use crate::state::{MerklePatriciaTrie, MerkleProof, BatchMerkleProof, RangeProof, TicketData};

/// Types of state proofs that can be generated
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Range proof for a set of keys
    RangeProof,
}

/// Request for generating a state proof
#[derive(Debug, Clone)]
pub struct ProofRequest {
    pub proof_type: ProofType,
    pub keys: Vec<Vec<u8>>,
    pub range: Option<(Vec<u8>, Vec<u8>)>, // (start_key, end_key) for range proofs
    pub block_height: u64,
    pub state_root: Hash,
}

/// Response containing the generated proof
#[derive(Debug, Clone)]
pub struct ProofResponse {
    pub proof_type: ProofType,
    pub proof_data: ProofData,
    pub block_height: u64,
    pub state_root: Hash,
    pub proof_size: usize,
}

/// Different types of proof data
#[derive(Debug, Clone)]
pub enum ProofData {
    Single(MerkleProof),
    Batch(BatchMerkleProof),
    Range(RangeProof),
}

/// Configuration for proof generation
#[derive(Debug, Clone)]
pub struct ProofConfig {
    /// Maximum number of keys in a batch proof
    pub max_batch_size: usize,
    /// Maximum range size for range proofs
    pub max_range_size: usize,
    /// Enable proof compression
    pub enable_compression: bool,
    /// Cache frequently requested proofs
    pub enable_caching: bool,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            max_range_size: 1000,
            enable_compression: true,
            enable_caching: true,
        }
    }
}

/// Manages state proof generation and verification for light clients
pub struct StateProofManager {
    config: ProofConfig,
    proof_cache: HashMap<Hash, ProofResponse>,
    trie: MerklePatriciaTrie,
}

impl StateProofManager {
    /// Create a new state proof manager
    pub fn new(config: ProofConfig, trie: MerklePatriciaTrie) -> Self {
        Self {
            config,
            proof_cache: HashMap::new(),
            trie,
        }
    }

    /// Generate a proof for a single UTXO
    pub fn generate_utxo_proof(&self, outpoint: &OutPoint) -> Result<ProofResponse, ConsensusError> {
        let key = self.encode_utxo_key(outpoint);
        let proof = self.trie.generate_proof(&key)?;
        
        Ok(ProofResponse {
            proof_type: ProofType::UtxoProof,
            proof_data: ProofData::Single(proof.clone()),
            block_height: 0, // Would be set by caller
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Single(proof.clone())),
        })
    }

    /// Generate a proof for multiple UTXOs efficiently
    pub fn generate_utxo_batch_proof(&self, outpoints: &[OutPoint]) -> Result<ProofResponse, ConsensusError> {
        if outpoints.len() > self.config.max_batch_size {
            return Err(ConsensusError::TrieError(format!(
                "Batch size {} exceeds maximum {}", 
                outpoints.len(), 
                self.config.max_batch_size
            )));
        }

        let keys: Vec<Vec<u8>> = outpoints.iter()
            .map(|outpoint| self.encode_utxo_key(outpoint))
            .collect();

        let batch_proof = self.trie.generate_batch_proof(&keys)?;
        
        Ok(ProofResponse {
            proof_type: ProofType::BatchProof,
            proof_data: ProofData::Batch(batch_proof.clone()),
            block_height: 0,
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Batch(batch_proof.clone())),
        })
    }

    /// Generate a proof for a ticket
    pub fn generate_ticket_proof(&self, ticket_id: &TicketId) -> Result<ProofResponse, ConsensusError> {
        let key = self.encode_ticket_key(ticket_id);
        let proof = self.trie.generate_proof(&key)?;
        
        Ok(ProofResponse {
            proof_type: ProofType::TicketProof,
            proof_data: ProofData::Single(proof.clone()),
            block_height: 0,
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Single(proof.clone())),
        })
    }

    /// Generate a range proof for UTXOs within a specific range
    pub fn generate_utxo_range_proof(
        &self, 
        start_outpoint: &OutPoint, 
        end_outpoint: &OutPoint
    ) -> Result<ProofResponse, ConsensusError> {
        let start_key = self.encode_utxo_key(start_outpoint);
        let end_key = self.encode_utxo_key(end_outpoint);
        
        let range_proof = self.trie.generate_range_proof(&start_key, &end_key)?;
        
        if range_proof.included_keys.len() > self.config.max_range_size {
            return Err(ConsensusError::TrieError(format!(
                "Range size {} exceeds maximum {}", 
                range_proof.included_keys.len(), 
                self.config.max_range_size
            )));
        }
        
        Ok(ProofResponse {
            proof_type: ProofType::RangeProof,
            proof_data: ProofData::Range(range_proof.clone()),
            block_height: 0,
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Range(range_proof.clone())),
        })
    }

    /// Generate a proof for masternode existence
    pub fn generate_masternode_proof(&self, masternode_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        let key = self.encode_masternode_key(masternode_key);
        let proof = self.trie.generate_proof(&key)?;
        
        Ok(ProofResponse {
            proof_type: ProofType::MasternodeProof,
            proof_data: ProofData::Single(proof.clone()),
            block_height: 0,
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Single(proof.clone())),
        })
    }

    /// Generate a proof for governance proposal state
    pub fn generate_governance_proof(&self, proposal_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        let key = self.encode_proposal_key(proposal_key);
        let proof = self.trie.generate_proof(&key)?;
        
        Ok(ProofResponse {
            proof_type: ProofType::GovernanceProof,
            proof_data: ProofData::Single(proof.clone()),
            block_height: 0,
            state_root: self.trie.root_hash(),
            proof_size: self.calculate_proof_size(&ProofData::Single(proof.clone())),
        })
    }

    /// Verify a UTXO proof
    pub fn verify_utxo_proof(
        &self, 
        proof: &MerkleProof, 
        expected_utxo: Option<&Utxo>
    ) -> Result<bool, ConsensusError> {
        let expected_value = if let Some(utxo) = expected_utxo {
            Some(bincode::serialize(utxo)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?)
        } else {
            None
        };

        MerklePatriciaTrie::verify_proof(proof, expected_value.as_deref())
    }

    /// Verify a ticket proof
    pub fn verify_ticket_proof(
        &self, 
        proof: &MerkleProof, 
        expected_ticket: Option<&TicketData>
    ) -> Result<bool, ConsensusError> {
        let expected_value = if let Some(ticket) = expected_ticket {
            Some(bincode::serialize(ticket)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?)
        } else {
            None
        };

        MerklePatriciaTrie::verify_proof(proof, expected_value.as_deref())
    }

    /// Verify a batch proof
    pub fn verify_batch_proof(
        &self, 
        proof: &BatchMerkleProof, 
        expected_values: &[Option<Vec<u8>>]
    ) -> Result<bool, ConsensusError> {
        MerklePatriciaTrie::verify_batch_proof(proof, expected_values)
    }

    /// Verify a range proof
    pub fn verify_range_proof(&self, proof: &RangeProof) -> Result<bool, ConsensusError> {
        MerklePatriciaTrie::verify_range_proof(proof)
    }

    /// Get proof statistics
    pub fn get_proof_stats(&self) -> ProofStats {
        ProofStats {
            cached_proofs: self.proof_cache.len(),
            trie_nodes: self.trie.node_count(),
            root_hash: self.trie.root_hash(),
            config: self.config.clone(),
        }
    }

    /// Clear proof cache
    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
        info!("Cleared proof cache");
    }

    // Private helper methods

    fn calculate_proof_size(&self, proof_data: &ProofData) -> usize {
        match proof_data {
            ProofData::Single(proof) => {
                bincode::serialize(proof).map(|data| data.len()).unwrap_or(0)
            }
            ProofData::Batch(proof) => {
                bincode::serialize(proof).map(|data| data.len()).unwrap_or(0)
            }
            ProofData::Range(proof) => {
                bincode::serialize(proof).map(|data| data.len()).unwrap_or(0)
            }
        }
    }

    fn encode_utxo_key(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"utxo:");
        key.extend_from_slice(&outpoint.txid);
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    fn encode_ticket_key(&self, ticket_id: &TicketId) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"ticket:");
        key.extend_from_slice(ticket_id.as_ref());
        key
    }

    fn encode_masternode_key(&self, mn_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"masternode:");
        key.extend_from_slice(mn_key);
        key
    }

    fn encode_proposal_key(&self, prop_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"proposal:");
        key.extend_from_slice(prop_key);
        key
    }
}

/// Statistics about proof generation and verification
#[derive(Debug, Clone)]
pub struct ProofStats {
    pub cached_proofs: usize,
    pub trie_nodes: usize,
    pub root_hash: Hash,
    pub config: ProofConfig,
}

/// Light client interface for requesting proofs
pub trait LightClientProofInterface {
    /// Request a UTXO proof
    fn request_utxo_proof(&self, outpoint: &OutPoint) -> Result<ProofResponse, ConsensusError>;
    
    /// Request a batch of UTXO proofs
    fn request_utxo_batch_proof(&self, outpoints: &[OutPoint]) -> Result<ProofResponse, ConsensusError>;
    
    /// Request a ticket proof
    fn request_ticket_proof(&self, ticket_id: &TicketId) -> Result<ProofResponse, ConsensusError>;
    
    /// Request a masternode proof
    fn request_masternode_proof(&self, masternode_key: &[u8]) -> Result<ProofResponse, ConsensusError>;
    
    /// Request a governance proof
    fn request_governance_proof(&self, proposal_key: &[u8]) -> Result<ProofResponse, ConsensusError>;
}

impl LightClientProofInterface for StateProofManager {
    fn request_utxo_proof(&self, outpoint: &OutPoint) -> Result<ProofResponse, ConsensusError> {
        self.generate_utxo_proof(outpoint)
    }
    
    fn request_utxo_batch_proof(&self, outpoints: &[OutPoint]) -> Result<ProofResponse, ConsensusError> {
        self.generate_utxo_batch_proof(outpoints)
    }
    
    fn request_ticket_proof(&self, ticket_id: &TicketId) -> Result<ProofResponse, ConsensusError> {
        self.generate_ticket_proof(ticket_id)
    }
    
    fn request_masternode_proof(&self, masternode_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        self.generate_masternode_proof(masternode_key)
    }
    
    fn request_governance_proof(&self, proposal_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        self.generate_governance_proof(proposal_key)
    }
}
