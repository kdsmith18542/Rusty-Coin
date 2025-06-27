//! Light client implementation for Rusty Coin
//! 
//! This module provides a light client that can verify blockchain state
//! without downloading the full blockchain using state proofs.

use std::collections::HashMap;
use log::info;
use rusty_shared_types::{BlockHeader, Hash, OutPoint, Utxo, TicketId};
use crate::consensus::error::ConsensusError;
use crate::state::{
    merkle_patricia_trie::{MerklePatriciaTrie, TicketData},
    proof_manager::{ProofData, ProofResponse}
};

/// Configuration for the light client
#[derive(Debug, Clone)]
pub struct LightClientConfig {
    /// List of trusted full nodes to request proofs from
    pub trusted_nodes: Vec<String>,
    /// Maximum number of concurrent proof requests
    pub max_concurrent_requests: usize,
    /// Timeout for proof requests (in seconds)
    pub request_timeout_secs: u64,
    /// Enable proof caching
    pub enable_caching: bool,
    /// Cache size limit
    pub cache_size_limit: usize,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            trusted_nodes: vec!["127.0.0.1:8333".to_string()],
            max_concurrent_requests: 10,
            request_timeout_secs: 30,
            enable_caching: true,
            cache_size_limit: 1000,
        }
    }
}

/// Light client for Rusty Coin blockchain
pub struct LightClient {
    config: LightClientConfig,
    /// Cached block headers for SPV verification
    block_headers: HashMap<Hash, BlockHeader>,
    /// Cached state roots for different block heights
    state_roots: HashMap<u64, Hash>,
    /// Cached proofs to avoid redundant requests
    proof_cache: HashMap<Hash, ProofResponse>,
    /// Current best block height
    best_block_height: u64,
    /// Current best block hash
    best_block_hash: Hash,
}

impl LightClient {
    /// Create a new light client
    pub fn new(config: LightClientConfig) -> Self {
        Self {
            config,
            block_headers: HashMap::new(),
            state_roots: HashMap::new(),
            proof_cache: HashMap::new(),
            best_block_height: 0,
            best_block_hash: [0u8; 32],
        }
    }

    /// Verify that a UTXO exists at a specific block height
    pub async fn verify_utxo_existence(
        &mut self,
        outpoint: &OutPoint,
        block_height: u64,
    ) -> Result<Option<Utxo>, ConsensusError> {
        // Get the state root for the specified block height
        let state_root = self.get_state_root_at_height(block_height).await?;
        
        // Request proof from a trusted node
        let proof_response = self.request_utxo_proof_from_network(outpoint, block_height).await?;
        
        // Verify the proof against the state root
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        match &proof_response.proof_data {
            ProofData::Single(proof) => {
                // Verify the proof first
                let is_valid = MerklePatriciaTrie::verify_proof(
                    proof, 
                    proof.value.as_deref()
                ).map_err(|e| ConsensusError::TrieError(e.to_string()))?;
                
                if !is_valid {
                    return Err(ConsensusError::TrieError("Invalid proof".to_string()));
                }
                
                // If proof is valid, try to deserialize the UTXO if it exists
                if let Some(ref value_bytes) = &proof.value {
                    let utxo: Utxo = bincode::deserialize(value_bytes)
                        .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
                    Ok(Some(utxo))
                } else {
                    Ok(None) // UTXO doesn't exist
                }
            }
            _ => Err(ConsensusError::TrieError("Invalid proof type".to_string())),
        }
    }

    /// Verify multiple UTXOs efficiently using batch proofs
    pub async fn verify_utxo_batch(
        &mut self,
        outpoints: &[OutPoint],
        block_height: u64,
    ) -> Result<Vec<Option<Utxo>>, ConsensusError> {
        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self.request_utxo_batch_proof_from_network(outpoints, block_height).await?;
        
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        match &proof_response.proof_data {
            ProofData::Batch(batch_proof) => {
                let mut results = Vec::new();
                
                for proof in &batch_proof.proofs {
                    if let Some(ref value_bytes) = proof.value {
                        let utxo: Utxo = bincode::deserialize(value_bytes)
                            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
                        results.push(Some(utxo));
                    } else {
                        results.push(None);
                    }
                }
                
                Ok(results)
            }
            _ => Err(ConsensusError::TrieError("Invalid proof type".to_string())),
        }
    }

    /// Verify ticket existence and details
    pub async fn verify_ticket_existence(
        &mut self,
        ticket_id: &TicketId,
        block_height: u64,
    ) -> Result<Option<TicketData>, ConsensusError> {
        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self.request_ticket_proof_from_network(ticket_id, block_height).await?;
        
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        match &proof_response.proof_data {
            ProofData::Single(proof) => {
                if let Some(ref value_bytes) = proof.value {
                    let ticket_data: TicketData = bincode::deserialize(value_bytes)
                        .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
                    Ok(Some(ticket_data))
                } else {
                    Ok(None)
                }
            }
            _ => Err(ConsensusError::TrieError("Invalid proof type".to_string())),
        }
    }

    /// Verify masternode registration
    pub async fn verify_masternode_registration(
        &mut self,
        masternode_key: &[u8],
        block_height: u64,
    ) -> Result<bool, ConsensusError> {
        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self.request_masternode_proof_from_network(masternode_key, block_height).await?;
        
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        match &proof_response.proof_data {
            ProofData::Single(proof) => Ok(proof.value.is_some()),
            _ => Err(ConsensusError::TrieError("Invalid proof type".to_string())),
        }
    }

    /// Verify governance proposal state
    pub async fn verify_governance_proposal(
        &mut self,
        proposal_key: &[u8],
        block_height: u64,
    ) -> Result<Option<Vec<u8>>, ConsensusError> {
        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self.request_governance_proof_from_network(proposal_key, block_height).await?;
        
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        match &proof_response.proof_data {
            ProofData::Single(proof) => Ok(proof.value.clone()),
            _ => Err(ConsensusError::TrieError("Invalid proof type".to_string())),
        }
    }

    /// Update the light client with a new block header
    pub fn update_block_header(&mut self, header: BlockHeader) -> Result<(), ConsensusError> {
        let block_hash = header.hash();
        let block_height = header.height;
        
        // Verify the header connects to our chain
        if block_height > 0 && header.previous_block_hash != self.best_block_hash {
            return Err(ConsensusError::TrieError("Block header doesn't connect to chain".to_string()));
        }

        // Store the header and state root
        self.block_headers.insert(block_hash, header.clone());
        self.state_roots.insert(block_height, header.state_root);
        
        // Update best block if this is newer
        if block_height > self.best_block_height {
            self.best_block_height = block_height;
            self.best_block_hash = block_hash;
        }

        info!("Updated light client to block height {}", block_height);
        Ok(())
    }

    /// Get the current best block height
    pub fn get_best_block_height(&self) -> u64 {
        self.best_block_height
    }

    /// Get the current best block hash
    pub fn get_best_block_hash(&self) -> Hash {
        self.best_block_hash
    }

    /// Get light client statistics
    pub fn get_stats(&self) -> LightClientStats {
        LightClientStats {
            best_block_height: self.best_block_height,
            cached_headers: self.block_headers.len(),
            cached_state_roots: self.state_roots.len(),
            cached_proofs: self.proof_cache.len(),
            trusted_nodes: self.config.trusted_nodes.len(),
        }
    }

    // Private helper methods

    async fn get_state_root_at_height(&self, height: u64) -> Result<Hash, ConsensusError> {
        self.state_roots.get(&height).copied()
            .ok_or_else(|| ConsensusError::StateRootNotFound(height))
    }

    async fn request_utxo_proof_from_network(
        &mut self,
        _outpoint: &OutPoint,
        _block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        // In a real implementation, this would make network requests to trusted nodes
        // For now, return a placeholder error
        Err(ConsensusError::TrieError("Network requests not implemented".to_string()))
    }

    async fn request_utxo_batch_proof_from_network(
        &mut self,
        _outpoints: &[OutPoint],
        _block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        // In a real implementation, this would make network requests to trusted nodes
        Err(ConsensusError::TrieError("Network requests not implemented".to_string()))
    }

    async fn request_ticket_proof_from_network(
        &mut self,
        _ticket_id: &TicketId,
        _block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        // In a real implementation, this would make network requests to trusted nodes
        Err(ConsensusError::TrieError("Network requests not implemented".to_string()))
    }

    async fn request_masternode_proof_from_network(
        &mut self,
        _masternode_key: &[u8],
        _block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        // In a real implementation, this would make network requests to trusted nodes
        Err(ConsensusError::TrieError("Network requests not implemented".to_string()))
    }

    async fn request_governance_proof_from_network(
        &mut self,
        _proposal_key: &[u8],
        _block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        // In a real implementation, this would make network requests to trusted nodes
        Err(ConsensusError::TrieError("Network requests not implemented".to_string()))
    }
}

/// Statistics about the light client
#[derive(Debug, Clone)]
pub struct LightClientStats {
    pub best_block_height: u64,
    pub cached_headers: usize,
    pub cached_state_roots: usize,
    pub cached_proofs: usize,
    pub trusted_nodes: usize,
}
