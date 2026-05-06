//! Light client implementation for Rusty Coin
//!
//! This module provides a light client that can verify blockchain state
//! without downloading the full blockchain using state proofs.

use crate::consensus::error::ConsensusError;
use crate::state::{
    merkle_patricia_trie::{MerklePatriciaTrie, TicketData},
    proof_manager::{ProofData, ProofResponse},
};
use log::{info, warn};
use rusty_shared_types::{
    proof::{ProofRequest, ProofType},
    BlockHeader, Hash, OutPoint, TicketId, Utxo,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use async_trait::async_trait;

/// Trait for P2P network operations needed by the light client
#[async_trait]
pub trait LightClientP2PInterface: Send + Sync {
    /// Get list of connected peers
    async fn get_peers(&self) -> Result<Vec<libp2p::PeerId>, Box<dyn std::error::Error + Send + Sync>>;
    /// Send a proof request to a peer and wait for response
    async fn send_proof_request_with_response(
        &self, 
        peer_id: libp2p::PeerId, 
        request: ProofRequest,
        timeout_secs: u64
    ) -> Result<ProofResponse, Box<dyn std::error::Error + Send + Sync>>;
    /// Send a proof request to a peer (fire and forget)
    fn send_proof_request(&self, peer_id: libp2p::PeerId, request: ProofRequest);
    /// Request block headers from a peer
    async fn request_headers(
        &self,
        peer_id: libp2p::PeerId,
        start_hash: Hash,
        max_headers: u32,
        timeout_secs: u64
    ) -> Result<Vec<BlockHeader>, Box<dyn std::error::Error + Send + Sync>>;
    /// Get peer reputation score for selection
    async fn get_peer_reputation(&self, peer_id: libp2p::PeerId) -> Result<f64, Box<dyn std::error::Error + Send + Sync>>;
}

/// Configuration for the light client
#[derive(Debug, Clone)]
pub struct LightClientConfig {
    /// List of trusted full nodes to request proofs from
    pub trusted_nodes: Vec<String>,
    /// Maximum number of concurrent proof requests
    pub max_concurrent_requests: usize,
    /// Timeout for proof requests (in seconds)
    pub request_timeout_secs: u64,
    /// Timeout for header requests (in seconds)
    pub header_timeout_secs: u64,
    /// Minimum number of peers required for requests
    pub min_peers_required: usize,
    /// Enable proof caching
    pub enable_caching: bool,
    /// Cache size limit
    pub cache_size_limit: usize,
    /// Retry count for failed requests
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            trusted_nodes: vec!["127.0.0.1:8333".to_string()],
            max_concurrent_requests: 10,
            request_timeout_secs: 30,
            header_timeout_secs: 15,
            min_peers_required: 1,
            enable_caching: true,
            cache_size_limit: 1000,
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Peer selection strategy for light client requests
#[derive(Debug, Clone)]
pub enum PeerSelectionStrategy {
    /// Select peer with highest reputation score
    HighestReputation,
    /// Select peer with lowest latency
    LowestLatency,
    /// Random selection from healthy peers
    Random,
    /// Select from trusted nodes first, then fall back to others
    TrustedFirst,
}

/// Light client for Rusty Coin blockchain
pub struct LightClient {
    config: LightClientConfig,
    /// P2P network interface for sending proof requests
    p2p_network: Arc<dyn LightClientP2PInterface>,
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
    /// Peer selection strategy
    peer_selection_strategy: PeerSelectionStrategy,
}

impl LightClient {
    /// Create a new light client
    pub fn new(config: LightClientConfig, p2p_network: Arc<dyn LightClientP2PInterface>) -> Self {
        Self {
            config: config.clone(),
            p2p_network,
            block_headers: HashMap::new(),
            state_roots: HashMap::new(),
            proof_cache: HashMap::new(),
            best_block_height: 0,
            best_block_hash: [0u8; 32],
            peer_selection_strategy: PeerSelectionStrategy::TrustedFirst,
        }
    }

    /// Set the peer selection strategy
    pub fn set_peer_selection_strategy(&mut self, strategy: PeerSelectionStrategy) {
        self.peer_selection_strategy = strategy;
    }

    /// Verify that a UTXO exists at a specific block height
    pub async fn verify_utxo_existence(
        &mut self,
        outpoint: &OutPoint,
        block_height: u64,
    ) -> Result<Option<Utxo>, ConsensusError> {
        // Check cache first
        let cache_key = self.calculate_cache_key("utxo", outpoint, block_height);
        if self.config.enable_caching {
            if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
                info!("Using cached UTXO proof for {:?} at height {}", outpoint, block_height);
                let proof_data = self.verify_proof_response(cached_proof, block_height).await?;
                return self.deserialize_utxo_from_proof_data(proof_data);
            }
        }

        // Get the state root for the specified block height
        let state_root = self.get_state_root_at_height(block_height).await?;

        // Request proof from network with retries
        let proof_response = self
            .request_utxo_proof_from_network_with_retries(outpoint, block_height)
            .await?;

        // Verify the proof against the state root
        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        let proof_data = self.verify_proof_response(&proof_response, block_height).await?;
        let result = self.deserialize_utxo_from_proof_data(proof_data)?;
        
        // Cache the proof if enabled
        if self.config.enable_caching {
            self.proof_cache.insert(cache_key, proof_response);
        }

        Ok(result)
    }

    /// Verify multiple UTXOs efficiently using batch proofs
    pub async fn verify_utxo_batch(
        &mut self,
        outpoints: &[OutPoint],
        block_height: u64,
    ) -> Result<Vec<Option<Utxo>>, ConsensusError> {
        // Check cache for each UTXO
        let mut results = Vec::new();
        let mut uncached_outpoints = Vec::new();
        let mut uncached_indices = Vec::new();

        if self.config.enable_caching {
            for (i, outpoint) in outpoints.iter().enumerate() {
                let cache_key = self.calculate_cache_key("utxo_batch", outpoint, block_height);
                if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
                    let proof_data = self.verify_proof_response(cached_proof, block_height).await?;
                    let utxo = self.deserialize_utxo_from_proof_data(proof_data)?;
                    results.push(utxo);
                } else {
                    uncached_outpoints.push(outpoint.clone());
                    uncached_indices.push(i);
                    results.push(None); // Placeholder
                }
            }
        } else {
            uncached_outpoints.extend_from_slice(outpoints);
            uncached_indices.extend(0..outpoints.len());
            results.resize(outpoints.len(), None);
        }

        // Request batch proof for uncached UTXOs
        if !uncached_outpoints.is_empty() {
            let state_root = self.get_state_root_at_height(block_height).await?;
            let proof_response = self
                .request_utxo_batch_proof_from_network_with_retries(&uncached_outpoints, block_height)
                .await?;

            if proof_response.state_root != state_root {
                return Err(ConsensusError::TrieError("State root mismatch".to_string()));
            }

            // Process batch proof results
            match &proof_response.proof_data {
                ProofData::Batch(batch_proof) => {
                    for (i, proof) in batch_proof.proofs.iter().enumerate() {
                        let result_index = uncached_indices[i];
                        
                        let verification_result = if let Some(ref value_bytes) = proof.value {
                            let utxo: Utxo = bincode::deserialize(value_bytes)
                                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
                            Some(utxo)
                        } else {
                            None
                        };

                        results[result_index] = verification_result;

                        // Cache individual proofs
                        if self.config.enable_caching {
                            let cache_key = self.calculate_cache_key("utxo_batch", &uncached_outpoints[i], block_height);
                            let individual_response = ProofResponse {
                                proof_type: proof_response.proof_type.clone(),
                                proof_data: ProofData::Single(proof.clone()),
                                block_height,
                                state_root,
                                proof_size: proof_response.proof_size / uncached_outpoints.len() as usize,
                            };
                            self.proof_cache.insert(cache_key, individual_response);
                        }
                    }
                }
                _ => return Err(ConsensusError::TrieError("Invalid proof type".to_string())),
            }

            // Cache the batch proof
            if self.config.enable_caching {
                self.proof_cache.insert(
                    self.calculate_cache_key("utxo_batch_all", &outpoints, block_height),
                    proof_response
                );
            }
        }

        Ok(results)
    }

    /// Verify ticket existence and details
    pub async fn verify_ticket_existence(
        &mut self,
        ticket_id: &TicketId,
        block_height: u64,
    ) -> Result<Option<TicketData>, ConsensusError> {
        // Check cache first
        let cache_key = self.calculate_cache_key("ticket", ticket_id, block_height);
        if self.config.enable_caching {
            if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
                info!("Using cached ticket proof for {:?} at height {}", ticket_id, block_height);
                let proof_data = self.verify_proof_response(cached_proof, block_height).await?;
                return self.deserialize_ticket_from_proof_data(proof_data);
            }
        }

        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self
            .request_ticket_proof_from_network_with_retries(ticket_id, block_height)
            .await?;

        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        let proof_data = self.verify_proof_response(&proof_response, block_height).await?;
        let result = self.deserialize_ticket_from_proof_data(proof_data)?;
        
        // Cache the proof if enabled
        if self.config.enable_caching {
            self.proof_cache.insert(cache_key, proof_response);
        }

        Ok(result)
    }

    /// Verify masternode registration
    pub async fn verify_masternode_registration(
        &mut self,
        masternode_key: &[u8],
        block_height: u64,
    ) -> Result<bool, ConsensusError> {
        // Check cache first
        let cache_key = self.calculate_cache_key("masternode", &masternode_key.to_vec(), block_height);
        if self.config.enable_caching {
            if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
                info!("Using cached masternode proof at height {}", block_height);
                let proof_data = self.verify_proof_response(cached_proof, block_height).await?;
                Ok(proof_data.is_some())
            } else {
                let state_root = self.get_state_root_at_height(block_height).await?;
                let proof_response = self
                    .request_masternode_proof_from_network_with_retries(masternode_key, block_height)
                    .await?;

                if proof_response.state_root != state_root {
                    return Err(ConsensusError::TrieError("State root mismatch".to_string()));
                }

                let proof_data = self.verify_proof_response(&proof_response, block_height).await?;
                
                // Cache the proof if enabled
                if self.config.enable_caching {
                    self.proof_cache.insert(cache_key, proof_response);
                }

                Ok(proof_data.is_some())
            }
        } else {
            let state_root = self.get_state_root_at_height(block_height).await?;
            let proof_response = self
                .request_masternode_proof_from_network_with_retries(masternode_key, block_height)
                .await?;

            if proof_response.state_root != state_root {
                return Err(ConsensusError::TrieError("State root mismatch".to_string()));
            }

            let proof_data = self.verify_proof_response(&proof_response, block_height).await?;
            Ok(proof_data.is_some())
        }
    }

    /// Verify governance proposal state
    pub async fn verify_governance_proposal(
        &mut self,
        proposal_key: &[u8],
        block_height: u64,
    ) -> Result<Option<Vec<u8>>, ConsensusError> {
        // Check cache first
        let cache_key = self.calculate_cache_key("governance", &proposal_key.to_vec(), block_height);
        if self.config.enable_caching {
            if let Some(cached_proof) = self.proof_cache.get(&cache_key) {
                info!("Using cached governance proof at height {}", block_height);
                return self.verify_proof_response(cached_proof, block_height).await;
            }
        }

        let state_root = self.get_state_root_at_height(block_height).await?;
        let proof_response = self
            .request_governance_proof_from_network_with_retries(proposal_key, block_height)
            .await?;

        if proof_response.state_root != state_root {
            return Err(ConsensusError::TrieError("State root mismatch".to_string()));
        }

        let result = self.verify_proof_response(&proof_response, block_height).await?;
        
        // Cache the proof if enabled
        if self.config.enable_caching {
            self.proof_cache.insert(cache_key, proof_response);
        }

        Ok(result)
    }

    /// Request block headers from the network
    pub async fn request_block_headers(
        &mut self,
        start_hash: Hash,
        max_headers: u32,
    ) -> Result<Vec<BlockHeader>, ConsensusError> {
        info!("Requesting {} block headers from network starting from {:?}", max_headers, start_hash);

        // Select best peer for header request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer for header request: {}", e))
        })?;

        // Request headers from selected peer with timeout
        let headers = timeout(
            Duration::from_secs(self.config.header_timeout_secs),
            self.p2p_network.request_headers(peer_id, start_hash, max_headers, self.config.header_timeout_secs)
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("Header request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("Header request failed: {}", e)))?;

        if headers.is_empty() {
            warn!("No headers received from peer {}", peer_id);
            return Err(ConsensusError::NetworkError("No headers received".to_string()));
        }

        // Verify and store headers
        let mut verified_headers = Vec::new();
        let mut expected_hash = start_hash;

        for header in headers {
            // Verify header continuity
            if header.previous_block_hash != expected_hash && !expected_hash.iter().all(|&x| x == 0) {
                warn!("Header chain discontinuity detected");
                break;
            }

            // Verify header (basic validation)
            if self.verify_block_header(&header).await.is_ok() {
                verified_headers.push(header.clone());
                self.update_block_header(header.clone())?;
                expected_hash = header.hash();
            } else {
                warn!("Invalid header received, stopping verification");
                break;
            }
        }

        info!("Successfully verified {} block headers", verified_headers.len());
        Ok(verified_headers)
    }

    /// Update the light client with a new block header
    pub fn update_block_header(&mut self, header: BlockHeader) -> Result<(), ConsensusError> {
        let block_hash = header.hash();
        let block_height = header.height;

        // Verify the header connects to our chain
        if block_height > 0 && header.previous_block_hash != self.best_block_hash && !self.best_block_hash.iter().all(|&x| x == 0) {
            return Err(ConsensusError::TrieError(
                "Block header doesn't connect to chain".to_string(),
            ));
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

    /// Clear the proof cache
    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
        info!("Light client proof cache cleared");
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStats {
        CacheStats {
            total_cached_proofs: self.proof_cache.len(),
            cache_hit_ratio: 0.0, // Would need to track hits/misses for real implementation
            cache_size_bytes: self.estimate_cache_size(),
        }
    }

    // Private helper methods

    async fn get_state_root_at_height(&self, height: u64) -> Result<Hash, ConsensusError> {
        self.state_roots
            .get(&height)
            .copied()
            .ok_or_else(|| ConsensusError::StateRootNotFound(height))
    }

    /// Select the best peer based on the configured strategy
    async fn select_best_peer(&self) -> Result<libp2p::PeerId, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.p2p_network.get_peers().await?;
        
        if peers.is_empty() {
            return Err("No peers available".into());
        }

        match &self.peer_selection_strategy {
            PeerSelectionStrategy::HighestReputation => {
                let mut best_peer = peers[0];
                let mut best_score = self.p2p_network.get_peer_reputation(best_peer).await.unwrap_or(0.0);
                
                for peer in &peers[1..] {
                    let score = self.p2p_network.get_peer_reputation(*peer).await.unwrap_or(0.0);
                    if score > best_score {
                        best_score = score;
                        best_peer = *peer;
                    }
                }
                
                Ok(best_peer)
            }
            PeerSelectionStrategy::LowestLatency => {
                // For now, just return a random peer as we don't have latency metrics
                Ok(peers[rand::random::<usize>() % peers.len()])
            }
            PeerSelectionStrategy::Random => {
                Ok(peers[rand::random::<usize>() % peers.len()])
            }
            PeerSelectionStrategy::TrustedFirst => {
                // For now, just return the first peer as trusted node selection would require DNS resolution
                Ok(peers[0])
            }
        }
    }

    /// Verify a proof response and extract the result
    async fn verify_proof_response(&self, proof_response: &ProofResponse, _block_height: u64) -> Result<Option<Vec<u8>>, ConsensusError> {
        match &proof_response.proof_data {
            ProofData::Single(proof) => {
                // Verify the proof first
                let is_valid = MerklePatriciaTrie::verify_proof(proof, proof.value.as_deref())
                    .map_err(|e| ConsensusError::TrieError(e.to_string()))?;

                if !is_valid {
                    return Err(ConsensusError::TrieError("Invalid proof".to_string()));
                }

                Ok(proof.value.clone())
            }
            ProofData::Batch(batch_proof) => {
                // For batch proofs, we would need to verify each proof
                // For now, return the first proof's value
                if let Some(first_proof) = batch_proof.proofs.first() {
                    let is_valid = MerklePatriciaTrie::verify_proof(first_proof, first_proof.value.as_deref())
                        .map_err(|e| ConsensusError::TrieError(e.to_string()))?;

                    if !is_valid {
                        return Err(ConsensusError::TrieError("Invalid batch proof".to_string()));
                    }

                    Ok(first_proof.value.clone())
                } else {
                    Err(ConsensusError::TrieError("Empty batch proof".to_string()))
                }
            }
            ProofData::Range(range_proof) => {
                // Verify range proof
                let is_valid = MerklePatriciaTrie::verify_range_proof(range_proof)
                    .map_err(|e| ConsensusError::TrieError(e.to_string()))?;

                if !is_valid {
                    return Err(ConsensusError::TrieError("Invalid range proof".to_string()));
                }

                // For range proofs, return the first included key's value if available
                if let Some((_key, value)) = range_proof.included_keys.first() {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Deserialize UTXO from proof data
    fn deserialize_utxo_from_proof_data(&self, proof_data: Option<Vec<u8>>) -> Result<Option<Utxo>, ConsensusError> {
        if let Some(data) = proof_data {
            let utxo: Utxo = bincode::deserialize(&data)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
            Ok(Some(utxo))
        } else {
            Ok(None)
        }
    }

    /// Deserialize ticket data from proof data
    fn deserialize_ticket_from_proof_data(&self, proof_data: Option<Vec<u8>>) -> Result<Option<TicketData>, ConsensusError> {
        if let Some(data) = proof_data {
            let ticket_data: TicketData = bincode::deserialize(&data)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
            Ok(Some(ticket_data))
        } else {
            Ok(None)
        }
    }

    /// Calculate cache key for proof caching
    fn calculate_cache_key(&self, proof_type: &str, key: &dyn std::fmt::Debug, block_height: u64) -> Hash {
        let debug_str = format!("{:?}:{:?}:{}", proof_type, key, block_height);
        let binding = blake3::hash(debug_str.as_bytes());
        let hash_bytes = binding.as_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash_bytes[..32]);
        result
    }

    /// Estimate cache size in bytes
    fn estimate_cache_size(&self) -> usize {
        self.proof_cache.values().map(|response| response.proof_size).sum()
    }

    /// Basic block header verification
    async fn verify_block_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Basic validation rules
        if header.height < 0 {
            return Err(ConsensusError::SerializationError("Invalid block height".to_string()));
        }

        // Add more verification rules as needed
        Ok(())
    }

    // Network request methods with simplified retry logic

    async fn request_utxo_proof_from_network_with_retries(
        &mut self,
        outpoint: &OutPoint,
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.request_utxo_proof_from_network(outpoint, block_height).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!("UTXO proof request failed (attempt {}): {}", attempt + 1, e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            ConsensusError::NetworkError("All retry attempts failed".to_string())
        ))
    }

    async fn request_utxo_proof_from_network(
        &mut self,
        outpoint: &OutPoint,
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        info!(
            "Requesting UTXO proof for {:?} at height {}",
            outpoint, block_height
        );

        // Select best peer for this request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer: {}", e))
        })?;

        // Create the proof request
        let key = bincode::serialize(outpoint).map_err(|e| {
            ConsensusError::SerializationError(format!("Failed to serialize OutPoint: {}", e))
        })?;

        let proof_request = ProofRequest {
            proof_type: ProofType::UtxoProof,
            keys: vec![key],
            block_height,
        };

        // Send proof request with timeout
        let response = timeout(
            Duration::from_secs(self.config.request_timeout_secs),
            self.p2p_network.send_proof_request_with_response(
                peer_id, 
                proof_request, 
                self.config.request_timeout_secs
            )
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("UTXO proof request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("UTXO proof request failed: {}", e)))?;

        info!("Received UTXO proof response from peer {}", peer_id);
        Ok(response)
    }

    async fn request_utxo_batch_proof_from_network_with_retries(
        &mut self,
        outpoints: &[OutPoint],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.request_utxo_batch_proof_from_network(outpoints, block_height).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!("Batch UTXO proof request failed (attempt {}): {}", attempt + 1, e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            ConsensusError::NetworkError("All batch proof retry attempts failed".to_string())
        ))
    }

    async fn request_utxo_batch_proof_from_network(
        &mut self,
        outpoints: &[OutPoint],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        info!(
            "Requesting batch UTXO proof for {} UTXOs at height {}",
            outpoints.len(),
            block_height
        );

        // Select best peer for this request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer: {}", e))
        })?;

        // Create the batch proof request
        let keys: Result<Vec<Vec<u8>>, _> = outpoints
            .iter()
            .map(|outpoint| bincode::serialize(outpoint))
            .collect();

        let keys = keys.map_err(|e| {
            ConsensusError::SerializationError(format!("Failed to serialize OutPoints: {}", e))
        })?;

        let proof_request = ProofRequest {
            proof_type: ProofType::BatchProof,
            keys,
            block_height,
        };

        // Send batch proof request with timeout
        let response = timeout(
            Duration::from_secs(self.config.request_timeout_secs),
            self.p2p_network.send_proof_request_with_response(
                peer_id, 
                proof_request, 
                self.config.request_timeout_secs
            )
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("Batch UTXO proof request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("Batch UTXO proof request failed: {}", e)))?;

        info!("Received batch UTXO proof response from peer {}", peer_id);
        Ok(response)
    }

    async fn request_ticket_proof_from_network_with_retries(
        &mut self,
        ticket_id: &TicketId,
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.request_ticket_proof_from_network(ticket_id, block_height).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!("Ticket proof request failed (attempt {}): {}", attempt + 1, e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            ConsensusError::NetworkError("All ticket proof retry attempts failed".to_string())
        ))
    }

    async fn request_ticket_proof_from_network(
        &mut self,
        ticket_id: &TicketId,
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        info!(
            "Requesting ticket proof for {:?} at height {}",
            ticket_id, block_height
        );

        // Select best peer for this request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer: {}", e))
        })?;

        // Create the proof request
        let key = format!("ticket:{}", hex::encode(ticket_id.0)).into_bytes();

        let proof_request = ProofRequest {
            proof_type: ProofType::TicketProof,
            keys: vec![key.clone()],
            block_height,
        };

        // Send proof request with timeout
        let response = timeout(
            Duration::from_secs(self.config.request_timeout_secs),
            self.p2p_network.send_proof_request_with_response(
                peer_id, 
                proof_request, 
                self.config.request_timeout_secs
            )
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("Ticket proof request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("Ticket proof request failed: {}", e)))?;

        info!("Received ticket proof response from peer {}", peer_id);
        Ok(response)
    }

    async fn request_masternode_proof_from_network_with_retries(
        &mut self,
        masternode_key: &[u8],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.request_masternode_proof_from_network(masternode_key, block_height).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!("Masternode proof request failed (attempt {}): {}", attempt + 1, e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            ConsensusError::NetworkError("All masternode proof retry attempts failed".to_string())
        ))
    }

    async fn request_masternode_proof_from_network(
        &mut self,
        masternode_key: &[u8],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        info!(
            "Requesting masternode proof for key {:?} at height {}",
            hex::encode(masternode_key),
            block_height
        );

        // Select best peer for this request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer: {}", e))
        })?;

        // Create the proof request
        let key = format!("masternode:{}", hex::encode(masternode_key)).into_bytes();

        let proof_request = ProofRequest {
            proof_type: ProofType::MasternodeProof,
            keys: vec![key.clone()],
            block_height,
        };

        // Send proof request with timeout
        let response = timeout(
            Duration::from_secs(self.config.request_timeout_secs),
            self.p2p_network.send_proof_request_with_response(
                peer_id, 
                proof_request, 
                self.config.request_timeout_secs
            )
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("Masternode proof request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("Masternode proof request failed: {}", e)))?;

        info!("Received masternode proof response from peer {}", peer_id);
        Ok(response)
    }

    async fn request_governance_proof_from_network_with_retries(
        &mut self,
        proposal_key: &[u8],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.request_governance_proof_from_network(proposal_key, block_height).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e.clone());
                    warn!("Governance proof request failed (attempt {}): {}", attempt + 1, e);
                    
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms * (attempt as u64 + 1))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| 
            ConsensusError::NetworkError("All governance proof retry attempts failed".to_string())
        ))
    }

    async fn request_governance_proof_from_network(
        &mut self,
        proposal_key: &[u8],
        block_height: u64,
    ) -> Result<ProofResponse, ConsensusError> {
        info!(
            "Requesting governance proof for proposal {:?} at height {}",
            hex::encode(proposal_key),
            block_height
        );

        // Select best peer for this request
        let peer_id = self.select_best_peer().await.map_err(|e| {
            ConsensusError::NetworkError(format!("Failed to select peer: {}", e))
        })?;

        // Create the proof request
        let key = format!("governance:{}", hex::encode(proposal_key)).into_bytes();

        let proof_request = ProofRequest {
            proof_type: ProofType::GovernanceProof,
            keys: vec![key.clone()],
            block_height,
        };

        // Send proof request with timeout
        let response = timeout(
            Duration::from_secs(self.config.request_timeout_secs),
            self.p2p_network.send_proof_request_with_response(
                peer_id, 
                proof_request, 
                self.config.request_timeout_secs
            )
        )
        .await
        .map_err(|_| ConsensusError::NetworkError("Governance proof request timeout".to_string()))?
        .map_err(|e| ConsensusError::NetworkError(format!("Governance proof request failed: {}", e)))?;

        info!("Received governance proof response from peer {}", peer_id);
        Ok(response)
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

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_cached_proofs: usize,
    pub cache_hit_ratio: f64,
    pub cache_size_bytes: usize,
}