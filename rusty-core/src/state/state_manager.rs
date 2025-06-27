//! Comprehensive state manager for Rusty Coin
//! 
//! This module provides a unified interface for all state management
//! operations including Merkle Patricia Trie, snapshots, proofs, and fast sync.

use std::collections::HashMap;
use std::path::PathBuf;
use log::{info, warn, error, debug};

use rusty_shared_types::{Hash, OutPoint, Utxo, TicketId, BlockHeader};
use crate::consensus::error::ConsensusError;
use crate::consensus::utxo_set::UtxoSet;
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::governance_state::ActiveProposals;
use crate::state::{
    MerklePatriciaTrie, TicketData,
    StateProofManager, ProofConfig, ProofResponse, LightClientProofInterface,
    SnapshotManager, SnapshotConfig, StateSnapshot, SnapshotStats,
    FastSyncCoordinator, FastSyncConfig, FastSyncStatus, FastSyncStats,
};

/// Configuration for the comprehensive state manager
#[derive(Debug, Clone)]
pub struct StateManagerConfig {
    /// Configuration for state proofs
    pub proof_config: ProofConfig,
    /// Configuration for snapshots
    pub snapshot_config: SnapshotConfig,
    /// Configuration for fast sync
    pub fast_sync_config: FastSyncConfig,
    /// Enable fast sync
    pub enable_fast_sync: bool,
    /// Enable automatic snapshots
    pub enable_auto_snapshots: bool,
    /// Enable state proof caching
    pub enable_proof_caching: bool,
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            proof_config: ProofConfig::default(),
            snapshot_config: SnapshotConfig::default(),
            fast_sync_config: FastSyncConfig::default(),
            enable_fast_sync: true,
            enable_auto_snapshots: true,
            enable_proof_caching: true,
        }
    }
}

/// Comprehensive state manager that coordinates all state operations
pub struct StateManager {
    config: StateManagerConfig,
    /// Merkle Patricia Trie for state commitment
    trie: MerklePatriciaTrie,
    /// State proof manager for light clients
    proof_manager: StateProofManager,
    /// Snapshot manager for fast sync and rollbacks
    snapshot_manager: SnapshotManager,
    /// Fast sync coordinator
    fast_sync_coordinator: Option<FastSyncCoordinator>,
    /// Current block height
    current_height: u64,
    /// Current state root
    current_state_root: Hash,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(config: StateManagerConfig) -> Result<Self, ConsensusError> {
        // Initialize Merkle Patricia Trie
        let trie = MerklePatriciaTrie::new();
        
        // Initialize proof manager
        let proof_manager = StateProofManager::new(config.proof_config.clone(), trie.clone());
        
        // Initialize snapshot manager
        let snapshot_manager = SnapshotManager::new(config.snapshot_config.clone())?;
        
        // Initialize fast sync coordinator if enabled
        let fast_sync_coordinator = if config.enable_fast_sync {
            Some(FastSyncCoordinator::new(
                config.fast_sync_config.clone(),
                config.snapshot_config.clone(),
                true,
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            trie,
            proof_manager,
            snapshot_manager,
            fast_sync_coordinator,
            current_height: 0,
            current_state_root: [0u8; 32],
        })
    }

    /// Update the state with a new block
    pub fn update_state(
        &mut self,
        block_height: u64,
        block_hash: Hash,
        utxo_set: &UtxoSet,
        live_tickets: &LiveTicketsPool,
        masternode_list: &HashMap<Vec<u8>, Vec<u8>>,
        active_proposals: &ActiveProposals,
    ) -> Result<Hash, ConsensusError> {
        info!("Updating state for block height {}", block_height);

        // Convert data structures for trie
        let utxo_map: HashMap<OutPoint, Utxo> = utxo_set.iter()
            .map(|(outpoint, utxo)| (outpoint.clone(), utxo.clone()))
            .collect();

        let ticket_map: HashMap<TicketId, TicketData> = live_tickets.tickets.iter()
            .map(|(ticket_id, ticket)| {
                let ticket_data = TicketData {
                    owner: ticket.pubkey.clone(),
                    value: ticket.value,
                    expiration_height: ticket.height + 50000,
                    creation_height: ticket.height,
                };
                (*ticket_id, ticket_data)
            })
            .collect();

        let proposal_map: HashMap<Vec<u8>, Vec<u8>> = active_proposals.proposals.iter()
            .map(|(proposal_id, proposal)| {
                let key = format!("prop_{}", hex::encode(proposal_id)).into_bytes();
                let value = bincode::serialize(proposal).unwrap_or_default();
                (key, value)
            })
            .collect();

        // Create new trie from state data
        self.trie = MerklePatriciaTrie::from_state_data(
            &utxo_map,
            &ticket_map,
            masternode_list,
            &proposal_map,
        )?;

        // Update current state
        self.current_height = block_height;
        self.current_state_root = self.trie.root_hash();

        // Update proof manager with new trie
        self.proof_manager = StateProofManager::new(self.config.proof_config.clone(), self.trie.clone());

        // Create snapshot if needed
        if self.config.enable_auto_snapshots && 
           self.snapshot_manager.should_create_snapshot(block_height) {
            self.create_snapshot(block_hash, utxo_set, live_tickets, masternode_list, active_proposals)?;
        }

        Ok(self.current_state_root)
    }

    /// Create a state snapshot
    pub fn create_snapshot(
        &mut self,
        block_hash: Hash,
        utxo_set: &UtxoSet,
        live_tickets: &LiveTicketsPool,
        masternode_list: &HashMap<Vec<u8>, Vec<u8>>,
        active_proposals: &ActiveProposals,
    ) -> Result<Hash, ConsensusError> {
        let _snapshot_hash = self.snapshot_manager.create_snapshot(
            self.current_height,
            block_hash.into(),
            self.current_state_root.into(),
            utxo_set,
            live_tickets,
            masternode_list,
            active_proposals,
            &self.trie,
        )?;
        Ok(block_hash)
    }

    /// Rollback to a previous state
    pub fn rollback_to_height(&mut self, target_height: u64) -> Result<StateSnapshot, ConsensusError> {
        info!("Rolling back state to height {}", target_height);
        
        let snapshot = self.snapshot_manager.rollback_to_height(target_height)?;
        
        // Reconstruct trie from snapshot
        self.trie = MerklePatriciaTrie::from_state_data(
            &snapshot.utxo_set,
            &snapshot.live_tickets,
            &snapshot.masternode_list,
            &snapshot.active_proposals,
        )?;

        // Update current state
        self.current_height = snapshot.metadata.block_height;
        self.current_state_root = snapshot.metadata.state_root;

        // Update proof manager
        self.proof_manager = StateProofManager::new(self.config.proof_config.clone(), self.trie.clone());

        Ok(snapshot)
    }

    /// Start fast sync if appropriate
    pub async fn maybe_start_fast_sync(
        &mut self,
        network_height: u64,
    ) -> Result<bool, ConsensusError> {
        if let Some(ref mut coordinator) = self.fast_sync_coordinator {
            coordinator.maybe_start_fast_sync(self.current_height, network_height).await
        } else {
            Ok(false)
        }
    }

    /// Get the current state root
    pub fn get_state_root(&self) -> Hash {
        self.current_state_root
    }

    /// Get the current block height
    pub fn get_current_height(&self) -> u64 {
        self.current_height
    }

    /// Get state manager statistics
    pub fn get_stats(&self) -> StateManagerStats {
        let proof_stats = self.proof_manager.get_proof_stats();
        let snapshot_stats = self.snapshot_manager.get_stats();
        let fast_sync_stats = self.fast_sync_coordinator.as_ref()
            .map(|c| c.get_stats())
            .unwrap_or_else(|| FastSyncStats {
                status: FastSyncStatus::NotStarted,
                available_snapshots: 0,
                target_height: None,
                sync_duration_secs: 0,
                peers_count: 0,
            });

        StateManagerStats {
            current_height: self.current_height,
            current_state_root: self.current_state_root,
            trie_nodes: self.trie.node_count(),
            proof_stats,
            snapshot_stats,
            fast_sync_stats,
            config: self.config.clone(),
        }
    }

    /// Generate a UTXO proof
    pub fn generate_utxo_proof(&self, outpoint: &OutPoint) -> Result<ProofResponse, ConsensusError> {
        self.proof_manager.generate_utxo_proof(outpoint)
    }

    /// Generate a batch UTXO proof
    pub fn generate_utxo_batch_proof(&self, outpoints: &[OutPoint]) -> Result<ProofResponse, ConsensusError> {
        self.proof_manager.generate_utxo_batch_proof(outpoints)
    }

    /// Generate a ticket proof
    pub fn generate_ticket_proof(&self, ticket_id: &TicketId) -> Result<ProofResponse, ConsensusError> {
        self.proof_manager.generate_ticket_proof(ticket_id)
    }

    /// Generate a masternode proof
    pub fn generate_masternode_proof(&self, masternode_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        self.proof_manager.generate_masternode_proof(masternode_key)
    }

    /// Generate a governance proof
    pub fn generate_governance_proof(&self, proposal_key: &[u8]) -> Result<ProofResponse, ConsensusError> {
        self.proof_manager.generate_governance_proof(proposal_key)
    }

    /// Get available snapshot heights
    pub fn get_available_snapshots(&self) -> Vec<u64> {
        self.snapshot_manager.get_available_snapshots()
    }

    /// Load a specific snapshot
    pub fn load_snapshot(&self, block_height: u64) -> Result<StateSnapshot, ConsensusError> {
        self.snapshot_manager.load_snapshot(block_height)
    }

    /// Get fast sync status
    pub fn get_fast_sync_status(&self) -> FastSyncStatus {
        self.fast_sync_coordinator.as_ref()
            .map(|c| c.get_status())
            .unwrap_or(FastSyncStatus::NotStarted)
    }

    /// Add peer snapshot information for fast sync
    pub fn add_peer_snapshot(&mut self, peer_id: String, metadata: crate::state::SnapshotMetadata, peer_height: u64) {
        if let Some(ref mut coordinator) = self.fast_sync_coordinator {
            coordinator.add_peer_snapshot(peer_id, metadata, peer_height);
        }
    }

    /// Remove peer snapshots when peer disconnects
    pub fn remove_peer_snapshots(&mut self, peer_id: &str) {
        if let Some(ref mut coordinator) = self.fast_sync_coordinator {
            coordinator.remove_peer_snapshots(peer_id);
        }
    }

    /// Enable or disable fast sync
    pub fn set_fast_sync_enabled(&mut self, enabled: bool) {
        if let Some(ref mut coordinator) = self.fast_sync_coordinator {
            coordinator.set_enabled(enabled);
        }
    }

    /// Clear proof cache
    pub fn clear_proof_cache(&mut self) {
        self.proof_manager.clear_cache();
    }

    /// Validate state integrity
    pub fn validate_state_integrity(&self) -> Result<bool, ConsensusError> {
        // Verify that the current state root matches the trie root
        let computed_root = self.trie.root_hash();
        if computed_root != self.current_state_root {
            return Ok(false);
        }

        // Additional integrity checks could be added here
        // - Verify UTXO set consistency
        // - Verify ticket pool consistency
        // - Verify masternode list consistency

        Ok(true)
    }

    pub fn load_state_from_snapshot(&mut self, block_height: u64) -> Result<(), ConsensusError> {
        let snapshot = self.snapshot_manager.load_snapshot(block_height)?;
        self.current_height = snapshot.metadata.block_height;
        self.current_state_root = snapshot.metadata.state_root.into();
        self.trie = MerklePatriciaTrie::from_state_data(
            &snapshot.utxo_set,
            &snapshot.live_tickets,
            &snapshot.masternode_list,
            &snapshot.active_proposals,
        )?;
        self.proof_manager = StateProofManager::new(self.config.proof_config.clone(), self.trie.clone());
        Ok(())
    }
}

/// Implement light client proof interface for the state manager
impl LightClientProofInterface for StateManager {
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

/// Comprehensive statistics about the state manager
#[derive(Debug, Clone)]
pub struct StateManagerStats {
    pub current_height: u64,
    pub current_state_root: Hash,
    pub trie_nodes: usize,
    pub proof_stats: crate::state::ProofStats,
    pub snapshot_stats: SnapshotStats,
    pub fast_sync_stats: FastSyncStats,
    pub config: StateManagerConfig,
}
