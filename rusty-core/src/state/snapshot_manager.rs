//! State snapshot and rollback manager
//! 
//! This module provides functionality for creating state snapshots
//! and rolling back to previous states for fast sync and chain reorganizations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use crate::consensus::error::ConsensusError;
use crate::state::merkle_patricia_trie::MerklePatriciaTrie;
use rusty_shared_types::{Hash, OutPoint, Utxo, TicketId, BlockHeader};
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::governance_state::ActiveProposals;
use crate::state::TicketData;
use zerocopy::AsBytes;
use crate::consensus::utxo_set::UtxoSet;

/// Configuration for snapshot management
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Directory to store snapshots
    pub snapshot_dir: PathBuf,
    /// Interval between automatic snapshots (in blocks)
    pub snapshot_interval: u64,
    /// Maximum number of snapshots to keep
    pub max_snapshots: usize,
    /// Enable compression for snapshots
    pub enable_compression: bool,
    /// Enable incremental snapshots
    pub enable_incremental: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_dir: PathBuf::from("snapshots"),
            snapshot_interval: 1000, // Every 1000 blocks
            max_snapshots: 10,
            enable_compression: true,
            enable_incremental: true,
        }
    }
}

/// Metadata for a state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height of the snapshot
    pub block_height: u64,
    /// Block hash of the snapshot
    pub block_hash: Hash,
    /// State root hash
    pub state_root: Hash,
    /// Timestamp when snapshot was created
    pub timestamp: u64,
    /// Size of the snapshot in bytes
    pub size_bytes: u64,
    /// Whether this is an incremental snapshot
    pub is_incremental: bool,
    /// Parent snapshot hash (for incremental snapshots)
    pub parent_snapshot: Option<Hash>,
    /// Snapshot format version
    pub version: u32,
}

/// Complete state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,
    /// UTXO set at the snapshot height
    pub utxo_set: HashMap<OutPoint, Utxo>,
    /// Live tickets pool
    pub live_tickets: HashMap<TicketId, TicketData>,
    /// Masternode list
    pub masternode_list: HashMap<Vec<u8>, Vec<u8>>,
    /// Active governance proposals
    pub active_proposals: HashMap<Vec<u8>, Vec<u8>>,
    /// Merkle Patricia Trie state
    pub trie_nodes: HashMap<Hash, Vec<u8>>, // Serialized trie nodes
    /// Additional state data
    pub additional_data: HashMap<String, Vec<u8>>,
}

/// Incremental snapshot containing only changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalSnapshot {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,
    /// UTXO changes (added/removed)
    pub utxo_changes: HashMap<OutPoint, Option<Utxo>>, // None = removed
    /// Ticket changes
    pub ticket_changes: HashMap<TicketId, Option<TicketData>>,
    /// Masternode changes
    pub masternode_changes: HashMap<Vec<u8>, Option<Vec<u8>>>,
    /// Proposal changes
    pub proposal_changes: HashMap<Vec<u8>, Option<Vec<u8>>>,
    /// Trie node changes
    pub trie_changes: HashMap<Hash, Option<Vec<u8>>>,
}

/// Manages state snapshots and rollbacks
pub struct SnapshotManager {
    config: SnapshotConfig,
    /// Available snapshots indexed by block height
    snapshots: HashMap<u64, SnapshotMetadata>,
    /// Current state for incremental snapshots
    current_state: Option<StateSnapshot>,
    /// Last snapshot height
    last_snapshot_height: u64,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(config: SnapshotConfig) -> Result<Self, ConsensusError> {
        // Create snapshot directory if it doesn't exist
        if !config.snapshot_dir.exists() {
            fs::create_dir_all(&config.snapshot_dir)
                .map_err(|e| ConsensusError::StateError(format!("Failed to create snapshot directory: {}", e)))?;
        }

        let mut manager = Self {
            config,
            snapshots: HashMap::new(),
            current_state: None,
            last_snapshot_height: 0,
        };

        // Load existing snapshots
        manager.load_existing_snapshots()?;

        Ok(manager)
    }

    /// Create a full state snapshot
    pub fn create_snapshot(
        &mut self,
        block_height: u64,
        block_hash: Hash,
        state_root: Hash,
        utxo_set: &UtxoSet,
        live_tickets: &LiveTicketsPool,
        masternode_list: &HashMap<Vec<u8>, Vec<u8>>,
        active_proposals: &ActiveProposals,
        _trie: &MerklePatriciaTrie,
    ) -> Result<Hash, ConsensusError> {
        info!("Creating state snapshot at height {}", block_height);

        // Convert UTXO set to HashMap
        let utxo_map: HashMap<OutPoint, Utxo> = utxo_set.iter()
            .map(|(outpoint, utxo)| (outpoint.clone(), utxo.clone()))
            .collect();

        // Convert live tickets to HashMap with TicketData
        let ticket_map: HashMap<TicketId, TicketData> = live_tickets.tickets.iter()
            .map(|(ticket_id, ticket)| {
                let ticket_data = TicketData {
                    owner: ticket.pubkey.clone(),
                    value: ticket.value,
                    expiration_height: ticket.height + 50000, // Placeholder for expiration_height, needs actual logic
                    creation_height: ticket.height,
                };
                (*ticket_id, ticket_data)
            })
            .collect();

        // Convert active proposals
        let proposal_map: HashMap<Vec<u8>, Vec<u8>> = active_proposals.proposals.iter()
            .map(|(proposal_id, proposal)| {
                let key = format!("prop_{}", hex::encode(proposal_id)).into_bytes();
                let value = bincode::serialize(proposal).unwrap_or_default();
                (key, value)
            })
            .collect();

        // Serialize trie nodes
        // TODO: Add public method to iterate over trie nodes
        let trie_nodes: HashMap<Hash, Vec<u8>> = HashMap::new(); // Placeholder

        let metadata = SnapshotMetadata {
            block_height,
            block_hash,
            state_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            size_bytes: 0, // Will be calculated after serialization
            is_incremental: false,
            parent_snapshot: None,
            version: 1,
        };

        let snapshot = StateSnapshot {
            metadata: metadata.clone(),
            utxo_set: utxo_map,
            live_tickets: ticket_map,
            masternode_list: masternode_list.clone(),
            active_proposals: proposal_map,
            trie_nodes,
            additional_data: HashMap::new(),
        };

        // Save snapshot to disk
        let snapshot_hash = self.save_snapshot(&snapshot)?;
        
        // Update metadata with actual size
        let mut updated_metadata = metadata;
        updated_metadata.size_bytes = self.get_snapshot_size(&snapshot_hash)?;
        
        // Store metadata
        self.snapshots.insert(block_height, updated_metadata);
        self.current_state = Some(snapshot);
        self.last_snapshot_height = block_height;

        // Clean up old snapshots
        self.cleanup_old_snapshots()?;

        info!("Created snapshot at height {} with hash {}", block_height, hex::encode(snapshot_hash.as_bytes()));
        Ok(snapshot_hash)
    }

    /// Create an incremental snapshot
    pub fn create_incremental_snapshot(
        &mut self,
        block_height: u64,
        block_hash: Hash,
        state_root: Hash,
        utxo_changes: &HashMap<OutPoint, Option<Utxo>>,
        ticket_changes: &HashMap<TicketId, Option<TicketData>>,
        masternode_changes: &HashMap<Vec<u8>, Option<Vec<u8>>>,
        proposal_changes: &HashMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<Hash, ConsensusError> {
        if !self.config.enable_incremental {
            return Err(ConsensusError::StateError("Incremental snapshots disabled".to_string()));
        }

        let parent_snapshot = self.snapshots.get(&self.last_snapshot_height)
            .map(|meta| blake3::hash(&bincode::serialize(meta).unwrap_or_default()).into());

        let metadata = SnapshotMetadata {
            block_height,
            block_hash,
            state_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            size_bytes: 0,
            is_incremental: true,
            parent_snapshot,
            version: 1,
        };

        let incremental_snapshot = IncrementalSnapshot {
            metadata: metadata.clone(),
            utxo_changes: utxo_changes.clone(),
            ticket_changes: ticket_changes.clone(),
            masternode_changes: masternode_changes.clone(),
            proposal_changes: proposal_changes.clone(),
            trie_changes: HashMap::new(), // Would be populated with actual trie changes
        };

        let snapshot_hash = self.save_incremental_snapshot(&incremental_snapshot)?;
        
        let mut updated_metadata = metadata;
        updated_metadata.size_bytes = self.get_incremental_snapshot_size(&snapshot_hash)?;
        
        self.snapshots.insert(block_height, updated_metadata);

        info!("Created incremental snapshot at height {} with hash {}", block_height, hex::encode(snapshot_hash.as_bytes()));
        Ok(snapshot_hash)
    }

    /// Load a snapshot and restore state
    pub fn load_snapshot(&self, block_height: u64) -> Result<StateSnapshot, ConsensusError> {
        let metadata = self.snapshots.get(&block_height)
            .ok_or_else(|| ConsensusError::StateError(format!("No snapshot at height {}", block_height)))?;

        if metadata.is_incremental {
            // For incremental snapshots, we need to reconstruct the full state
            self.reconstruct_state_from_incremental(block_height)
        } else {
            // Load full snapshot directly
            self.load_full_snapshot(block_height)
        }
    }

    /// Rollback to a previous state
    pub fn rollback_to_height(&mut self, target_height: u64) -> Result<StateSnapshot, ConsensusError> {
        info!("Rolling back to height {}", target_height);

        // Find the best snapshot at or before the target height
        let snapshot_height = self.snapshots.keys()
            .filter(|&&height| height <= target_height)
            .max()
            .copied()
            .ok_or_else(|| ConsensusError::StateError(format!("No snapshot available for rollback to height {}", target_height)))?;

        // Load the snapshot
        let snapshot = self.load_snapshot(snapshot_height)?;

        // If the snapshot is not exactly at the target height, we would need to
        // replay blocks from the snapshot height to the target height
        // For now, we'll just return the snapshot state
        
        self.current_state = Some(snapshot.clone());
        info!("Rolled back to snapshot at height {}", snapshot_height);

        Ok(snapshot)
    }

    /// Check if a snapshot should be created at the given height
    pub fn should_create_snapshot(&self, block_height: u64) -> bool {
        block_height > 0 && 
        (block_height - self.last_snapshot_height) >= self.config.snapshot_interval
    }

    /// Get snapshot statistics
    pub fn get_stats(&self) -> SnapshotStats {
        let total_size: u64 = self.snapshots.values()
            .map(|meta| meta.size_bytes)
            .sum();

        let incremental_count = self.snapshots.values()
            .filter(|meta| meta.is_incremental)
            .count();

        SnapshotStats {
            total_snapshots: self.snapshots.len(),
            incremental_snapshots: incremental_count,
            full_snapshots: self.snapshots.len() - incremental_count,
            total_size_bytes: total_size,
            last_snapshot_height: self.last_snapshot_height,
            available_heights: self.snapshots.keys().copied().collect(),
        }
    }

    /// Get available snapshot heights
    pub fn get_available_snapshots(&self) -> Vec<u64> {
        let mut heights: Vec<u64> = self.snapshots.keys().copied().collect();
        heights.sort();
        heights
    }

    // Private helper methods

    fn load_existing_snapshots(&mut self) -> Result<(), ConsensusError> {
        if !self.config.snapshot_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.config.snapshot_dir)
            .map_err(|e| ConsensusError::StateError(format!("Failed to read snapshot directory: {}", e)))? {
            
            let entry = entry.map_err(|e| ConsensusError::StateError(e.to_string()))?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("meta") {
                if let Ok(metadata_bytes) = fs::read(&path) {
                    if let Ok(metadata) = bincode::deserialize::<SnapshotMetadata>(&metadata_bytes) {
                        self.snapshots.insert(metadata.block_height, metadata.clone());
                        if metadata.block_height > self.last_snapshot_height {
                            self.last_snapshot_height = metadata.block_height;
                        }
                    }
                }
            }
        }

        info!("Loaded {} existing snapshots", self.snapshots.len());
        Ok(())
    }

    fn save_snapshot(&self, snapshot: &StateSnapshot) -> Result<Hash, ConsensusError> {
        let snapshot_data = if self.config.enable_compression {
            // In a real implementation, we would compress the data here
            bincode::serialize(snapshot)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?
        } else {
            bincode::serialize(snapshot)
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?
        };

        let snapshot_hash = blake3::hash(&snapshot_data);
        let snapshot_path = self.config.snapshot_dir.join(format!("{}.snapshot", hex::encode(snapshot_hash.as_bytes())));
        let metadata_path = self.config.snapshot_dir.join(format!("{}.meta", hex::encode(snapshot_hash.as_bytes())));

        // Save snapshot data
        fs::write(&snapshot_path, &snapshot_data)
            .map_err(|e| ConsensusError::StateError(format!("Failed to save snapshot: {}", e)))?;

        // Save metadata
        let metadata_data = bincode::serialize(&snapshot.metadata)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        fs::write(&metadata_path, &metadata_data)
            .map_err(|e| ConsensusError::StateError(format!("Failed to save metadata: {}", e)))?;

        Ok(snapshot_hash.into())
    }

    fn save_incremental_snapshot(&self, snapshot: &IncrementalSnapshot) -> Result<Hash, ConsensusError> {
        let snapshot_data = bincode::serialize(snapshot)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

        let snapshot_hash = blake3::hash(&snapshot_data);
        let snapshot_path = self.config.snapshot_dir.join(format!("{}.inc", hex::encode(snapshot_hash.as_bytes())));
        let metadata_path = self.config.snapshot_dir.join(format!("{}.meta", hex::encode(snapshot_hash.as_bytes())));

        fs::write(&snapshot_path, &snapshot_data)
            .map_err(|e| ConsensusError::StateError(format!("Failed to save incremental snapshot: {}", e)))?;

        let metadata_data = bincode::serialize(&snapshot.metadata)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        fs::write(&metadata_path, &metadata_data)
            .map_err(|e| ConsensusError::StateError(format!("Failed to save metadata: {}", e)))?;

        Ok(snapshot_hash.into())
    }

    fn load_full_snapshot(&self, block_height: u64) -> Result<StateSnapshot, ConsensusError> {
        let metadata = self.snapshots.get(&block_height)
            .ok_or_else(|| ConsensusError::StateError(format!("No snapshot at height {}", block_height)))?;

        let snapshot_hash = blake3::hash(&bincode::serialize(metadata).unwrap_or_default());
        let snapshot_path = self.config.snapshot_dir.join(format!("{}.snapshot", hex::encode(snapshot_hash.as_bytes())));

        let snapshot_data = fs::read(&snapshot_path)
            .map_err(|e| ConsensusError::StateError(format!("Failed to read snapshot: {}", e)))?;

        let snapshot: StateSnapshot = bincode::deserialize(&snapshot_data)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

        Ok(snapshot)
    }

    fn reconstruct_state_from_incremental(&self, _block_height: u64) -> Result<StateSnapshot, ConsensusError> {
        // This would reconstruct the full state by applying incremental changes
        // to the base snapshot. For now, return an error as this is complex to implement.
        Err(ConsensusError::StateError("Incremental snapshot reconstruction not implemented".to_string()))
    }

    fn get_snapshot_size(&self, snapshot_hash: &Hash) -> Result<u64, ConsensusError> {
        let snapshot_path = self.config.snapshot_dir.join(format!("{}.snapshot", hex::encode(snapshot_hash.as_bytes())));
        let metadata = fs::metadata(&snapshot_path)
            .map_err(|e| ConsensusError::StateError(format!("Failed to get snapshot size: {}", e)))?;
        Ok(metadata.len())
    }

    fn get_incremental_snapshot_size(&self, snapshot_hash: &Hash) -> Result<u64, ConsensusError> {
        let snapshot_path = self.config.snapshot_dir.join(format!("{}.inc", hex::encode(snapshot_hash.as_bytes())));
        let metadata = fs::metadata(&snapshot_path)
            .map_err(|e| ConsensusError::StateError(format!("Failed to get incremental snapshot size: {}", e)))?;
        Ok(metadata.len())
    }

    fn cleanup_old_snapshots(&mut self) -> Result<(), ConsensusError> {
        if self.snapshots.len() <= self.config.max_snapshots {
            return Ok(());
        }

        // Sort snapshots by height and remove oldest ones
        let mut heights: Vec<u64> = self.snapshots.keys().copied().collect();
        heights.sort();

        let to_remove = heights.len() - self.config.max_snapshots;
        for &height in &heights[..to_remove] {
            if let Some(metadata) = self.snapshots.remove(&height) {
                // Remove snapshot files
                let snapshot_hash = blake3::hash(&bincode::serialize(&metadata).unwrap_or_default());
                let snapshot_path = if metadata.is_incremental {
                    self.config.snapshot_dir.join(format!("{}.inc", hex::encode(snapshot_hash.as_bytes())))
                } else {
                    self.config.snapshot_dir.join(format!("{}.snapshot", hex::encode(snapshot_hash.as_bytes())))
                };
                let metadata_path = self.config.snapshot_dir.join(format!("{}.meta", hex::encode(snapshot_hash.as_bytes())));

                let _ = fs::remove_file(&snapshot_path);
                let _ = fs::remove_file(&metadata_path);
            }
        }

        info!("Cleaned up {} old snapshots", to_remove);
        Ok(())
    }
}

/// Statistics about snapshots
#[derive(Debug, Clone)]
pub struct SnapshotStats {
    pub total_snapshots: usize,
    pub incremental_snapshots: usize,
    pub full_snapshots: usize,
    pub total_size_bytes: u64,
    pub last_snapshot_height: u64,
    pub available_heights: Vec<u64>,
}
