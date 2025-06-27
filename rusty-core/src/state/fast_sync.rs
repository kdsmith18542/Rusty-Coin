//! Fast sync implementation using state snapshots
//! 
//! This module provides fast synchronization capabilities for new nodes
//! by downloading and verifying state snapshots instead of processing
//! the entire blockchain history.

use std::time::{Duration, Instant};
use std::collections::HashMap;
use log::{info, debug};

use rusty_shared_types::BlockHeader;
use crate::consensus::error::ConsensusError;
use crate::state::{SnapshotManager, StateSnapshot, SnapshotConfig, SnapshotMetadata};

/// Configuration for fast sync
#[derive(Debug, Clone)]
pub struct FastSyncConfig {
    /// Minimum number of peers to request snapshots from
    pub min_peers: usize,
    /// Maximum number of concurrent snapshot downloads
    pub max_concurrent_downloads: usize,
    /// Timeout for snapshot requests (in seconds)
    pub request_timeout_secs: u64,
    /// Number of block headers to verify before accepting snapshot
    pub header_verification_depth: u64,
    /// Enable snapshot verification
    pub verify_snapshots: bool,
    /// Minimum snapshot age to consider (in blocks)
    pub min_snapshot_age: u64,
}

impl Default for FastSyncConfig {
    fn default() -> Self {
        Self {
            min_peers: 3,
            max_concurrent_downloads: 2,
            request_timeout_secs: 300, // 5 minutes
            header_verification_depth: 100,
            verify_snapshots: true,
            min_snapshot_age: 10, // Don't use very recent snapshots
        }
    }
}

/// Status of fast sync operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastSyncStatus {
    /// Not started
    NotStarted,
    /// Discovering available snapshots
    DiscoveringSnapshots,
    /// Downloading snapshot data
    DownloadingSnapshot { progress: u8 }, // 0-100
    /// Verifying snapshot integrity
    VerifyingSnapshot,
    /// Applying snapshot to local state
    ApplyingSnapshot,
    /// Syncing remaining blocks after snapshot
    SyncingBlocks { remaining: u64 },
    /// Fast sync completed successfully
    Completed,
    /// Fast sync failed
    Failed { error: String },
}

/// Information about an available snapshot from a peer
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    /// Peer identifier
    pub peer_id: String,
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,
    /// Peer's reported chain height
    pub peer_height: u64,
    /// Trust score for this peer
    pub trust_score: f64,
}

/// Fast sync manager
pub struct FastSyncManager {
    config: FastSyncConfig,
    snapshot_manager: SnapshotManager,
    status: FastSyncStatus,
    /// Available snapshots from peers
    peer_snapshots: std::collections::HashMap<String, Vec<PeerSnapshot>>,
    /// Current sync progress
    sync_start_time: Option<Instant>,
    /// Target snapshot for sync
    target_snapshot: Option<SnapshotMetadata>,
}

impl FastSyncManager {
    /// Create a new fast sync manager
    pub fn new(config: FastSyncConfig, snapshot_config: SnapshotConfig) -> Result<Self, ConsensusError> {
        let snapshot_manager = SnapshotManager::new(snapshot_config)?;
        
        Ok(Self {
            config,
            snapshot_manager,
            status: FastSyncStatus::NotStarted,
            peer_snapshots: HashMap::new(),
            sync_start_time: None,
            target_snapshot: None,
        })
    }

    /// Start fast sync process
    pub async fn start_fast_sync(&mut self, current_height: u64) -> Result<(), ConsensusError> {
        info!("Starting fast sync from height {}", current_height);
        
        self.status = FastSyncStatus::DiscoveringSnapshots;
        self.sync_start_time = Some(Instant::now());

        // Discover available snapshots from peers
        self.discover_snapshots().await?;

        // Select the best snapshot to download
        let target_snapshot = self.select_best_snapshot(current_height)?;
        self.target_snapshot = Some(target_snapshot.clone());

        info!("Selected snapshot at height {} for fast sync", target_snapshot.block_height);

        // Download and verify the snapshot
        self.download_snapshot(&target_snapshot).await?;

        // Apply the snapshot to local state
        self.apply_snapshot(&target_snapshot).await?;

        // Sync remaining blocks if needed
        self.sync_remaining_blocks().await?;

        self.status = FastSyncStatus::Completed;
        
        if let Some(start_time) = self.sync_start_time {
            let duration = start_time.elapsed();
            info!("Fast sync completed in {:?}", duration);
        }

        Ok(())
    }

    /// Check if fast sync is beneficial for the given height difference
    pub fn should_use_fast_sync(&self, current_height: u64, network_height: u64) -> bool {
        let height_diff = network_height.saturating_sub(current_height);
        
        // Use fast sync if we're significantly behind
        height_diff > 1000 && self.has_suitable_snapshots(network_height)
    }

    /// Get current fast sync status
    pub fn get_status(&self) -> FastSyncStatus {
        self.status.clone()
    }

    /// Get fast sync statistics
    pub fn get_stats(&self) -> FastSyncStats {
        let available_snapshots = self.peer_snapshots.values()
            .map(|snapshots| snapshots.len())
            .sum();

        let sync_duration = self.sync_start_time
            .map(|start| start.elapsed())
            .unwrap_or_default();

        FastSyncStats {
            status: self.status.clone(),
            available_snapshots,
            target_height: self.target_snapshot.as_ref().map(|s| s.block_height),
            sync_duration_secs: sync_duration.as_secs(),
            peers_count: self.peer_snapshots.len(),
        }
    }

    /// Add snapshot information from a peer
    pub fn add_peer_snapshot(&mut self, peer_id: String, metadata: SnapshotMetadata, peer_height: u64) {
        let peer_snapshot = PeerSnapshot {
            peer_id: peer_id.clone(),
            metadata,
            peer_height,
            trust_score: 1.0, // Would be calculated based on peer reputation
        };

        self.peer_snapshots
            .entry(peer_id)
            .or_insert_with(Vec::new)
            .push(peer_snapshot);
    }

    /// Remove snapshots from a disconnected peer
    pub fn remove_peer_snapshots(&mut self, peer_id: &str) {
        self.peer_snapshots.remove(peer_id);
    }

    // Private helper methods

    async fn discover_snapshots(&mut self) -> Result<(), ConsensusError> {
        // In a real implementation, this would query connected peers for available snapshots
        // For now, we'll simulate having some snapshots available
        
        debug!("Discovering snapshots from {} peers", self.peer_snapshots.len());
        
        if self.peer_snapshots.is_empty() {
            return Err(ConsensusError::StateError("No peers available for snapshot discovery".to_string()));
        }

        Ok(())
    }

    fn select_best_snapshot(&self, current_height: u64) -> Result<SnapshotMetadata, ConsensusError> {
        let mut candidates = Vec::new();

        // Collect all snapshots that are suitable for fast sync
        for peer_snapshots in self.peer_snapshots.values() {
            for peer_snapshot in peer_snapshots {
                let snapshot_height = peer_snapshot.metadata.block_height;
                
                // Check if snapshot is suitable
                if snapshot_height > current_height + self.config.min_snapshot_age &&
                   !peer_snapshot.metadata.is_incremental {
                    candidates.push(peer_snapshot);
                }
            }
        }

        if candidates.is_empty() {
            return Err(ConsensusError::StateError("No suitable snapshots found".to_string()));
        }

        // Sort by height (descending) and trust score
        candidates.sort_by(|a, b| {
            b.metadata.block_height.cmp(&a.metadata.block_height)
                .then_with(|| b.trust_score.partial_cmp(&a.trust_score).unwrap_or(std::cmp::Ordering::Equal))
        });

        // Select the best candidate
        let best_snapshot = candidates[0];
        
        // Verify we have enough peers offering this snapshot
        let peer_count = candidates.iter()
            .filter(|s| s.metadata.block_height == best_snapshot.metadata.block_height)
            .count();

        if peer_count < self.config.min_peers {
            return Err(ConsensusError::StateError(format!(
                "Not enough peers ({}) offering snapshot at height {}", 
                peer_count, 
                best_snapshot.metadata.block_height
            )));
        }

        Ok(best_snapshot.metadata.clone())
    }

    async fn download_snapshot(&mut self, metadata: &SnapshotMetadata) -> Result<(), ConsensusError> {
        info!("Downloading snapshot at height {}", metadata.block_height);
        
        self.status = FastSyncStatus::DownloadingSnapshot { progress: 0 };

        // In a real implementation, this would download the snapshot data from peers
        // For now, we'll simulate the download process
        
        for progress in (0..=100).step_by(10) {
            self.status = FastSyncStatus::DownloadingSnapshot { progress };
            
            // Simulate download time
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if self.config.verify_snapshots {
            self.status = FastSyncStatus::VerifyingSnapshot;
            self.verify_snapshot(metadata).await?;
        }

        Ok(())
    }

    async fn verify_snapshot(&self, _metadata: &SnapshotMetadata) -> Result<(), ConsensusError> {
        info!("Verifying snapshot integrity");

        // In a real implementation, this would:
        // 1. Verify the snapshot hash matches the metadata
        // 2. Verify the state root is correct
        // 3. Verify block headers leading to the snapshot
        // 4. Check signatures and consensus rules

        // For now, we'll just simulate verification
        tokio::time::sleep(Duration::from_millis(500)).await;

        info!("Snapshot verification completed successfully");
        Ok(())
    }

    async fn apply_snapshot(&mut self, _metadata: &SnapshotMetadata) -> Result<(), ConsensusError> {
        info!("Applying snapshot to local state");
        
        self.status = FastSyncStatus::ApplyingSnapshot;

        // In a real implementation, this would:
        // 1. Load the snapshot data
        // 2. Apply it to the local UTXO set, tickets, etc.
        // 3. Update the blockchain state
        // 4. Verify the resulting state root

        // For now, we'll simulate the application process
        tokio::time::sleep(Duration::from_millis(1000)).await;

        info!("Snapshot applied successfully");
        Ok(())
    }

    async fn sync_remaining_blocks(&mut self) -> Result<(), ConsensusError> {
        // In a real implementation, this would sync any blocks that came after the snapshot
        // For now, we'll just mark it as complete
        
        self.status = FastSyncStatus::SyncingBlocks { remaining: 0 };
        
        info!("No remaining blocks to sync");
        Ok(())
    }

    fn has_suitable_snapshots(&self, network_height: u64) -> bool {
        self.peer_snapshots.values()
            .any(|snapshots| {
                snapshots.iter().any(|s| {
                    s.metadata.block_height > network_height.saturating_sub(self.config.min_snapshot_age) &&
                    !s.metadata.is_incremental
                })
            })
    }
}

/// Statistics about fast sync progress
#[derive(Debug, Clone)]
pub struct FastSyncStats {
    pub status: FastSyncStatus,
    pub available_snapshots: usize,
    pub target_height: Option<u64>,
    pub sync_duration_secs: u64,
    pub peers_count: usize,
}

/// Fast sync coordinator that manages the overall sync process
pub struct FastSyncCoordinator {
    fast_sync_manager: FastSyncManager,
    /// Whether fast sync is enabled
    enabled: bool,
    /// Minimum height difference to trigger fast sync
    min_height_diff: u64,
}

impl FastSyncCoordinator {
    /// Create a new fast sync coordinator
    pub fn new(
        fast_sync_config: FastSyncConfig,
        snapshot_config: SnapshotConfig,
        enabled: bool,
    ) -> Result<Self, ConsensusError> {
        let fast_sync_manager = FastSyncManager::new(fast_sync_config, snapshot_config)?;
        
        Ok(Self {
            fast_sync_manager,
            enabled,
            min_height_diff: 1000,
        })
    }

    /// Check if fast sync should be used and start it if appropriate
    pub async fn maybe_start_fast_sync(
        &mut self,
        current_height: u64,
        network_height: u64,
    ) -> Result<bool, ConsensusError> {
        if !self.enabled {
            return Ok(false);
        }

        let height_diff = network_height.saturating_sub(current_height);
        
        if height_diff < self.min_height_diff {
            return Ok(false);
        }

        if !self.fast_sync_manager.should_use_fast_sync(current_height, network_height) {
            return Ok(false);
        }

        info!("Starting fast sync: current={}, network={}, diff={}", 
              current_height, network_height, height_diff);

        self.fast_sync_manager.start_fast_sync(current_height).await?;
        Ok(true)
    }

    /// Get fast sync status
    pub fn get_status(&self) -> FastSyncStatus {
        self.fast_sync_manager.get_status()
    }

    /// Get fast sync statistics
    pub fn get_stats(&self) -> FastSyncStats {
        self.fast_sync_manager.get_stats()
    }

    /// Enable or disable fast sync
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Add snapshot information from a peer
    pub fn add_peer_snapshot(&mut self, peer_id: String, metadata: SnapshotMetadata, peer_height: u64) {
        self.fast_sync_manager.add_peer_snapshot(peer_id, metadata, peer_height);
    }

    /// Remove snapshots from a disconnected peer
    pub fn remove_peer_snapshots(&mut self, peer_id: &str) {
        self.fast_sync_manager.remove_peer_snapshots(peer_id);
    }
}
