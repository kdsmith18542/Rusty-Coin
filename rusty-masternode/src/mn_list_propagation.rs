//! Masternode list propagation and synchronization across the network

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{info, warn, error, debug};

use rusty_shared_types::masternode::{MasternodeList, MasternodeEntry, MasternodeID, MasternodeStatus};
use rusty_shared_types::Hash;
use rusty_p2p::types::{
    P2PMessage, MasternodeListRequest, MasternodeListResponse, MasternodeUpdate, 
    MasternodeUpdateType, MasternodeListSync
};
use blake3;

/// Configuration for masternode list propagation
#[derive(Debug, Clone)]
pub struct MNListPropagationConfig {
    /// How often to sync masternode list with peers (in seconds)
    pub sync_interval_secs: u64,
    /// Maximum age of masternode list before requesting full sync (in blocks)
    pub max_list_age_blocks: u64,
    /// Number of peers to sync with simultaneously
    pub max_sync_peers: usize,
    /// Timeout for masternode list requests (in seconds)
    pub request_timeout_secs: u64,
    /// Maximum number of masternode updates to batch together
    pub max_update_batch_size: usize,
}

impl Default for MNListPropagationConfig {
    fn default() -> Self {
        Self {
            sync_interval_secs: 30,
            max_list_age_blocks: 100,
            max_sync_peers: 5,
            request_timeout_secs: 30,
            max_update_batch_size: 50,
        }
    }
}

/// Manages masternode list propagation and synchronization
pub struct MNListPropagationManager {
    /// Current masternode list
    masternode_list: Arc<Mutex<MasternodeList>>,
    /// Configuration
    config: MNListPropagationConfig,
    /// Pending outgoing messages
    outgoing_messages: Arc<Mutex<Vec<P2PMessage>>>,
    /// Peers we're currently syncing with
    syncing_peers: Arc<Mutex<HashSet<String>>>, // Using String for peer ID
    /// Last sync times with peers
    last_sync_times: Arc<Mutex<HashMap<String, Instant>>>,
    /// Pending masternode updates to broadcast
    pending_updates: Arc<Mutex<Vec<MasternodeUpdate>>>,
    /// Current block height
    current_block_height: Arc<Mutex<u64>>,
    /// Hash of current masternode list
    current_list_hash: Arc<Mutex<Hash>>,
}

impl MNListPropagationManager {
    /// Create a new masternode list propagation manager
    pub fn new(
        masternode_list: Arc<Mutex<MasternodeList>>,
        config: MNListPropagationConfig,
    ) -> Self {
        let initial_hash = {
            let list = masternode_list.lock().unwrap();
            Self::calculate_list_hash(&list)
        };

        Self {
            masternode_list,
            config,
            outgoing_messages: Arc::new(Mutex::new(Vec::new())),
            syncing_peers: Arc::new(Mutex::new(HashSet::new())),
            last_sync_times: Arc::new(Mutex::new(HashMap::new())),
            pending_updates: Arc::new(Mutex::new(Vec::new())),
            current_block_height: Arc::new(Mutex::new(0)),
            current_list_hash: Arc::new(Mutex::new(initial_hash)),
        }
    }

    /// Calculate hash of masternode list for synchronization
    fn calculate_list_hash(list: &MasternodeList) -> Hash {
        let serialized = bincode::serialize(list).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Update current block height
    pub fn update_block_height(&self, height: u64) {
        let mut current_height = self.current_block_height.lock().unwrap();
        *current_height = height;
    }

    /// Add a masternode update to be propagated
    pub fn add_masternode_update(
        &self,
        masternode_id: MasternodeID,
        update_type: MasternodeUpdateType,
        entry: Option<MasternodeEntry>,
        signature: Vec<u8>,
    ) {
        let block_height = *self.current_block_height.lock().unwrap();
        
        let update = MasternodeUpdate {
            masternode_id,
            update_type,
            entry,
            block_height,
            signature,
        };

        {
            let mut pending = self.pending_updates.lock().unwrap();
            pending.push(update);
        }

        // Trigger immediate broadcast if we have enough updates
        self.maybe_broadcast_updates();
    }

    /// Broadcast pending masternode updates
    fn maybe_broadcast_updates(&self) {
        let updates = {
            let mut pending = self.pending_updates.lock().unwrap();
            if pending.len() >= self.config.max_update_batch_size {
                pending.drain(..).collect()
            } else {
                return; // Not enough updates to broadcast yet
            }
        };

        for update in updates {
            let message = P2PMessage::MasternodeUpdate(update);
            let mut outgoing = self.outgoing_messages.lock().unwrap();
            outgoing.push(message);
        }

        info!("Broadcasted {} masternode updates", self.config.max_update_batch_size);
    }

    /// Force broadcast all pending updates
    pub fn flush_pending_updates(&self) {
        let updates = {
            let mut pending = self.pending_updates.lock().unwrap();
            pending.drain(..).collect()
        };

        if !updates.is_empty() {
            for update in updates {
                let message = P2PMessage::MasternodeUpdate(update);
                let mut outgoing = self.outgoing_messages.lock().unwrap();
                outgoing.push(message);
            }

            info!("Flushed {} pending masternode updates", updates.len());
        }
    }

    /// Handle incoming masternode list request
    pub fn handle_list_request(&self, request: MasternodeListRequest, peer_id: String) {
        debug!("Received masternode list request from peer {}", peer_id);

        let (list_hash, block_height, masternodes) = {
            let list = self.masternode_list.lock().unwrap();
            let current_height = *self.current_block_height.lock().unwrap();
            let hash = Self::calculate_list_hash(&list);
            
            // Check if peer wants full list or just updates
            let entries: Vec<MasternodeEntry> = if request.request_full_list {
                list.map.values().cloned().collect()
            } else {
                // For incremental updates, we'd need to track what the peer has
                // For now, just send full list
                list.map.values().cloned().collect()
            };

            (hash, current_height, entries)
        };

        let response = MasternodeListResponse {
            version: request.version,
            list_hash,
            block_height,
            masternodes,
            is_full_list: true,
        };

        let message = P2PMessage::MasternodeListResponse(response);
        let mut outgoing = self.outgoing_messages.lock().unwrap();
        outgoing.push(message);

        info!("Sent masternode list response to peer {} with {} entries", peer_id, masternodes.len());
    }

    /// Handle incoming masternode list response
    pub fn handle_list_response(&self, response: MasternodeListResponse, peer_id: String) {
        debug!("Received masternode list response from peer {}", peer_id);

        // Verify the response hash
        let received_list = MasternodeList {
            map: response.masternodes.iter()
                .map(|entry| (MasternodeID(entry.identity.collateral_outpoint.clone()), entry.clone()))
                .collect(),
        };
        
        let calculated_hash = Self::calculate_list_hash(&received_list);
        if calculated_hash != response.list_hash {
            warn!("Masternode list hash mismatch from peer {}", peer_id);
            return;
        }

        // Update our masternode list if the peer's is newer
        let should_update = {
            let current_height = *self.current_block_height.lock().unwrap();
            response.block_height > current_height || 
            (response.block_height == current_height && response.list_hash != *self.current_list_hash.lock().unwrap())
        };

        if should_update {
            {
                let mut list = self.masternode_list.lock().unwrap();
                *list = received_list;
            }
            
            {
                let mut current_hash = self.current_list_hash.lock().unwrap();
                *current_hash = response.list_hash;
            }

            info!("Updated masternode list from peer {} with {} entries at height {}", 
                  peer_id, response.masternodes.len(), response.block_height);
        }

        // Remove peer from syncing set
        {
            let mut syncing = self.syncing_peers.lock().unwrap();
            syncing.remove(&peer_id);
        }
    }

    /// Handle incoming masternode update
    pub fn handle_masternode_update(&self, update: MasternodeUpdate, peer_id: String) {
        debug!("Received masternode update from peer {} for masternode {:?}", 
               peer_id, update.masternode_id);

        // TODO: Verify the update signature
        // For now, we'll trust the update

        // Apply the update to our masternode list
        let mut list = self.masternode_list.lock().unwrap();
        
        match update.update_type {
            MasternodeUpdateType::Registration => {
                if let Some(entry) = update.entry {
                    list.map.insert(update.masternode_id.clone(), entry);
                    info!("Applied masternode registration for {:?}", update.masternode_id);
                }
            }
            MasternodeUpdateType::StatusChange => {
                if let Some(entry) = update.entry {
                    list.map.insert(update.masternode_id.clone(), entry);
                    info!("Applied masternode status change for {:?}", update.masternode_id);
                }
            }
            MasternodeUpdateType::Deregistration => {
                list.map.remove(&update.masternode_id);
                info!("Applied masternode deregistration for {:?}", update.masternode_id);
            }
            MasternodeUpdateType::PoSeUpdate => {
                if let Some(entry) = list.map.get_mut(&update.masternode_id) {
                    // Update PoSe-related fields
                    entry.last_successful_pose_height = update.block_height as u32;
                    info!("Applied PoSe update for {:?}", update.masternode_id);
                }
            }
            MasternodeUpdateType::DKGParticipation => {
                if let Some(entry) = list.map.get_mut(&update.masternode_id) {
                    // Update DKG participation stats
                    entry.dkg_participation_count += 1;
                    info!("Applied DKG participation update for {:?}", update.masternode_id);
                }
            }
        }

        // Update our list hash
        let new_hash = Self::calculate_list_hash(&list);
        drop(list); // Release the lock
        
        {
            let mut current_hash = self.current_list_hash.lock().unwrap();
            *current_hash = new_hash;
        }
    }

    /// Request masternode list from a peer
    pub fn request_masternode_list(&self, peer_id: String, request_full: bool) {
        let last_known_hash = *self.current_list_hash.lock().unwrap();
        
        let request = MasternodeListRequest {
            version: 1,
            last_known_hash: Some(last_known_hash),
            request_full_list: request_full,
        };

        let message = P2PMessage::MasternodeListRequest(request);
        let mut outgoing = self.outgoing_messages.lock().unwrap();
        outgoing.push(message);

        // Track that we're syncing with this peer
        {
            let mut syncing = self.syncing_peers.lock().unwrap();
            syncing.insert(peer_id.clone());
        }

        {
            let mut last_sync = self.last_sync_times.lock().unwrap();
            last_sync.insert(peer_id.clone(), Instant::now());
        }

        info!("Requested masternode list from peer {}", peer_id);
    }

    /// Periodic sync with peers
    pub fn periodic_sync(&self, connected_peers: Vec<String>) {
        let now = Instant::now();
        let sync_interval = Duration::from_secs(self.config.sync_interval_secs);

        // Find peers we haven't synced with recently
        let peers_to_sync: Vec<String> = connected_peers
            .into_iter()
            .filter(|peer_id| {
                let last_sync = self.last_sync_times.lock().unwrap();
                match last_sync.get(peer_id) {
                    Some(last_time) => now.duration_since(*last_time) > sync_interval,
                    None => true, // Never synced with this peer
                }
            })
            .take(self.config.max_sync_peers)
            .collect();

        for peer_id in peers_to_sync {
            self.request_masternode_list(peer_id, false);
        }

        // Flush any pending updates
        self.flush_pending_updates();
    }

    /// Get pending outgoing messages
    pub fn get_outgoing_messages(&self) -> Vec<P2PMessage> {
        let mut outgoing = self.outgoing_messages.lock().unwrap();
        let messages = outgoing.clone();
        outgoing.clear();
        messages
    }

    /// Get current masternode list statistics
    pub fn get_stats(&self) -> MNListStats {
        let list = self.masternode_list.lock().unwrap();
        let total_count = list.map.len();
        let active_count = list.map.values()
            .filter(|entry| entry.status == MasternodeStatus::Active)
            .count();
        
        MNListStats {
            total_masternodes: total_count,
            active_masternodes: active_count,
            current_hash: *self.current_list_hash.lock().unwrap(),
            block_height: *self.current_block_height.lock().unwrap(),
            syncing_peers: self.syncing_peers.lock().unwrap().len(),
        }
    }
}

/// Statistics about masternode list propagation
#[derive(Debug, Clone)]
pub struct MNListStats {
    pub total_masternodes: usize,
    pub active_masternodes: usize,
    pub current_hash: Hash,
    pub block_height: u64,
    pub syncing_peers: usize,
}
