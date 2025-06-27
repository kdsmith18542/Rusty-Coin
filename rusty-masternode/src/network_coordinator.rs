//! Network coordinator for masternode operations
//! 
//! This module coordinates between the P2P network layer and masternode-specific
//! functionality including list propagation, DKG coordination, and PoSe handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{info, warn, error, debug};

use rusty_shared_types::masternode::{MasternodeList, MasternodeEntry, MasternodeID};
use rusty_shared_types::dkg_messages::DKGMessage;
use rusty_p2p::types::{P2PMessage, MasternodeListRequest, MasternodeListResponse, MasternodeUpdate, MasternodeListSync};
use crate::mn_list_propagation::{MNListPropagationManager, MNListPropagationConfig};
use crate::dkg_manager::DKGManager;

/// Configuration for the masternode network coordinator
#[derive(Debug, Clone)]
pub struct MNNetworkCoordinatorConfig {
    /// How often to perform periodic maintenance (in seconds)
    pub maintenance_interval_secs: u64,
    /// Maximum number of concurrent P2P operations
    pub max_concurrent_operations: usize,
    /// Timeout for network operations (in seconds)
    pub operation_timeout_secs: u64,
}

impl Default for MNNetworkCoordinatorConfig {
    fn default() -> Self {
        Self {
            maintenance_interval_secs: 60,
            max_concurrent_operations: 10,
            operation_timeout_secs: 30,
        }
    }
}

/// Coordinates masternode network operations
pub struct MNNetworkCoordinator {
    /// Masternode list propagation manager
    mn_list_manager: Arc<MNListPropagationManager>,
    /// DKG manager for threshold signatures
    dkg_manager: Arc<DKGManager>,
    /// Configuration
    config: MNNetworkCoordinatorConfig,
    /// Connected peers
    connected_peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    /// Outgoing message queue
    outgoing_messages: Arc<Mutex<Vec<P2PMessage>>>,
    /// Last maintenance time
    last_maintenance: Arc<Mutex<Instant>>,
}

/// Information about a connected peer
#[derive(Debug, Clone)]
struct PeerInfo {
    peer_id: String,
    connected_at: Instant,
    last_activity: Instant,
    is_masternode: bool,
    masternode_id: Option<MasternodeID>,
    protocol_version: u32,
}

impl MNNetworkCoordinator {
    /// Create a new masternode network coordinator
    pub fn new(
        masternode_list: Arc<Mutex<MasternodeList>>,
        our_masternode_id: MasternodeID,
    auth_private_key: ed25519_dalek::SecretKey,
        config: MNNetworkCoordinatorConfig,
    ) -> Self {
        let mn_list_config = MNListPropagationConfig::default();
        let mn_list_manager = Arc::new(MNListPropagationManager::new(
            masternode_list,
            mn_list_config,
        ));

        let dkg_params = rusty_shared_types::dkg::DKGParams::default();
        let dkg_manager = Arc::new(DKGManager::new(
            our_masternode_id,
            auth_private_key,
            dkg_params,
        ));

        Self {
            mn_list_manager,
            dkg_manager,
            config,
            connected_peers: Arc::new(Mutex::new(HashMap::new())),
            outgoing_messages: Arc::new(Mutex::new(Vec::new())),
            last_maintenance: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Handle a peer connecting
    pub fn handle_peer_connected(&self, peer_id: String, is_masternode: bool, masternode_id: Option<MasternodeID>) {
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            is_masternode,
            masternode_id,
            protocol_version: 1, // Default version
        };

        {
            let mut peers = self.connected_peers.lock().unwrap();
            peers.insert(peer_id.clone(), peer_info);
        }

        info!("Peer {} connected (masternode: {})", peer_id, is_masternode);

        // If this is a masternode peer, request their masternode list
        if is_masternode {
            self.mn_list_manager.request_masternode_list(peer_id, false);
        }
    }

    /// Handle a peer disconnecting
    pub fn handle_peer_disconnected(&self, peer_id: String) {
        {
            let mut peers = self.connected_peers.lock().unwrap();
            peers.remove(&peer_id);
        }

        info!("Peer {} disconnected", peer_id);
    }

    /// Handle incoming P2P message
    pub fn handle_p2p_message(&self, message: P2PMessage, peer_id: String) -> Result<(), String> {
        // Update peer activity
        {
            let mut peers = self.connected_peers.lock().unwrap();
            if let Some(peer_info) = peers.get_mut(&peer_id) {
                peer_info.last_activity = Instant::now();
            }
        }

        match message {
            // Masternode list propagation messages
            P2PMessage::MasternodeListRequest(request) => {
                self.mn_list_manager.handle_list_request(request, peer_id);
                Ok(())
            }
            P2PMessage::MasternodeListResponse(response) => {
                self.mn_list_manager.handle_list_response(response, peer_id);
                Ok(())
            }
            P2PMessage::MasternodeUpdate(update) => {
                self.mn_list_manager.handle_masternode_update(update, peer_id);
                Ok(())
            }
            P2PMessage::MasternodeListSync(sync) => {
                self.handle_masternode_list_sync(sync, peer_id);
                Ok(())
            }
            _ => {
                // Not a masternode-specific message, ignore
                Ok(())
            }
        }
    }

    /// Handle DKG message
    pub fn handle_dkg_message(&self, message: DKGMessage) -> Result<(), String> {
        self.dkg_manager.handle_dkg_message(message)
            .map_err(|e| format!("DKG error: {}", e))
    }

    /// Handle masternode list sync message
    fn handle_masternode_list_sync(&self, sync: MasternodeListSync, peer_id: String) {
        debug!("Received masternode list sync from peer {}", peer_id);

        // Compare our list hash with peer's hash
        let stats = self.mn_list_manager.get_stats();
        
        if sync.our_list_hash != stats.current_hash {
            // Our lists are different, determine who has the newer one
            if sync.peer_block_height > stats.block_height {
                // Peer has newer list, request it
                info!("Peer {} has newer masternode list (height {} vs {}), requesting update", 
                      peer_id, sync.peer_block_height, stats.block_height);
                self.mn_list_manager.request_masternode_list(peer_id, true);
            } else if sync.peer_block_height < stats.block_height {
                // We have newer list, send it to peer
                info!("We have newer masternode list than peer {} (height {} vs {})", 
                      peer_id, stats.block_height, sync.peer_block_height);
                // The peer should request our list, but we could proactively send updates
            }
        }
    }

    /// Update current block height
    pub fn update_block_height(&self, height: u64) {
        self.mn_list_manager.update_block_height(height);
        // Also update DKG manager if it needs block height
    }

    /// Add a masternode update to be propagated
    pub fn propagate_masternode_update(
        &self,
        masternode_id: MasternodeID,
        update_type: rusty_p2p::types::MasternodeUpdateType,
        entry: Option<MasternodeEntry>,
        signature: Vec<u8>,
    ) {
        self.mn_list_manager.add_masternode_update(masternode_id, update_type, entry, signature);
    }

    /// Perform periodic maintenance
    pub fn periodic_maintenance(&self) {
        let now = Instant::now();
        let should_run_maintenance = {
            let mut last_maintenance = self.last_maintenance.lock().unwrap();
            if now.duration_since(*last_maintenance) > Duration::from_secs(self.config.maintenance_interval_secs) {
                *last_maintenance = now;
                true
            } else {
                false
            }
        };

        if should_run_maintenance {
            self.run_maintenance();
        }
    }

    /// Run maintenance tasks
    fn run_maintenance(&self) {
        debug!("Running masternode network maintenance");

        // Get list of connected peers
        let connected_peer_ids: Vec<String> = {
            let peers = self.connected_peers.lock().unwrap();
            peers.keys().cloned().collect()
        };

        // Perform masternode list synchronization
        self.mn_list_manager.periodic_sync(connected_peer_ids);

        // Clean up expired DKG sessions
        let stats = self.mn_list_manager.get_stats();
        self.dkg_manager.cleanup_expired_sessions(stats.block_height);

        // Remove inactive peers
        self.cleanup_inactive_peers();

        debug!("Masternode network maintenance completed");
    }

    /// Remove peers that haven't been active recently
    fn cleanup_inactive_peers(&self) {
        let inactive_timeout = Duration::from_secs(300); // 5 minutes
        let now = Instant::now();

        let inactive_peers: Vec<String> = {
            let peers = self.connected_peers.lock().unwrap();
            peers.iter()
                .filter(|(_, info)| now.duration_since(info.last_activity) > inactive_timeout)
                .map(|(peer_id, _)| peer_id.clone())
                .collect()
        };

        if !inactive_peers.is_empty() {
            let mut peers = self.connected_peers.lock().unwrap();
            for peer_id in &inactive_peers {
                peers.remove(peer_id);
            }
            warn!("Removed {} inactive peers", inactive_peers.len());
        }
    }

    /// Get all pending outgoing messages
    pub fn get_outgoing_messages(&self) -> Vec<P2PMessage> {
        // Collect messages from all managers
        let mut all_messages = Vec::new();

        // Get masternode list propagation messages
        let mn_list_messages = self.mn_list_manager.get_outgoing_messages();
        all_messages.extend(mn_list_messages);

        // Get DKG messages and convert them to P2P messages
        let dkg_messages = self.dkg_manager.get_outgoing_messages();
        for dkg_msg in dkg_messages {
            // TODO: Convert DKG messages to P2P messages
            // This would require adding DKG message types to P2PMessage enum
            debug!("DKG message ready for broadcast: {:?}", dkg_msg);
        }

        // Get any coordinator-specific messages
        let coordinator_messages = {
            let mut outgoing = self.outgoing_messages.lock().unwrap();
            let messages = outgoing.clone();
            outgoing.clear();
            messages
        };
        all_messages.extend(coordinator_messages);

        all_messages
    }

    /// Get network statistics
    pub fn get_network_stats(&self) -> MNNetworkStats {
        let peers = self.connected_peers.lock().unwrap();
        let total_peers = peers.len();
        let masternode_peers = peers.values().filter(|p| p.is_masternode).count();

        let mn_list_stats = self.mn_list_manager.get_stats();

        MNNetworkStats {
            total_connected_peers: total_peers,
            masternode_peers,
            total_masternodes: mn_list_stats.total_masternodes,
            active_masternodes: mn_list_stats.active_masternodes,
            syncing_peers: mn_list_stats.syncing_peers,
            current_block_height: mn_list_stats.block_height,
            list_hash: mn_list_stats.current_hash,
        }
    }

    /// Get connected masternode peers
    pub fn get_masternode_peers(&self) -> Vec<(String, MasternodeID)> {
        let peers = self.connected_peers.lock().unwrap();
        peers.values()
            .filter_map(|info| {
                if info.is_masternode {
                    info.masternode_id.map(|mn_id| (info.peer_id.clone(), mn_id))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if a specific masternode is connected
    pub fn is_masternode_connected(&self, masternode_id: &MasternodeID) -> bool {
        let peers = self.connected_peers.lock().unwrap();
        peers.values().any(|info| info.masternode_id.as_ref() == Some(masternode_id))
    }
}

/// Network statistics for masternode operations
#[derive(Debug, Clone)]
pub struct MNNetworkStats {
    pub total_connected_peers: usize,
    pub masternode_peers: usize,
    pub total_masternodes: usize,
    pub active_masternodes: usize,
    pub syncing_peers: usize,
    pub current_block_height: u64,
    pub list_hash: rusty_shared_types::Hash,
}
