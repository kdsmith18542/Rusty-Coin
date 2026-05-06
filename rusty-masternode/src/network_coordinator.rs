//! Network coordinator for masternode operations
//!
//! This module coordinates between the P2P network layer and masternode-specific
//! functionality including list propagation, DKG coordination, and PoSe handling.

use std::net::SocketAddr;
use std::sync::{atomic::AtomicU64, Mutex, MutexGuard, PoisonError};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use thiserror::Error;

use rusty_shared_types::{
    masternode::{MasternodeEntry, MasternodeID, MasternodeList},
    p2p::{MasternodeListRequest, MasternodeListSync, MasternodeUpdateType, P2PMessage},
};

use crate::{
    dkg_manager::DKGManager,
    mn_list_propagation::{MNListPropagationConfig, MNListPropagationManager},
    pose_coordinator::PoSeCoordinator,
};

#[derive(Error, Debug)]
pub enum NetworkCoordinatorError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("DKG error: {0}")]
    DkgError(#[from] crate::dkg_manager::DKGManagerError),

    #[error("Poison error: {0}")]
    PoisonError(String),

    #[error("PoSe error: {0}")]
    PoseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("String error: {0}")]
    StringError(String),
}

// Generic implementation for all PoisonError<Mutex<T>>
impl<T> From<PoisonError<Mutex<T>>> for NetworkCoordinatorError {
    fn from(err: PoisonError<Mutex<T>>) -> Self {
        NetworkCoordinatorError::PoisonError(err.to_string())
    }
}

// Implementation for MutexGuard
impl<T> From<PoisonError<MutexGuard<'_, T>>> for NetworkCoordinatorError {
    fn from(err: PoisonError<MutexGuard<'_, T>>) -> Self {
        NetworkCoordinatorError::PoisonError(err.to_string())
    }
}

// Generic implementation for all PoisonError<MutexGuard> is sufficient

// For bincode serialization errors
impl From<Box<bincode::ErrorKind>> for NetworkCoordinatorError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        NetworkCoordinatorError::SerializationError(err.to_string())
    }
}

type Result<T> = std::result::Result<T, NetworkCoordinatorError>;

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
    /// PoSe (Proof of Service) coordinator
    pose_coordinator: Option<Arc<PoSeCoordinator>>,
    /// Current block height
    current_block_height: AtomicU64,
    /// Current block hash
    current_block_hash: Mutex<[u8; 32]>,
    /// Last sync time
    last_sync_time: Mutex<Instant>,
    /// Network sender
    network_sender: mpsc::Sender<(P2PMessage, SocketAddr)>,
    /// Request ID counter for generating unique request IDs
    request_id_counter: AtomicU64,
    /// Operator private key for signing updates
    operator_keypair: ed25519_dalek::Keypair,
}

impl MNNetworkCoordinator {
    /// Create a new masternode network coordinator
    pub fn new(
        masternode_list: Arc<Mutex<MasternodeList>>,
        our_masternode_id: rusty_shared_types::MasternodeID,
        auth_keypair: ed25519_dalek::Keypair,
        _config: MNNetworkCoordinatorConfig,
        pose_coordinator: Option<Arc<PoSeCoordinator>>,
    ) -> Self {
        let _current_block_height = Arc::new(Mutex::new(0));
        // Clone the masternode list for DKG manager before it's moved
        let masternode_list_for_dkg = masternode_list.clone();

        // Initialize the masternode list propagation manager
        let mn_list_manager = Arc::new(MNListPropagationManager::new(
            masternode_list,
            MNListPropagationConfig::default(),
        ));

        let dkg_params = rusty_shared_types::dkg::DKGParams {
            min_participants: 3,
            max_participants: 10,
            threshold_percentage: 67, // 67% threshold
            commitment_timeout_blocks: 10,
            share_timeout_blocks: 10,
            complaint_timeout_blocks: 5,
            justification_timeout_blocks: 5,
        };

        let dkg_manager = Arc::new(DKGManager::new(
            our_masternode_id.clone(),
            ed25519_dalek::Keypair::from_bytes(&auth_keypair.to_bytes())
                .expect("Keypair conversion failed"),
            masternode_list_for_dkg,
            dkg_params,
        ));

        let (network_sender, _network_receiver) = mpsc::channel();
        Self {
            mn_list_manager,
            dkg_manager,
            pose_coordinator,
            current_block_height: AtomicU64::new(0),
            current_block_hash: Mutex::new([0u8; 32]),
            last_sync_time: Mutex::new(Instant::now()),
            network_sender,
            request_id_counter: AtomicU64::new(1),
            operator_keypair: ed25519_dalek::Keypair::from_bytes(&auth_keypair.to_bytes())
                .expect("Keypair conversion failed"),
        }
    }

    /// Generate a unique request ID
    fn generate_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Handle a peer connecting
    pub fn handle_peer_connected(
        &self,
        peer_id: String,
        is_masternode: bool,
        _masternode_id: Option<rusty_shared_types::MasternodeID>,
    ) {
        info!("Peer {} connected (masternode: {})", peer_id, is_masternode);

        // If this is a masternode peer, request their masternode list
        if is_masternode {
            let _ = self.mn_list_manager.request_masternode_list(peer_id);
        }
    }

    /// Handle a peer disconnecting
    pub fn handle_peer_disconnected(&self, peer_id: String) {
        info!("Peer {} disconnected", peer_id);
    }

    /// Handle incoming P2P message
    pub async fn handle_p2p_message(&self, message: P2PMessage, peer_id: String) -> Result<()> {
        let peer_addr: SocketAddr = peer_id.parse().map_err(|e| {
            NetworkCoordinatorError::NetworkError(format!("Invalid peer address: {}", e))
        })?;

        match message {
            P2PMessage::MasternodeListSync(sync) => {
                self.handle_masternode_list_sync(sync, peer_addr).await
            }
            P2PMessage::PoSeResponse(_response) => {
                // PoSe response handling removed as the method is not available
                debug!("Received PoSe response from peer {}", peer_addr);
                Ok(())
            }
            _ => {
                warn!("Received unsupported message type: {:?}", message);
                Ok(())
            }
        }
    }

    /// Handle masternode list sync message
    async fn handle_masternode_list_sync(
        &self,
        sync: MasternodeListSync,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        self.mn_list_manager
            .handle_full_list_sync(sync.masternodes, peer_addr.to_string())
            .map_err(|e| NetworkCoordinatorError::NetworkError(e.to_string()))
    }

    /// Update the current block height and notify all components
    pub fn update_block_height(&self, height: u64, block_hash: [u8; 32]) -> Result<()> {
        // Update masternode list manager
        self.mn_list_manager
            .update_block_height(height)
            .map_err(|e| NetworkCoordinatorError::StringError(e.to_string()))?;
        // Update DKG manager with real block hash
        self.dkg_manager
            .update_block_height(height, block_hash)
            .map_err(|e| NetworkCoordinatorError::DkgError(e))?;
        // Update internal state
        self.current_block_height
            .store(height, std::sync::atomic::Ordering::Relaxed);
        *self.current_block_hash.lock()? = block_hash;
        Ok(())
    }

    /// Add a masternode update to be propagated
    pub fn propagate_masternode_update(
        &self,
        update_type: MasternodeUpdateType,
        entry: Option<MasternodeEntry>,
    ) -> Result<()> {
        // Validate input based on update type
        match update_type {
            MasternodeUpdateType::Registration
            | MasternodeUpdateType::StatusChange
            | MasternodeUpdateType::PoSeUpdate
            | MasternodeUpdateType::DKGParticipation => {
                if entry.is_none() {
                    return Err(NetworkCoordinatorError::StringError(
                        "Masternode entry is required for this operation".to_string(),
                    ));
                }
                Ok::<(), NetworkCoordinatorError>(())
            }
            MasternodeUpdateType::Deregistration => {
                if entry.is_some() {
                    return Err(NetworkCoordinatorError::StringError(
                        "Masternode entry should be None for Delete operation".to_string(),
                    ));
                }
                Ok::<(), NetworkCoordinatorError>(())
            }
        }?;

        // Get the current block height and hash
        let current_height = self
            .current_block_height
            .load(std::sync::atomic::Ordering::Relaxed);
        let _current_hash = *self.current_block_hash.lock()?;

        // Create the masternode update based on the entry (if available)
        let masternode_id = if let Some(ref entry) = entry {
            MasternodeID(entry.identity.collateral_outpoint.clone())
        } else {
            // For deregistration, we need the masternode ID to be provided somehow
            // For now, we'll use a placeholder - this should be passed as a parameter
            return Err(NetworkCoordinatorError::StringError(
                "Masternode ID required for deregistration".to_string(),
            ));
        };

        // Create and add the update to the propagation manager
        // Use the operator private key for signing (protocol-compliant)
        let operator_private_key_bytes: &[u8; 32] = self.operator_keypair.secret.as_bytes();
        self.mn_list_manager
            .add_masternode_update(update_type, entry, operator_private_key_bytes)
            .map_err(|e| NetworkCoordinatorError::StringError(e))?;

        info!(
            "Propagated masternode update for {:?} at block height {}",
            masternode_id, current_height
        );

        Ok(())
    }

    /// Sync masternode list with peers
    async fn sync_masternode_list(&self) -> Result<()> {
        // Check if we need to sync (e.g., if it's been more than 1 hour since last sync)
        let last_sync = *self.last_sync_time.lock()?;
        if last_sync.elapsed() < Duration::from_secs(3600) {
            return Ok(());
        }

        info!("Starting masternode list sync");

        // Get current block height and hash
        let _current_height = self
            .current_block_height
            .load(std::sync::atomic::Ordering::Relaxed);
        let _current_hash = *self.current_block_hash.lock()?;

        // Request masternode list from peers
        let peer_count = 0; // Peer tracking removed

        if peer_count == 0 {
            warn!("No connected peers to sync masternode list with");
            return Ok(());
        }

        let _network_sender = self.network_sender.clone();
        let _request = MasternodeListRequest {
            request_id: self.generate_request_id(),
        };

        // Peer communication removed as peer tracking is not available
        warn!("Masternode list sync disabled - peer tracking removed");

        Ok(())
    }

    /// Remove peers that haven't been active recently
    async fn cleanup_inactive_peers(&self) -> Result<()> {
        // Peer tracking removed, nothing to clean up
        Ok(())
    }

    /// Get network statistics
    pub fn get_network_stats(&self) -> Result<MNNetworkStats> {
        // Peer tracking removed, return default values
        let total_peers = 0;
        let masternode_peers = 0;

        // Get current block height
        let current_block_height = self
            .current_block_height
            .load(std::sync::atomic::Ordering::Relaxed);

        Ok(MNNetworkStats {
            total_peers,
            masternode_peers,
            dkg_sessions: self.dkg_manager.get_active_session_count(),
            current_block_height,
            last_updated: Instant::now(),
        })
    }

    /// Perform periodic maintenance
    pub async fn periodic_maintenance(&self) -> Result<()> {
        debug!("Starting periodic maintenance");

        // Sync masternode list with peers
        if let Err(e) = self.sync_masternode_list().await {
            error!("Failed to sync masternode list: {}", e);
        }

        // Perform DKG maintenance
        let block_hash = *self.current_block_hash.lock()?;
        if let Err(e) = self
            .dkg_manager
            .as_ref()
            .periodic_maintenance(block_hash)
            .await
        {
            error!("DKG maintenance failed: {}", e);
        }

        // Perform PoSe maintenance if coordinator is available
        if let Some(pose) = &self.pose_coordinator {
            if let Err(e) = pose.periodic_maintenance() {
                error!("PoSe maintenance failed: {}", e);
            }
        }

        // Clean up inactive peers
        if let Err(e) = self.cleanup_inactive_peers().await {
            error!("Failed to clean up inactive peers: {}", e);
        }

        debug!("Completed periodic maintenance");
        Ok(())
    }

    /// Get all pending outgoing messages
    pub fn get_pending_messages(&self) -> Result<Vec<(P2PMessage, SocketAddr)>> {
        let messages = Vec::new();

        // Peer tracking removed, cannot broadcast messages
        warn!("Message broadcasting disabled - peer tracking removed");

        Ok(messages)
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast_message(&self, _message: P2PMessage) -> Result<()> {
        warn!("Message broadcasting disabled - peer tracking removed");
        Ok(())
    }

    /// Send a message to a specific peer
    pub fn send_message(&self, message: P2PMessage, peer_addr: SocketAddr) -> Result<()> {
        self.network_sender
            .send((message, peer_addr))
            .map_err(|e| NetworkCoordinatorError::StringError(e.to_string()))
    }

    /// Handle a new connection from a peer
    pub fn handle_new_connection(&self, peer_addr: SocketAddr, is_masternode: bool) -> Result<()> {
        debug!(
            "New {} connected: {}",
            if is_masternode {
                "masternode peer"
            } else {
                "peer"
            },
            peer_addr
        );
        Ok(())
    }

    /// Handle a disconnected peer
    pub fn handle_disconnect(&self, peer_addr: SocketAddr) -> Result<()> {
        debug!("Peer disconnected: {}", peer_addr);
        Ok(())
    }

    /// Get connected masternode peers
    pub fn get_masternode_peers(&self) -> Vec<(String, rusty_shared_types::MasternodeID)> {
        // Peer tracking removed, return empty list
        Vec::new()
    }

    /// Check if a specific masternode is connected
    pub fn is_masternode_connected(
        &self,
        _masternode_id: &rusty_shared_types::MasternodeID,
    ) -> bool {
        // Peer tracking removed, always return false
        false
    }
}

/// Network statistics for masternode operations
#[derive(Debug, Clone)]
pub struct MNNetworkStats {
    /// Total number of connected peers
    pub total_peers: usize,
    /// Number of connected masternode peers
    pub masternode_peers: usize,
    /// Number of active DKG sessions
    pub dkg_sessions: usize,
    /// Current blockchain height
    pub current_block_height: u64,
    /// When these stats were last updated
    pub last_updated: Instant,
}
