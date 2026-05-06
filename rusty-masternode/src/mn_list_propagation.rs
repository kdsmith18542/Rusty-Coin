//! Masternode list propagation and synchronization across the network

use ed25519_dalek::{Signer, Verifier};
use log::{debug, info};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake3;
use rusty_shared_types::{
    masternode::{MasternodeEntry, MasternodeID, MasternodeList, MasternodeStatus},
    p2p::{
        MasternodeListRequest, MasternodeListResponse, MasternodeUpdate, MasternodeUpdateType,
        P2PMessage,
    },
    Hash,
};

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
        // Sort the entries for deterministic hashing
        let mut entries: Vec<_> = list.map.iter().collect();
        entries.sort_by_key(|(id, _)| *id);

        // Serialize the sorted list
        let serialized = bincode::serialize(&entries).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Update current block height
    pub fn update_block_height(&self, height: u64) -> Result<(), String> {
        let mut current_height = self
            .current_block_height
            .lock()
            .map_err(|e| e.to_string())?;
        *current_height = height;
        Ok(())
    }

    /// Verify the signature of a masternode update
    fn verify_update_signature(&self, update: &MasternodeUpdate) -> Result<bool, String> {
        // Get the entry from the update - return error if not present
        let entry = update
            .entry
            .as_ref()
            .ok_or("MasternodeUpdate must have an entry for signature verification")?;

        // Get the operator public key from the masternode entry
        let operator_public_key = &entry.identity.operator_public_key;

        // Create the message to verify (serialize update without signature)
        let mut update_for_verification = update.clone();
        update_for_verification.signature = vec![]; // Clear signature for verification

        let message = bincode::serialize(&update_for_verification)
            .map_err(|e| format!("Failed to serialize update for verification: {}", e))?;

        // Verify signature using the operator public key
        let signature_bytes: [u8; 64] = update
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length, expected 64 bytes".to_string())?;

        // Use Ed25519 verification
        let public_key = ed25519_dalek::PublicKey::from_bytes(operator_public_key)
            .map_err(|e| format!("Invalid public key format: {}", e))?;

        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        public_key
            .verify(&message, &signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    /// Add a masternode update to be propagated
    pub fn add_masternode_update(
        &self,
        update_type: MasternodeUpdateType,
        entry: Option<MasternodeEntry>,
        operator_private_key: &[u8; 32],
    ) -> Result<(), String> {
        let block_height = *self
            .current_block_height
            .lock()
            .map_err(|e| e.to_string())?;

        let entry = entry.ok_or("Masternode entry is required for update")?;
        let masternode_id = MasternodeID(entry.identity.collateral_outpoint.clone());

        let mut update = MasternodeUpdate {
            masternode_id,
            update_type,
            entry: Some(entry),
            block_height,
            signature: vec![], // Will be filled by signing
        };

        // Sign the update
        self.sign_masternode_update(&mut update, operator_private_key)?;

        {
            let mut pending = self.pending_updates.lock().map_err(|e| e.to_string())?;
            pending.push(update);
        }

        // Trigger immediate broadcast if we have enough updates
        let _ = self.maybe_broadcast_updates();

        Ok(())
    }

    /// Broadcast pending masternode updates
    fn maybe_broadcast_updates(&self) -> Result<(), String> {
        let updates = {
            let mut pending = self.pending_updates.lock().map_err(|e| e.to_string())?;
            if pending.len() >= self.config.max_update_batch_size {
                pending.drain(..).collect::<Vec<_>>()
            } else {
                return Ok(()); // Not enough updates to broadcast yet
            }
        };

        let mut outgoing = self.outgoing_messages.lock().map_err(|e| e.to_string())?;
        for update in updates {
            let message = P2PMessage::MasternodeUpdate(update);
            outgoing.push(message);
        }

        info!(
            "Broadcasted {} masternode updates",
            self.config.max_update_batch_size
        );
        Ok(())
    }

    /// Force broadcast all pending updates
    pub fn flush_pending_updates(&self) -> Result<(), String> {
        let updates = {
            let mut pending = self.pending_updates.lock().map_err(|e| e.to_string())?;
            let len = pending.len();
            let updates = pending.drain(..).collect::<Vec<_>>();
            (updates, len)
        };

        let (updates, len) = updates;
        if !updates.is_empty() {
            let mut outgoing = self.outgoing_messages.lock().map_err(|e| e.to_string())?;
            for update in updates {
                let message = P2PMessage::MasternodeUpdate(update);
                outgoing.push(message);
            }

            info!("Flushed {} pending masternode updates", len);
        }

        Ok(())
    }

    /// Handle incoming masternode list request
    pub fn handle_list_request(
        &self,
        request: MasternodeListRequest,
        peer_id: String,
    ) -> Result<(), String> {
        debug!(
            "Received masternode list request from peer {} with request_id {}",
            peer_id, request.request_id
        );

        // Get a snapshot of the current masternode list
        let (masternodes, _current_hash, count) = {
            let list = self.masternode_list.lock().map_err(|e| e.to_string())?;
            let hash = self.current_list_hash.lock().map_err(|e| e.to_string())?;

            // For now, always send the full list
            // In a real implementation, we might track what the peer has and only send updates
            let entries: Vec<MasternodeEntry> = list.map.values().cloned().collect();
            let count = entries.len();

            (entries, *hash, count)
        };

        // Create and send the response
        let response = MasternodeListResponse {
            request_id: request.request_id, // Echo back the request ID
            masternodes,
        };

        let message = P2PMessage::MasternodeListResponse(response);
        let mut outgoing = self.outgoing_messages.lock().map_err(|e| e.to_string())?;
        outgoing.push(message);

        info!(
            "Sent masternode list response to peer {} with {} entries",
            peer_id, count
        );

        Ok(())
    }

    /// Handle incoming masternode list response
    pub fn handle_list_response(
        &self,
        response: MasternodeListResponse,
        peer_id: String,
    ) -> Result<(), String> {
        debug!(
            "Received masternode list response from peer {} with request_id {}",
            peer_id, response.request_id
        );

        // Store the length before moving response.masternodes
        let num_entries = response.masternodes.len();

        // Create a masternode list from the response
        let map: HashMap<_, _> = response
            .masternodes
            .into_iter()
            .map(|entry| {
                (
                    MasternodeID(entry.identity.collateral_outpoint.clone()),
                    entry,
                )
            })
            .collect();

        let received_list = MasternodeList { map };

        // Calculate the hash of the received list
        let received_hash = Self::calculate_list_hash(&received_list);

        // Always update for now since we don't have block height info in the response
        // In a real implementation, we might want to track request IDs and verify hashes
        {
            let mut list = self.masternode_list.lock().map_err(|e| e.to_string())?;
            *list = received_list;
        }

        {
            let mut current_hash = self.current_list_hash.lock().map_err(|e| e.to_string())?;
            *current_hash = received_hash;
        }

        info!(
            "Updated masternode list from peer {} with {} entries",
            peer_id, num_entries
        );

        // Remove peer from syncing set
        {
            let mut syncing = self.syncing_peers.lock().map_err(|e| e.to_string())?;
            syncing.remove(&peer_id);
        }

        Ok(())
    }

    /// Handle incoming masternode update
    pub fn handle_masternode_update(
        &self,
        update: MasternodeUpdate,
        peer_id: String,
    ) -> Result<(), String> {
        debug!(
            "Received masternode update from peer {} for masternode {:?}",
            peer_id, update.masternode_id
        );

        // Verify the update signature
        if !self.verify_update_signature(&update)? {
            return Err(format!(
                "Invalid signature for masternode update from peer {}",
                peer_id
            ));
        }

        // Apply the update to our masternode list
        let mut list = self.masternode_list.lock().unwrap();

        match update.update_type {
            MasternodeUpdateType::Registration => {
                let entry = update
                    .entry
                    .ok_or("Registration update requires entry data")?;
                let outpoint = entry.identity.collateral_outpoint.clone();
                info!("Applied masternode registration for {:?}", outpoint);
                list.map.insert(MasternodeID(outpoint), entry);
            }
            MasternodeUpdateType::StatusChange => {
                let entry = update
                    .entry
                    .ok_or("Status change update requires entry data")?;
                let outpoint = entry.identity.collateral_outpoint.clone();
                info!("Applied masternode status change for {:?}", outpoint);
                list.map.insert(MasternodeID(outpoint), entry);
            }
            MasternodeUpdateType::Deregistration => {
                let outpoint = update.masternode_id.0.clone();
                list.map.remove(&update.masternode_id);
                info!("Applied masternode deregistration for {:?}", outpoint);
            }
            MasternodeUpdateType::PoSeUpdate => {
                let masternode_id = update.masternode_id.clone();
                if let Some(entry) = list.map.get_mut(&masternode_id) {
                    // Update PoSe-related fields using the block height from the update
                    entry.last_successful_pose_height = update.block_height as u32;
                    info!("Applied PoSe update for {:?}", masternode_id);
                }
            }
            MasternodeUpdateType::DKGParticipation => {
                let masternode_id = update.masternode_id.clone();
                if let Some(entry) = list.map.get_mut(&masternode_id) {
                    // Update DKG participation stats
                    entry.dkg_participation_count += 1;
                    info!("Applied DKG participation update for {:?}", masternode_id);
                }
            }
        }

        // Update our list hash
        let new_hash = Self::calculate_list_hash(&list);
        drop(list); // Release the lock

        {
            let mut current_hash = self.current_list_hash.lock().map_err(|e| e.to_string())?;
            *current_hash = new_hash;
        }

        // Update last sync time
        {
            let mut last_sync = self.last_sync_times.lock().map_err(|e| e.to_string())?;
            last_sync.insert(peer_id.clone(), Instant::now());
        }

        info!("Processed masternode update from peer {}", peer_id);
        Ok(())
    }

    /// Request masternode list from a peer
    pub fn request_masternode_list(&self, peer_id: String) -> Result<(), String> {
        debug!("Requesting masternode list from peer {}", peer_id);

        // Check if we're already syncing with this peer
        {
            let mut syncing = self.syncing_peers.lock().map_err(|e| e.to_string())?;
            if syncing.contains(&peer_id) {
                debug!("Already syncing with peer {}", peer_id);
                return Ok(());
            }
            syncing.insert(peer_id.clone());
        }

        // Generate a unique request ID
        let request_id = {
            let mut rng = rand::thread_rng();
            rng.gen::<u64>()
        };

        // Create and send request
        let request = MasternodeListRequest { request_id };

        let message = P2PMessage::MasternodeListRequest(request);
        let mut outgoing = self.outgoing_messages.lock().map_err(|e| e.to_string())?;
        outgoing.push(message);

        // Update last sync time
        {
            let mut last_sync = self.last_sync_times.lock().map_err(|e| e.to_string())?;
            last_sync.insert(peer_id.clone(), Instant::now());
        }

        info!(
            "Sent masternode list request to peer {} with request_id {}",
            peer_id, request_id
        );
        Ok(())
    }

    /// Periodic sync with peers
    pub fn periodic_sync(&self, connected_peers: Vec<String>) -> Result<(), String> {
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

        // Request lists from peers and collect any errors
        let mut last_error = None;
        for peer_id in peers_to_sync {
            if let Err(e) = self.request_masternode_list(peer_id) {
                last_error = Some(e);
            }
        }

        // Flush any pending updates
        let _ = self.flush_pending_updates();

        // Return the last error if there was one, or Ok(()) otherwise
        match last_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
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
        let active_count = list
            .map
            .values()
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

    /// Handle a full masternode list sync (replace local list with received entries)
    pub fn handle_full_list_sync(
        &self,
        entries: Vec<MasternodeEntry>,
        peer_id: String,
    ) -> Result<(), String> {
        let map: HashMap<_, _> = entries
            .into_iter()
            .map(|entry| {
                (
                    MasternodeID(entry.identity.collateral_outpoint.clone()),
                    entry,
                )
            })
            .collect();
        let received_list = MasternodeList { map };
        let received_hash = Self::calculate_list_hash(&received_list);
        {
            let mut list = self.masternode_list.lock().map_err(|e| e.to_string())?;
            *list = received_list;
        }
        {
            let mut current_hash = self.current_list_hash.lock().map_err(|e| e.to_string())?;
            *current_hash = received_hash;
        }
        info!(
            "Updated masternode list from peer {} via full sync",
            peer_id
        );
        Ok(())
    }

    /// Sign a masternode update using the operator private key
    fn sign_masternode_update(
        &self,
        update: &mut MasternodeUpdate,
        operator_private_key: &[u8; 32],
    ) -> Result<(), String> {
        // Create the message to sign (serialize update without signature)
        let mut update_for_signing = update.clone();
        update_for_signing.signature = vec![]; // Clear signature for signing

        let message = bincode::serialize(&update_for_signing)
            .map_err(|e| format!("Failed to serialize update for signing: {}", e))?;

        // Create Ed25519 keypair from private key
        let private_key = ed25519_dalek::SecretKey::from_bytes(operator_private_key)
            .map_err(|e| format!("Invalid private key format: {}", e))?;

        let public_key = ed25519_dalek::PublicKey::from(&private_key);
        let keypair = ed25519_dalek::Keypair {
            secret: private_key,
            public: public_key,
        };

        // Sign the message
        let signature = keypair.sign(&message);

        // Store the signature in the update
        update.signature = signature.to_bytes().to_vec();

        Ok(())
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
