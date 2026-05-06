//! PoSe (Proof of Service) coordinator for managing challenges and responses across the network

use crate::pose::{PoSeConfig, PoSeManager, PoSeStats};
use ed25519_dalek::{Keypair, Signer};
use log::{error, info};
use rusty_shared_types::{
    masternode::{MasternodeID, MasternodeList, MasternodeStatus, PoSeChallenge},
    p2p::P2PMessage,
    Hash,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use thiserror::Error;

type Result<T> = std::result::Result<T, PoSeCoordinatorError>;

#[derive(Error, Debug)]
pub enum PoSeCoordinatorError {
    #[error("Poison error: {0}")]
    PoisonError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Challenge error: {0}")]
    ChallengeError(String),
    #[error("Response error: {0}")]
    ResponseError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Error: {0}")]
    StringError(String),
    #[error("Not a masternode")]
    NotAMasternode,
    #[error("Invalid masternode ID")]
    InvalidMasternodeId,
}

impl<T> From<PoisonError<T>> for PoSeCoordinatorError {
    fn from(err: PoisonError<T>) -> Self {
        PoSeCoordinatorError::PoisonError(err.to_string())
    }
}

impl From<String> for PoSeCoordinatorError {
    fn from(err: String) -> Self {
        PoSeCoordinatorError::StringError(err)
    }
}

impl From<&str> for PoSeCoordinatorError {
    fn from(err: &str) -> Self {
        PoSeCoordinatorError::StringError(err.to_string())
    }
}

/// Configuration for PoSe coordination
#[derive(Debug, Clone)]
pub struct PoSeCoordinatorConfig {
    /// How often to check for PoSe maintenance tasks (in seconds)
    pub maintenance_interval_secs: u64,
    /// How long to keep PoSe history (in blocks)
    pub history_retention_blocks: u64,
    /// Whether this node participates in PoSe challenges
    pub participate_in_challenges: bool,
    /// Whether this node responds to PoSe challenges
    pub respond_to_challenges: bool,
}

impl Default for PoSeCoordinatorConfig {
    fn default() -> Self {
        Self {
            maintenance_interval_secs: 30,
            history_retention_blocks: 10000, // ~1 week at 2.5 min blocks
            participate_in_challenges: true,
            respond_to_challenges: true,
        }
    }
}

/// Coordinates PoSe operations across the network
pub struct PoSeCoordinator {
    /// PoSe manager for handling challenges and responses
    pose_manager: Arc<Mutex<PoSeManager>>,
    /// Our masternode ID (if we are a masternode)
    our_masternode_id: Option<MasternodeID>,
    /// Our keypair for signing
    keypair: Option<Keypair>,
    /// Configuration
    config: PoSeCoordinatorConfig,
    /// Current masternode list
    masternode_list: Arc<Mutex<MasternodeList>>,
    /// Current block height
    current_block_height: Arc<Mutex<u64>>,
    /// Outgoing P2P messages
    outgoing_messages: Arc<Mutex<Vec<P2PMessage>>>,
    /// Last maintenance time
    last_maintenance: Arc<Mutex<Instant>>,
    /// Pending slashing recommendations
    pending_slashes: Arc<Mutex<Vec<MasternodeID>>>,
}

impl PoSeCoordinator {
    /// Create a new PoSe coordinator
    pub fn new(
        pose_config: PoSeConfig,
        coordinator_config: PoSeCoordinatorConfig,
        masternode_list: Arc<Mutex<MasternodeList>>,
        our_masternode_id: Option<MasternodeID>,
        keypair: Option<Keypair>,
    ) -> Self {
        let pose_manager = Arc::new(Mutex::new(PoSeManager::new(pose_config)));

        Self {
            pose_manager,
            our_masternode_id,
            keypair,
            config: coordinator_config,
            masternode_list,
            current_block_height: Arc::new(Mutex::new(0)),
            outgoing_messages: Arc::new(Mutex::new(Vec::new())),
            last_maintenance: Arc::new(Mutex::new(Instant::now())),
            pending_slashes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Update current block height and trigger PoSe operations if needed
    pub fn update_block_height(&self, height: u64, block_hash: &Hash) {
        {
            let mut current_height = self.current_block_height.lock().unwrap();
            *current_height = height;
        }

        // Check if we should generate new challenges
        if self.config.participate_in_challenges {
            if let (Some(our_id), Some(ref keypair)) = (&self.our_masternode_id, &self.keypair) {
                if let Err(e) = self.maybe_generate_challenges(height, block_hash, our_id, keypair)
                {
                    error!("Failed to generate PoSe challenges: {}", e);
                }
            }
        }

        // Perform periodic maintenance
        let _ = self.periodic_maintenance();
    }

    /// Generate PoSe challenges if it's time to do
    fn maybe_generate_challenges(
        &self,
        block_height: u64,
        block_hash: &Hash,
        our_masternode_id: &MasternodeID,
        keypair: &Keypair,
    ) -> Result<()> {
        // Check if we should participate in challenges
        if !self.config.participate_in_challenges {
            return Ok(());
        }

        // (Using a fixed interval of 10 blocks for now, can be made configurable if needed)
        if block_height % 10 != 0 {
            return Ok(());
        }

        // Get the current masternode list
        let masternode_list = self
            .masternode_list
            .lock()
            .map_err(|e| e.to_string())?
            .clone();

        // Get a read lock on the PoSe manager
        let mut pose_manager = self.pose_manager.lock().map_err(|e| e.to_string())?;

        // Select challenger masternodes for this block
        let challengers = pose_manager
            .select_challengers(block_height, block_hash, &masternode_list)
            .map_err(|e| format!("Failed to select challengers: {}", e))?;

        let targets = pose_manager
            .select_challenge_targets(block_height, block_hash, &masternode_list, &challengers)
            .map_err(|e| format!("Failed to select challenge targets: {}", e))?;

        if !targets.is_empty() {
            info!(
                "Selected {} masternodes for PoSe challenges at height {}",
                targets.len(),
                block_height
            );

            // Create and broadcast challenges for each target
            for target_id in targets {
                let challenge_data =
                    pose_manager.serialize_challenge_for_signing(&PoSeChallenge {
                        challenge_nonce: pose_manager.generate_challenge_nonce(
                            block_height,
                            &target_id,
                            block_hash,
                        ),
                        challenge_block_hash: block_hash.clone(),
                        challenger_masternode_id: our_masternode_id.clone(),
                        challenge_generation_block_height: block_height,
                        signature: vec![], // Will be signed below
                    })?;

                let signature = keypair.sign(&challenge_data);
                let challenge = PoSeChallenge {
                    challenge_nonce: pose_manager.generate_challenge_nonce(
                        block_height,
                        &target_id,
                        block_hash,
                    ),
                    challenge_block_hash: block_hash.clone(),
                    challenger_masternode_id: our_masternode_id.clone(),
                    challenge_generation_block_height: block_height,
                    signature: signature.to_bytes().to_vec(),
                };

                // Add to active challenges
                pose_manager
                    .active_challenges
                    .insert(target_id.clone(), challenge.clone());

                // Broadcast the challenge
                drop(pose_manager); // Release the lock before broadcasting
                self.broadcast_pose_challenge(challenge)?;

                // Re-acquire the lock for the next iteration
                pose_manager = self.pose_manager.lock().map_err(|e| e.to_string())?;
            }
        }

        Ok(())
    }

    /// Broadcast a PoSe challenge
    fn broadcast_pose_challenge(&self, challenge: PoSeChallenge) -> Result<()> {
        info!(
            "Broadcasting PoSe challenge for masternode {:?} at height {}",
            challenge.challenger_masternode_id, challenge.challenge_generation_block_height
        );

        // Create P2P message for the challenge
        let p2p_message = P2PMessage::PoSeChallenge(challenge.clone());

        // Add to outgoing messages queue for network layer to process
        {
            let mut outgoing = self.outgoing_messages.lock()?;
            outgoing.push(p2p_message);
        }

        info!(
            "PoSe challenge queued for network broadcast: nonce={:?}, target_height={}",
            challenge.challenge_nonce, challenge.challenge_generation_block_height
        );

        Ok(())
    }

    /// Broadcast a PoSe response
    pub fn broadcast_pose_response(
        &self,
        response: rusty_shared_types::PoSeResponse,
    ) -> Result<()> {
        info!("Broadcasting PoSe response from masternode");

        // Construct the expected PoSeResponse type for P2PMessage
        let pose_response = rusty_shared_types::masternode::PoSeResponse {
            challenge_nonce: response.challenge_nonce,
            signed_block_hash: response.signed_block_hash.clone(),
            target_masternode_id: rusty_shared_types::masternode::MasternodeID(
                response.target_masternode_id.0.clone(),
            ),
        };
        let p2p_message = P2PMessage::PoSeResponse(pose_response);

        // Add to outgoing messages queue for network layer to process
        {
            let mut outgoing = self.outgoing_messages.lock()?;
            outgoing.push(p2p_message);
        }

        info!("PoSe response queued for network broadcast");

        Ok(())
    }

    /// Broadcast a PoSe slashing evidence
    pub fn broadcast_slashing_evidence(&self, masternode_id: &MasternodeID) -> Result<()> {
        info!(
            "Broadcasting PoSe slashing evidence for masternode {:?}",
            masternode_id
        );

        // Create slashing evidence message (would need to be defined in P2PMessage enum)
        // For now, we'll use a generic approach and add the slashing to pending
        {
            let mut pending_slashes = self.pending_slashes.lock()?;
            if !pending_slashes.contains(masternode_id) {
                pending_slashes.push(masternode_id.clone());
                info!(
                    "Added masternode {:?} to pending slashes list",
                    masternode_id
                );
            }
        }

        // In a full implementation, this would create a specific slashing evidence message
        // and broadcast it to the network for other nodes to verify
        info!(
            "PoSe slashing evidence processed for masternode {:?}",
            masternode_id
        );

        Ok(())
    }

    /// Perform periodic maintenance tasks
    pub fn periodic_maintenance(&self) -> Result<()> {
        let now = Instant::now();
        let mut last_run = self.last_maintenance.lock()?;

        // Only run maintenance every 5 minutes
        if now.duration_since(*last_run) < Duration::from_secs(300) {
            return Ok(());
        }

        *last_run = now;

        // Clean up old challenges
        // let mut pending_challenges = self.pending_challenges.lock()?;
        // let current_time = std::time::SystemTime::now()
        //     .duration_since(std::time::UNIX_EPOCH)
        //     .map_err(|e| PoSeCoordinatorError::StringError(e.to_string()))?
        //     .as_secs();

        // pending_challenges.retain(|_, challenge| {
        //     current_time - challenge.timestamp < self.config.challenge_timeout_secs
        // });

        Ok(())
    }

    /// Get PoSe statistics for a masternode
    pub fn get_masternode_stats(&self, masternode_id: &MasternodeID) -> PoSeStats {
        let pose_manager = self.pose_manager.lock().unwrap();
        pose_manager.get_masternode_pose_stats(masternode_id)
    }

    /// Get all masternodes that should be slashed
    pub fn get_pending_slashes(&self) -> Vec<MasternodeID> {
        let mut pending_slashes = self.pending_slashes.lock().unwrap();
        let slashes = pending_slashes.clone();
        pending_slashes.clear();
        slashes
    }

    /// Get outgoing P2P messages
    pub fn get_outgoing_messages(&self) -> Vec<P2PMessage> {
        let mut outgoing = self.outgoing_messages.lock().unwrap();
        let messages = outgoing.clone();
        outgoing.clear();
        messages
    }

    /// Get overall PoSe network statistics
    pub fn get_network_stats(&self) -> PoSeNetworkStats {
        let masternode_list = self.masternode_list.lock().unwrap();
        let pose_manager = self.pose_manager.lock().unwrap();

        let total_masternodes = masternode_list.map.len();
        let active_masternodes = masternode_list
            .map
            .values()
            .filter(|entry| entry.status == MasternodeStatus::Active)
            .count();

        let active_challenges = pose_manager.get_active_challenges().len();
        let pending_slashes = self.pending_slashes.lock().unwrap().len();

        PoSeNetworkStats {
            total_masternodes,
            active_masternodes,
            active_challenges,
            pending_slashes,
            current_block_height: *self.current_block_height.lock().unwrap(),
        }
    }
}

/// Network-wide PoSe statistics
#[derive(Debug, Clone)]
pub struct PoSeNetworkStats {
    pub total_masternodes: usize,
    pub active_masternodes: usize,
    pub active_challenges: usize,
    pub pending_slashes: usize,
    pub current_block_height: u64,
}
