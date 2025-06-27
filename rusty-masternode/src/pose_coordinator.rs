//! PoSe (Proof of Service) coordinator for managing challenges and responses across the network

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{info, warn, error, debug};

use rusty_shared_types::masternode::{MasternodeList, MasternodeID, PoSeChallenge, PoSeResponse, MasternodeStatus};
use rusty_shared_types::Hash;
use rusty_p2p::types::P2PMessage;
use crate::pose::{PoSeManager, PoSeConfig, PoSeStats};
use ed25519_dalek::SecretKey;

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
    /// Our private key for signing
    private_key: Option<SigningKey>,
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
        private_key: Option<SigningKey>,
    ) -> Self {
        let pose_manager = Arc::new(Mutex::new(PoSeManager::new(pose_config)));

        Self {
            pose_manager,
            our_masternode_id,
            private_key,
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
            if let (Some(our_id), Some(ref private_key)) = (&self.our_masternode_id, &self.private_key) {
                self.maybe_generate_challenges(height, block_hash, our_id, private_key);
            }
        }

        // Perform periodic maintenance
        self.periodic_maintenance();
    }

    /// Generate PoSe challenges if it's time to do so
    fn maybe_generate_challenges(
        &self,
        block_height: u64,
        block_hash: &Hash,
        our_masternode_id: &MasternodeID,
        private_key: &SigningKey,
    ) {
        let mut pose_manager = self.pose_manager.lock().unwrap();
        
        if pose_manager.should_generate_challenges(block_height) {
            let masternode_list = self.masternode_list.lock().unwrap();
            
            match pose_manager.generate_challenges(
                block_height,
                block_hash,
                &masternode_list,
                private_key,
                our_masternode_id,
            ) {
                Ok(challenges) => {
                    drop(masternode_list); // Release the lock
                    drop(pose_manager); // Release the lock
                    
                    // Broadcast challenges
                    for challenge in challenges {
                        self.broadcast_pose_challenge(challenge);
                    }
                }
                Err(e) => {
                    error!("Failed to generate PoSe challenges: {}", e);
                }
            }
        }
    }

    /// Handle incoming PoSe challenge
    pub fn handle_pose_challenge(&self, challenge: PoSeChallenge) -> Result<(), String> {
        // Check if this challenge is for us
        if let Some(our_id) = &self.our_masternode_id {
            if challenge.challenger_masternode_id == *our_id {
                // This is a challenge we generated, ignore it
                return Ok(());
            }

            // Check if we need to respond to this challenge
            if self.config.respond_to_challenges {
                // Find if we are the target (this would need to be determined by the challenge content)
                // For now, we'll assume all masternodes should validate challenges
                self.validate_and_maybe_respond_to_challenge(challenge)?;
            }
        }

        Ok(())
    }

    /// Validate a challenge and respond if we are the target
    fn validate_and_maybe_respond_to_challenge(&self, challenge: PoSeChallenge) -> Result<(), String> {
        // First, validate the challenge signature
        let masternode_list = self.masternode_list.lock().unwrap();
        let challenger_entry = masternode_list.map.get(&challenge.challenger_masternode_id)
            .ok_or_else(|| format!("Challenger masternode {:?} not found", challenge.challenger_masternode_id))?;

        // TODO: Validate challenge signature using challenger's public key
        
        // If we are a masternode and this challenge might be for us, check if we should respond
        if let (Some(our_id), Some(ref private_key)) = (&self.our_masternode_id, &self.private_key) {
            // In a real implementation, we'd need to determine if this challenge is specifically for us
            // For now, we'll use a simple heuristic based on the challenge nonce
            let should_respond = self.is_challenge_for_us(&challenge, our_id);
            
            if should_respond {
                let pose_manager = self.pose_manager.lock().unwrap();
                match pose_manager.generate_pose_response(&challenge, our_id, private_key) {
                    Ok(response) => {
                        drop(pose_manager);
                        drop(masternode_list);
                        self.broadcast_pose_response(response);
                        info!("Generated and broadcasted PoSe response for challenge from {:?}", 
                              challenge.challenger_masternode_id);
                    }
                    Err(e) => {
                        error!("Failed to generate PoSe response: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Determine if a challenge is for us (simplified heuristic)
    fn is_challenge_for_us(&self, challenge: &PoSeChallenge, our_id: &MasternodeID) -> bool {
        // This is a simplified implementation
        // In reality, the challenge would contain the target masternode ID
        // or we'd use a deterministic function to determine targets
        let hash_input = format!("{:?}{}", challenge.challenge_nonce, our_id.0[0]);
        let hash = blake3::hash(hash_input.as_bytes());
        hash.as_bytes()[0] % 10 == 0 // 10% chance we are the target
    }

    /// Handle incoming PoSe response
    pub fn handle_pose_response(&self, response: PoSeResponse) -> Result<(), String> {
        let current_height = *self.current_block_height.lock().unwrap();
        let masternode_list = self.masternode_list.lock().unwrap();
        
        let mut pose_manager = self.pose_manager.lock().unwrap();
        match pose_manager.handle_pose_response(response.clone(), current_height, &masternode_list) {
            Ok(is_valid) => {
                if is_valid {
                    info!("Valid PoSe response processed from masternode {:?}", response.target_masternode_id);
                } else {
                    warn!("Invalid PoSe response from masternode {:?}", response.target_masternode_id);
                    // Could trigger slashing process here
                }
            }
            Err(e) => {
                error!("Failed to process PoSe response: {}", e);
            }
        }

        Ok(())
    }

    /// Broadcast a PoSe challenge
    fn broadcast_pose_challenge(&self, challenge: PoSeChallenge) {
        // Convert to P2P message and queue for broadcast
        // Note: This would require adding PoSeChallenge to P2PMessage enum
        debug!("Broadcasting PoSe challenge: {:?}", challenge);
        
        // For now, we'll store it in a way that can be retrieved
        // In a real implementation, this would be added to P2PMessage enum
    }

    /// Broadcast a PoSe response
    fn broadcast_pose_response(&self, response: PoSeResponse) {
        let message = P2PMessage::PoSeResponse(response);
        let mut outgoing = self.outgoing_messages.lock().unwrap();
        outgoing.push(message);
    }

    /// Perform periodic maintenance tasks
    fn periodic_maintenance(&self) {
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
        let current_height = *self.current_block_height.lock().unwrap();
        
        // Check for timed-out challenges
        let mut pose_manager = self.pose_manager.lock().unwrap();
        let timed_out_masternodes = pose_manager.check_challenge_timeouts(current_height);
        
        // Add timed-out masternodes to pending slashes
        if !timed_out_masternodes.is_empty() {
            let mut pending_slashes = self.pending_slashes.lock().unwrap();
            for mn_id in &timed_out_masternodes {
                if pose_manager.should_slash_masternode(mn_id) {
                    pending_slashes.push(mn_id.clone());
                    warn!("Masternode {:?} marked for slashing due to PoSe failures", mn_id);
                }
            }
        }

        // Clean up old history
        pose_manager.cleanup_old_history(current_height, self.config.history_retention_blocks);

        debug!("PoSe maintenance completed. Processed {} timeouts", timed_out_masternodes.len());
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
        let active_masternodes = masternode_list.map.values()
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
