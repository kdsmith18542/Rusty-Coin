use ed25519_dalek::{PublicKey, Signature, Keypair, SecretKey};
use rusty_crypto::signature::verify_signature;
use rusty_shared_types::{Hash, ConsensusParams};
use rusty_shared_types::masternode::{MasternodeID, PoSeChallenge, PoSeResponse, MasternodeIdentity, MasternodeList, MasternodeStatus};
use std::collections::{HashMap, HashSet};
use log::{info, warn, error, debug};
use rand::{SeedableRng, Rng};
use rand_chacha::ChaCha8Rng;
use blake3;

/// PoSe protocol configuration parameters
#[derive(Debug, Clone)]
pub struct PoSeConfig {
    /// How often PoSe challenges are generated (in blocks)
    pub challenge_period_blocks: u64,
    /// Number of challenger masternodes per period
    pub num_challengers: usize,
    /// Timeout for PoSe responses (in seconds)
    pub response_timeout_seconds: u64,
    /// Maximum number of consecutive failures before slashing
    pub max_consecutive_failures: u32,
    /// Minimum number of masternodes required for PoSe
    pub min_masternodes_for_pose: usize,
    /// Consensus parameters
    pub consensus_params: ConsensusParams,
}

impl Default for PoSeConfig {
    fn default() -> Self {
        Self {
            challenge_period_blocks: 60, // ~2.5 hours at 2.5 min blocks
            num_challengers: 3,
            response_timeout_seconds: 60,
            max_consecutive_failures: 3,
            min_masternodes_for_pose: 10,
            consensus_params: ConsensusParams::default(),
        }
    }
}

/// PoSe challenge manager for coordinating challenges and responses
pub struct PoSeManager {
    config: PoSeConfig,
    active_challenges: HashMap<MasternodeID, PoSeChallenge>,
    challenge_history: HashMap<MasternodeID, Vec<PoSeChallengeRecord>>,
    pending_responses: HashMap<MasternodeID, PoSeResponse>,
}

/// Record of a PoSe challenge for tracking purposes
#[derive(Debug, Clone)]
struct PoSeChallengeRecord {
    challenge: PoSeChallenge,
    response: Option<PoSeResponse>,
    response_received_at: Option<u64>, // Block height when response was received
    is_valid: Option<bool>,
}

impl PoSeManager {
    /// Create a new PoSe manager
    pub fn new(config: PoSeConfig) -> Self {
        Self {
            config,
            active_challenges: HashMap::new(),
            challenge_history: HashMap::new(),
            pending_responses: HashMap::new(),
        }
    }

    /// Check if it's time to generate new PoSe challenges
    pub fn should_generate_challenges(&self, current_block_height: u64) -> bool {
        current_block_height % self.config.challenge_period_blocks == 0
    }

    /// Generate PoSe challenges for the current period
    pub fn generate_challenges(
        &mut self,
        current_block_height: u64,
        block_hash: &Hash,
        masternode_list: &MasternodeList,
        challenger_private_key: &Keypair,
        our_masternode_id: &MasternodeID,
    ) -> Result<Vec<PoSeChallenge>, String> {
        if masternode_list.map.len() < self.config.min_masternodes_for_pose {
            return Ok(Vec::new()); // Not enough masternodes for PoSe
        }

        // Select challenger masternodes deterministically
        let challengers = self.select_challengers(current_block_height, block_hash, masternode_list)?;

        // Check if we are one of the selected challengers
        if !challengers.contains(our_masternode_id) {
            return Ok(Vec::new()); // We are not a challenger this period
        }

        // Select target masternodes for challenges
        let targets = self.select_challenge_targets(current_block_height, block_hash, masternode_list, &challengers)?;

        let mut challenges = Vec::new();

        for target_id in targets {
            let challenge_nonce = self.generate_challenge_nonce(current_block_height, &target_id, block_hash);

            let challenge = PoSeChallenge {
                challenge_nonce,
                challenge_block_hash: *block_hash,
                challenger_masternode_id: our_masternode_id.clone(),
                challenge_generation_block_height: current_block_height,
                signature: vec![], // Will be filled below
            };

            // Sign the challenge
            let challenge_data = self.serialize_challenge_for_signing(&challenge)?;
            let signature = challenger_private_key.sign(&challenge_data);

            let mut signed_challenge = challenge;
            signed_challenge.signature = signature.to_bytes().to_vec();

            // Store the challenge
            self.active_challenges.insert(target_id.clone(), signed_challenge.clone());

            challenges.push(signed_challenge);

            info!("Generated PoSe challenge for masternode {:?} at height {}", target_id, current_block_height);
        }

        Ok(challenges)
    }

    /// Select challenger masternodes using deterministic pseudo-random function
    fn select_challengers(
        &self,
        block_height: u64,
        block_hash: &Hash,
        masternode_list: &MasternodeList,
    ) -> Result<Vec<MasternodeID>, String> {
        let active_masternodes: Vec<&MasternodeID> = masternode_list.map
            .iter()
            .filter(|(_, entry)| entry.status == MasternodeStatus::Active)
            .map(|(id, _)| id)
            .collect();

        if active_masternodes.len() < self.config.num_challengers {
            return Err("Not enough active masternodes for challenger selection".to_string());
        }

        // Create deterministic seed from block height and hash
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&block_height.to_le_bytes());
        seed_data.extend_from_slice(block_hash);
        seed_data.extend_from_slice(b"POSE_CHALLENGER_SELECTION");

        let seed_hash = blake3::hash(&seed_data);
        let mut rng = ChaCha8Rng::from_seed(*seed_hash.as_bytes());

        // Select challengers
        let mut selected_indices = HashSet::new();
        let mut challengers = Vec::new();

        while challengers.len() < self.config.num_challengers && selected_indices.len() < active_masternodes.len() {
            let index = rng.gen_range(0..active_masternodes.len());
            if selected_indices.insert(index) {
                challengers.push(active_masternodes[index].clone());
            }
        }

        Ok(challengers)
    }

    /// Select target masternodes for challenges
    fn select_challenge_targets(
        &self,
        block_height: u64,
        block_hash: &Hash,
        masternode_list: &MasternodeList,
        challengers: &[MasternodeID],
    ) -> Result<Vec<MasternodeID>, String> {
        let active_masternodes: Vec<&MasternodeID> = masternode_list.map
            .iter()
            .filter(|(_, entry)| entry.status == MasternodeStatus::Active)
            .map(|(id, _)| id)
            .collect();

        // Create deterministic seed for target selection
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&block_height.to_le_bytes());
        seed_data.extend_from_slice(block_hash);
        seed_data.extend_from_slice(b"POSE_TARGET_SELECTION");

        let seed_hash = blake3::hash(&seed_data);
        let mut rng = ChaCha8Rng::from_seed(*seed_hash.as_bytes());

        // Select targets (excluding challengers)
        let challenger_set: HashSet<&MasternodeID> = challengers.iter().collect();
        let eligible_targets: Vec<&MasternodeID> = active_masternodes
            .into_iter()
            .filter(|id| !challenger_set.contains(id))
            .collect();

        if eligible_targets.is_empty() {
            return Ok(Vec::new());
        }

        // Select a subset of targets (e.g., 10% of eligible masternodes)
        let num_targets = (eligible_targets.len() / 10).max(1).min(eligible_targets.len());
        let mut selected_indices = HashSet::new();
        let mut targets = Vec::new();

        while targets.len() < num_targets && selected_indices.len() < eligible_targets.len() {
            let index = rng.gen_range(0..eligible_targets.len());
            if selected_indices.insert(index) {
                targets.push(eligible_targets[index].clone());
            }
        }

        Ok(targets)
    }

    /// Generate a deterministic challenge nonce
    fn generate_challenge_nonce(&self, block_height: u64, target_id: &MasternodeID, block_hash: &Hash) -> u64 {
        let mut nonce_data = Vec::new();
        nonce_data.extend_from_slice(&block_height.to_le_bytes());
        nonce_data.extend_from_slice(&target_id.0.txid);
        nonce_data.extend_from_slice(block_hash);
        nonce_data.extend_from_slice(b"POSE_CHALLENGE_NONCE");

        let nonce_hash = blake3::hash(&nonce_data);
        u64::from_le_bytes(nonce_hash.as_bytes()[0..8].try_into().unwrap())
    }

    /// Serialize challenge data for signing
    fn serialize_challenge_for_signing(&self, challenge: &PoSeChallenge) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        data.extend_from_slice(&challenge.challenge_nonce.to_le_bytes());
        data.extend_from_slice(&challenge.challenge_block_hash);
        data.extend_from_slice(&challenge.challenger_masternode_id.0.txid);
        data.extend_from_slice(&challenge.challenge_generation_block_height.to_le_bytes());
        Ok(data)
    }
}

pub fn verify_pose_response(
    challenge: &PoSeChallenge,
    response: &PoSeResponse,
    masternode_identity: &MasternodeIdentity,
    current_block_height: u64,
    params: &ConsensusParams,
) -> bool {
    // 1. Verify the response signature
    let response_data = bincode::serialize(response)
        .expect("Failed to serialize PoSeResponse");

    // Convert owner public key bytes to VerifyingKey
    let owner_pubkey_bytes: [u8; 32] = masternode_identity.collateral_ownership_public_key.clone().try_into().expect("Invalid public key length");
    let owner_verifying_key = VerifyingKey::from_bytes(&owner_pubkey_bytes).expect("Invalid verifying key");

    // Check if the challenge and response nonces match
    if challenge.challenge_nonce != response.challenge_nonce {
        error!("PoSe response nonce mismatch: expected {}, got {}", challenge.challenge_nonce, response.challenge_nonce);
        return false;
    }

    // Verify the signed block hash matches the challenge block hash
    if challenge.challenge_block_hash != response.signed_block_hash.as_slice().try_into().expect("Invalid signed block hash length") {
        error!("PoSe response signed block hash mismatch");
        return false;
    }

    // Verify the response signature against the target masternode's operator public key
    // The response signature signs the challenge_nonce + signed_block_hash
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&response.challenge_nonce.to_le_bytes());
    signed_data.extend_from_slice(&response.signed_block_hash);

    let signature_result = Signature::from_bytes(response.signed_block_hash.as_slice().try_into().map_err(|_| "Invalid signature length").unwrap());

    if signature_result.is_err() {
        error!("Invalid PoSe response signature: {}", signature_result.unwrap_err());
        return false;
    }
    let response_signature = signature_result.unwrap();

    if verify_signature(
        &owner_verifying_key.to_bytes(), // Use the public key bytes for verify_signature
        &signed_data,
        &response_signature,
    ).is_err() {
        error!("PoSe response signature verification failed for masternode {:?}. Signed data hash: {:?}", response.target_masternode_id, blake3::hash(&signed_data));
        return false;
    }

    // 2. Check for response timeliness
    // (This requires `current_block_height` and `challenge_generation_block_height`)
    if current_block_height > challenge.challenge_generation_block_height + params.pose_response_timeout_seconds {
        warn!("PoSe response for masternode {:?} is too late (challenge at {}, response at {})",
              response.target_masternode_id, challenge.challenge_generation_block_height, current_block_height);
        return false;
    }

    info!("PoSe response for masternode {:?} is valid.", response.target_masternode_id);
    true
}

impl PoSeManager {
    /// Handle incoming PoSe response
    pub fn handle_pose_response(
        &mut self,
        response: PoSeResponse,
        current_block_height: u64,
        masternode_list: &MasternodeList,
    ) -> Result<bool, String> {
        // Find the corresponding challenge
        let challenge = self.active_challenges.remove(&response.target_masternode_id)
            .ok_or_else(|| format!("No active challenge found for masternode {:?}", response.target_masternode_id))?;

        // Get the masternode identity for verification
        let masternode_entry = masternode_list.get_masternode(&response.target_masternode_id)
            .ok_or_else(|| format!("Masternode {:?} not found in list", response.target_masternode_id))?;
        let masternode_identity = &masternode_entry.identity;

        let is_valid = verify_pose_response(
            &challenge,
            &response,
            masternode_identity,
            current_block_height,
            &self.config.consensus_params,
        );

        // Record the response in history
        let record = PoSeChallengeRecord {
            challenge: challenge.clone(),
            response: Some(response),
            response_received_at: Some(current_block_height),
            is_valid: Some(is_valid),
        };
        self.challenge_history.entry(challenge.challenger_masternode_id.clone())
            .or_default()
            .push(record);

        Ok(is_valid)
    }

    /// Generate a PoSe response for a received challenge
    pub fn generate_pose_response(
        &self,
        challenge: &PoSeChallenge,
        our_masternode_id: &MasternodeID,
        private_key: &Keypair,
    ) -> Result<PoSeResponse, String> {
        // Sign the challenge_nonce and challenge_block_hash
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&challenge.challenge_nonce.to_le_bytes());
        data_to_sign.extend_from_slice(&challenge.challenge_block_hash);

        let signature = private_key.sign(&data_to_sign);

        Ok(PoSeResponse {
            challenge_nonce: challenge.challenge_nonce,
            signed_block_hash: signature.to_bytes().to_vec(), // The signature itself is the signed_block_hash
            target_masternode_id: our_masternode_id.clone(),
        })
    }

    /// Check for timed-out challenges and mark masternodes as non-responsive
    pub fn check_challenge_timeouts(
        &mut self,
        current_block_height: u64,
    ) -> Vec<MasternodeID> {
        let timeout_blocks = self.config.response_timeout_seconds / 150; // Assuming ~2.5 min blocks
        let mut timed_out_masternodes = Vec::new();

        let expired_challenges: Vec<MasternodeID> = self.active_challenges
            .iter()
            .filter(|(_, challenge)| {
                current_block_height - challenge.challenge_generation_block_height > timeout_blocks
            })
            .map(|(mn_id, _)| mn_id.clone())
            .collect();

        for mn_id in expired_challenges {
            if let Some(challenge) = self.active_challenges.remove(&mn_id) {
                // Record the timeout
                let challenge_record = PoSeChallengeRecord {
                    challenge,
                    response: None,
                    response_received_at: None,
                    is_valid: Some(false),
                };

                self.challenge_history
                    .entry(mn_id.clone())
                    .or_insert_with(Vec::new)
                    .push(challenge_record);

                timed_out_masternodes.push(mn_id.clone());
                warn!("PoSe challenge timed out for masternode {:?}", mn_id);
            }
        }

        timed_out_masternodes
    }

    /// Get PoSe statistics for a masternode
    pub fn get_masternode_pose_stats(&self, masternode_id: &MasternodeID) -> PoSeStats {
        let history = self.challenge_history.get(masternode_id).cloned().unwrap_or_default();

        let total_challenges = history.len();
        let successful_responses = history.iter()
            .filter(|record| record.is_valid == Some(true))
            .count();
        let failed_responses = history.iter()
            .filter(|record| record.is_valid == Some(false))
            .count();
        let pending_challenges = if self.active_challenges.contains_key(masternode_id) { 1 } else { 0 };

        // Calculate consecutive failures
        let mut consecutive_failures = 0;
        for record in history.iter().rev() {
            if record.is_valid == Some(false) {
                consecutive_failures += 1;
            } else if record.is_valid == Some(true) {
                break;
            }
        }

        PoSeStats {
            total_challenges,
            successful_responses,
            failed_responses,
            pending_challenges,
            consecutive_failures,
            success_rate: if total_challenges > 0 {
                successful_responses as f32 / total_challenges as f32
            } else {
                1.0
            },
        }
    }

    /// Check if a masternode should be slashed for PoSe failures
    pub fn should_slash_masternode(&self, masternode_id: &MasternodeID) -> bool {
        let stats = self.get_masternode_pose_stats(masternode_id);
        stats.consecutive_failures >= self.config.max_consecutive_failures
    }

    /// Get all active challenges
    pub fn get_active_challenges(&self) -> &HashMap<MasternodeID, PoSeChallenge> {
        &self.active_challenges
    }

    /// Clear old challenge history to prevent memory bloat
    pub fn cleanup_old_history(&mut self, current_block_height: u64, max_age_blocks: u64) {
        for (_, history) in self.challenge_history.iter_mut() {
            history.retain(|record| {
                current_block_height - record.challenge.challenge_generation_block_height <= max_age_blocks
            });
        }

        // Remove empty histories
        self.challenge_history.retain(|_, history| !history.is_empty());
    }
}

/// PoSe statistics for a masternode
#[derive(Debug, Clone)]
pub struct PoSeStats {
    pub total_challenges: usize,
    pub successful_responses: usize,
    pub failed_responses: usize,
    pub pending_challenges: usize,
    pub consecutive_failures: u32,
    pub success_rate: f32,
}