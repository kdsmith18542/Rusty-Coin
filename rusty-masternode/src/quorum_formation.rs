//! Masternode quorum formation with deterministic selection algorithms
//!
//! This module implements deterministic quorum formation for various masternode services
//! including OxideSend, FerrousShield, governance, and PoSe challenges.

use blake3;
use hex;
use log::{debug, info};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

use rusty_shared_types::masternode::MasternodeID;
use rusty_shared_types::{
    dkg::{DKGParams, DKGParticipant, DKGSession, DKGSessionID},
    masternode::{MasternodeEntry, MasternodeList, MasternodeStatus},
    Hash,
};

/// Configuration for quorum formation
#[derive(Debug, Clone)]
pub struct QuorumConfig {
    /// Minimum number of active masternodes required for quorum formation
    pub min_active_masternodes: usize,
    /// OxideSend quorum size
    pub oxidesend_quorum_size: usize,
    /// FerrousShield coordinator quorum size
    pub ferrousshield_quorum_size: usize,
    /// Governance voting quorum size
    pub governance_quorum_size: usize,
    /// PoSe challenger count
    pub pose_challenger_count: usize,
    /// Minimum masternode score for quorum participation
    pub min_masternode_score: f32,
    /// Maximum number of consecutive quorum participations before rotation
    pub max_consecutive_participations: u32,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            min_active_masternodes: 10,
            oxidesend_quorum_size: 12,
            ferrousshield_quorum_size: 7,
            governance_quorum_size: 15,
            pose_challenger_count: 3,
            min_masternode_score: 0.8,
            max_consecutive_participations: 5,
        }
    }
}

/// Types of quorums that can be formed
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuorumType {
    OxideSend,
    FerrousShield,
    Governance,
    PoSeChallenger,
    DKGParticipant,
    Custom(String),
}

/// Represents a formed quorum with its members and metadata
#[derive(Debug, Clone)]
pub struct FormedQuorum {
    pub quorum_type: QuorumType,
    pub quorum_id: Hash,
    pub members: Vec<rusty_shared_types::masternode::MasternodeID>,
    pub threshold: u32,
    pub creation_block_height: u64,
    pub creation_block_hash: Hash,
    pub expiration_block_height: u64,
    pub dkg_session: Option<DKGSession>,
    pub selection_seed: Hash,
}

/// Masternode scoring criteria for quorum selection
#[derive(Debug, Clone)]
pub struct MasternodeScore {
    pub masternode_id: rusty_shared_types::masternode::MasternodeID,
    pub uptime_score: f32,        // Based on PoSe success rate
    pub dkg_score: f32,           // Based on DKG participation success
    pub participation_score: f32, // Based on recent quorum participation
    pub reputation_score: f32,    // Overall reputation
    pub total_score: f32,
}

/// Quorum formation manager
pub struct QuorumFormationManager {
    config: QuorumConfig,
    active_quorums: HashMap<Hash, FormedQuorum>,
    masternode_participation_history:
        HashMap<rusty_shared_types::masternode::MasternodeID, Vec<QuorumParticipation>>,
}

/// Record of masternode participation in quorums
#[derive(Debug, Clone)]
struct QuorumParticipation {
    quorum_type: QuorumType,
}

impl QuorumFormationManager {
    /// Create a new quorum formation manager
    pub fn new(config: QuorumConfig) -> Self {
        Self {
            config,
            active_quorums: HashMap::new(),
            masternode_participation_history: HashMap::new(),
        }
    }

    /// Form a quorum for a specific service type
    pub fn form_quorum(
        &mut self,
        quorum_type: QuorumType,
        masternode_list: &MasternodeList,
        block_height: u64,
        block_hash: &Hash,
        additional_criteria: Option<Box<dyn Fn(&MasternodeEntry) -> bool + '_>>,
    ) -> Result<FormedQuorum, String> {
        // Check if we have enough active masternodes
        let active_masternodes = self.get_active_masternodes(masternode_list);
        if active_masternodes.len() < self.config.min_active_masternodes {
            return Err(format!(
                "Insufficient active masternodes: {} < {}",
                active_masternodes.len(),
                self.config.min_active_masternodes
            ));
        }

        // Get quorum size for this type
        let quorum_size = self.get_quorum_size(&quorum_type);
        if active_masternodes.len() < quorum_size {
            return Err(format!(
                "Insufficient masternodes for {} quorum: {} < {}",
                self.quorum_type_name(&quorum_type),
                active_masternodes.len(),
                quorum_size
            ));
        }

        // Score and filter masternodes
        let mut scored_masternodes = self.score_masternodes(&active_masternodes, &quorum_type, masternode_list);

        // Apply additional criteria if provided
        if let Some(criteria) = additional_criteria {
            scored_masternodes.retain(|score| {
                if let Some(entry) = masternode_list.map.get(&score.masternode_id) {
                    criteria(entry)
                } else {
                    false
                }
            });
        }

        // Filter by minimum score
        scored_masternodes.retain(|score| score.total_score >= self.config.min_masternode_score);

        if scored_masternodes.len() < quorum_size {
            return Err(format!(
                "Insufficient qualified masternodes for {} quorum after filtering",
                self.quorum_type_name(&quorum_type)
            ));
        }

        // Deterministic selection using DPRF
        let selected_masternodes = self.deterministic_selection(
            &scored_masternodes,
            quorum_size,
            &quorum_type,
            block_height,
            block_hash,
        )?;

        // Calculate threshold
        let threshold = self.calculate_threshold(quorum_size, &quorum_type);

        // Generate quorum ID
        let quorum_id = self.generate_quorum_id(&selected_masternodes, &quorum_type, block_hash);

        // Create DKG session if needed
        let dkg_session = if self.requires_dkg(&quorum_type) {
            Some(self.create_dkg_session(
                &selected_masternodes,
                threshold,
                block_height,
                &quorum_id,
                masternode_list,
            )?)
        } else {
            None
        };

        // Calculate expiration
        let expiration_block_height = block_height + self.get_quorum_duration(&quorum_type);

        let quorum = FormedQuorum {
            quorum_type: quorum_type.clone(),
            quorum_id,
            members: selected_masternodes.clone(),
            threshold,
            creation_block_height: block_height,
            creation_block_hash: *block_hash,
            expiration_block_height,
            dkg_session,
            selection_seed: self.generate_selection_seed(&quorum_type, block_height, block_hash),
        };

        // Record participation (using references to avoid cloning the quorum)
        for mn_id in &selected_masternodes {
            self.record_participation(mn_id.clone(), &quorum);
        }

        // Store active quorum (clone is necessary here as we need to return the quorum)
        self.active_quorums.insert(quorum_id, quorum.clone());

        info!(
            "Formed {} quorum with {} members at height {}",
            self.quorum_type_name(&quorum_type),
            selected_masternodes.len(),
            block_height
        );

        Ok(quorum)
    }

    /// Get active masternodes from the masternode list
    fn get_active_masternodes(
        &self,
        masternode_list: &MasternodeList,
    ) -> Vec<rusty_shared_types::masternode::MasternodeID> {
        masternode_list
            .map
            .iter()
            .filter(|(_, entry)| entry.status == MasternodeStatus::Active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Score masternodes for quorum selection
    fn score_masternodes(
        &self,
        masternodes: &[rusty_shared_types::masternode::MasternodeID],
        quorum_type: &QuorumType,
        masternode_list: &MasternodeList,
    ) -> Vec<MasternodeScore> {
        masternodes
            .iter()
            .filter_map(|mn_id| {
                // Get the masternode entry for real data
                let mn_entry = masternode_list.map.get(mn_id)?;

                // Get participation history without cloning if possible
                let participation_history = self
                    .masternode_participation_history
                    .get(mn_id)
                    .map(|hist| hist.as_slice())
                    .unwrap_or(&[]);

                // Calculate uptime score based on PoSe failure count
                // Lower failure count = higher score
                // Max failures considered: 10, score decreases linearly
                let max_failures = 10.0;
                let uptime_score = (1.0 - (mn_entry.pose_failure_count as f32 / max_failures)).max(0.0);

                // Calculate DKG score directly from success rate
                let dkg_score = mn_entry.dkg_success_rate;

                // Calculate participation score (lower is better for load balancing)
                let recent_participations = participation_history
                    .iter()
                    .filter(|p| p.quorum_type == *quorum_type)
                    .count() as f32;
                let participation_score = (1.0 / (1.0 + recent_participations * 0.1)).max(0.1);

                // Calculate reputation score (combination of factors)
                let reputation_score = (uptime_score + dkg_score + participation_score) / 3.0;

                // Total score with weights
                let total_score = uptime_score * 0.4
                    + dkg_score * 0.3
                    + participation_score * 0.2
                    + reputation_score * 0.1;

                Some(MasternodeScore {
                    masternode_id: mn_id.clone(),
                    uptime_score,
                    dkg_score,
                    participation_score,
                    reputation_score,
                    total_score,
                })
            })
            .collect()
    }

    /// Deterministic selection using pseudo-random function
    fn deterministic_selection(
        &self,
        scored_masternodes: &[MasternodeScore],
        quorum_size: usize,
        quorum_type: &QuorumType,
        block_height: u64,
        block_hash: &Hash,
    ) -> Result<Vec<rusty_shared_types::masternode::MasternodeID>, String> {
        if scored_masternodes.is_empty() {
            return Err("No masternodes available for selection".to_string());
        }

        // Ensure we have enough masternodes to form a quorum
        if scored_masternodes.len() < quorum_size {
            return Err(format!(
                "Not enough masternodes ({} available, {} needed)",
                scored_masternodes.len(),
                quorum_size
            ));
        }

        let seed = self.generate_selection_seed(quorum_type, block_height, block_hash);
        // Convert Hash to [u8; 32] for the seed
        let seed_bytes: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "Failed to convert seed to [u8; 32]")?;
        let mut rng = ChaCha8Rng::from_seed(seed_bytes);

        // Simple weighted random selection based on scores
        let total_score: f32 = scored_masternodes.iter().map(|s| s.total_score).sum();
        if total_score <= 0.0 {
            return Err("No valid masternodes with positive scores".to_string());
        }

        let mut selected = Vec::with_capacity(quorum_size);
        let mut available: Vec<_> = scored_masternodes.iter().collect();

        while selected.len() < quorum_size && !available.is_empty() {
            let random_value: f32 = rng.gen_range(0.0..total_score);
            let mut cumulative = 0.0;

            for (i, mn) in available.iter().enumerate() {
                cumulative += mn.total_score;
                if random_value <= cumulative || i == available.len() - 1 {
                    let selected_id = mn.masternode_id.clone();
                    selected.push(selected_id);
                    available.remove(i);
                    break;
                }
            }
        }

        Ok(selected)
    }

    /// Generate deterministic seed for selection
    fn generate_selection_seed(
        &self,
        quorum_type: &QuorumType,
        block_height: u64,
        block_hash: &Hash,
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();
        // Convert quorum type to string and use its bytes
        let type_str = match quorum_type {
            QuorumType::OxideSend => "oxidesend",
            QuorumType::FerrousShield => "ferrousshield",
            QuorumType::Governance => "governance",
            QuorumType::PoSeChallenger => "pose_challenger",
            QuorumType::DKGParticipant => "dkg_participant",
            QuorumType::Custom(s) => s.as_str(),
        };
        hasher.update(type_str.as_bytes());
        hasher.update(&block_height.to_be_bytes());
        // Convert Hash to bytes using as_ref() which is implemented for Hash
        hasher.update(block_hash.as_ref());
        let hash_result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash_result.as_bytes());
        Hash::from(hash_bytes)
    }

    /// Create DKG session for the quorum using actual masternode operator public keys
    ///
    /// # Arguments
    /// * `members` - List of masternode IDs to include in the DKG session
    /// * `threshold` - Minimum number of participants needed for threshold signing
    /// * `block_height` - Current block height for session timeout calculations
    /// * `quorum_id` - Unique ID for this quorum
    /// * `masternode_list` - Reference to the current masternode list to get operator public keys
    ///
    /// # Returns
    /// A new DKGSession if successful, or an error string if any masternode is not found or missing required keys
    pub fn create_dkg_session(
        &self,
        members: &[rusty_shared_types::masternode::MasternodeID],
        threshold: u32,
        block_height: u64,
        quorum_id: &Hash,
        masternode_list: &MasternodeList,
    ) -> Result<DKGSession, String> {
        // Verify we have enough participants
        if (members.len() as u32) < threshold {
            return Err(format!(
                "Insufficient participants: {} < {}",
                members.len(),
                threshold
            ));
        }

        // Prepare DKG parameters according to protocol specs
        // Create DKG parameters with defaults from DKGParams::default()
        let mut params = DKGParams::default();
        // Override specific parameters as needed
        params.min_participants = threshold;
        params.max_participants = members.len() as u32;

        // Convert MasternodeIDs to DKG participants with their actual operator public keys
        let participants: Vec<DKGParticipant> = members
            .iter()
            .enumerate()
            .map(
                |(i, id): (usize, &rusty_shared_types::masternode::MasternodeID)| {
                    // Look up the masternode in the masternode list
                    let mn_entry = masternode_list
                        .map
                        .get(&id)
                        .ok_or_else(|| format!("Masternode not found: {:?}", id))?;

                    // Get the operator public key as bytes
                    let operator_key = mn_entry.identity.operator_public_key.to_vec();
                    if operator_key.is_empty() {
                        return Err(format!("Masternode {:?} has no operator public key", id));
                    }

                    Ok(DKGParticipant {
                        masternode_id: rusty_shared_types::MasternodeID(id.0.clone()),
                        participant_index: i as u32,
                        public_key: operator_key,
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        // Create a new DKG session
        let session_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(quorum_id.as_ref());
            hasher.update(&block_height.to_be_bytes());
            let hash_result = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash_result.as_bytes());
            DKGSessionID(Hash::from(hash_bytes))
        };

        // Create the DKG session with all required parameters
        // Pass params by reference as expected by the DKGSession::new signature
        Ok(DKGSession::new(
            session_id,
            participants,
            threshold,
            block_height,
            &params, // Pass by reference
        ))
    }

    /// Record masternode participation in a quorum
    fn record_participation(
        &mut self,
        mn_id: rusty_shared_types::masternode::MasternodeID,
        quorum: &FormedQuorum,
    ) {
        let participation = QuorumParticipation {
            quorum_type: quorum.quorum_type.clone(),
        };

        self.masternode_participation_history
            .entry(mn_id)
            .or_insert_with(Vec::new)
            .push(participation);
    }

    /// Get quorum size for a specific type
    fn get_quorum_size(&self, quorum_type: &QuorumType) -> usize {
        match quorum_type {
            QuorumType::OxideSend => self.config.oxidesend_quorum_size,
            QuorumType::FerrousShield => self.config.ferrousshield_quorum_size,
            QuorumType::Governance => self.config.governance_quorum_size,
            QuorumType::PoSeChallenger => self.config.pose_challenger_count,
            QuorumType::DKGParticipant => self.config.oxidesend_quorum_size, // Default to OxideSend size
            QuorumType::Custom(_) => self.config.oxidesend_quorum_size,      // Default size
        }
    }

    /// Calculate threshold for a quorum
    fn calculate_threshold(&self, quorum_size: usize, _quorum_type: &QuorumType) -> u32 {
        // Use 2/3 threshold for most quorums
        ((quorum_size * 2 + 2) / 3) as u32
    }

    /// Check if quorum type requires DKG
    fn requires_dkg(&self, quorum_type: &QuorumType) -> bool {
        matches!(
            quorum_type,
            QuorumType::OxideSend | QuorumType::FerrousShield | QuorumType::DKGParticipant
        )
    }

    /// Get quorum duration in blocks
    fn get_quorum_duration(&self, quorum_type: &QuorumType) -> u64 {
        match quorum_type {
            QuorumType::OxideSend => 100,     // ~4 hours
            QuorumType::FerrousShield => 200, // ~8 hours
            QuorumType::Governance => 1000,   // ~2.5 days
            QuorumType::PoSeChallenger => 60, // ~2.5 hours
            QuorumType::DKGParticipant => 50, // ~2 hours
            QuorumType::Custom(_) => 100,     // Default duration
        }
    }

    /// Get human-readable name for quorum type
    fn quorum_type_name(&self, quorum_type: &QuorumType) -> &'static str {
        match quorum_type {
            QuorumType::OxideSend => "OxideSend",
            QuorumType::FerrousShield => "FerrousShield",
            QuorumType::Governance => "Governance",
            QuorumType::PoSeChallenger => "PoSeChallenger",
            QuorumType::DKGParticipant => "DKGParticipant",
            QuorumType::Custom(_) => "Custom",
        }
    }

    /// Generate a unique quorum ID based on the members, type, and block hash
    fn generate_quorum_id(
        &self,
        members: &[MasternodeID],
        quorum_type: &QuorumType,
        block_hash: &Hash,
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();

        // Include quorum type in the hash
        let type_str = self.quorum_type_name(quorum_type);
        hasher.update(type_str.as_bytes());

        // Include all member IDs in the hash
        for member in members {
            // Convert MasternodeID to bytes in a deterministic way
            let txid_bytes = member.0.txid.as_ref();
            let vout_bytes = member.0.vout.to_be_bytes();
            hasher.update(txid_bytes);
            hasher.update(&vout_bytes);
        }

        // Include block hash in the hash
        hasher.update(block_hash.as_ref());

        // Finalize the hash
        let hash_result = hasher.finalize();

        // Convert the hash to our Hash type
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash_result.as_bytes());
        Hash::from(hash_bytes)
    }

    /// Get active quorum by ID
    pub fn get_quorum(&self, quorum_id: &Hash) -> Option<&FormedQuorum> {
        self.active_quorums.get(quorum_id)
    }

    /// Get all active quorums of a specific type
    pub fn get_quorums_by_type(&self, quorum_type: &QuorumType) -> Vec<&FormedQuorum> {
        self.active_quorums
            .values()
            .filter(|quorum| quorum.quorum_type == *quorum_type)
            .collect()
    }

    /// Clean up expired quorums
    pub fn cleanup_expired_quorums(&mut self, current_block_height: u64) {
        let expired_quorums: Vec<Hash> = self
            .active_quorums
            .iter()
            .filter(|(_, quorum)| current_block_height > quorum.expiration_block_height)
            .map(|(id, _)| *id)
            .collect();

        for quorum_id in expired_quorums {
            self.active_quorums.remove(&quorum_id);
            debug!("Removed expired quorum {}", hex::encode(quorum_id));
        }
    }

    /// Get statistics about quorum formation
    pub fn get_formation_stats(&self) -> QuorumFormationStats {
        let total_active_quorums = self.active_quorums.len();
        let quorums_by_type =
            self.active_quorums
                .values()
                .fold(HashMap::new(), |mut acc, quorum| {
                    *acc.entry(quorum.quorum_type.clone()).or_insert(0) += 1;
                    acc
                });

        QuorumFormationStats {
            total_active_quorums,
            quorums_by_type,
            total_masternode_participations: self.masternode_participation_history.len(),
        }
    }
}

/// Statistics about quorum formation
#[derive(Debug, Clone)]
pub struct QuorumFormationStats {
    pub total_active_quorums: usize,
    pub quorums_by_type: HashMap<QuorumType, usize>,
    pub total_masternode_participations: usize,
}
