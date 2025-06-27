//! Masternode quorum formation with deterministic selection algorithms
//! 
//! This module implements deterministic quorum formation for various masternode services
//! including OxideSend, FerrousShield, governance, and PoSe challenges.

use std::collections::{HashMap, HashSet};
use log::{info, warn, error, debug};
use rand::{SeedableRng, Rng};
use rand_chacha::ChaCha8Rng;
use blake3;
use hex;

use rusty_shared_types::masternode::{MasternodeList, MasternodeEntry, MasternodeID, MasternodeStatus};
use rusty_shared_types::dkg::{DKGSession, DKGSessionID, DKGParticipant, DKGParams};
use rusty_shared_types::Hash;

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
#[derive(Debug, Clone, PartialEq, Hash)]
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
    pub members: Vec<MasternodeID>,
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
    pub masternode_id: MasternodeID,
    pub uptime_score: f32,        // Based on PoSe success rate
    pub dkg_score: f32,           // Based on DKG participation success
    pub participation_score: f32,  // Based on recent quorum participation
    pub reputation_score: f32,     // Overall reputation
    pub total_score: f32,
}

/// Quorum formation manager
pub struct QuorumFormationManager {
    config: QuorumConfig,
    active_quorums: HashMap<Hash, FormedQuorum>,
    masternode_participation_history: HashMap<MasternodeID, Vec<QuorumParticipation>>,
}

/// Record of masternode participation in quorums
#[derive(Debug, Clone)]
struct QuorumParticipation {
    quorum_id: Hash,
    quorum_type: QuorumType,
    block_height: u64,
    performance_score: f32,
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
        additional_criteria: Option<Box<dyn Fn(&MasternodeEntry) -> bool>>,
    ) -> Result<FormedQuorum, String> {
        // Check if we have enough active masternodes
        let active_masternodes = self.get_active_masternodes(masternode_list);
        if active_masternodes.len() < self.config.min_active_masternodes {
            return Err(format!("Insufficient active masternodes: {} < {}", 
                              active_masternodes.len(), self.config.min_active_masternodes));
        }

        // Get quorum size for this type
        let quorum_size = self.get_quorum_size(&quorum_type);
        if active_masternodes.len() < quorum_size {
            return Err(format!("Insufficient masternodes for {} quorum: {} < {}", 
                              self.quorum_type_name(&quorum_type), active_masternodes.len(), quorum_size));
        }

        // Score and filter masternodes
        let mut scored_masternodes = self.score_masternodes(&active_masternodes, &quorum_type);
        
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
            return Err(format!("Insufficient qualified masternodes for {} quorum after filtering", 
                              self.quorum_type_name(&quorum_type)));
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

        // Record participation
        for mn_id in &selected_masternodes {
            self.record_participation(mn_id.clone(), &quorum);
        }

        // Store active quorum
        self.active_quorums.insert(quorum_id, quorum.clone());

        info!("Formed {} quorum with {} members at height {}", 
              self.quorum_type_name(&quorum_type), selected_masternodes.len(), block_height);

        Ok(quorum)
    }

    /// Get active masternodes from the masternode list
    fn get_active_masternodes(&self, masternode_list: &MasternodeList) -> Vec<MasternodeID> {
        masternode_list.map
            .iter()
            .filter(|(_, entry)| entry.status == MasternodeStatus::Active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Score masternodes for quorum selection
    fn score_masternodes(&self, masternodes: &[MasternodeID], quorum_type: &QuorumType) -> Vec<MasternodeScore> {
        masternodes.iter().map(|mn_id| {
            let participation_history = self.masternode_participation_history.get(mn_id).cloned().unwrap_or_default();
            
            // Calculate uptime score (placeholder - would use PoSe data)
            let uptime_score = 0.95; // Default high score
            
            // Calculate DKG score (placeholder - would use actual DKG performance)
            let dkg_score = 0.90; // Default high score
            
            // Calculate participation score (lower is better for load balancing)
            let recent_participations = participation_history.iter()
                .filter(|p| p.quorum_type == *quorum_type)
                .count() as f32;
            let participation_score = (1.0 / (1.0 + recent_participations * 0.1)).max(0.1);
            
            // Calculate reputation score (combination of factors)
            let reputation_score = (uptime_score + dkg_score + participation_score) / 3.0;
            
            // Total score with weights
            let total_score = uptime_score * 0.4 + dkg_score * 0.3 + participation_score * 0.2 + reputation_score * 0.1;
            
            MasternodeScore {
                masternode_id: mn_id.clone(),
                uptime_score,
                dkg_score,
                participation_score,
                reputation_score,
                total_score,
            }
        }).collect()
    }

    /// Deterministic selection using pseudo-random function
    fn deterministic_selection(
        &self,
        scored_masternodes: &[MasternodeScore],
        quorum_size: usize,
        quorum_type: &QuorumType,
        block_height: u64,
        block_hash: &Hash,
    ) -> Result<Vec<MasternodeID>, String> {
        // Create deterministic seed
        let seed = self.generate_selection_seed(quorum_type, block_height, block_hash);
        let mut rng = ChaCha8Rng::from_seed(*seed.as_bytes());

        // Sort masternodes by score (descending) for deterministic ordering
        let mut sorted_masternodes = scored_masternodes.to_vec();
        sorted_masternodes.sort_by(|a, b| b.total_score.partial_cmp(&a.total_score).unwrap_or(std::cmp::Ordering::Equal));

        // Use weighted random selection based on scores
        let mut selected = Vec::new();
        let mut available = sorted_masternodes;

        for _ in 0..quorum_size {
            if available.is_empty() {
                break;
            }

            // Calculate total weight
            let total_weight: f32 = available.iter().map(|mn| mn.total_score).sum();
            
            // Select based on weighted probability
            let mut random_weight = rng.gen::<f32>() * total_weight;
            let mut selected_index = 0;
            
            for (i, mn) in available.iter().enumerate() {
                random_weight -= mn.total_score;
                if random_weight <= 0.0 {
                    selected_index = i;
                    break;
                }
            }

            let selected_mn = available.remove(selected_index);
            selected.push(selected_mn.masternode_id);
        }

        if selected.len() < quorum_size {
            return Err(format!("Could not select enough masternodes: {} < {}", selected.len(), quorum_size));
        }

        Ok(selected)
    }

    /// Generate deterministic seed for selection
    fn generate_selection_seed(&self, quorum_type: &QuorumType, block_height: u64, block_hash: &Hash) -> Hash {
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(&block_height.to_le_bytes());
        seed_data.extend_from_slice(block_hash);
        seed_data.extend_from_slice(self.quorum_type_name(quorum_type).as_bytes());
        seed_data.extend_from_slice(b"QUORUM_SELECTION_SEED");
        blake3::hash(&seed_data).into()
    }

    /// Generate quorum ID
    fn generate_quorum_id(&self, members: &[MasternodeID], quorum_type: &QuorumType, block_hash: &Hash) -> Hash {
        let mut id_data = Vec::new();
        for member in members {
            id_data.extend_from_slice(&member.0);
        }
        id_data.extend_from_slice(self.quorum_type_name(quorum_type).as_bytes());
        id_data.extend_from_slice(block_hash);
        blake3::hash(&id_data).into()
    }

    /// Create DKG session for the quorum
    fn create_dkg_session(
        &self,
        members: &[MasternodeID],
        threshold: u32,
        block_height: u64,
        quorum_id: &Hash,
    ) -> Result<DKGSession, String> {
        let participants: Vec<DKGParticipant> = members
            .iter()
            .enumerate()
            .map(|(index, mn_id)| DKGParticipant {
                masternode_id: mn_id.clone(),
                participant_index: index as u32,
                public_key: vec![0u8; 32], // TODO: Get actual public key
            })
            .collect();

        let dkg_session_id = DKGSessionID(*quorum_id);
        let dkg_params = DKGParams::default();

        Ok(DKGSession::new(
            dkg_session_id,
            participants,
            threshold,
            block_height,
            &dkg_params,
        ))
    }

    /// Record masternode participation in a quorum
    fn record_participation(&mut self, mn_id: MasternodeID, quorum: &FormedQuorum) {
        let participation = QuorumParticipation {
            quorum_id: quorum.quorum_id,
            quorum_type: quorum.quorum_type.clone(),
            block_height: quorum.creation_block_height,
            performance_score: 1.0, // Default score, would be updated based on actual performance
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
            QuorumType::Custom(_) => self.config.oxidesend_quorum_size, // Default size
        }
    }

    /// Calculate threshold for a quorum
    fn calculate_threshold(&self, quorum_size: usize, _quorum_type: &QuorumType) -> u32 {
        // Use 2/3 threshold for most quorums
        ((quorum_size * 2 + 2) / 3) as u32
    }

    /// Check if quorum type requires DKG
    fn requires_dkg(&self, quorum_type: &QuorumType) -> bool {
        matches!(quorum_type, QuorumType::OxideSend | QuorumType::FerrousShield | QuorumType::DKGParticipant)
    }

    /// Get quorum duration in blocks
    fn get_quorum_duration(&self, quorum_type: &QuorumType) -> u64 {
        match quorum_type {
            QuorumType::OxideSend => 100,        // ~4 hours
            QuorumType::FerrousShield => 200,    // ~8 hours
            QuorumType::Governance => 1000,      // ~2.5 days
            QuorumType::PoSeChallenger => 60,    // ~2.5 hours
            QuorumType::DKGParticipant => 50,    // ~2 hours
            QuorumType::Custom(_) => 100,        // Default duration
        }
    }

    /// Get human-readable name for quorum type
    fn quorum_type_name(&self, quorum_type: &QuorumType) -> &str {
        match quorum_type {
            QuorumType::OxideSend => "OxideSend",
            QuorumType::FerrousShield => "FerrousShield",
            QuorumType::Governance => "Governance",
            QuorumType::PoSeChallenger => "PoSeChallenger",
            QuorumType::DKGParticipant => "DKGParticipant",
            QuorumType::Custom(name) => name,
        }
    }

    /// Get active quorum by ID
    pub fn get_quorum(&self, quorum_id: &Hash) -> Option<&FormedQuorum> {
        self.active_quorums.get(quorum_id)
    }

    /// Get all active quorums of a specific type
    pub fn get_quorums_by_type(&self, quorum_type: &QuorumType) -> Vec<&FormedQuorum> {
        self.active_quorums.values()
            .filter(|quorum| quorum.quorum_type == *quorum_type)
            .collect()
    }

    /// Clean up expired quorums
    pub fn cleanup_expired_quorums(&mut self, current_block_height: u64) {
        let expired_quorums: Vec<Hash> = self.active_quorums
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
        let quorums_by_type = self.active_quorums.values()
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
