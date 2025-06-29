use serde::{Serialize, Deserialize};
use crate::{OutPoint, TxOutput, TxInput};

use std::collections::HashMap;

/// Represents the unique identifier for a Masternode, derived from its collateral UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MasternodeID(pub OutPoint);

impl MasternodeID {
    /// Get the bytes representation of the MasternodeID
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap_or_default()
    }
}

impl From<OutPoint> for MasternodeID {
    fn from(outpoint: OutPoint) -> Self {
        MasternodeID(outpoint)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MasternodeIdentity {
    pub collateral_outpoint: OutPoint,
    pub operator_public_key: Vec<u8>, // Ed25519 public key
    pub network_address: String, // IP:Port
    pub collateral_ownership_public_key: Vec<u8>, // Public key associated with collateral UTXO
    pub dkg_public_key: Option<Vec<u8>>, // BLS public key for DKG participation
    pub supported_dkg_versions: Vec<u32>, // Supported DKG protocol versions
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeRegistration {
    pub masternode_identity: MasternodeIdentity,
    pub signature: Vec<u8>, // Signature by collateral_ownership_public_key over the identity data
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MasternodeStatus {
    Registered,
    Active,
    Offline,
    Probation,
    Banned,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeEntry {
    pub identity: MasternodeIdentity,
    pub status: MasternodeStatus,
    pub last_successful_pose_height: u32,
    pub pose_failure_count: u32,
    pub last_slashed_height: Option<u32>,
    pub dkg_participation_count: u32, // Number of DKG sessions participated in
    pub dkg_success_rate: f32, // Success rate in DKG sessions (0.0 to 1.0)
    pub active_dkg_sessions: Vec<crate::dkg::DKGSessionID>, // Currently active DKG sessions
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeList {
    pub map: HashMap<MasternodeID, MasternodeEntry>,
}

impl MasternodeList {
    pub fn new() -> Self {
        MasternodeList { map: HashMap::new() }
    }

    pub fn register_masternode(&mut self, registration: MasternodeRegistration, current_height: u32) -> Result<(), String> {
        // Basic validation (more comprehensive validation would be in consensus/masternode.rs)
        let mn_id = MasternodeID(registration.masternode_identity.collateral_outpoint.clone());
        if self.map.contains_key(&mn_id) {
            return Err("Masternode already registered".to_string());
        }

        // In a real scenario, signature verification and collateral amount check would happen here
        // For now, we'll assume validity for the purpose of struct definition.

        let entry = MasternodeEntry {
            identity: registration.masternode_identity,
            status: MasternodeStatus::Registered,
            last_successful_pose_height: current_height,
            pose_failure_count: 0,
            last_slashed_height: None,
            dkg_participation_count: 0,
            dkg_success_rate: 0.0,
            active_dkg_sessions: Vec::new(),
        };
        self.map.insert(mn_id, entry);
        Ok(())
    }

    pub fn update_masternode_status(&mut self, mn_id: MasternodeID, new_status: MasternodeStatus) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(&mn_id) {
            entry.status = new_status;
            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    pub fn get_masternode(&self, mn_id: &MasternodeID) -> Option<&MasternodeEntry> {
        self.map.get(mn_id)
    }

    pub fn remove_masternode(&mut self, mn_id: &MasternodeID) -> Option<MasternodeEntry> {
        self.map.remove(mn_id)
    }

    pub fn count_active_masternodes(&self) -> usize {
        self.map.values()
            .filter(|mn| mn.status == MasternodeStatus::Active)
            .count()
    }

    pub fn total_voting_power(&self) -> u64 {
        // For now, simple count of active masternodes, could be weighted by stake later
        self.count_active_masternodes() as u64
    }

    pub fn reset_pose_failure_count(&mut self, mn_id: &MasternodeID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.pose_failure_count = 0;
            Ok(())
        } else {
            Err("Masternode not found for resetting PoSe failure count.".to_string())
        }
    }

    pub fn increment_pose_failure_count(&mut self, mn_id: &MasternodeID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.pose_failure_count += 1;
            Ok(())
        } else {
            Err("Masternode not found for incrementing PoSe failure count.".to_string())
        }
    }

    pub fn deregister_masternode(&mut self, mn_id: &MasternodeID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            // In a real scenario, this would involve more complex logic,
            // such as releasing collateral or marking for removal after a cool-down period.
            entry.status = MasternodeStatus::Banned;
            Ok(())
        } else {
            Err("Masternode not found for deregistration".to_string())
        }
    }

    pub fn select_masternodes_for_quorum(&self, count: usize) -> Vec<&MasternodeEntry> {
        // TODO: Implement sophisticated quorum selection logic (e.g., deterministic, pseudo-random, based on uptime/performance).
        // For now, a simple selection of active masternodes.
        self.map.values()
            .filter(|mn| mn.status == MasternodeStatus::Active)
            .take(count)
            .collect()
    }

    /// Select masternodes for DKG participation based on DKG success rate and availability
    pub fn select_masternodes_for_dkg(&self, count: usize, min_success_rate: f32) -> Vec<&MasternodeEntry> {
        let mut candidates: Vec<&MasternodeEntry> = self.map.values()
            .filter(|mn| {
                mn.status == MasternodeStatus::Active &&
                mn.dkg_success_rate >= min_success_rate &&
                mn.identity.dkg_public_key.is_some() &&
                !mn.identity.supported_dkg_versions.is_empty()
            })
            .collect();

        // Sort by DKG success rate (descending) and participation count (ascending for load balancing)
        candidates.sort_by(|a, b| {
            b.dkg_success_rate.partial_cmp(&a.dkg_success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.dkg_participation_count.cmp(&b.dkg_participation_count))
        });

        candidates.into_iter().take(count).collect()
    }

    /// Update DKG participation statistics for a masternode
    pub fn update_dkg_participation(&mut self, mn_id: &MasternodeID, success: bool) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.dkg_participation_count += 1;

            // Update success rate using exponential moving average
            let alpha = 0.1; // Smoothing factor
            if success {
                entry.dkg_success_rate = entry.dkg_success_rate * (1.0 - alpha) + alpha;
            } else {
                entry.dkg_success_rate = entry.dkg_success_rate * (1.0 - alpha);
            }

            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    /// Add a DKG session to a masternode's active sessions
    pub fn add_active_dkg_session(&mut self, mn_id: &MasternodeID, session_id: crate::dkg::DKGSessionID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            if !entry.active_dkg_sessions.contains(&session_id) {
                entry.active_dkg_sessions.push(session_id);
            }
            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    /// Remove a DKG session from a masternode's active sessions
    pub fn remove_active_dkg_session(&mut self, mn_id: &MasternodeID, session_id: &crate::dkg::DKGSessionID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.active_dkg_sessions.retain(|id| id != session_id);
            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    /// Get masternodes that support a specific DKG version
    pub fn get_masternodes_by_dkg_version(&self, version: u32) -> Vec<&MasternodeEntry> {
        self.map.values()
            .filter(|mn| {
                mn.status == MasternodeStatus::Active &&
                mn.identity.supported_dkg_versions.contains(&version)
            })
            .collect()
    }

    pub fn distribute_rewards(&mut self, block_height: u32, total_block_reward: u64) {
        let active_masternodes: Vec<&MasternodeID> = self.map.iter()
            .filter(|(_, mn)| mn.status == MasternodeStatus::Active)
            .map(|(id, _)| id)
            .collect();

        if active_masternodes.is_empty() {
            return; // No active masternodes to reward
        }

        let reward_per_masternode = total_block_reward / active_masternodes.len() as u64;

        for mn_id in active_masternodes {
            // In a real implementation, this would create reward transactions
            // and send them to the masternode's payout address.
            // For now, we'll just print a message.
            println!("Masternode {:?} receives {} rewards at block height {}", mn_id, reward_per_masternode, block_height);
        }
    }
}

// Placeholder for Masternode-related transactions (MN_REGISTER_TX, MN_SLASH_TX, etc.)
// These would likely be special transaction types or have specific payload structures.

// Example: MN_REGISTER_TX payload structure
// The MnRegisterTxPayload struct is no longer needed as MasternodeIdentity directly represents the payload fields.

// PoSe related structs
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PoSeChallenge {
    pub challenge_nonce: u64,
    pub challenge_block_hash: [u8; 32],
    pub challenger_masternode_id: MasternodeID,
    pub challenge_generation_block_height: u64,
    pub signature: Vec<u8>, // Signature by challenger's operator key
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PoSeResponse {
    pub challenge_nonce: u64,
    pub signed_block_hash: Vec<u8>, // Signature by target's operator key over challenge_block_hash
    pub target_masternode_id: MasternodeID,
}

// OxideSend related structs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxInputLock {
    pub txid: [u8; 32],
    pub input_index: u32,
    pub masternode_id: MasternodeID,
    pub signature: Vec<u8>, // Signature by masternode's operator key over txid and input_index
}

// FerrousShield related structs (simplified)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FerrousShieldMixRequest {
    pub amount: u64,
    pub participant_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FerrousShieldMixOutput {
    pub output: TxOutput,
    pub participant_signature: Vec<u8>, // Signature by participant over the output
}

/// Represents the reason for a Masternode slashing event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlashingReason {
    MasternodeNonResponse,
    DoubleSigning,
    InvalidBlockProposal,
    InvalidTransaction,
    GovernanceViolation,
}

/// Represents the type of malicious behavior for slashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MaliciousActionType {
    DoubleSigning,
    InvalidServiceProvision,
    GovernanceViolation,
}

/// Proof for a Masternode malicious behavior slashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MasternodeMaliciousProof {
    /// The ID of the Masternode being slashed.
    pub masternode_id: MasternodeID,
    /// The type of malicious action detected.
    pub malicious_action_type: MaliciousActionType,
    /// The block height at which the malicious behavior was detected or proven.
    pub detection_block_height: u64,
    /// Cryptographic proof of the malicious action (e.g., conflicting signatures for double-signing).
    pub proof_data: Vec<u8>,
}

/// Represents a signature from a witness masternode for a non-participation proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// The ID of the witness Masternode.
    pub masternode_id: MasternodeID,
    /// Signature by the witness masternode's operator key over the MasternodeNonParticipationProof hash (or a specific message).
    pub signature: Vec<u8>,
}

/// Proof for a Masternode non-participation slashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MasternodeNonParticipationProof {
    /// The ID of the Masternode being slashed.
    pub masternode_id: MasternodeID,
    /// The block height at which the non-participation was detected.
    pub detection_block_height: u64,
    /// The full PoSe challenge that was not responded to.
    pub challenge: PoSeChallenge, // Changed from Option<Hash>
    /// The PoSe response (if any was submitted, but invalid/untimely).
    pub response: Option<PoSeResponse>,
    /// Signatures from a quorum of witness masternodes attesting to the non-participation.
    pub witness_signatures: Vec<WitnessSignature>, // Replaced proof_data
}

/// Represents a Masternode slashing transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MasternodeSlashTx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub masternode_id: MasternodeID,
    pub reason: SlashingReason,
    pub proof: Vec<u8>,
    pub lock_time: u32,
    pub fee: u64,
    pub witness: Vec<Vec<u8>>,
}