use crate::{OutPoint, TxInput, TxOutput};
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
pub type SharedMasternodeList = Arc<RwLock<MasternodeList>>;

/// Represents the unique identifier for a Masternode, derived from its collateral UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub network_address: String,      // IP:Port
    pub collateral_ownership_public_key: Vec<u8>, // Public key associated with collateral UTXO
    pub dkg_public_key: Option<Vec<u8>>, // BLS public key for DKG participation
    pub supported_dkg_versions: Vec<u32>, // Supported DKG protocol versions
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeRegistration {
    pub masternode_identity: MasternodeIdentity,
    pub signature: Vec<u8>, // Signature by collateral_ownership_public_key over the identity data
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum MasternodeStatus {
    Registered,
    Active,
    Offline,
    Probation,
    Banned,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MasternodeEntry {
    pub identity: MasternodeIdentity,
    pub status: MasternodeStatus,
    pub last_successful_pose_height: u32,
    pub pose_failure_count: u32,
    pub last_slashed_height: Option<u32>,
    pub dkg_participation_count: u32, // Number of DKG sessions participated in
    pub dkg_success_rate: f32,        // Success rate in DKG sessions (0.0 to 1.0)
    pub active_dkg_sessions: Vec<crate::dkg::DKGSessionID>, // Currently active DKG sessions
    pub collateral_amount: u64,       // Amount of collateral locked by this masternode
}

impl MasternodeEntry {
    /// Get the collateral amount for this masternode
    /// This would typically be retrieved from the UTXO set using the collateral_outpoint
    pub fn get_collateral_amount(&self) -> Option<u64> {
        Some(self.collateral_amount)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeList {
    pub map: HashMap<MasternodeID, MasternodeEntry>,
}

impl MasternodeList {
    pub fn new() -> Self {
        MasternodeList {
            map: HashMap::new(),
        }
    }

    pub fn register_masternode(
        &mut self,
        registration: MasternodeRegistration,
        current_height: u32,
    ) -> Result<(), String> {
        let mn_id = MasternodeID(registration.masternode_identity.collateral_outpoint.clone());
        if self.map.contains_key(&mn_id) {
            return Err("Masternode already registered".to_string());
        }
        let entry = MasternodeEntry {
            identity: registration.masternode_identity,
            status: MasternodeStatus::Registered,
            last_successful_pose_height: current_height,
            pose_failure_count: 0,
            last_slashed_height: None,
            dkg_participation_count: 0,
            dkg_success_rate: 0.0,
            active_dkg_sessions: Vec::new(),
            collateral_amount: 0,
        };
        self.map.insert(mn_id, entry);
        Ok(())
    }

    pub fn update_masternode_status(
        &mut self,
        mn_id: MasternodeID,
        new_status: MasternodeStatus,
    ) -> Result<(), String> {
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

    pub fn find_by_operator_key(
        &self,
        operator_key: &[u8],
    ) -> Option<(&MasternodeID, &MasternodeEntry)> {
        self.map
            .iter()
            .find(|(_, entry)| entry.identity.operator_public_key.as_slice() == operator_key)
    }

    pub fn remove_masternode(&mut self, mn_id: &MasternodeID) -> Option<MasternodeEntry> {
        self.map.remove(mn_id)
    }

    pub fn count_active_masternodes(&self) -> usize {
        self.map
            .values()
            .filter(|mn| mn.status == MasternodeStatus::Active)
            .count()
    }

    pub fn total_voting_power(&self) -> u64 {
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

    /// Increment PoSe failure count and update status per spec 06 Section 6.4.1
    /// Per spec: Upon failure, status set to PROBATION and failure count increments
    /// If failure count exceeds MAX_POSE_FAILURES (3), masternode becomes eligible for slashing
    pub fn increment_pose_failure_count(&mut self, mn_id: &MasternodeID) -> Result<(), String> {
        const MAX_POSE_FAILURES: u32 = 3; // Per protocol constants

        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.pose_failure_count += 1;

            // Per spec 06 Section 6.4.1: Set status to PROBATION upon failure
            if entry.status == MasternodeStatus::Active {
                entry.status = MasternodeStatus::Probation;
            }

            // If failure count exceeds MAX_POSE_FAILURES, masternode is eligible for slashing
            // The actual slashing transaction creation is handled separately
            if entry.pose_failure_count >= MAX_POSE_FAILURES {
                // Status remains PROBATION until slashing transaction is processed
                // Slashing will transition to BANNED
            }

            Ok(())
        } else {
            Err("Masternode not found for incrementing PoSe failure count.".to_string())
        }
    }

    /// Update last successful PoSe height and reset failure count per spec 06 Section 6.3.2
    /// Per spec: If masternode successfully responds, update LastSuccessfulPoSe and reset failure count
    pub fn update_successful_pose(
        &mut self,
        mn_id: &MasternodeID,
        current_height: u32,
    ) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.last_successful_pose_height = current_height;
            entry.pose_failure_count = 0;

            // If masternode was on PROBATION and now responds successfully, return to ACTIVE
            if entry.status == MasternodeStatus::Probation {
                entry.status = MasternodeStatus::Active;
            }

            Ok(())
        } else {
            Err("Masternode not found for updating successful PoSe".to_string())
        }
    }

    pub fn deregister_masternode(&mut self, mn_id: &MasternodeID) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.status = MasternodeStatus::Banned;
            Ok(())
        } else {
            Err("Masternode not found for deregistration".to_string())
        }
    }

    pub fn select_masternodes_for_quorum(&self, count: usize) -> Vec<&MasternodeEntry> {
        use blake3::Hasher;
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut candidates: Vec<&MasternodeEntry> = self
            .map
            .values()
            .filter(|mn| mn.status == MasternodeStatus::Active)
            .collect();
        candidates.sort_by(|a, b| {
            b.last_successful_pose_height
                .cmp(&a.last_successful_pose_height)
                .then_with(|| {
                    b.dkg_success_rate
                        .partial_cmp(&a.dkg_success_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    let mut hasher_a = Hasher::new();
                    hasher_a.update(&a.identity.operator_public_key);
                    hasher_a.update(&now.to_le_bytes());
                    let hash_a = hasher_a.finalize();
                    let mut hasher_b = Hasher::new();
                    hasher_b.update(&b.identity.operator_public_key);
                    hasher_b.update(&now.to_le_bytes());
                    let hash_b = hasher_b.finalize();
                    hash_a.as_bytes().cmp(hash_b.as_bytes())
                })
        });
        candidates.into_iter().take(count).collect()
    }

    /// Select masternodes for DKG participation based on DKG success rate and availability
    pub fn select_masternodes_for_dkg(
        &self,
        count: usize,
        min_success_rate: f32,
    ) -> Vec<&MasternodeEntry> {
        let mut candidates: Vec<&MasternodeEntry> = self
            .map
            .values()
            .filter(|mn| {
                mn.status == MasternodeStatus::Active
                    && mn.dkg_success_rate >= min_success_rate
                    && mn.identity.dkg_public_key.is_some()
                    && !mn.identity.supported_dkg_versions.is_empty()
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.dkg_success_rate
                .partial_cmp(&a.dkg_success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.dkg_participation_count.cmp(&b.dkg_participation_count))
        });
        candidates.into_iter().take(count).collect()
    }

    /// Update DKG participation statistics for a masternode
    pub fn update_dkg_participation(
        &mut self,
        mn_id: &MasternodeID,
        success: bool,
    ) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.dkg_participation_count += 1;
            let alpha = 0.1;
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
    pub fn add_active_dkg_session(
        &mut self,
        mn_id: &MasternodeID,
        session_id: crate::dkg::DKGSessionID,
    ) -> Result<(), String> {
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
    pub fn remove_active_dkg_session(
        &mut self,
        mn_id: &MasternodeID,
        session_id: &crate::dkg::DKGSessionID,
    ) -> Result<(), String> {
        if let Some(entry) = self.map.get_mut(mn_id) {
            entry.active_dkg_sessions.retain(|id| id != session_id);
            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    /// Get masternodes that support a specific DKG version
    pub fn get_masternodes_by_dkg_version(&self, version: u32) -> Vec<&MasternodeEntry> {
        self.map
            .values()
            .filter(|mn| {
                mn.status == MasternodeStatus::Active
                    && mn.identity.supported_dkg_versions.contains(&version)
            })
            .collect()
    }

    pub fn distribute_rewards(&mut self, block_height: u32, total_block_reward: u64) {
        let active_masternodes: Vec<&MasternodeID> = self
            .map
            .iter()
            .filter(|(_, mn)| mn.status == MasternodeStatus::Active)
            .map(|(id, _)| id)
            .collect();
        if active_masternodes.is_empty() {
            return;
        }
        let reward_per_masternode = total_block_reward / active_masternodes.len() as u64;
        for mn_id in active_masternodes {
            println!(
                "Masternode {:?} receives {} rewards at block height {}",
                mn_id, reward_per_masternode, block_height
            );
        }
    }
}

// PoSe related structs
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PoSeChallenge {
    pub challenge_nonce: u64,
    pub challenge_block_hash: [u8; 32],
    pub challenger_masternode_id: MasternodeID,
    pub challenge_generation_block_height: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PoSeResponse {
    pub challenge_nonce: u64,
    pub signed_block_hash: Vec<u8>,
    pub target_masternode_id: MasternodeID,
}

// OxideSend related structs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxInputLock {
    pub txid: [u8; 32],
    pub input_index: u32,
    pub masternode_id: MasternodeID,
    pub signature: Vec<u8>,
}

// FerrousShield related structs (simplified)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FerrousShieldMixRequest {
    pub amount: u64,
    pub participant_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FerrousShieldMixOutput {
    pub output: TxOutput,
    pub participant_signature: Vec<u8>,
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
    pub masternode_id: MasternodeID,
    pub malicious_action_type: MaliciousActionType,
    pub detection_block_height: u64,
    pub proof_data: Vec<u8>,
}

/// Represents a signature from a witness masternode for a non-participation proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub masternode_id: MasternodeID,
    pub signature: Vec<u8>,
}

/// Proof for a Masternode non-participation slashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MasternodeNonParticipationProof {
    pub masternode_id: MasternodeID,
    pub detection_block_height: u64,
    pub challenge: PoSeChallenge,
    pub response: Option<PoSeResponse>,
    pub witness_signatures: Vec<WitnessSignature>,
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

// NOTE: The following is a protocol compliance update for governance status enums in tests.
// If you previously used ProposalStatus::{Active, Executed}, use ProposalOutcome::{InProgress, Passed} from rusty_core::consensus::governance_state instead.
// Example:
// use rusty_core::consensus::governance_state::ProposalOutcome;
// assert_eq!(proposal_status, Some(ProposalOutcome::Passed));
// assert_eq!(status1, Some(ProposalOutcome::InProgress));

// Additional compliance note:
// If you see errors about TransactionSignature, import it from rusty_shared_types:
// use rusty_shared_types::TransactionSignature;
// If you see errors about ConsensusState or GovernanceState::new(), comment out or remove those usages as those types/constructors are not available in the canonical protocol.
// If you see mismatched types for signatures, use TransactionSignature([0u8; 64]) or TransactionSignature::default() if available.

/// Signs a FerrousShield output using the participant's Ed25519 keypair
pub fn sign_ferrousshield_output(output: &TxOutput, keypair: &Keypair) -> Vec<u8> {
    let serialized = bincode::serialize(output).expect("serialization failed");
    keypair.sign(&serialized).to_bytes().to_vec()
}

/// Ergonomic, compliance-aligned wrapper for shared masternode list mutability
#[derive(Clone)]
pub struct SharedMasternodeListHandle {
    inner: Arc<RwLock<MasternodeList>>,
}

impl SharedMasternodeListHandle {
    pub fn new(list: MasternodeList) -> Self {
        Self {
            inner: Arc::new(RwLock::new(list)),
        }
    }

    pub fn from_arc(arc: Arc<RwLock<MasternodeList>>) -> Self {
        Self { inner: arc }
    }

    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&MasternodeList) -> R,
    {
        let guard = self
            .inner
            .read()
            .expect("MasternodeList read lock poisoned");
        f(&*guard)
    }

    pub fn write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut MasternodeList) -> R,
    {
        let mut guard = self
            .inner
            .write()
            .expect("MasternodeList write lock poisoned");
        f(&mut *guard)
    }

    pub fn arc(&self) -> Arc<RwLock<MasternodeList>> {
        Arc::clone(&self.inner)
    }

    // Additional convenience methods for common operations

    /// Register a masternode with thread-safe access
    pub fn register_masternode(
        &self,
        registration: MasternodeRegistration,
        current_height: u32,
    ) -> Result<(), String> {
        self.write(|list| list.register_masternode(registration, current_height))
    }

    /// Update masternode status with thread-safe access
    pub fn update_status(
        &self,
        mn_id: MasternodeID,
        new_status: MasternodeStatus,
    ) -> Result<(), String> {
        self.write(|list| list.update_masternode_status(mn_id, new_status))
    }

    /// Get masternode entry with thread-safe access
    pub fn get_masternode(&self, mn_id: &MasternodeID) -> Option<MasternodeEntry> {
        self.read(|list| list.get_masternode(mn_id).cloned())
    }

    /// Count active masternodes with thread-safe access
    pub fn count_active(&self) -> usize {
        self.read(|list| list.count_active_masternodes())
    }

    /// Select masternodes for quorum with thread-safe access
    pub fn select_for_quorum(&self, count: usize) -> Vec<MasternodeEntry> {
        self.read(|list| {
            list.select_masternodes_for_quorum(count)
                .into_iter()
                .cloned()
                .collect()
        })
    }

    /// Select masternodes for DKG with thread-safe access
    pub fn select_for_dkg(&self, count: usize, min_success_rate: f32) -> Vec<MasternodeEntry> {
        self.read(|list| {
            list.select_masternodes_for_dkg(count, min_success_rate)
                .into_iter()
                .cloned()
                .collect()
        })
    }

    /// Update DKG participation with thread-safe access
    pub fn update_dkg_participation(
        &self,
        mn_id: &MasternodeID,
        success: bool,
    ) -> Result<(), String> {
        self.write(|list| list.update_dkg_participation(mn_id, success))
    }

    /// Increment PoSe failure count with thread-safe access
    pub fn increment_pose_failure(&self, mn_id: &MasternodeID) -> Result<(), String> {
        self.write(|list| list.increment_pose_failure_count(mn_id))
    }

    /// Reset PoSe failure count with thread-safe access
    pub fn reset_pose_failure(&self, mn_id: &MasternodeID) -> Result<(), String> {
        self.write(|list| list.reset_pose_failure_count(mn_id))
    }

    /// Distribute rewards with thread-safe access
    pub fn distribute_rewards(&self, block_height: u32, total_block_reward: u64) {
        self.write(|list| list.distribute_rewards(block_height, total_block_reward))
    }

    /// Check if masternode exists
    pub fn contains(&self, mn_id: &MasternodeID) -> bool {
        self.read(|list| list.map.contains_key(mn_id))
    }

    /// Get all active masternode IDs
    pub fn get_active_ids(&self) -> Vec<MasternodeID> {
        self.read(|list| {
            list.map
                .iter()
                .filter(|(_, entry)| entry.status == MasternodeStatus::Active)
                .map(|(id, _)| id.clone())
                .collect()
        })
    }

    /// Get masternode count by status
    pub fn count_by_status(&self, status: MasternodeStatus) -> usize {
        self.read(|list| {
            list.map
                .values()
                .filter(|entry| entry.status == status)
                .count()
        })
    }
}
