use serde::{Deserialize, Serialize};
use bincode;
use std::collections::HashMap;
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use crate::masternode::MaliciousActionType;
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];
pub type Hash = [u8; 32];
pub type PubKeyHash = [u8; 20];

/// Represents a ticket in the Proof-of-Stake system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    /// The unique identifier of this ticket
    pub id: TicketId,
    /// The public key of the ticket owner
    pub pubkey: Vec<u8>,
    /// The block height when this ticket was created
    pub height: u64,
    /// The value of the ticket in satoshis
    pub value: u64,
    /// The status of the ticket (live, voted, expired, etc.)
    pub status: TicketStatus,
}

/// Represents the status of a ticket
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TicketStatus {
    Live,
    Voted,
    Expired,
    Revoked,
}

/// Represents a ticket ID in the Proof-of-Stake system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TicketId(pub [u8; 32]);

impl std::fmt::Display for TicketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl PartialOrd for TicketId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TicketId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare the byte arrays lexicographically
        self.0.cmp(&other.0)
    }
}

impl TicketId {
    /// Converts the TicketId to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Creates a TicketId from a byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TicketId(bytes)
    }
}

impl From<[u8; 32]> for TicketId {
    fn from(bytes: [u8; 32]) -> Self {
        TicketId(bytes)
    }
}

impl AsRef<[u8]> for TicketId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub mod governance;
pub mod masternode;
pub mod dkg;
pub mod dkg_messages;

use governance::{GovernanceProposal, GovernanceVote};

/// Represents a reference to a specific transaction output.
#[derive(Debug, Clone, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub struct OutPoint {
    /// The transaction ID (hash) of the transaction containing the output.
    pub txid: [u8; 32],
    /// The index of the output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(self)
    }
}

impl From<[u8; 32]> for OutPoint {
    fn from(txid: [u8; 32]) -> Self {
        OutPoint {
            txid,
            vout: 0, // Default vout to 0 when converting from a raw txid
        }
    }
}

/// Represents a transaction input, referencing a previous transaction's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    /// The `OutPoint` referencing the output being spent.
    pub previous_output: OutPoint,
    /// The script signature, providing proof of ownership.
    pub script_sig: Vec<u8>,
    /// A sequence number, typically used for replace-by-fee or relative lock-times.
    pub sequence: u32,
    /// Cryptographic witnesses for SegWit-like transactions (e.g., signatures, public keys).
    pub witness: Vec<Vec<u8>>,
}

/// Represents a transaction output, specifying a value and a locking script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// The value of the output in satoshis.
    pub value: u64,
    /// The locking script (scriptPubKey) that defines the conditions for spending this output.
    pub script_pubkey: Vec<u8>,
    /// Optional memo field for arbitrary data, typically for OP_RETURN outputs.
    pub memo: Option<Vec<u8>>,
}

impl TxOutput {
    /// Creates a new `TxOutput` without a memo.
    ///
    /// # Arguments
    /// * `value` - The value of the output in satoshis
    /// * `script_pubkey` - The locking script that defines spending conditions
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        TxOutput { value, script_pubkey, memo: None }
    }

    /// Creates a new `TxOutput` with a memo field.
    ///
    /// # Arguments
    /// * `value` - The value of the output in satoshis
    /// * `script_pubkey` - The locking script that defines spending conditions
    /// * `memo` - Optional memo data for OP_RETURN outputs
    pub fn new_with_memo(value: u64, script_pubkey: Vec<u8>, memo: Option<Vec<u8>>) -> Self {
        TxOutput { value, script_pubkey, memo }
    }

    /// Extracts the public key hash from a P2PKH script, if applicable.
    pub fn extract_public_key_hash(&self) -> Option<PubKeyHash> {
        // P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        // The public key hash is bytes 3 to 22
        if self.script_pubkey.len() == 25
            && self.script_pubkey[0] == 0x76 // OP_DUP
            && self.script_pubkey[1] == 0xA9 // OP_HASH160
            && self.script_pubkey[2] == 0x14 // PUSHDATA(20)
            && self.script_pubkey[23] == 0x88 // OP_EQUALVERIFY
            && self.script_pubkey[24] == 0xAC // OP_CHECKSIG
        {
            let mut public_key_hash = [0u8; 20];
            public_key_hash.copy_from_slice(&self.script_pubkey[3..23]);
            Some(public_key_hash)
        } else {
            None
        }
    }
}

/// Represents a standard transaction in the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardTransaction {
    /// The version of the transaction format.
    pub version: u32,
    /// A list of transaction inputs.
    pub inputs: Vec<TxInput>,
    /// A list of transaction outputs.
    pub outputs: Vec<TxOutput>,
    /// The lock time of the transaction, specifying the earliest time or block height it can be included in a block.
    pub lock_time: u32,
    /// The transaction fee, calculated as the sum of input values minus the sum of output values.
    pub fee: u64,
    /// Cryptographic witnesses for SegWit-like transactions (e.g., signatures, public keys).
    pub witness: Vec<Vec<u8>>,
}

/// Represents the different types of transactions supported by the blockchain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Transaction {
    Standard {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        fee: u64,
        witness: Vec<Vec<u8>>,
    },
    Coinbase {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    MasternodeRegister {
        masternode_identity: MasternodeIdentity,
        signature: TransactionSignature,
        lock_time: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        witness: Vec<Vec<u8>>,
    },
    MasternodeCollateral {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        masternode_identity: MasternodeIdentity,
        collateral_amount: u64,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    GovernanceProposal(GovernanceProposal),
    GovernanceVote(GovernanceVote),
    /// Activation transaction for approved governance proposals
    ActivateProposal {
        version: u32,
        proposal_id: Hash,
        activation_block_height: u64,
        approval_proof: governance::ApprovalProof,
        activator_signature: TransactionSignature,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    TicketPurchase {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        ticket_id: [u8; 32],
        locked_amount: u64,
        lock_time: u32,
        fee: u64,
        ticket_address: Vec<u8>,
        witness: Vec<Vec<u8>>,
    },
    TicketRedemption {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        ticket_id: [u8; 32],
        lock_time: u32,
        fee: u64,
        witness: Vec<Vec<u8>>,
    },
    MasternodeSlashTx(crate::masternode::MasternodeSlashTx),
}

impl Transaction {
    /// Returns a slice of `TxInput`s for the transaction.
    ///
    /// This method provides a unified way to access the inputs regardless of the transaction type.
    pub fn get_inputs(&self) -> &[TxInput] {
        match self {
            Transaction::Standard { inputs, .. } => inputs,
            Transaction::Coinbase { inputs, .. } => inputs,
            Transaction::MasternodeRegister { inputs, .. } => inputs,
            Transaction::MasternodeCollateral { inputs, .. } => inputs,
            Transaction::GovernanceProposal(proposal) => proposal.inputs.as_slice(),
            Transaction::GovernanceVote(vote) => vote.inputs.as_slice(),
            Transaction::ActivateProposal { inputs, .. } => inputs,
            Transaction::TicketPurchase { inputs, .. } => inputs,
            Transaction::TicketRedemption { inputs, .. } => inputs,
            Transaction::MasternodeSlashTx(tx) => tx.inputs.as_slice(),
        }
    }

    /// Returns the transaction fee.
    ///
    /// This method provides a unified way to access the transaction fee.
    pub fn get_fee(&self) -> u64 {
        match self {
            Transaction::Standard { fee, .. } => *fee,
            Transaction::TicketPurchase { fee, .. } => *fee,
            Transaction::TicketRedemption { fee, .. } => *fee,
            Transaction::GovernanceProposal(proposal) => proposal.fee,
            Transaction::GovernanceVote(vote) => vote.fee,
            Transaction::ActivateProposal { .. } => 0, // Activation fee is handled through inputs/outputs
            Transaction::MasternodeSlashTx(tx) => tx.fee,
            _ => 0, // Other transaction types might not have an explicit fee field
        }
    }

    /// Returns a slice of `TxOutput`s for the transaction.
    ///
    /// This method provides a unified way to access the outputs regardless of the transaction type.
    pub fn get_outputs(&self) -> &[TxOutput] {
        match self {
            Transaction::Standard { outputs, .. } => outputs,
            Transaction::Coinbase { outputs, .. } => outputs,
            Transaction::MasternodeRegister { outputs, .. } => outputs,
            Transaction::MasternodeCollateral { outputs, .. } => outputs,
            Transaction::GovernanceProposal(proposal) => proposal.outputs.as_slice(),
            Transaction::GovernanceVote(vote) => vote.outputs.as_slice(),
            Transaction::ActivateProposal { outputs, .. } => outputs,
            Transaction::TicketPurchase { outputs, .. } => outputs,
            Transaction::TicketRedemption { outputs, .. } => outputs,
            Transaction::MasternodeSlashTx(tx) => tx.outputs.as_slice(),
        }
    }

    /// Returns a mutable slice of `TxOutput`s for the transaction.
    ///
    /// This method provides a unified way to access and modify the outputs regardless of the transaction type.
    pub fn get_outputs_mut(&mut self) -> &mut Vec<TxOutput> {
        match self {
            Transaction::Standard { outputs, .. } => outputs,
            Transaction::Coinbase { outputs, .. } => outputs,
            Transaction::MasternodeRegister { outputs, .. } => outputs,
            Transaction::MasternodeCollateral { outputs, .. } => outputs,
            Transaction::GovernanceProposal(proposal) => &mut proposal.outputs,
            Transaction::GovernanceVote(vote) => &mut vote.outputs,
            Transaction::ActivateProposal { outputs, .. } => outputs,
            Transaction::TicketPurchase { outputs, .. } => outputs,
            Transaction::TicketRedemption { outputs, .. } => outputs,
            Transaction::MasternodeSlashTx(tx) => &mut tx.outputs,
        }
    }

    /// Returns the lock time of the transaction.
    ///
    /// This method provides a unified way to access the lock time regardless of the transaction type.
    pub fn get_lock_time(&self) -> u32 {
        match self {
            Transaction::Standard { lock_time, .. } => *lock_time,
            Transaction::Coinbase { lock_time, .. } => *lock_time,
            Transaction::MasternodeRegister { lock_time, .. } => *lock_time,
            Transaction::MasternodeCollateral { lock_time, .. } => *lock_time,
            Transaction::GovernanceProposal(proposal) => proposal.lock_time,
            Transaction::GovernanceVote(vote) => vote.lock_time,
            Transaction::ActivateProposal { lock_time, .. } => *lock_time,
            Transaction::TicketPurchase { lock_time, .. } => *lock_time,
            Transaction::TicketRedemption { lock_time, .. } => *lock_time,
            Transaction::MasternodeSlashTx(tx) => tx.lock_time,
        }
    }

    /// Returns the canonical byte representation of the transaction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(self)
    }

    /// Calculates and returns the transaction ID (hash) of the transaction.
    pub fn txid(&self) -> [u8; 32] {
        let bytes = self.to_bytes().unwrap();
        blake3::hash(&bytes).into()
    }

    /// Checks if the transaction is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        matches!(self, Transaction::Coinbase { .. })
    }

    /// Returns the number of inputs in the transaction.
    pub fn input_count(&self) -> usize {
        self.get_inputs().len()
    }

    /// Returns the number of outputs in the transaction.
    pub fn output_count(&self) -> usize {
        self.get_outputs().len()
    }

    /// Returns a slice of cryptographic witnesses for the transaction.
    pub fn get_witnesses(&self) -> &[Vec<u8>] {
        match self {
            Transaction::Standard { witness, .. } => witness,
            Transaction::Coinbase { witness, .. } => witness,
            Transaction::MasternodeRegister { witness, .. } => witness,
            Transaction::MasternodeCollateral { witness, .. } => witness,
            Transaction::ActivateProposal { witness, .. } => witness,
            Transaction::TicketPurchase { witness, .. } => witness,
            Transaction::TicketRedemption { witness, .. } => witness,
            // GovernanceProposal and GovernanceVote do not have direct 'witness' fields,
            // their signatures are part of their respective structs.
            Transaction::GovernanceProposal(_) => &[],
            Transaction::GovernanceVote(_) => &[],
            Transaction::MasternodeSlashTx(tx) => tx.witness.as_slice(),
        }
    }

    /// Returns a mutable slice of cryptographic witnesses for the transaction.
    pub fn get_witnesses_mut(&mut self) -> &mut Vec<Vec<u8>> {
        match self {
            Transaction::Standard { witness, .. } => witness,
            Transaction::Coinbase { witness, .. } => witness,
            Transaction::MasternodeRegister { witness, .. } => witness,
            Transaction::MasternodeCollateral { witness, .. } => witness,
            Transaction::ActivateProposal { witness, .. } => witness,
            Transaction::TicketPurchase { witness, .. } => witness,
            Transaction::TicketRedemption { witness, .. } => witness,
            // For these types, witnesses are not directly mutable through a shared reference.
            // They are part of the internal structure of the enum variant.
            Transaction::GovernanceProposal(_) => panic!("Cannot get mutable witnesses for GovernanceProposal"),
            Transaction::GovernanceVote(_) => panic!("Cannot get mutable witnesses for GovernanceVote"),
            Transaction::MasternodeSlashTx(tx) => &mut tx.witness,
        }
    }

    /// Sets the witnesses for the transaction.
    pub fn set_witnesses(&mut self, witnesses: Vec<Vec<u8>>) {
        match self {
            Self::Standard { witness, .. } => *witness = witnesses,
            Self::Coinbase { witness, .. } => *witness = witnesses,
            Self::MasternodeRegister { witness, .. } => *witness = witnesses,
            Self::MasternodeCollateral { witness, .. } => *witness = witnesses,
            Self::GovernanceProposal(_) => {}
            Self::GovernanceVote(_) => {}
            Self::ActivateProposal { witness, .. } => *witness = witnesses,
            Self::TicketPurchase { witness, .. } => *witness = witnesses,
            Self::TicketRedemption { witness, .. } => *witness = witnesses,
            Self::MasternodeSlashTx(_) => {}
        }
    }

    /// Returns the BLAKE3 hash of the transaction's serialized bytes
    pub fn hash(&self) -> [u8; 32] {
        match self.to_bytes() {
            Ok(bytes) => blake3::hash(&bytes).into(),
            Err(_) => [0u8; 32], // Should never happen for valid transactions
        }
    }
}

/// MasternodeID is a unique identifier for a Masternode, derived from its collateral outpoint.
#[derive(Debug, Clone, PartialEq, Eq, StdHash, Serialize, Deserialize)]
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
        // For now, we\'ll assume validity for the purpose of struct definition.

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

    /// Get a list of masternodes that support a specific DKG version
    pub fn get_masternodes_by_dkg_version(&self, version: u32) -> Vec<&MasternodeEntry> {
        self.map.values()
            .filter(|mn| mn.identity.supported_dkg_versions.contains(&version))
            .collect()
    }

    pub fn distribute_rewards(&mut self, block_height: u32, total_block_reward: u64) {
        let active_masternodes: Vec<MasternodeID> = self.map.iter()
            .filter(|(_, mn)| mn.status == MasternodeStatus::Active)
            .map(|(id, _)| id.clone())
            .collect();

        if active_masternodes.is_empty() { return; }

        let reward_per_masternode = total_block_reward / active_masternodes.len() as u64;

        for mn_id in active_masternodes {
            // In a real system, this would update the UTXO set, create new outputs, etc.
            // For now, we simulate by simply noting the reward.
            println!("Masternode {:?} received {} satoshis at height {}", mn_id, reward_per_masternode, block_height);
        }
    }
}

/// Proof-of-Service (PoSe) challenge issued to a Masternode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoSeChallenge {
    pub challenge_nonce: u64,
    pub challenge_block_hash: [u8; 32],
    pub challenger_masternode_id: MasternodeID,
    pub challenge_generation_block_height: u64,
    pub signature: Vec<u8>, // Signature by challenger's operator key
}

/// Proof-of-Service (PoSe) response from a Masternode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoSeResponse {
    pub challenge_nonce: u64,
    pub signed_block_hash: Vec<u8>, // Signature by target's operator key over challenge_block_hash
    pub target_masternode_id: MasternodeID,
}

/// Represents a lock on a transaction input, typically by a Masternode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputLock {
    pub txid: [u8; 32],
    pub input_index: u32,
    pub masternode_id: MasternodeID,
    pub signature: Vec<u8>, // Signature by masternode's operator key over txid and input_index
}

/// Request for a mixing service (e.g., CoinJoin, FerrousShield).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FerrousShieldMixRequest {
    pub amount: u64,
    pub participant_public_key: Vec<u8>,
}

/// Output from a mixing service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FerrousShieldMixOutput {
    pub output: TxOutput,
    pub participant_signature: Vec<u8>, // Signature by participant over the output
}

/// Reasons for Masternode slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingReason {
    MasternodeNonResponse,
    DoubleSigning,
    InvalidBlockProposal,
    InvalidTransaction,
    GovernanceViolation,
}

impl StdHash for SlashingReason {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        match self {
            SlashingReason::MasternodeNonResponse => "MasternodeNonResponse".hash(state),
            SlashingReason::DoubleSigning => "DoubleSigning".hash(state),
            SlashingReason::InvalidBlockProposal => "InvalidBlockProposal".hash(state),
            SlashingReason::InvalidTransaction => "InvalidTransaction".hash(state),
            SlashingReason::GovernanceViolation => "GovernanceViolation".hash(state),
        }
    }
}

/// Proof of a malicious action by a Masternode, leading to slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Signature from a witness Masternode for non-participation proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// The ID of the witness Masternode.
    pub masternode_id: MasternodeID,
    /// Signature by the witness masternode's operator key over the MasternodeNonParticipationProof hash (or a specific message).
    pub signature: Vec<u8>,
}

/// Proof of Masternode non-participation, leading to slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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



/// UtxoId is a unique identifier for a UTXO, derived from its OutPoint.
#[derive(Debug, Clone, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub struct UtxoId(pub OutPoint);

impl UtxoId {
    /// Get the bytes representation of the UtxoId
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap_or_default()
    }
}

impl From<OutPoint> for UtxoId {
    fn from(outpoint: OutPoint) -> Self {
        UtxoId(outpoint)
    }
}

/// Represents an unspent transaction output (UTXO).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    pub output: TxOutput,
    pub is_coinbase: bool,
    pub creation_height: u64,
}

impl Utxo {
    /// Returns the `OutPoint` that identifies this UTXO.
    pub fn outpoint(&self) -> OutPoint {
        // In a real scenario, the OutPoint would be derived from the transaction
        // it belongs to and its index within that transaction. For this simplified
        // UTXO struct, we might need to add a `txid` field or calculate it.
        // For now, let's assume a dummy OutPoint or that it's set externally.
        OutPoint {
            txid: [0; 32], // Placeholder
            vout: 0,       // Placeholder
        }
    }
}

/// Represents a coinbase transaction, which creates new coins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseTransaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

/// Represents a cryptographic signature used in transactions and other messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSignature {
    #[serde(with = "serde_bytes")]
    pub bytes: [u8; 64],
}

impl TransactionSignature {
    pub fn new(bytes: [u8; 64]) -> Self {
        TransactionSignature { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// Represents a block header in the blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
    pub difficulty_target: u32,
    pub height: u64,
    pub state_root: [u8; 32],
}

impl BlockHeader {
    /// Calculates the hash of the block header.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).unwrap();
        blake3::hash(&bytes).into()
    }

    /// Checks if the block header indicates a Proof-of-Stake block.
    pub fn is_proof_of_stake(&self) -> bool {
        // PoS blocks have a specific version or other flag.
        // For now, assume version 2 indicates PoS.
        self.version == 2
    }
}

/// Represents a block in the blockchain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub ticket_votes: Vec<TicketVote>,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Calculates the hash of the block.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).unwrap();
        blake3::hash(&bytes).into()
    }
}

/// Represents a vote cast by a ticket in a Proof-of-Stake system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TicketVote {
    pub ticket_id: [u8; 32],
    pub block_hash: [u8; 32],
    pub vote: VoteType,
    pub signature: TransactionSignature,
}

/// Defines the type of vote for a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteType {
    Yes = 0,
    No = 1,
    Abstain = 2
}

impl VoteType {
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(VoteType::Yes),
            1 => Ok(VoteType::No),
            2 => Ok(VoteType::Abstain),
            _ => Err(format!("Invalid VoteType value: {}", value)),
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// Represents the blockchain structure and its parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockChain;

/// Defines the consensus parameters for the blockchain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Minimum stake required to participate in voting (in satoshis)
    pub min_stake: u64,
    /// Maximum number of tickets per stake transaction
    pub max_tickets_per_stake: u32,
    /// Ticket price (in satoshis)
    pub ticket_price: u64,
    /// Ticket maturity period (in blocks)
    pub ticket_maturity: u32,
    /// Ticket expiry period (in blocks)
    pub ticket_expiry: u32,
    /// Number of tickets to select for voting in each round
    pub tickets_per_round: usize,
    /// Minimum time between blocks (in seconds)
    pub min_block_time: u64,
    /// Reward amount for a participating ticket (in satoshis)
    pub reward_amount: u64,
    /// Target number of live tickets
    pub target_live_tickets: u64,
    /// Adjustment factor for ticket price
    pub price_adjustment_factor: f64,
    /// Window over which to adjust difficulty (in blocks)
    pub difficulty_adjustment_window: u32,
    /// Halving interval for block rewards (in blocks)
    pub halving_interval: u64,
    /// Initial block reward (in satoshis)
    pub initial_block_reward: u64,
    /// Ratio of total reward allocated to PoS stakers (0.0 to 1.0)
    pub pos_reward_ratio: f64,
    /// Address for the PoW miner's reward (example: a simple public key hash)
    pub miner_address: Vec<u8>,
    /// Period for ticket price adjustment (in blocks)
    pub ticket_price_adjustment_period: u64,
    /// Maximum allowed ticket price
    pub max_ticket_price: u64,
    /// Minimum allowed ticket price
    pub min_ticket_price: u64,

    // Governance parameters
    pub proposal_stake_amount: u64,
    pub voting_period_blocks: u64,
    pub pos_voting_quorum_percentage: f64,
    pub mn_voting_quorum_percentage: f64,
    pub pos_approval_percentage: f64,
    pub mn_approval_percentage: f64,
    pub activation_delay_blocks: u64,
    /// Grace period in blocks before a non-participating ticket can be slashed.
    pub grace_period_blocks: u64,
    /// Period in blocks during which repeated non-participation results in increased penalties.
    pub slash_forgiveness_period: u64,
    /// Percentage of a ticket's value to be burned for malicious behavior (e.g., double-voting).
    pub malicious_behavior_slash_percentage: f64,

    /// Period for Masternode Proof-of-Service challenges (in blocks)
    pub pose_challenge_period_blocks: u64,
    /// Number of Masternodes to select as challengers for PoSe
    pub num_pose_challengers: u32,
    /// Number of Masternodes to select as targets for PoSe per period
    pub num_pose_targets_per_period: u32,
    /// Timeout for Masternode Proof-of-Service responses (in seconds)
    pub pose_response_timeout_seconds: u64,
    /// Maximum number of PoSe failures before slashing
    pub max_pose_failures: u32,
    /// Period in blocks after which PoSe failure count resets
    pub reset_failures_period: u32,
    pub min_witness_signatures: u32,
    pub pos_finality_depth: u32,
    /// Maximum block size in bytes
    pub max_block_size: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        ConsensusParams {
            min_stake: 100_000_000_000, // 1000 RustyCoin
            max_tickets_per_stake: 1, // Only 1 ticket per stake for simplicity
            ticket_price: 1_000_000_000, // 10 RustyCoin
            ticket_maturity: 10, // 10 blocks
            ticket_expiry: 2880 * 12, // Approx 1 month (2880 blocks/day * 30 days)
            tickets_per_round: 5, // Select 5 tickets for voting in each round
            min_block_time: 60, // 60 seconds
            reward_amount: 1_000_000, // 0.01 RustyCoin per ticket
            target_live_tickets: 1000, // Target 1000 live tickets in the network
            price_adjustment_factor: 0.05, // 5% adjustment per period
            difficulty_adjustment_window: 144, // Adjust difficulty every 144 blocks (approx 1 day)
            halving_interval: 210_000, // Halve reward every 210,000 blocks
            initial_block_reward: 50_000_000_000, // 500 RustyCoin
            pos_reward_ratio: 0.6, // 60% of total reward to PoS stakers
            miner_address: vec![0u8; 20], // Placeholder
            ticket_price_adjustment_period: 144, // Adjust ticket price every 144 blocks
            max_ticket_price: 10_000_000_000, // Max 100 RustyCoin
            min_ticket_price: 100_000_000, // Min 1 RustyCoin

            // Governance parameters
            proposal_stake_amount: 100_000_000_000, // 1000 RustyCoin to propose
            voting_period_blocks: 20160, // Approximately 2 weeks (14 days * 1440 blocks/day)
            pos_voting_quorum_percentage: 0.1, // 10% of PoS tickets must vote for quorum
            mn_voting_quorum_percentage: 0.6, // 60% of Masternodes must vote for quorum
            pos_approval_percentage: 0.75, // 75% approval for PoS votes
            mn_approval_percentage: 0.8, // 80% approval for Masternode votes
            activation_delay_blocks: 144, // 1 day delay for activation
            grace_period_blocks: 10, // 10 blocks grace period for PoSe non-participation
            slash_forgiveness_period: 100, // After 100 blocks, PoSe failure count resets
            malicious_behavior_slash_percentage: 0.5, // 50% slash for malicious behavior

            // Masternode Proof-of-Service parameters
            pose_challenge_period_blocks: 10, // Challenge every 10 blocks
            num_pose_challengers: 3, // 3 Masternodes selected as challengers
            num_pose_targets_per_period: 5, // 5 Masternodes targeted per period
            pose_response_timeout_seconds: 300, // 5 minutes to respond
            max_pose_failures: 5, // 5 failures before slashing
            reset_failures_period: 1440, // Reset failures after 1 day (1440 blocks)
            min_witness_signatures: 3, // Minimum 3 witness signatures for a valid proof
            pos_finality_depth: 6, // 6 blocks for PoS finality (reorg protection)
            max_block_size: 4_000_000, // 4 MB
        }
    }
}

impl ConsensusParams {
    pub fn testnet() -> Self {
        ConsensusParams {
            min_stake: 1_000_000, // 0.01 RustyCoin
            ticket_price: 10_000, // 0.0001 RustyCoin
            ticket_maturity: 2,
            ticket_expiry: 144, // 1 day
            tickets_per_round: 2,
            min_block_time: 10,
            reward_amount: 100_000, // 0.001 RustyCoin
            target_live_tickets: 100,
            difficulty_adjustment_window: 10,
            halving_interval: 1000,
            initial_block_reward: 1_000_000_000, // 10 RustyCoin
            pos_reward_ratio: 0.8,
            ticket_price_adjustment_period: 10,
            max_ticket_price: 1_000_000, // 0.01 RustyCoin
            min_ticket_price: 1_000, // 0.00001 RustyCoin
            proposal_stake_amount: 10_000_000, // 0.1 RustyCoin
            voting_period_blocks: 100,
            activation_delay_blocks: 10,
            grace_period_blocks: 2,
            slash_forgiveness_period: 10,
            malicious_behavior_slash_percentage: 0.75,
            pose_challenge_period_blocks: 5,
            num_pose_challengers: 1,
            num_pose_targets_per_period: 2,
            pose_response_timeout_seconds: 60,
            max_pose_failures: 2,
            reset_failures_period: 100,
            min_witness_signatures: 1,
            pos_finality_depth: 3,
            max_block_size: 1_000_000, // 1 MB
            ..Default::default()
        }
    }

    pub fn regtest() -> Self {
        ConsensusParams {
            min_stake: 100,
            max_tickets_per_stake: 1,
            ticket_price: 10,
            ticket_maturity: 1,
            ticket_expiry: 10,
            tickets_per_round: 1,
            min_block_time: 1,
            reward_amount: 1,
            target_live_tickets: 10,
            price_adjustment_factor: 0.1,
            difficulty_adjustment_window: 5,
            halving_interval: 100,
            initial_block_reward: 100,
            pos_reward_ratio: 0.9,
            ticket_price_adjustment_period: 5,
            max_ticket_price: 1000,
            min_ticket_price: 1,
            proposal_stake_amount: 100,
            voting_period_blocks: 10,
            pos_voting_quorum_percentage: 0.05,
            mn_voting_quorum_percentage: 0.1,
            pos_approval_percentage: 0.5,
            mn_approval_percentage: 0.6,
            activation_delay_blocks: 1,
            grace_period_blocks: 1,
            slash_forgiveness_period: 5,
            malicious_behavior_slash_percentage: 0.9,
            pose_challenge_period_blocks: 1,
            num_pose_challengers: 1,
            num_pose_targets_per_period: 1,
            pose_response_timeout_seconds: 10,
            max_pose_failures: 1,
            reset_failures_period: 10,
            min_witness_signatures: 1,
            pos_finality_depth: 1,
            max_block_size: 100_000, // 100 KB
            ..Default::default()
        }
    }
}
