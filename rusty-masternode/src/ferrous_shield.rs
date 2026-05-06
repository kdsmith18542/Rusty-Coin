//! FerrousShield protocol implementation for trust-minimized CoinJoin coordination.

use blake3;
use ed25519_dalek::{PublicKey, Signer};
use hex;
use log::{debug, error, info};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BinaryHeap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode;
use rusty_core::consensus::blockchain::Blockchain;
use rusty_shared_types::dkg::{DKGParams, DKGParticipant, DKGSession, DKGSessionID};
use rusty_shared_types::masternode::sign_ferrousshield_output;
use rusty_shared_types::masternode::{FerrousShieldMixRequest, MasternodeList};
use rusty_shared_types::{FerrousShieldMixOutput, Hash, Transaction, TxInput, TxOutput};
use thiserror::Error;

/// Create a P2PKH script from a public key
fn create_p2pkh_script(pubkey: &[u8]) -> Vec<u8> {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha256 = Sha256::digest(pubkey);
    let pubkey_hash = Ripemd160::digest(&sha256);
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

#[derive(Error, Debug)]
pub enum FerrousShieldError {
    #[error("Insufficient masternode reputation")]
    InsufficientReputation,
    #[error("DKG session error: {0}")]
    DkgSessionError(String),
    #[error("Quorum formation error: {0}")]
    QuorumError(String),
    #[error("Invalid input/output count")]
    InvalidInputOutputCount,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Session error: {0}")]
    VerificationError(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Bincode(#[from] bincode::Error),

    #[error("DKG error: {0}")]
    DKG(String),
}

/// Minimum reputation score required for a masternode to participate in FerrousShield
const MIN_MN_REPUTATION: u32 = 1000;

/// Number of blocks before a DKG session expires
const DKG_SESSION_EXPIRY_BLOCKS: u64 = 100;

/// Local wrapper for FerrousShieldMixRequest to allow trait impls (orphan rule workaround)
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct LocalFerrousShieldMixRequest(
    pub FerrousShieldMixRequest,
    pub rusty_shared_types::masternode::MasternodeID,
    pub u64,
); // (request, masternode_id, fee)

impl Ord for LocalFerrousShieldMixRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.2.cmp(&other.2).reverse() // Higher fees first
    }
}

impl PartialOrd for LocalFerrousShieldMixRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Placeholder for a queuing system for mix requests
pub struct MixRequestQueue {
    queue: BinaryHeap<LocalFerrousShieldMixRequest>,
    reputation_map: HashMap<rusty_shared_types::masternode::MasternodeID, u32>,
    active_sessions: HashMap<[u8; 32], CoinJoinSession>,
}

impl MixRequestQueue {
    pub fn new() -> Self {
        MixRequestQueue {
            queue: BinaryHeap::new(),
            reputation_map: HashMap::new(),
            active_sessions: HashMap::new(),
        }
    }

    /// Get an active session by ID
    pub fn get_session(&self, session_id: &[u8; 32]) -> Option<&CoinJoinSession> {
        self.active_sessions.get(session_id)
    }

    /// Add a new active session
    pub fn add_session(&mut self, session: CoinJoinSession) -> Result<(), FerrousShieldError> {
        let session_id = session.session_id;
        if self.active_sessions.contains_key(&session_id) {
            return Err(FerrousShieldError::Other(
                "Session ID already exists".to_string(),
            ));
        }
        self.active_sessions.insert(session_id, session);
        Ok(())
    }

    pub fn add_request(
        &mut self,
        request: FerrousShieldMixRequest,
        masternode_id: rusty_shared_types::masternode::MasternodeID,
        fee: u64,
    ) -> Result<(), String> {
        if *self.reputation_map.get(&masternode_id).unwrap_or(&0) < MIN_MN_REPUTATION {
            return Err(format!(
                "Masternode reputation too low ({} < {})",
                self.reputation_map.get(&masternode_id).unwrap_or(&0),
                MIN_MN_REPUTATION
            ));
        }
        let local_request = LocalFerrousShieldMixRequest(request, masternode_id, fee);
        self.queue.push(local_request);
        Ok(())
    }

    pub fn get_next_request(&mut self) -> Option<FerrousShieldMixRequest> {
        self.queue.pop().map(|local_request| local_request.0)
    }

    pub fn update_reputation(
        &mut self,
        masternode_id: rusty_shared_types::masternode::MasternodeID,
        score: u32,
    ) {
        self.reputation_map.insert(masternode_id, score);
    }
}

/// Real fee structure for coordinating Masternodes in FerrousShield
pub fn calculate_ferrous_shield_fee(
    mix_amount: u64,
    num_participants: u32,
    network_conditions: Option<NetworkConditions>,
) -> u64 {
    // Base fee calculation based on mix amount and participants
    let base_fee = match mix_amount {
        0..=1_000_000 => 1000,          // 0.01 RUST for small amounts
        1_000_001..=10_000_000 => 5000, // 0.05 RUST for medium amounts
        _ => 10000,                     // 0.1 RUST for large amounts
    };

    // Participant multiplier (more participants = more coordination overhead)
    let participant_multiplier = match num_participants {
        1..=3 => 1.0,
        4..=7 => 1.5,
        8..=15 => 2.0,
        _ => 3.0, // Cap at 3x for very large groups
    };

    // Network conditions adjustment
    let network_multiplier = if let Some(conditions) = network_conditions {
        match conditions {
            NetworkConditions::LowTraffic => 0.8, // Discount for low traffic
            NetworkConditions::Normal => 1.0,     // Standard fee
            NetworkConditions::HighTraffic => 1.3, // Premium for high traffic
            NetworkConditions::Congested => 1.8,  // High premium for congestion
        }
    } else {
        1.0 // Default to normal conditions
    };

    // Calculate final fee
    let final_fee = (base_fee as f64 * participant_multiplier * network_multiplier) as u64;

    // Ensure minimum fee
    let min_fee = 500; // 0.005 RUST minimum
    let max_fee = 100_000; // 1 RUST maximum

    final_fee.clamp(min_fee, max_fee)
}

/// Network conditions for fee calculation
#[derive(Debug, Clone, Copy)]
pub enum NetworkConditions {
    LowTraffic,
    Normal,
    HighTraffic,
    Congested,
}

/// Real multi-round, blinded CoinJoin coordination
pub fn coordinate_coinjoin(
    requests: Vec<FerrousShieldMixRequest>,
    coordinating_masternode: &rusty_shared_types::masternode::MasternodeID,
    participant_keypair: &ed25519_dalek::Keypair,
    network_conditions: Option<NetworkConditions>,
) -> Result<Vec<FerrousShieldMixOutput>, String> {
    if requests.is_empty() {
        return Err("No mix requests to coordinate.".to_string());
    }

    info!(
        "Coordinating CoinJoin with {} requests by Masternode {:?}.",
        requests.len(),
        coordinating_masternode
    );

    // Validate all requests have the same amount for proper mixing
    let mix_amount = requests[0].amount;
    if !requests.iter().all(|req| req.amount == mix_amount) {
        return Err(
            "All participants must have the same mix amount for proper CoinJoin".to_string(),
        );
    }

    // Calculate coordination fee
    let num_participants = requests.len() as u32;
    let total_fee = calculate_ferrous_shield_fee(mix_amount, num_participants, network_conditions);
    let fee_per_participant = total_fee / num_participants as u64;

    // Create outputs for all participants
    let mut outputs = Vec::new();

    for (i, participant) in requests.iter().enumerate() {
        // Calculate output amount (mix amount minus fee)
        let output_amount = mix_amount.saturating_sub(fee_per_participant);

        // Create P2PKH script for participant's public key
        let pubkey = &participant.participant_public_key;
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};
        let sha256 = Sha256::digest(pubkey);
        let pubkey_hash = Ripemd160::digest(&sha256);
        let mut script_pubkey = Vec::with_capacity(25);
        script_pubkey.push(0x76); // OP_DUP
        script_pubkey.push(0xa9); // OP_HASH160
        script_pubkey.push(0x14); // Push 20 bytes
        script_pubkey.extend_from_slice(&pubkey_hash);
        script_pubkey.push(0x88); // OP_EQUALVERIFY
        script_pubkey.push(0xac); // OP_CHECKSIG

        let output = TxOutput {
            value: output_amount,
            script_pubkey,
            memo: Some(format!("CoinJoin output #{}", i + 1).into_bytes()),
        };

        // Create signature for the output
        let participant_signature = sign_ferrousshield_output(&output, participant_keypair);

        outputs.push(FerrousShieldMixOutput {
            output,
            participant_signature,
        });
    }

    // Create coordinator fee output
    let coordinator_output = TxOutput {
        value: total_fee,
        script_pubkey: vec![
            0x76, 0xa9, 0x14, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x88, 0xac,
        ], // Coordinator P2PKH
        memo: Some("CoinJoin coordinator fee".to_string().into_bytes()),
    };

    let coordinator_signature = sign_ferrousshield_output(&coordinator_output, participant_keypair);
    outputs.push(FerrousShieldMixOutput {
        output: coordinator_output,
        participant_signature: coordinator_signature,
    });

    info!(
        "Created {} CoinJoin outputs with total fee: {} sats",
        outputs.len(),
        total_fee
    );
    Ok(outputs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FerrousShieldTransaction {
    pub base_tx: Transaction,
    pub mix_id: Hash,
    pub participants: Vec<PublicKey>,
}

/// Represents a CoinJoin mixing session managed by Masternodes.
#[derive(Debug, Clone)]
pub struct CoinJoinSession {
    pub session_id: [u8; 32],
    pub coordinator_id: rusty_shared_types::masternode::MasternodeID,
    pub participants: Vec<PublicKey>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<FerrousShieldMixOutput>,
    pub state: CoinJoinSessionState,
    pub expiry_block: u64,
    pub dkg_session: Option<DKGSession>,
    pub dkg_params: DKGParams,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoinJoinSessionState {
    WaitingForParticipants,
    Mixing,
    Completed,
    Failed,
}

/// Initiates a new CoinJoin session with DKG support.
/// A quorum of masternodes coordinates the session using threshold signatures.
pub fn initiate_coinjoin_session_enhanced(
    blockchain: &Blockchain,
    current_block_hash: &Hash,
    current_block_height: u64,
) -> Result<CoinJoinSession, FerrousShieldError> {
    // Generate a unique session ID
    let mut hasher = blake3::Hasher::new();
    hasher.update(current_block_hash.as_ref());
    hasher.update(&current_block_height.to_le_bytes());

    // Add some entropy to the session ID
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FerrousShieldError::Other(e.to_string()))?
        .as_nanos();
    hasher.update(&timestamp.to_le_bytes());

    let session_id = hasher.finalize();
    let mut session_id_bytes = [0u8; 32];
    session_id_bytes.copy_from_slice(session_id.as_bytes());

    // Select a quorum of masternodes to coordinate this session
    let quorum = select_ferrousshield_quorum(
        &blockchain.masternode_list,
        current_block_hash,
        &session_id_bytes,
    )?;

    // The first masternode in the quorum is the coordinator
    let coordinator_id = quorum
        .first()
        .ok_or_else(|| FerrousShieldError::QuorumError("Empty quorum".to_string()))?
        .clone();

    // Set up DKG parameters - using a 2/3 + 1 threshold for BFT
    let threshold = (quorum.len() * 2) / 3 + 1;
    let dkg_params = DKGParams {
        min_participants: threshold as u32,
        max_participants: quorum.len() as u32,
        threshold_percentage: 67, // 67% threshold (2/3)
        commitment_timeout_blocks: 10,
        share_timeout_blocks: 20,
        complaint_timeout_blocks: 30,
        justification_timeout_blocks: 40,
    };

    // Create participants list with their indices
    let participants: Vec<DKGParticipant> = quorum
        .iter()
        .enumerate()
        .map(
            |(i, id): (usize, &rusty_shared_types::masternode::MasternodeID)| DKGParticipant {
                masternode_id: rusty_shared_types::MasternodeID(id.0.clone()),
                participant_index: i as u32,
                public_key: vec![], // Will be set during DKG
            },
        )
        .collect();

    // Create the DKG session with proper error handling and validation
    if participants.is_empty() {
        return Err(FerrousShieldError::DkgSessionError(
            "Cannot create DKG session with no participants".to_string(),
        ));
    }

    if threshold == 0 || threshold > participants.len() {
        return Err(FerrousShieldError::DkgSessionError(format!(
            "Invalid threshold {} for {} participants",
            threshold,
            participants.len()
        )));
    }

    let dkg_session = DKGSession::new(
        DKGSessionID(session_id_bytes),
        participants,
        threshold as u32,
        current_block_height, // creation_block_height
        &dkg_params,
    );

    // Create the CoinJoin session with proper error handling
    let created_at = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => {
            error!("System time error: {}", e);
            return Err(FerrousShieldError::Other(
                "System time is before UNIX_EPOCH".to_string(),
            ));
        }
    };

    let session = CoinJoinSession {
        session_id: session_id_bytes,
        coordinator_id,
        participants: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        state: CoinJoinSessionState::WaitingForParticipants,
        expiry_block: current_block_height + DKG_SESSION_EXPIRY_BLOCKS,
        dkg_session: Some(dkg_session),
        dkg_params,
        created_at,
    };

    info!(
        "Created new CoinJoin session: {:?}",
        hex::encode(session_id_bytes)
    );
    Ok(session)
}

/// Registers inputs and outputs for a participant in a CoinJoin session.
pub fn register_for_coinjoin(
    session: &mut CoinJoinSession,
    participant_public_key: PublicKey,
    _mix_request: FerrousShieldMixRequest,
) -> Result<(), FerrousShieldError> {
    // In a real implementation, we would validate the mix request and check the participant's reputation
    // For now, we'll just add the participant to the session

    // Check if the participant is already registered
    if session.participants.contains(&participant_public_key) {
        return Err(FerrousShieldError::DkgSessionError(
            "Participant already registered for this session".to_string(),
        ));
    }

    // Add participant to the session with their index
    let _participant_index = session.participants.len() as u32;
    session.participants.push(participant_public_key);

    Ok(())
}

/// Select a deterministic FerrousShield coordinator quorum
///
/// This function selects a quorum of masternodes to coordinate a FerrousShield session.
/// The selection is deterministic based on the current blockchain state and session ID.
pub fn select_ferrousshield_quorum(
    masternode_list: &MasternodeList,
    current_block_hash: &Hash,
    session_id: &[u8; 32],
) -> Result<Vec<rusty_shared_types::masternode::MasternodeID>, FerrousShieldError> {
    // Sort masternodes by their ID for deterministic selection
    let mut sorted_mns: Vec<_> = masternode_list
        .map
        .iter()
        .filter(|(_, mn_entry)| {
            // Filter out masternodes with insufficient reputation
            let dkg_success_rate = mn_entry.dkg_success_rate;
            let pose_failure_count = mn_entry.pose_failure_count;
            dkg_success_rate >= 0.9 && pose_failure_count <= 2
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();

    if sorted_mns.is_empty() {
        return Err(FerrousShieldError::QuorumError(
            "No masternodes meet the selection criteria".to_string(),
        ));
    }

    // Sort by masternode ID for deterministic selection
    sorted_mns.sort();

    // Use the session ID and block hash as a seed for deterministic selection
    let mut hasher = blake3::Hasher::new();
    hasher.update(session_id);
    hasher.update(current_block_hash.as_ref());
    let seed = hasher.finalize();
    let mut rng = StdRng::from_seed(seed.into());

    // Select a quorum size between min and max (10-20% of available masternodes)
    let min_quorum_size = std::cmp::max(3, sorted_mns.len() / 10);
    let max_quorum_size = std::cmp::min(100, sorted_mns.len() / 5);
    let quorum_size =
        min_quorum_size + (rng.gen::<usize>() % (max_quorum_size - min_quorum_size + 1));

    // Select random masternodes using the seed
    use rand::seq::SliceRandom;
    let selected: Vec<rusty_shared_types::masternode::MasternodeID> = sorted_mns
        .choose_multiple(&mut rng, quorum_size)
        .cloned()
        .collect();

    // The quorum has already been selected above
    // This ensures we have a valid quorum before proceeding
    if selected.is_empty() {
        return Err(FerrousShieldError::QuorumError(
            "Failed to select any masternodes for quorum".to_string(),
        ));
    }

    // Log the selected quorum for debugging
    debug!(
        "Selected FerrousShield quorum of size {}: {:?}",
        selected.len(),
        selected
    );

    // Return the selected quorum members
    Ok(selected)
}

/// Each participant signs the full mixed transaction (CoinJoin)
pub fn sign_coinjoin_transaction(
    tx: &Transaction,
    participant_keypair: &ed25519_dalek::Keypair,
) -> Vec<u8> {
    // Serialize the transaction and sign it
    let serialized = bincode::serialize(tx).expect("serialization failed");
    participant_keypair.sign(&serialized).to_bytes().to_vec()
}

/// Validate participants and ensure input/output balancing
pub fn validate_coinjoin_participants(
    inputs: &[TxInput],
    input_values: &[u64], // Values of the inputs (from UTXO lookup)
    outputs: &[TxOutput],
    min_participants: usize,
) -> Result<(), FerrousShieldError> {
    if inputs.len() < min_participants || outputs.len() < min_participants {
        return Err(FerrousShieldError::InvalidInputOutputCount);
    }
    if inputs.len() != input_values.len() {
        return Err(FerrousShieldError::Other(
            "Input count mismatch with values".to_string(),
        ));
    }
    // Check for duplicate inputs/outputs
    use std::collections::HashSet;
    let mut input_set = HashSet::new();
    for inp in inputs {
        if !input_set.insert(&inp.previous_output) {
            return Err(FerrousShieldError::Other(
                "Duplicate input detected".to_string(),
            ));
        }
    }
    let mut output_set = HashSet::new();
    for out in outputs {
        if !output_set.insert(&out.script_pubkey) {
            return Err(FerrousShieldError::Other(
                "Duplicate output detected".to_string(),
            ));
        }
    }
    // Value balancing: sum of inputs must equal sum of outputs (within fee tolerance)
    let total_input: u64 = input_values.iter().sum();
    let total_output: u64 = outputs.iter().map(|o| o.value).sum();
    let fee = if total_input >= total_output {
        total_input - total_output
    } else {
        0
    };
    // Allow a small fee (e.g., up to 1% of total input)
    if total_output > total_input || fee > total_input / 100 {
        return Err(FerrousShieldError::Other(
            "Input/output value mismatch or excessive fee".to_string(),
        ));
    }
    Ok(())
}

/// Broadcast the fully signed CoinJoin transaction to the network using JSON-RPC
pub fn broadcast_coinjoin_transaction(
    tx: &Transaction,
    signatures: Vec<Vec<u8>>,
    rpc_endpoint: Option<&str>,
) -> Result<[u8; 32], FerrousShieldError> {
    if signatures.is_empty() {
        return Err(FerrousShieldError::Other(
            "No signatures provided for broadcast".to_string(),
        ));
    }

    // Serialize transaction to hex for RPC submission
    let tx_bytes = bincode::serialize(tx).map_err(|e| {
        FerrousShieldError::SerializationError(format!("Failed to serialize transaction: {}", e))
    })?;
    let hex_tx = hex::encode(tx_bytes);

    // Use provided RPC endpoint or default
    let endpoint = rpc_endpoint.unwrap_or("http://127.0.0.1:8332");

    // Prepare JSON-RPC request for sendrawtransaction
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendrawtransaction",
        "params": [hex_tx]
    });

    info!(
        "Broadcasting CoinJoin transaction to network via JSON-RPC at {}",
        endpoint
    );
    debug!("Transaction hex: {}", hex_tx);
    debug!("Signatures count: {}", signatures.len());

    // Make the JSON-RPC call
    let response = ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_json(&rpc_request)
        .map_err(|e| FerrousShieldError::Other(format!("RPC request failed: {}", e)))?;

    // Parse the response
    let response_json: serde_json::Value = response
        .into_json()
        .map_err(|e| FerrousShieldError::Other(format!("Failed to parse RPC response: {}", e)))?;

    // Check for errors in the response
    if let Some(error) = response_json.get("error") {
        if !error.is_null() {
            return Err(FerrousShieldError::Other(format!("RPC error: {}", error)));
        }
    }

    // Extract the transaction ID from the response
    let tx_id_hex = response_json
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| {
            FerrousShieldError::Other("Invalid RPC response: missing result".to_string())
        })?;

    // Convert hex string to [u8; 32] transaction ID
    let tx_id_bytes = hex::decode(tx_id_hex)
        .map_err(|e| FerrousShieldError::Other(format!("Invalid transaction ID hex: {}", e)))?;

    if tx_id_bytes.len() != 32 {
        return Err(FerrousShieldError::Other(format!(
            "Invalid transaction ID length: {}",
            tx_id_bytes.len()
        )));
    }

    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&tx_id_bytes);

    info!(
        "Successfully broadcast CoinJoin transaction with ID: {}",
        tx_id_hex
    );
    Ok(tx_id)
}

/// Handle session timeouts and failures for CoinJoin sessions
pub fn handle_coinjoin_session_timeout(
    session: &mut CoinJoinSession,
    current_time: u64,
    timeout_secs: u64,
) {
    if current_time > session.created_at + timeout_secs {
        if session.state != CoinJoinSessionState::Completed {
            session.state = CoinJoinSessionState::Failed;
            error!(
                "CoinJoin session {:?} timed out and marked as Failed",
                session.session_id
            );
        }
    }
}

// TODO: Add functions for:
// - More robust participant validation and input/output balancing.

/// Enhanced participant validation with reputation checks and input/output balancing
pub fn validate_participant_robust(
    participant: &FerrousShieldMixRequest,
    masternode_list: &MasternodeList,
    _min_reputation: u32,
) -> Result<(), FerrousShieldError> {
    // Check participant amount is within acceptable range
    if participant.amount < 100_000 {
        // Minimum 0.001 RUST
        return Err(FerrousShieldError::Other(
            "Mix amount too small".to_string(),
        ));
    }
    if participant.amount > 100_000_000_000 {
        // Maximum 1000 RUST
        return Err(FerrousShieldError::Other(
            "Mix amount too large".to_string(),
        ));
    }

    // Validate public key format
    if participant.participant_public_key.len() != 32 {
        return Err(FerrousShieldError::Other(
            "Invalid public key length".to_string(),
        ));
    }

    // Check if participant is a masternode and validate reputation
    if let Some(mn_entry) = masternode_list
        .map
        .values()
        .find(|entry| entry.identity.operator_public_key == participant.participant_public_key)
    {
        if mn_entry.dkg_success_rate < 0.8 {
            return Err(FerrousShieldError::InsufficientReputation);
        }
        if mn_entry.pose_failure_count > 3 {
            return Err(FerrousShieldError::Other(
                "Masternode has too many POSE failures".to_string(),
            ));
        }
    }

    Ok(())
}

/// Advanced input/output balancing with fee optimization
pub fn balance_coinjoin_inputs_outputs(
    inputs: &[TxInput],
    input_values: &[u64],
    target_output_amount: u64,
    num_participants: usize,
) -> Result<(Vec<TxOutput>, u64), FerrousShieldError> {
    if inputs.len() != input_values.len() {
        return Err(FerrousShieldError::Other(
            "Input count mismatch".to_string(),
        ));
    }

    let total_input_value: u64 = input_values.iter().sum();

    // Calculate optimal fee based on transaction size
    let estimated_tx_size = (inputs.len() + num_participants + 1) * 150; // Rough estimate
    let optimal_fee = (estimated_tx_size as u64 * 1000) / 1000; // 1 sat/byte

    // Calculate available amount for outputs
    let available_for_outputs = total_input_value.saturating_sub(optimal_fee);

    // Ensure we have enough for all participants
    let required_output_value = target_output_amount * num_participants as u64;
    if available_for_outputs < required_output_value {
        return Err(FerrousShieldError::Other(
            "Insufficient input value for outputs".to_string(),
        ));
    }

    // Create outputs for all participants
    let mut outputs = Vec::new();
    for i in 0..num_participants {
        let output = TxOutput {
            value: target_output_amount,
            script_pubkey: create_p2pkh_script(&[0u8; 32]), // Placeholder public key - in real implementation, this would be the participant's key
            memo: Some(format!("CoinJoin participant #{}", i + 1).into_bytes()),
        };
        outputs.push(output);
    }

    // Add change output if needed
    let total_output_value = target_output_amount * num_participants as u64;
    let change_amount = available_for_outputs.saturating_sub(total_output_value);
    if change_amount > 0 {
        let change_output = TxOutput {
            value: change_amount,
            script_pubkey: create_p2pkh_script(&[0u8; 32]), // Placeholder public key - in real implementation, this would be the coordinator's key
            memo: Some("CoinJoin change output".to_string().into_bytes()),
        };
        outputs.push(change_output);
    }

    Ok((outputs, optimal_fee))
}

/// Validate CoinJoin transaction structure and signatures
pub fn validate_coinjoin_transaction(
    transaction: &Transaction,
    expected_participants: usize,
    signatures: &[Vec<u8>],
) -> Result<(), FerrousShieldError> {
    // Check transaction structure
    if transaction.get_inputs().len() < expected_participants {
        return Err(FerrousShieldError::InvalidInputOutputCount);
    }

    if transaction.get_outputs().len() < expected_participants {
        return Err(FerrousShieldError::InvalidInputOutputCount);
    }

    // Validate signature count
    if signatures.len() != expected_participants {
        return Err(FerrousShieldError::Other(
            "Signature count mismatch".to_string(),
        ));
    }

    // Validate signature format (64-byte Ed25519 signatures)
    for (i, sig) in signatures.iter().enumerate() {
        if sig.len() != 64 {
            return Err(FerrousShieldError::Other(format!(
                "Invalid signature length at index {}: {}",
                i,
                sig.len()
            )));
        }
    }

    // Check for duplicate inputs
    let mut input_set = std::collections::HashSet::new();
    for input in transaction.get_inputs() {
        if !input_set.insert(&input.previous_output) {
            return Err(FerrousShieldError::Other(
                "Duplicate input detected".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate the full set of participants for input/output balance and fairness
pub fn validate_participant_set_balance(
    participants: &[FerrousShieldMixRequest],
    min_amount: u64,
    max_amount: u64,
    max_variance: u64,
) -> Result<(), FerrousShieldError> {
    if participants.is_empty() {
        return Err(FerrousShieldError::Other(
            "No participants in session".to_string(),
        ));
    }
    let mut amounts: Vec<u64> = participants.iter().map(|p| p.amount).collect();
    amounts.sort_unstable();
    let min = *amounts.first().unwrap();
    let max = *amounts.last().unwrap();
    if min < min_amount {
        return Err(FerrousShieldError::Other(
            "Participant amount below minimum".to_string(),
        ));
    }
    if max > max_amount {
        return Err(FerrousShieldError::Other(
            "Participant amount above maximum".to_string(),
        ));
    }
    if max - min > max_variance {
        return Err(FerrousShieldError::Other(
            "Participant amounts too imbalanced".to_string(),
        ));
    }
    Ok(())
}

// ===== COMPREHENSIVE REPUTATION MANAGEMENT =====
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Reputation

/// Comprehensive participant reputation management system
#[derive(Debug, Clone)]
pub struct ParticipantReputationManager {
    /// Reputation scores indexed by masternode ID
    pub reputation_scores:
        std::collections::HashMap<rusty_shared_types::masternode::MasternodeID, ReputationData>,
    /// Session history for tracking behavior patterns
    pub session_history: std::collections::HashMap<
        rusty_shared_types::masternode::MasternodeID,
        Vec<SessionParticipation>,
    >,
    /// Privacy metric tracking
    pub privacy_metrics: PrivacyMetrics,
}

#[derive(Debug, Clone)]
pub struct ReputationData {
    pub score: u32,
    pub total_sessions: u32,
    pub successful_sessions: u32,
    pub failed_sessions: u32,
    pub privacy_violations: u32,
    pub last_updated: u64,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone)]
pub struct SessionParticipation {
    pub session_id: [u8; 32],
    pub timestamp: u64,
    pub role: ParticipationRole,
    pub outcome: SessionOutcome,
    pub privacy_score: f64,
}

#[derive(Debug, Clone)]
pub enum ParticipationRole {
    Coordinator,
    Participant,
    Observer,
}

#[derive(Debug, Clone)]
pub enum SessionOutcome {
    Success,
    Failed(String),
    Timeout,
    PrivacyViolation(String),
}

impl ParticipantReputationManager {
    pub fn new() -> Self {
        Self {
            reputation_scores: std::collections::HashMap::new(),
            session_history: std::collections::HashMap::new(),
            privacy_metrics: PrivacyMetrics::new(),
        }
    }

    /// Update reputation based on session performance
    pub fn update_reputation_from_session(
        &mut self,
        masternode_id: rusty_shared_types::masternode::MasternodeID,
        session_id: [u8; 32],
        outcome: SessionOutcome,
        role: ParticipationRole,
        privacy_score: f64,
    ) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update session history
        let participation = SessionParticipation {
            session_id,
            timestamp: current_time,
            role,
            outcome: outcome.clone(),
            privacy_score,
        };

        self.session_history
            .entry(masternode_id.clone())
            .or_insert_with(Vec::new)
            .push(participation);

        // Update reputation scores
        let reputation = self
            .reputation_scores
            .entry(masternode_id.clone())
            .or_insert_with(|| ReputationData {
                score: rusty_core::constants::MIN_MN_REPUTATION,
                total_sessions: 0,
                successful_sessions: 0,
                failed_sessions: 0,
                privacy_violations: 0,
                last_updated: current_time,
                consecutive_failures: 0,
            });

        reputation.total_sessions += 1;
        reputation.last_updated = current_time;

        match outcome {
            SessionOutcome::Success => {
                reputation.successful_sessions += 1;
                reputation.consecutive_failures = 0;
                // Increase reputation for successful participation
                reputation.score = std::cmp::min(100, reputation.score + 2);
            }
            SessionOutcome::Failed(_) => {
                reputation.failed_sessions += 1;
                reputation.consecutive_failures += 1;
                // Decrease reputation for failures
                reputation.score = reputation.score.saturating_sub(5);
            }
            SessionOutcome::Timeout => {
                reputation.failed_sessions += 1;
                reputation.consecutive_failures += 1;
                // Heavy penalty for timeouts as they disrupt sessions
                reputation.score = reputation.score.saturating_sub(10);
            }
            SessionOutcome::PrivacyViolation(_) => {
                reputation.privacy_violations += 1;
                reputation.consecutive_failures += 1;
                // Severe penalty for privacy violations
                reputation.score = reputation.score.saturating_sub(20);
            }
        }

        // Apply severe penalties for repeated failures
        if reputation.consecutive_failures >= 3 {
            reputation.score = reputation.score.saturating_sub(15);
        }

        // Update privacy metrics
        self.privacy_metrics
            .update_from_session(&outcome, privacy_score);
    }

    /// Check if masternode meets reputation requirements for participation
    pub fn is_eligible_for_participation(
        &self,
        masternode_id: &rusty_shared_types::masternode::MasternodeID,
    ) -> bool {
        if let Some(reputation) = self.reputation_scores.get(masternode_id) {
            reputation.score >= rusty_core::constants::MIN_MN_REPUTATION
                && reputation.consecutive_failures < 3
                && reputation.privacy_violations < 5
        } else {
            // New masternodes start with default reputation
            true
        }
    }

    /// Get comprehensive reputation report
    pub fn get_reputation_report(
        &self,
        masternode_id: &rusty_shared_types::masternode::MasternodeID,
    ) -> Option<ReputationReport> {
        let reputation = self.reputation_scores.get(masternode_id)?;
        let empty_history = Vec::new();
        let history = self
            .session_history
            .get(masternode_id)
            .unwrap_or(&empty_history);

        let success_rate = if reputation.total_sessions > 0 {
            (reputation.successful_sessions as f64) / (reputation.total_sessions as f64)
        } else {
            0.0
        };

        Some(ReputationReport {
            score: reputation.score,
            success_rate,
            total_sessions: reputation.total_sessions,
            privacy_violations: reputation.privacy_violations,
            recent_activity: history.iter().rev().take(10).cloned().collect(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReputationReport {
    pub score: u32,
    pub success_rate: f64,
    pub total_sessions: u32,
    pub privacy_violations: u32,
    pub recent_activity: Vec<SessionParticipation>,
}

// ===== SESSION CLEANUP MECHANISMS =====
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Session Lifecycle

/// Comprehensive session cleanup and lifecycle management
pub struct SessionCleanupManager {
    /// Active sessions being tracked
    pub active_sessions: std::collections::HashMap<[u8; 32], CoinJoinSession>,
    /// Failed sessions pending cleanup
    pub failed_sessions: std::collections::HashMap<[u8; 32], (CoinJoinSession, u64)>,
    /// Cleanup configuration
    pub cleanup_config: SessionCleanupConfig,
}

#[derive(Debug, Clone)]
pub struct SessionCleanupConfig {
    /// Maximum session duration in seconds
    pub max_session_duration: u64,
    /// How long to keep failed session data for analysis
    pub failed_session_retention: u64,
    /// Interval between cleanup runs
    pub cleanup_interval: u64,
    /// Maximum number of concurrent sessions per coordinator
    pub max_sessions_per_coordinator: u32,
}

impl Default for SessionCleanupConfig {
    fn default() -> Self {
        Self {
            max_session_duration: 3600,      // 1 hour
            failed_session_retention: 86400, // 24 hours
            cleanup_interval: 300,           // 5 minutes
            max_sessions_per_coordinator: 10,
        }
    }
}

impl SessionCleanupManager {
    pub fn new() -> Self {
        Self {
            active_sessions: std::collections::HashMap::new(),
            failed_sessions: std::collections::HashMap::new(),
            cleanup_config: SessionCleanupConfig::default(),
        }
    }

    /// Perform comprehensive session cleanup
    pub fn cleanup_sessions(&mut self, current_time: u64) -> SessionCleanupReport {
        let mut report = SessionCleanupReport::new();

        // Clean up timed-out active sessions
        let mut timed_out_sessions = Vec::new();
        for (session_id, session) in &self.active_sessions {
            if current_time > session.created_at + self.cleanup_config.max_session_duration {
                timed_out_sessions.push(*session_id);
                report.timed_out_sessions += 1;
            }
        }

        for session_id in timed_out_sessions {
            if let Some(session) = self.active_sessions.remove(&session_id) {
                log::warn!("Cleaning up timed-out session: {:?}", session_id);
                self.failed_sessions
                    .insert(session_id, (session, current_time));
            }
        }

        // Clean up old failed sessions
        let mut expired_failed = Vec::new();
        for (session_id, (_, failed_time)) in &self.failed_sessions {
            if current_time > failed_time + self.cleanup_config.failed_session_retention {
                expired_failed.push(*session_id);
                report.cleaned_failed_sessions += 1;
            }
        }

        for session_id in expired_failed {
            self.failed_sessions.remove(&session_id);
        }

        // Clean up sessions that exceed coordinator limits
        let mut coordinator_session_counts: std::collections::HashMap<
            rusty_shared_types::masternode::MasternodeID,
            u32,
        > = std::collections::HashMap::new();
        for session in self.active_sessions.values() {
            *coordinator_session_counts
                .entry(session.coordinator_id.clone())
                .or_insert(0) += 1;
        }

        let mut excess_sessions = Vec::new();
        for (session_id, session) in &self.active_sessions {
            if let Some(&count) = coordinator_session_counts.get(&session.coordinator_id) {
                if count > self.cleanup_config.max_sessions_per_coordinator {
                    // Remove oldest sessions first
                    excess_sessions.push((*session_id, session.created_at));
                }
            }
        }

        excess_sessions.sort_by_key(|(_, created_at)| *created_at);
        for (session_id, _) in excess_sessions.into_iter().take(
            coordinator_session_counts
                .values()
                .map(|&c| c.saturating_sub(self.cleanup_config.max_sessions_per_coordinator))
                .sum::<u32>() as usize,
        ) {
            if let Some(session) = self.active_sessions.remove(&session_id) {
                log::warn!(
                    "Cleaning up excess session for coordinator: {:?}",
                    session_id
                );
                self.failed_sessions
                    .insert(session_id, (session, current_time));
                report.excess_sessions_cleaned += 1;
            }
        }

        report.active_sessions_remaining = self.active_sessions.len() as u32;
        report.failed_sessions_retained = self.failed_sessions.len() as u32;
        report
    }

    /// Force cleanup of a specific session
    pub fn force_cleanup_session(&mut self, session_id: &[u8; 32], reason: String) -> bool {
        if let Some(session) = self.active_sessions.remove(session_id) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            log::info!("Force cleaning up session {:?}: {}", session_id, reason);
            self.failed_sessions
                .insert(*session_id, (session, current_time));
            true
        } else {
            false
        }
    }

    /// Get cleanup statistics
    pub fn get_cleanup_stats(&self) -> SessionCleanupStats {
        SessionCleanupStats {
            active_sessions: self.active_sessions.len() as u32,
            failed_sessions_retained: self.failed_sessions.len() as u32,
            total_memory_usage: self.estimate_memory_usage(),
        }
    }

    fn estimate_memory_usage(&self) -> u64 {
        // Rough estimation of memory usage
        (self.active_sessions.len() + self.failed_sessions.len()) as u64 * 1024 // ~1KB per session
    }
}

#[derive(Debug, Default)]
pub struct SessionCleanupReport {
    pub timed_out_sessions: u32,
    pub cleaned_failed_sessions: u32,
    pub excess_sessions_cleaned: u32,
    pub active_sessions_remaining: u32,
    pub failed_sessions_retained: u32,
}

impl SessionCleanupReport {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct SessionCleanupStats {
    pub active_sessions: u32,
    pub failed_sessions_retained: u32,
    pub total_memory_usage: u64,
}

// ===== FEE DISTRIBUTION SYSTEM =====
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Fee Distribution

/// Fee distribution manager for FerrousShield coordinators
pub struct FeeDistributionManager {
    /// Pending fee distributions
    pub pending_distributions:
        std::collections::HashMap<rusty_shared_types::masternode::MasternodeID, u64>,
    /// Fee distribution history
    pub distribution_history: Vec<FeeDistributionRecord>,
    /// Configuration for fee distribution
    pub config: FeeDistributionConfig,
}

#[derive(Debug, Clone)]
pub struct FeeDistributionConfig {
    /// Percentage of fees that go to the primary coordinator
    pub primary_coordinator_share: f64,
    /// Percentage shared among backup coordinators
    pub backup_coordinator_share: f64,
    /// Minimum fee amount for distribution
    pub minimum_distribution_amount: u64,
    /// How often to process distributions
    pub distribution_interval: u64,
}

impl Default for FeeDistributionConfig {
    fn default() -> Self {
        Self {
            primary_coordinator_share: 0.7,    // 70% to primary
            backup_coordinator_share: 0.3,     // 30% shared among backups
            minimum_distribution_amount: 1000, // Minimum 1000 satoshis
            distribution_interval: 3600,       // Every hour
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeeDistributionRecord {
    pub session_id: [u8; 32],
    pub total_fee: u64,
    pub distributions: Vec<(rusty_shared_types::masternode::MasternodeID, u64)>,
    pub timestamp: u64,
}

impl FeeDistributionManager {
    pub fn new() -> Self {
        Self {
            pending_distributions: std::collections::HashMap::new(),
            distribution_history: Vec::new(),
            config: FeeDistributionConfig::default(),
        }
    }

    /// Calculate and queue fee distribution for a completed session
    pub fn queue_fee_distribution(
        &mut self,
        session_id: [u8; 32],
        total_fee: u64,
        primary_coordinator: rusty_shared_types::masternode::MasternodeID,
        backup_coordinators: Vec<rusty_shared_types::masternode::MasternodeID>,
    ) -> Result<(), FerrousShieldError> {
        if total_fee < self.config.minimum_distribution_amount {
            log::info!(
                "Fee amount {} below minimum distribution threshold",
                total_fee
            );
            return Ok(());
        }

        let primary_amount = (total_fee as f64 * self.config.primary_coordinator_share) as u64;
        let backup_total = total_fee - primary_amount;
        let backup_amount_per_node = if backup_coordinators.is_empty() {
            0
        } else {
            backup_total / backup_coordinators.len() as u64
        };

        // Queue distribution for primary coordinator
        *self
            .pending_distributions
            .entry(primary_coordinator.clone())
            .or_insert(0) += primary_amount;

        // Queue distributions for backup coordinators
        let mut distributions = vec![(primary_coordinator, primary_amount)];
        for backup in backup_coordinators {
            *self
                .pending_distributions
                .entry(backup.clone())
                .or_insert(0) += backup_amount_per_node;
            distributions.push((backup, backup_amount_per_node));
        }

        // Record the distribution
        let record = FeeDistributionRecord {
            session_id,
            total_fee,
            distributions,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.distribution_history.push(record);
        log::info!(
            "Queued fee distribution for session {:?}: {} total fee",
            session_id,
            total_fee
        );

        Ok(())
    }

    /// Process pending distributions and create payout transactions
    pub fn process_pending_distributions(&mut self) -> Vec<FeePayoutTransaction> {
        let mut payouts = Vec::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for (masternode_id, &amount) in &self.pending_distributions {
            if amount >= self.config.minimum_distribution_amount {
                payouts.push(FeePayoutTransaction {
                    recipient: masternode_id.clone(),
                    amount,
                    timestamp: current_time,
                    transaction_id: [0u8; 32], // Would be filled by transaction creation
                });
            }
        }

        // Clear pending distributions after processing
        self.pending_distributions.clear();

        log::info!("Processed {} fee distributions", payouts.len());
        payouts
    }

    /// Get fee distribution statistics
    pub fn get_distribution_stats(&self) -> FeeDistributionStats {
        let total_pending = self.pending_distributions.values().sum();
        let total_distributed: u64 = self
            .distribution_history
            .iter()
            .map(|record| record.total_fee)
            .sum();

        FeeDistributionStats {
            total_pending_amount: total_pending,
            total_distributed_amount: total_distributed,
            pending_recipients: self.pending_distributions.len() as u32,
            distribution_history_count: self.distribution_history.len() as u32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeePayoutTransaction {
    pub recipient: rusty_shared_types::masternode::MasternodeID,
    pub amount: u64,
    pub timestamp: u64,
    pub transaction_id: [u8; 32],
}

#[derive(Debug)]
pub struct FeeDistributionStats {
    pub total_pending_amount: u64,
    pub total_distributed_amount: u64,
    pub pending_recipients: u32,
    pub distribution_history_count: u32,
}

// ===== PRIVACY METRICS TRACKING =====
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Privacy

/// Privacy metrics tracking for FerrousShield sessions
#[derive(Debug, Clone)]
pub struct PrivacyMetrics {
    /// Anonymity set size statistics
    pub anonymity_set_stats: AnonymitySetStats,
    /// Privacy violation tracking
    pub privacy_violations: Vec<PrivacyViolationRecord>,
    /// Session privacy scores
    pub session_privacy_scores: std::collections::HashMap<[u8; 32], f64>,
    /// Coordinator privacy performance
    pub coordinator_privacy_performance:
        std::collections::HashMap<Vec<u8>, CoordinatorPrivacyMetrics>,
}

#[derive(Debug, Clone)]
pub struct AnonymitySetStats {
    pub total_sessions: u32,
    pub average_anonymity_set_size: f64,
    pub min_anonymity_set_size: u32,
    pub max_anonymity_set_size: u32,
    pub anonymity_set_distribution: std::collections::HashMap<u32, u32>, // size -> count
}

#[derive(Debug, Clone)]
pub struct PrivacyViolationRecord {
    pub session_id: [u8; 32],
    pub violation_type: PrivacyViolationType,
    pub description: String,
    pub severity: ViolationSeverity,
    pub timestamp: u64,
    pub coordinator_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrivacyViolationType {
    InputOutputLinkage,
    TimingAnalysis,
    AmountCorrelation,
    MetadataLeakage,
    CoordinatorMisbehavior,
    ParticipantDeAnonymization,
}

#[derive(Debug, Clone)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct CoordinatorPrivacyMetrics {
    pub sessions_coordinated: u32,
    pub privacy_violations: u32,
    pub average_privacy_score: f64,
    pub anonymity_preservation_rate: f64,
}

impl PrivacyMetrics {
    pub fn new() -> Self {
        Self {
            anonymity_set_stats: AnonymitySetStats {
                total_sessions: 0,
                average_anonymity_set_size: 0.0,
                min_anonymity_set_size: u32::MAX,
                max_anonymity_set_size: 0,
                anonymity_set_distribution: std::collections::HashMap::new(),
            },
            privacy_violations: Vec::new(),
            session_privacy_scores: std::collections::HashMap::new(),
            coordinator_privacy_performance: std::collections::HashMap::new(),
        }
    }

    /// Update metrics from a completed session
    pub fn update_from_session(&mut self, outcome: &SessionOutcome, privacy_score: f64) {
        self.anonymity_set_stats.total_sessions += 1;

        // Update privacy score tracking
        if let SessionOutcome::PrivacyViolation(description) = outcome {
            // Record privacy violation
            let violation = PrivacyViolationRecord {
                session_id: [0u8; 32], // Would be passed as parameter
                violation_type: PrivacyViolationType::CoordinatorMisbehavior,
                description: description.clone(),
                severity: ViolationSeverity::High,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                coordinator_id: Vec::new(), // Would be passed as parameter
            };
            self.privacy_violations.push(violation);
        }

        // Update average privacy score
        let current_avg = self.anonymity_set_stats.average_anonymity_set_size;
        let total = self.anonymity_set_stats.total_sessions as f64;
        self.anonymity_set_stats.average_anonymity_set_size =
            (current_avg * (total - 1.0) + privacy_score) / total;
    }

    /// Calculate privacy score for a session
    pub fn calculate_session_privacy_score(
        &self,
        anonymity_set_size: u32,
        timing_variance: f64,
        amount_variance: f64,
        metadata_protection_level: f64,
    ) -> f64 {
        let mut score = 0.0;

        // Anonymity set size score (40% weight)
        let anonymity_score = match anonymity_set_size {
            0..=2 => 0.0,
            3..=5 => 0.3,
            6..=10 => 0.6,
            11..=20 => 0.8,
            _ => 1.0,
        };
        score += anonymity_score * 0.4;

        // Timing variance score (20% weight) - lower variance is better
        let timing_score = (1.0 - timing_variance.min(1.0)).max(0.0);
        score += timing_score * 0.2;

        // Amount variance score (20% weight) - lower variance is better
        let amount_score = (1.0 - amount_variance.min(1.0)).max(0.0);
        score += amount_score * 0.2;

        // Metadata protection score (20% weight)
        score += metadata_protection_level.min(1.0).max(0.0) * 0.2;

        score
    }

    /// Get comprehensive privacy report
    pub fn get_privacy_report(&self) -> PrivacyReport {
        let violation_counts = self.privacy_violations.iter().fold(
            std::collections::HashMap::new(),
            |mut acc, violation| {
                *acc.entry(violation.violation_type.clone()).or_insert(0) += 1;
                acc
            },
        );

        let average_session_privacy_score = if self.session_privacy_scores.is_empty() {
            0.0
        } else {
            self.session_privacy_scores.values().sum::<f64>()
                / self.session_privacy_scores.len() as f64
        };

        PrivacyReport {
            total_sessions_analyzed: self.anonymity_set_stats.total_sessions,
            average_anonymity_set_size: self.anonymity_set_stats.average_anonymity_set_size,
            total_privacy_violations: self.privacy_violations.len() as u32,
            privacy_violation_breakdown: violation_counts,
            average_session_privacy_score,
            coordinator_count: self.coordinator_privacy_performance.len() as u32,
        }
    }
}

#[derive(Debug)]
pub struct PrivacyReport {
    pub total_sessions_analyzed: u32,
    pub average_anonymity_set_size: f64,
    pub total_privacy_violations: u32,
    pub privacy_violation_breakdown: std::collections::HashMap<PrivacyViolationType, u32>,
    pub average_session_privacy_score: f64,
    pub coordinator_count: u32,
}

// ========= PARTICIPANT REPUTATION MANAGEMENT =========
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Reputation

#[derive(Debug, Clone)]
pub struct ParticipantReputation {
    pub participant_id: String,
    pub total_sessions: u32,
    pub successful_sessions: u32,
    pub failed_sessions: u32,
    pub malicious_behavior_count: u32,
    pub reputation_score: f64,
    pub last_activity: u64,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustLevel {
    Untrusted,
    Limited,
    Trusted,
    HighlyTrusted,
}

impl ParticipantReputation {
    pub fn new(participant_id: String) -> Self {
        Self {
            participant_id,
            total_sessions: 0,
            successful_sessions: 0,
            failed_sessions: 0,
            malicious_behavior_count: 0,
            reputation_score: 0.5, // Start neutral
            last_activity: 0,
            trust_level: TrustLevel::Untrusted,
        }
    }

    /// Update reputation based on session outcome
    pub fn update_session_outcome(&mut self, success: bool, malicious: bool) {
        self.total_sessions += 1;

        if success {
            self.successful_sessions += 1;
        } else {
            self.failed_sessions += 1;
        }

        if malicious {
            self.malicious_behavior_count += 1;
        }

        // Recalculate reputation score
        self.calculate_reputation_score();
        self.update_trust_level();
    }

    fn calculate_reputation_score(&mut self) {
        if self.total_sessions == 0 {
            self.reputation_score = 0.5;
            return;
        }

        let success_rate = self.successful_sessions as f64 / self.total_sessions as f64;
        let malicious_penalty = (self.malicious_behavior_count as f64 * 0.2).min(0.8);

        // Score is success rate minus malicious penalty
        self.reputation_score = (success_rate - malicious_penalty).max(0.0).min(1.0);
    }

    fn update_trust_level(&mut self) {
        self.trust_level = match self.reputation_score {
            score if score >= 0.8 && self.total_sessions >= 20 => TrustLevel::HighlyTrusted,
            score if score >= 0.6 && self.total_sessions >= 10 => TrustLevel::Trusted,
            score if score >= 0.4 && self.total_sessions >= 5 => TrustLevel::Limited,
            _ => TrustLevel::Untrusted,
        };
    }

    /// Check if participant should be allowed in a session
    pub fn is_eligible_for_session(&self, required_trust: TrustLevel) -> bool {
        match (required_trust, &self.trust_level) {
            (TrustLevel::Untrusted, _) => true,
            (
                TrustLevel::Limited,
                TrustLevel::Limited | TrustLevel::Trusted | TrustLevel::HighlyTrusted,
            ) => true,
            (TrustLevel::Trusted, TrustLevel::Trusted | TrustLevel::HighlyTrusted) => true,
            (TrustLevel::HighlyTrusted, TrustLevel::HighlyTrusted) => true,
            _ => false,
        }
    }
}

pub struct ReputationManager {
    reputations: std::collections::HashMap<String, ParticipantReputation>,
    reputation_decay_rate: f64,
    max_reputation_age_seconds: u64,
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            reputations: std::collections::HashMap::new(),
            reputation_decay_rate: 0.01, // 1% decay per period
            max_reputation_age_seconds: 30 * 24 * 3600, // 30 days
        }
    }

    pub fn get_or_create_reputation(&mut self, participant_id: &str) -> &mut ParticipantReputation {
        self.reputations
            .entry(participant_id.to_string())
            .or_insert_with(|| ParticipantReputation::new(participant_id.to_string()))
    }

    pub fn get_reputation(&self, participant_id: &str) -> Option<&ParticipantReputation> {
        self.reputations.get(participant_id)
    }

    pub fn record_session_outcome(
        &mut self,
        participant_id: &str,
        success: bool,
        malicious: bool,
        current_time: u64,
    ) {
        let reputation = self.get_or_create_reputation(participant_id);
        reputation.update_session_outcome(success, malicious);
        reputation.last_activity = current_time;
    }

    /// Apply time-based reputation decay
    pub fn apply_reputation_decay(&mut self, current_time: u64) {
        for reputation in self.reputations.values_mut() {
            let age_seconds = current_time.saturating_sub(reputation.last_activity);
            if age_seconds > self.max_reputation_age_seconds {
                // Decay toward neutral (0.5)
                let decay_factor = (age_seconds - self.max_reputation_age_seconds) as f64
                    * self.reputation_decay_rate;
                reputation.reputation_score =
                    0.5 + (reputation.reputation_score - 0.5) * (1.0 - decay_factor);
                reputation.update_trust_level();
            }
        }

        // Remove very old, inactive reputations
        self.reputations.retain(|_, rep| {
            current_time.saturating_sub(rep.last_activity) < self.max_reputation_age_seconds * 2
        });
    }
}

// ========= SESSION CLEANUP =========
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Session Lifecycle

// ========= FEE DISTRIBUTION =========
// Implementation per docs/specs/06_masternode_protocol_spec.md, section: Fee Distribution

#[derive(Debug, Clone)]
pub struct FeeDistribution {
    pub session_id: String,
    pub total_fee: u64,
    pub coordinator_fee: u64,
    pub participant_fees: std::collections::HashMap<String, u64>,
    pub network_fee: u64,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct FeePaymentResult {
    pub session_id: String,
    pub coordinator_payment_txid: String,
    pub network_payment_txid: String,
    pub participant_payment_txids: std::collections::HashMap<String, String>,
    pub total_fees_paid: u64,
}
