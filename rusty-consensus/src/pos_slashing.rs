use bincode;
use log::error;

use crate::error::ConsensusError;
use rusty_shared_types::TicketId;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PosSlashingError {
    #[error("Invalid proof data: {0}")]
    InvalidProof(String),

    #[error("Insufficient ticket value: {0}")]
    InsufficientTicketValue(String),

    #[error("Ticket not found: {0}")]
    TicketNotFound(String),

    #[error("Consensus error: {0}")]
    ConsensusError(#[from] ConsensusError),
}

type Result<T> = std::result::Result<T, PosSlashingError>;

/// Constants for PoS slashing configuration
const MAX_POS_SLASHING_PROOF_SIZE: usize = 4096; // 4KB max for slashing proof data
const POS_SLASHING_COOLDOWN_BLOCKS: u64 = 10080; // ~1 week at 2.5 min blocks
const GRACE_PERIOD_BLOCKS: u64 = 10; // Grace period before non-participation can be slashed
                                     // SLASH_FORGIVENESS_PERIOD is imported from rusty_core::protocol_constants

/// Helper function to create an unspendable output for burning slashed ticket funds.
pub fn create_ticket_burn_output(amount: u64) -> rusty_shared_types::TxOutput {
    // OP_RETURN script (0x6a) followed by data push (0x04) and 'rust' (0x72 0x75 0x73 0x74)
    // This creates a provably unspendable output that can still be pruned from the UTXO set
    let burn_script = vec![0x6a, 0x04, 0x72, 0x75, 0x73, 0x74];
    rusty_shared_types::TxOutput {
        value: amount,
        script_pubkey: burn_script,
        memo: None,
    }
}

/// Creates a PoS ticket non-participation slashing transaction.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket being slashed
/// * `proof` - Cryptographic proof of non-participation
/// * `ticket_input` - The UTXO being spent (ticket's locked funds)
/// * `ticket_value` - The value of the ticket being slashed
/// * `script_pubkey` - The script_pubkey of the ticket output
/// * `block_height` - Current blockchain height
///
/// # Returns
/// A new slashing transaction for ticket non-participation
pub fn create_ticket_non_participation_slashing_transaction(
    ticket_id: &TicketId,
    proof: rusty_shared_types::TicketNonParticipationProof,
    ticket_input: rusty_shared_types::TxInput,
    ticket_value: u64,
    script_pubkey: Vec<u8>,
    block_height: u64,
) -> Result<rusty_shared_types::Transaction> {
    // Verify proof data size
    if proof.witness_signatures.len() > MAX_POS_SLASHING_PROOF_SIZE {
        return Err(PosSlashingError::InvalidProof(
            "Proof data too large".to_string(),
        ));
    }

    // Calculate slashed amount (1% for non-participation according to protocol spec)
    let slashed_amount = (ticket_value as f64 * 0.01) as u64;
    let remaining = ticket_value.saturating_sub(slashed_amount);

    // Create burn output for slashed amount
    let mut outputs = vec![create_ticket_burn_output(slashed_amount)];

    // Create change output for remaining value
    if remaining > 0 {
        outputs.push(rusty_shared_types::TxOutput {
            value: remaining,
            script_pubkey: script_pubkey.clone(),
            memo: None,
        });
    }

    // Serialize proof data
    let _proof_data = bincode::serialize(&proof)
        .map_err(|e| PosSlashingError::InvalidProof(format!("Failed to serialize proof: {}", e)))?;

    // Create and return the slashing transaction
    Ok(
        rusty_shared_types::Transaction::TicketSlashNonParticipation {
            version: 1,
            inputs: vec![ticket_input],
            outputs,
            ticket_id: ticket_id.0,
            proof,
            lock_time: (block_height + POS_SLASHING_COOLDOWN_BLOCKS) as u32,
            fee: 0, // No fee for slashing transactions
            witness: vec![],
        },
    )
}

/// Creates a PoS ticket malicious behavior slashing transaction.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket being slashed
/// * `proof` - Cryptographic proof of malicious behavior
/// * `ticket_input` - The UTXO being spent (ticket's locked funds)
/// * `ticket_value` - The value of the ticket being slashed
/// * `script_pubkey` - The script_pubkey of the ticket output
/// * `block_height` - Current blockchain height
///
/// # Returns
/// A new slashing transaction for ticket malicious behavior
pub fn create_ticket_malicious_behavior_slashing_transaction(
    ticket_id: &TicketId,
    proof: rusty_shared_types::TicketMaliciousProof,
    ticket_input: rusty_shared_types::TxInput,
    ticket_value: u64,
    _script_pubkey: Vec<u8>,
    block_height: u64,
) -> Result<rusty_shared_types::Transaction> {
    // Verify proof data size
    if proof.proof_data.len() > MAX_POS_SLASHING_PROOF_SIZE {
        return Err(PosSlashingError::InvalidProof(
            "Proof data too large".to_string(),
        ));
    }

    // Calculate slashed amount (100% for malicious behavior according to protocol spec)
    let slashed_amount = (ticket_value as f64 * 1.0) as u64;

    // Create burn output for entire ticket value (100% slash)
    let outputs = vec![create_ticket_burn_output(slashed_amount)];

    // Create and return the slashing transaction
    Ok(rusty_shared_types::Transaction::TicketSlashMalicious {
        version: 1,
        inputs: vec![ticket_input],
        outputs,
        ticket_id: ticket_id.0,
        proof,
        lock_time: (block_height + POS_SLASHING_COOLDOWN_BLOCKS) as u32,
        fee: 0, // No fee for slashing transactions
        witness: vec![],
    })
}

/// Validates a PoS ticket non-participation slashing transaction.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket being slashed
/// * `proof` - The non-participation proof
/// * `current_height` - Current blockchain height
///
/// # Returns
/// Ok(()) if valid, error otherwise
pub fn validate_ticket_non_participation_slashing(
    _ticket_id: &TicketId,
    proof: &rusty_shared_types::TicketNonParticipationProof,
    current_height: u64,
) -> Result<()> {
    // Validate that the grace period has passed
    if current_height < proof.detection_block_height + GRACE_PERIOD_BLOCKS {
        return Err(PosSlashingError::InvalidProof(format!(
            "Grace period not yet passed. Current: {}, Required: {}",
            current_height,
            proof.detection_block_height + GRACE_PERIOD_BLOCKS
        )));
    }

    // Validate ticket ID matches
    if proof.ticket_id != _ticket_id.0 {
        return Err(PosSlashingError::InvalidProof(
            "Ticket ID mismatch".to_string(),
        ));
    }

    // Validate selection proof is not empty
    if proof.selection_proof.is_empty() {
        return Err(PosSlashingError::InvalidProof(
            "Selection proof is empty".to_string(),
        ));
    }

    // Validate witness signatures (at least one required)
    if proof.witness_signatures.is_empty() {
        return Err(PosSlashingError::InvalidProof(
            "No witness signatures provided".to_string(),
        ));
    }

    // Validate target block hash is not zero
    if proof.target_block_hash == [0u8; 32] {
        return Err(PosSlashingError::InvalidProof(
            "Invalid target block hash".to_string(),
        ));
    }

    Ok(())
}

/// Validates a PoS ticket malicious behavior slashing transaction.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket being slashed
/// * `proof` - The malicious behavior proof
/// * `current_height` - Current blockchain height
///
/// # Returns
/// Ok(()) if valid, error otherwise
pub fn validate_ticket_malicious_behavior_slashing(
    _ticket_id: &TicketId,
    proof: &rusty_shared_types::TicketMaliciousProof,
    _current_height: u64,
) -> Result<()> {
    // Validate ticket ID matches
    if proof.ticket_id != _ticket_id.0 {
        return Err(PosSlashingError::InvalidProof(
            "Ticket ID mismatch".to_string(),
        ));
    }

    // Validate proof data is not empty
    if proof.proof_data.is_empty() {
        return Err(PosSlashingError::InvalidProof(
            "Proof data is empty".to_string(),
        ));
    }

    // Validate witness signatures (at least one required)
    if proof.witness_signatures.is_empty() {
        return Err(PosSlashingError::InvalidProof(
            "No witness signatures provided".to_string(),
        ));
    }

    // Validate malicious action type
    match proof.malicious_action_type {
        rusty_shared_types::TicketMaliciousActionType::DoubleVoting => {
            // For double voting, proof data should contain two conflicting signatures
            if proof.proof_data.len() < 128 {
                // At least 2 Ed25519 signatures
                return Err(PosSlashingError::InvalidProof(
                    "Insufficient proof data for double voting".to_string(),
                ));
            }
        }
        rusty_shared_types::TicketMaliciousActionType::InvalidVote => {
            // For invalid vote, proof data should contain the invalid vote and validation error
            if proof.proof_data.len() < 64 {
                // At least one signature
                return Err(PosSlashingError::InvalidProof(
                    "Insufficient proof data for invalid vote".to_string(),
                ));
            }
        }
        rusty_shared_types::TicketMaliciousActionType::InvalidSignature => {
            // For invalid signature, proof data should contain the invalid signature
            if proof.proof_data.len() < 64 {
                // At least one signature
                return Err(PosSlashingError::InvalidProof(
                    "Insufficient proof data for invalid signature".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Detects double-voting by a ticket and creates a malicious behavior proof.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket that double-voted
/// * `vote1` - First vote signature and data
/// * `vote2` - Second conflicting vote signature and data
/// * `detection_height` - Block height where double-voting was detected
/// * `witness_signatures` - Signatures from witness nodes
///
/// # Returns
/// A malicious behavior proof for double-voting
pub fn create_double_voting_proof(
    ticket_id: &TicketId,
    vote1: (Vec<u8>, [u8; 32]), // (signature, block_hash)
    vote2: (Vec<u8>, [u8; 32]), // (signature, block_hash)
    detection_height: u64,
    witness_signatures: Vec<rusty_shared_types::WitnessSignature>,
) -> Result<rusty_shared_types::TicketMaliciousProof> {
    // Validate that the votes are actually conflicting
    if vote1.1 == vote2.1 {
        return Err(PosSlashingError::InvalidProof(
            "Votes are not conflicting".to_string(),
        ));
    }

    // Combine proof data: vote1 signature + vote1 block hash + vote2 signature + vote2 block hash
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&vote1.0); // First signature
    proof_data.extend_from_slice(&vote1.1); // First block hash
    proof_data.extend_from_slice(&vote2.0); // Second signature
    proof_data.extend_from_slice(&vote2.1); // Second block hash

    Ok(rusty_shared_types::TicketMaliciousProof {
        ticket_id: ticket_id.0,
        detection_block_height: detection_height,
        malicious_action_type: rusty_shared_types::TicketMaliciousActionType::DoubleVoting,
        proof_data,
        witness_signatures,
    })
}

/// Detects non-participation by a ticket and creates a non-participation proof.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket that failed to participate
/// * `target_block_hash` - The block hash for which the ticket was selected to vote
/// * `selection_height` - Block height where the ticket was selected for voting
/// * `selection_proof` - Cryptographic proof of selection (DPRF output)
/// * `detection_height` - Block height where non-participation was detected
/// * `witness_signatures` - Signatures from witness nodes
///
/// # Returns
/// A non-participation proof
pub fn create_non_participation_proof(
    ticket_id: &TicketId,
    target_block_hash: [u8; 32],
    selection_height: u64,
    selection_proof: Vec<u8>,
    detection_height: u64,
    witness_signatures: Vec<rusty_shared_types::WitnessSignature>,
) -> Result<rusty_shared_types::TicketNonParticipationProof> {
    // Validate selection proof is not empty
    if selection_proof.is_empty() {
        return Err(PosSlashingError::InvalidProof(
            "Selection proof is empty".to_string(),
        ));
    }

    // Validate target block hash is not zero
    if target_block_hash == [0u8; 32] {
        return Err(PosSlashingError::InvalidProof(
            "Invalid target block hash".to_string(),
        ));
    }

    // Validate detection height is after selection height
    if detection_height <= selection_height {
        return Err(PosSlashingError::InvalidProof(
            "Detection height must be after selection height".to_string(),
        ));
    }

    Ok(rusty_shared_types::TicketNonParticipationProof {
        ticket_id: ticket_id.0,
        detection_block_height: detection_height,
        target_block_hash,
        selection_block_height: selection_height,
        selection_proof,
        witness_signatures,
    })
}

/// Checks if a ticket should be slashed for repeated non-participation within the forgiveness period.
///
/// Per spec 03 Section 3.7: Repeated non-participation by the same ticket within a
/// SLASH_FORGIVENESS_PERIOD (e.g., 100 blocks) may result in an increased penalty or
/// temporary exclusion from the LIVE_TICKETS_POOL.
///
/// # Arguments
/// * `ticket_id` - The ID of the ticket to check
/// * `non_participation_count` - Number of times the ticket has failed to participate
/// * `last_slash_height` - Block height of the last slashing (if any)
/// * `current_height` - Current blockchain height
///
/// # Returns
/// True if the ticket should be slashed for repeated non-participation
pub fn should_slash_for_repeated_non_participation(
    _ticket_id: &TicketId,
    non_participation_count: u32,
    last_slash_height: Option<u64>,
    current_height: u64,
) -> bool {
    use rusty_core::protocol_constants::SLASH_FORGIVENESS_PERIOD;

    // If no previous slashing, check if non-participation count exceeds threshold
    if last_slash_height.is_none() {
        return non_participation_count >= 3; // Slash after 3 failures
    }

    let last_slash = last_slash_height.unwrap();
    let forgiveness_period = SLASH_FORGIVENESS_PERIOD as u64;

    // Per spec: If within forgiveness period, require more failures for additional slashing
    // This prevents rapid repeated slashing and gives tickets a chance to recover
    if current_height < last_slash + forgiveness_period {
        // Within forgiveness period: require more failures (e.g., 5 instead of 3)
        // This provides protection against rapid repeated slashing
        return non_participation_count >= 5;
    }

    // Outside forgiveness period, reset to normal threshold
    non_participation_count >= 3
}
