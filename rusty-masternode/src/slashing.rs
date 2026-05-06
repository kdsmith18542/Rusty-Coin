use log::error;
use serde::{Deserialize, Serialize};

use rusty_core::consensus::error::ConsensusError;
use rusty_core::protocol_constants::{
    MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE, NON_PARTICIPATION_SLASH_PERCENTAGE,
};
use rusty_shared_types::{
    masternode::{MasternodeID, MasternodeSlashTx, SlashingReason as SharedSlashingReason},
    Transaction, TxInput, TxOutput,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SlashingError {
    #[error("Invalid proof data: {0}")]
    InvalidProof(String),

    #[error("Insufficient collateral: {0}")]
    InsufficientCollateral(String),

    #[error("Consensus error: {0}")]
    ConsensusError(#[from] ConsensusError),
}

type Result<T> = std::result::Result<T, SlashingError>;

/// Constants for slashing configuration
const MAX_SLASHING_PROOF_SIZE: usize = 4096; // 4KB max for slashing proof data
const SLASHING_COOLDOWN_BLOCKS: u64 = 10080; // ~1 week at 2.5 min blocks

/// Represents the reason for a Masternode slashing event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Masternode failed to respond to challenges
    MasternodeNonResponse,
    /// Masternode signed conflicting blocks or transactions
    DoubleSigning,
    /// Masternode proposed an invalid block
    InvalidBlockProposal,
    /// Masternode included invalid transactions
    InvalidTransaction,
    /// Masternode violated governance rules
    GovernanceViolation,
    /// Masternode attempted to double-spend
    DoubleSpend,
}

/// Helper function to create an unspendable output for burning slashed funds.
pub fn create_burn_output(amount: u64) -> TxOutput {
    // OP_RETURN script (0x6a) followed by data push (0x04) and 'rust' (0x72 0x75 0x73 0x74)
    // This creates a provably unspendable output that can still be pruned from the UTXO set
    let burn_script = vec![0x6a, 0x04, 0x72, 0x75, 0x73, 0x74];
    TxOutput {
        value: amount,
        script_pubkey: burn_script,
        memo: None,
    }
}

/// Creates a slashing transaction that moves funds from the masternode's collateral to a burn address.
///
/// # Arguments
/// * `masternode_id` - The ID of the masternode being slashed
/// * `reason` - The reason for slashing
/// * `proof_data` - Cryptographic proof of the slashing offense
/// * `collateral_input` - The UTXO being spent (masternode's collateral)
/// * `collateral_value` - The value of the collateral being slashed
/// * `script_pubkey` - The script_pubkey of the collateral output
/// * `block_height` - Current blockchain height
///
/// # Returns
/// A new transaction that, when included in a block, will slash the masternode
pub fn create_slashing_transaction(
    masternode_id: &MasternodeID,
    reason: SlashingReason,
    proof_data: Vec<u8>,
    collateral_input: TxInput,
    collateral_value: u64,
    script_pubkey: Vec<u8>,
    block_height: u64,
) -> Result<Transaction> {
    // Verify proof data size
    if proof_data.len() > MAX_SLASHING_PROOF_SIZE {
        return Err(SlashingError::InvalidProof(
            "Proof data too large".to_string(),
        ));
    }

    // Calculate slashed amount based on protocol specifications
    let slashed_amount = match reason {
        SlashingReason::MasternodeNonResponse => {
            // 5% for non-participation according to protocol spec
            (collateral_value as f64 * NON_PARTICIPATION_SLASH_PERCENTAGE) as u64
        }
        SlashingReason::DoubleSigning
        | SlashingReason::InvalidBlockProposal
        | SlashingReason::InvalidTransaction
        | SlashingReason::GovernanceViolation
        | SlashingReason::DoubleSpend => {
            // 100% for malicious behavior according to protocol spec
            (collateral_value as f64 * MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE) as u64
        }
    };

    let remaining = collateral_value.saturating_sub(slashed_amount);

    // Create burn output for slashed amount
    let mut outputs = vec![create_burn_output(slashed_amount)];

    // Create change output if there's remaining value (only for non-participation)
    if remaining > 0 && reason == SlashingReason::MasternodeNonResponse {
        outputs.push(TxOutput {
            value: remaining,
            script_pubkey: script_pubkey.clone(),
            memo: None,
        });
    }

    // Map local SlashingReason to shared type
    let shared_reason = match reason {
        SlashingReason::MasternodeNonResponse => SharedSlashingReason::MasternodeNonResponse,
        SlashingReason::DoubleSigning => SharedSlashingReason::DoubleSigning,
        SlashingReason::InvalidBlockProposal => SharedSlashingReason::InvalidBlockProposal,
        SlashingReason::InvalidTransaction => SharedSlashingReason::InvalidTransaction,
        SlashingReason::GovernanceViolation => SharedSlashingReason::GovernanceViolation,
        SlashingReason::DoubleSpend => SharedSlashingReason::DoubleSigning,
    };

    // Create and return the slashing transaction
    Ok(Transaction::MasternodeSlashTx(MasternodeSlashTx {
        version: 1,
        inputs: vec![collateral_input],
        outputs,
        masternode_id: masternode_id.clone(),
        reason: shared_reason,
        proof: proof_data,
        lock_time: (block_height + SLASHING_COOLDOWN_BLOCKS) as u32, // Lock remaining funds for cooldown
        fee: 0, // No fee for slashing transactions
        witness: vec![],
    }))
}

/// Creates a non-participation slashing transaction for a masternode that failed PoSe challenges.
///
/// # Arguments
/// * `masternode_id` - The ID of the masternode being slashed
/// * `proof` - Cryptographic proof of non-participation
/// * `collateral_input` - The UTXO being spent (masternode's collateral)
/// * `collateral_value` - The value of the collateral being slashed
/// * `script_pubkey` - The script_pubkey of the collateral output
/// * `block_height` - Current blockchain height
///
/// # Returns
/// A new slashing transaction for non-participation
pub fn create_non_participation_slashing_transaction(
    masternode_id: &MasternodeID,
    proof: rusty_shared_types::MasternodeNonParticipationProof,
    collateral_input: TxInput,
    collateral_value: u64,
    script_pubkey: Vec<u8>,
    block_height: u64,
) -> Result<Transaction> {
    let proof_data = bincode::serialize(&proof)
        .map_err(|e| SlashingError::InvalidProof(format!("Failed to serialize proof: {}", e)))?;

    create_slashing_transaction(
        masternode_id,
        SlashingReason::MasternodeNonResponse,
        proof_data,
        collateral_input,
        collateral_value,
        script_pubkey,
        block_height,
    )
}

/// Creates a malicious behavior slashing transaction for a masternode that engaged in malicious acts.
///
/// # Arguments
/// * `masternode_id` - The ID of the masternode being slashed
/// * `proof` - Cryptographic proof of malicious behavior
/// * `collateral_input` - The UTXO being spent (masternode's collateral)
/// * `collateral_value` - The value of the collateral being slashed
/// * `script_pubkey` - The script_pubkey of the collateral output
/// * `block_height` - Current blockchain height
///
/// # Returns
/// A new slashing transaction for malicious behavior
pub fn create_malicious_behavior_slashing_transaction(
    masternode_id: &MasternodeID,
    proof: rusty_shared_types::MasternodeMaliciousProof,
    collateral_input: TxInput,
    collateral_value: u64,
    script_pubkey: Vec<u8>,
    block_height: u64,
) -> Result<Transaction> {
    let proof_data = bincode::serialize(&proof)
        .map_err(|e| SlashingError::InvalidProof(format!("Failed to serialize proof: {}", e)))?;

    create_slashing_transaction(
        masternode_id,
        SlashingReason::DoubleSigning, // Default to double signing for malicious behavior
        proof_data,
        collateral_input,
        collateral_value,
        script_pubkey,
        block_height,
    )
}

/// Validates a slashing transaction according to protocol specifications.
///
/// # Arguments
/// * `slash_tx` - The slashing transaction to validate
/// * `current_height` - Current blockchain height
///
/// # Returns
/// Ok(()) if valid, error otherwise
pub fn validate_slashing_transaction(
    slash_tx: &MasternodeSlashTx,
    current_height: u64,
) -> Result<()> {
    // Validate proof data size
    if slash_tx.proof.len() > MAX_SLASHING_PROOF_SIZE {
        return Err(SlashingError::InvalidProof(
            "Proof data too large".to_string(),
        ));
    }

    // Validate lock time (should be future block height)
    if slash_tx.lock_time as u64 <= current_height {
        return Err(SlashingError::InvalidProof("Invalid lock time".to_string()));
    }

    // Validate that there's exactly one input (the collateral)
    if slash_tx.inputs.len() != 1 {
        return Err(SlashingError::InvalidProof(
            "Slashing transaction must have exactly one input".to_string(),
        ));
    }

    // Validate that there's at least one output (the burn output)
    if slash_tx.outputs.is_empty() {
        return Err(SlashingError::InvalidProof(
            "Slashing transaction must have at least one output".to_string(),
        ));
    }

    // Validate that the first output is a burn output
    let first_output = &slash_tx.outputs[0];
    if first_output.script_pubkey != vec![0x6a, 0x04, 0x72, 0x75, 0x73, 0x74] {
        return Err(SlashingError::InvalidProof(
            "First output must be a burn output".to_string(),
        ));
    }

    Ok(())
}
