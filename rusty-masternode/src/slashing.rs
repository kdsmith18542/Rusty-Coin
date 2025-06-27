use rusty_shared_types::{Transaction, StandardTransaction, TxInput, TxOutput, MasternodeSlashTx, MasternodeID, OutPoint, Hash};
use rusty_core::consensus::state::BlockchainState;
use rusty_core::masternode::{MasternodeEntry, MasternodeStatus};
use rusty_core::error::ConsensusError;

// Represents the reason for a Masternode slashing event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashingReason {
    MasternodeNonResponse,
    DoubleSigning,
    InvalidBlockProposal,
    InvalidTransaction,
    GovernanceViolation,
    DoubleSpend,
}

// Helper function to create an unspendable output for burning slashed funds.
pub fn create_burn_output(amount: u64) -> TxOutput {
    // A common burn address script. Funds sent here are provably unspendable.
    // This is an example of an OP_RETURN-like script to burn tokens.
    // In a real blockchain, this would be a well-defined unspendable script.
    let burn_script = vec![0x6a, 0x04, 0x72, 0x75, 0x73, 0x74]; // OP_RETURN + 4 bytes 'rust'
    TxOutput { value: amount, script_pubkey: burn_script, memo: None }
}

pub fn create_slashing_transaction(
    masternode_id: &MasternodeID,
    reason: SlashingReason,
    proof_data: Vec<u8>,
    slashed_amount: u64,
    collateral_input: TxInput,
) -> Result<Transaction, ConsensusError> {
    let outputs = vec![create_burn_output(slashed_amount)];

    Ok(Transaction::MasternodeSlashTx(MasternodeSlashTx {
        version: 1,
        inputs: vec![collateral_input],
        outputs,
        masternode_id: masternode_id.clone(),
        reason: match reason {
            SlashingReason::MasternodeNonResponse => rusty_shared_types::masternode::SlashingReason::MasternodeNonResponse,
            SlashingReason::DoubleSigning => rusty_shared_types::masternode::SlashingReason::DoubleSigning,
            SlashingReason::InvalidBlockProposal => rusty_shared_types::masternode::SlashingReason::InvalidBlockProposal,
            SlashingReason::InvalidTransaction => rusty_shared_types::masternode::SlashingReason::InvalidTransaction,
            SlashingReason::GovernanceViolation => rusty_shared_types::masternode::SlashingReason::GovernanceViolation,
            SlashingReason::DoubleSpend => rusty_shared_types::masternode::SlashingReason::DoubleSigning, // Double-spend falls under double-signing for now
        },
        proof: proof_data,
        lock_time: 0,
        fee: 0,
        witness: vec![],
    }))
}
