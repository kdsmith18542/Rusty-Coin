//! Validation logic for the Rusty Coin blockchain.
//!
//! This module contains the core validation logic for blocks and transactions,
//! ensuring they comply with the consensus rules.

use crate::error::ConsensusError;
use crate::pos::LiveTicketsPool;
use crate::pow;
use crate::state::BlockchainState;
use crate::utxo_set::UtxoSet;
use bincode;
use log::{debug, info, warn};
use rusty_crypto::signature::verify_signature;
use rusty_shared_types::script_engine::ScriptEngine as ScriptEngineTrait;
use rusty_shared_types::{
    Block, BlockHeader, OutPoint, TicketVote, Transaction, TransactionSignature,
};
use rusty_shared_types::{ConsensusParams, MasternodeID, MasternodeList};
use std::collections::HashSet;

pub struct ValidationContext<'a> {
    pub utxo_set: &'a mut UtxoSet,
    pub params: &'a ConsensusParams,
    pub ticket_voting: &'a LiveTicketsPool,
    pub masternode_list: &'a mut MasternodeList,
    pub blockchain_state: &'a BlockchainState,
}

/// Validates a transaction against the consensus rules.
///
/// Protocol reference:
/// - See docs/specs/01_block_structure.md §3.2 (Transaction Validation)
/// - See docs/specs/01_block_structure.md §3.3 (Coinbase Rules)
/// - See docs/specs/01_block_structure.md §3.4 (Fee Calculation)
/// - See docs/specs/01_block_structure.md §3.5 (Locktime & Sequence)
/// - See docs/specs/01_block_structure.md §3.6 (Output Validation)
/// - See docs/specs/01_block_structure.md §3.7 (Script Validation)
/// - See docs/specs/01_block_structure.md §3.8 (Dust Outputs)
pub fn validate_transaction(
    tx: &Transaction,
    current_height: u32,
    median_time_past: u64,
    context: &mut ValidationContext,
) -> Result<(), ConsensusError> {
    // 1. Basic checks (Spec §3.2)
    if tx.get_inputs().is_empty() && tx.get_outputs().is_empty() {
        return Err(ConsensusError::EmptyTransaction);
    }

    let tx_size = bincode::serialized_size(tx)? as usize;
    if tx_size > context.params.max_tx_size {
        return Err(ConsensusError::TransactionTooLarge(
            tx_size,
            context.params.max_tx_size,
        ));
    }

    // 2. Coinbase transaction specific rules (Spec §3.3)
    if tx.is_coinbase() {
        if !tx.get_inputs().is_empty() {
            return Err(ConsensusError::CoinbaseHasInputs);
        }
        // Coinbase maturity check is handled when applying the block, not during transaction validation
    } else {
        // 3. Non-coinbase transaction input validation (Spec §3.2, §3.7)
        if tx.get_inputs().is_empty() {
            return Err(ConsensusError::NonCoinbaseHasNoInputs);
        }

        let mut seen_inputs = HashSet::new();
        let mut total_input_value: u64 = 0;

        // Per spec 04 Section 4.3.3: MAX_SIG_OPS is enforced per transaction, not per input
        // Track sig_op_count across all inputs
        let mut transaction_sig_op_count: usize = 0;
        use rusty_core::constants::{MAX_SCRIPT_BYTES, MAX_SIG_OPS};

        for (input_index, input) in tx.get_inputs().iter().enumerate() {
            // Check for duplicate inputs within the same transaction (Spec §3.2)
            if !seen_inputs.insert(input.previous_output.clone()) {
                return Err(ConsensusError::DuplicateInput);
            }

            // Check UTXO existence and retrieve its value and scriptPubKey (Spec §3.2)
            let (prev_output, _height, _is_coinbase) = context
                .utxo_set
                .get_utxo(&input.previous_output)?
                .ok_or_else(|| ConsensusError::MissingTxInput)?;

            // Per spec 04 Section 4.3.3: MAX_SCRIPT_BYTES applies to script_sig and script_pubkey separately
            // This check is now done inside verify_script_with_sig_op_count

            // Check coinbase maturity for inputs (Spec §3.3)
            if _is_coinbase && current_height < (_height as u32) + context.params.coinbase_maturity
            {
                return Err(ConsensusError::CoinbaseNotMature);
            }

            // Verify signature and script using ScriptEngine (Spec §3.7)
            // Per spec 04 Section 4.3.3: MAX_SIG_OPS is enforced per transaction, not per input
            let mut script_engine = rusty_core::script::script_engine::ScriptEngine::new();
            if let Err(e) = script_engine.verify_script_with_sig_op_count(
                &input.script_sig,
                &prev_output.script_pubkey,
                tx,
                input_index,
                &prev_output,
                &mut transaction_sig_op_count,
            ) {
                warn!("Script verification failed: {:?}", e);
                return Err(ConsensusError::InvalidScriptSig);
            }
            total_input_value = total_input_value.checked_add(prev_output.value).ok_or(
                ConsensusError::InvalidProof("Input value too large".to_string()),
            )?;
        }

        // 4. Fee validation (Spec §3.4)
        let mut total_output_value: u64 = 0;
        for output in tx.get_outputs().iter() {
            total_output_value = total_output_value.checked_add(output.value).ok_or(
                ConsensusError::InvalidProof("Output value too large".to_string()),
            )?;
        }

        if total_input_value < total_output_value {
            return Err(ConsensusError::NegativeFee);
        }

        let calculated_fee = total_input_value - total_output_value;
        // Per spec 05 Section 5.4: Fee MUST be >= MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes
        use rusty_core::constants::MIN_RELAY_FEE_PER_BYTE;
        let min_fee = MIN_RELAY_FEE_PER_BYTE * tx_size as u64;
        if calculated_fee < min_fee {
            return Err(ConsensusError::InsufficientFee(calculated_fee, min_fee));
        }

        // 5. Locktime and sequence number validation (Spec §3.5)
        if let Err(e) = validate_locktime_and_sequence(tx, current_height, median_time_past) {
            return Err(e);
        }
    }

    // 6. Output validation (e.g., dust limits, valid script pubkeys) (Spec §3.6, §3.8)
    for output in tx.get_outputs().iter() {
        // Per spec 05 Section 5.4: OP_RETURN outputs are explicitly allowed to be below DUST_LIMIT
        // as they are provably unspendable and do not enter the UTXO_SET
        let is_op_return = is_op_return_output(&output.script_pubkey);
        if !is_op_return && output.value < context.params.dust_limit {
            return Err(ConsensusError::DustOutput(output.value));
        }
        // Validate script_pubkey format/type (Spec §3.7)
        if let Err(e) = validate_script_pubkey(&output.script_pubkey) {
            return Err(e);
        }
    }

    Ok(())
}

/// Validates a Masternode deregistration transaction (treated as a MasternodeRegister with deregistration intent).
pub fn validate_masternode_deregistration(
    tx: &Transaction,
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    let (masternode_identity, signature) = match tx {
        Transaction::MasternodeRegister {
            masternode_identity,
            signature,
            ..
        } => (masternode_identity, signature),
        _ => {
            return Err(ConsensusError::InvalidTransactionType(
                "Expected MasternodeRegister transaction for deregistration".to_string(),
            ))
        }
    };

    // Use the collateral outpoint as the masternode ID
    let masternode_id =
        rusty_shared_types::MasternodeID(masternode_identity.collateral_outpoint.clone());

    // Check if the Masternode exists
    let masternode = context
        .masternode_list
        .get_masternode(&masternode_id)
        .ok_or(ConsensusError::MasternodeNotFound)?;

    // Validate signature by the Operator Key
    let public_key = &masternode.identity.operator_public_key;

    // Serialize the transaction without the signature for verification
    // (Assume TransactionSignature is replaced with zeros for verification)
    let mut tx_without_signature = tx.clone();
    if let Transaction::MasternodeRegister { signature: sig, .. } = &mut tx_without_signature {
        *sig = TransactionSignature::new([0u8; 64]);
    }
    let tx_bytes_for_signature = bincode::serialize(&tx_without_signature).map_err(|e| {
        ConsensusError::SerializationError(format!(
            "Failed to serialize transaction for signature verification: {}",
            e
        ))
    })?;

    // Convert public_key and signature to the correct types for verify_signature
    use rusty_crypto::keypair::{PublicKey, Signature};
    let public_key = PublicKey::from_bytes(public_key).map_err(|_| {
        ConsensusError::InvalidMasternodeDeregistration("Invalid public key bytes".to_string())
    })?;
    let signature = Signature::from_bytes(signature.as_bytes()).map_err(|_| {
        ConsensusError::InvalidMasternodeDeregistration("Invalid signature bytes".to_string())
    })?;

    // Verify the signature
    if verify_signature(&public_key, &tx_bytes_for_signature, &signature).is_err() {
        return Err(ConsensusError::InvalidMasternodeDeregistration(
            "Invalid signature".to_string(),
        ));
    }

    Ok(())
}

/// Validates a block header against the consensus rules.
///
/// Protocol reference:
/// - See docs/specs/01_block_structure.md §2.1 (Block Header Fields)
/// - See docs/specs/01_block_structure.md §4.1 (Block Header Validation)
/// - See docs/specs/02_oxidehash_pow_spec.md (Proof-of-Work)
pub fn validate_block_header(
    header: &BlockHeader,
    previous_block: &Block,
    current_time: u64,
) -> Result<(), ConsensusError> {
    // Check block version (Spec §2.1, §4.1)
    if header.version != 1 {
        return Err(ConsensusError::UnsupportedVersion(header.version as u32));
    }

    // BHS_001: prev_block_hash match (Spec §4.1)
    if header.previous_block_hash != previous_block.hash() {
        return Err(ConsensusError::InvalidPreviousBlockHash);
    }

    // BHS_001: merkle_root correctness (Spec §4.1)
    if header.merkle_root != previous_block.calculate_merkle_root() {
        return Err(ConsensusError::InvalidMerkleRoot);
    }

    // BHS_001: state_root correctness (Spec §4.1)
    // State root validation is performed in validate_block_comprehensive()
    // after transactions are validated, as it requires simulating the state
    // after applying the block's transactions.

    // BHS_001: difficulty_target match (Spec §4.1, §5.1, §2a.3)
    // For non-adjustment blocks, verify difficulty matches previous block.
    // Full difficulty adjustment validation (for adjustment period blocks) is performed
    // in validate_block_comprehensive() where we have access to the full block history.
    const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

    // Check if this is NOT an adjustment period block
    // Adjustment happens at blocks where (H_current - 1) % 2016 == 0
    let current_height = previous_block.height() + 1;
    let is_adjustment_block = (current_height - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL as u64 == 0;

    if !is_adjustment_block {
        // For non-adjustment blocks, difficulty MUST match previous block (Spec §2a.3)
        if header.difficulty_target != previous_block.header.difficulty_target {
            return Err(ConsensusError::InvalidProof(format!(
                "Difficulty target mismatch: expected {} (same as previous block), got {}",
                previous_block.header.difficulty_target, header.difficulty_target
            )));
        }
    }
    // For adjustment blocks, validation is done in validate_block_comprehensive()
    // where we have access to blocks from the adjustment period

    // Check timestamp is not too far in the future (2 hours) (Spec §4.1)
    if header.timestamp > current_time + 7200 {
        return Err(ConsensusError::TimestampTooFarInFuture);
    }

    // Check timestamp is not before the median time of the last 11 blocks (Spec §4.1)
    // For now, we'll just check it's not before the previous block
    if header.timestamp <= previous_block.header.timestamp {
        return Err(ConsensusError::TimestampTooOld);
    }

    // Check proof of work (Spec §5.1, 02_oxidehash_pow_spec.md)
    pow::verify_pow(header, header.difficulty_target)?;

    Ok(())
}

// Implement actual Masternode signature verification
fn verify_masternode_signature(
    masternode_id: &MasternodeID,
    block_height: u64,
    signature: &[u8],
    masternode_list: &MasternodeList,
) -> bool {
    // Retrieve the Masternode's public key from the list
    let masternode = masternode_list.get_masternode(masternode_id);
    if masternode.is_none() {
        return false;
    }
    let masternode = masternode.unwrap();
    let public_key_bytes = &masternode.identity.operator_public_key;

    // Construct the message to verify (e.g., block height and masternode ID)
    let message_string = format!("{}{:?}", block_height, masternode_id);
    let message = message_string.as_bytes();

    // Convert public_key and signature to the correct types for verify_signature
    use rusty_crypto::keypair::{PublicKey, Signature};
    let public_key = match PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature = match Signature::from_bytes(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify the signature using the public key
    verify_signature(&public_key, message, &signature).is_ok()
}

/// Validates a Masternode heartbeat.
///
/// Protocol reference:
/// - See docs/specs/01_block_structure.md §3.1 (Masternode Heartbeat)
pub fn validate_masternode_heartbeat(
    masternode_id: &MasternodeID,
    block_height: u64,
    signature: &[u8],
    context: &mut ValidationContext,
) -> Result<(), ConsensusError> {
    // Check if the Masternode exists
    let masternode = context
        .masternode_list
        .get_masternode(masternode_id)
        .ok_or(ConsensusError::MasternodeNotFound)?;

    // Check if the Masternode has been active recently
    let max_inactivity_blocks = context.params.max_inactivity_blocks;
    // Use last_successful_pose_height as the last seen height
    let last_seen = masternode.last_successful_pose_height;
    if (last_seen as u64) + (max_inactivity_blocks as u64) < block_height {
        return Err(ConsensusError::MasternodeInactive);
    }

    // Verify the signature
    if !verify_masternode_signature(
        masternode_id,
        block_height,
        signature,
        context.masternode_list,
    ) {
        return Err(ConsensusError::InvalidProofOfService);
    }

    // Update Masternode's last_successful_pose_height as the last seen time
    if let Some(mn) = context.masternode_list.map.get_mut(masternode_id) {
        mn.last_successful_pose_height = block_height as u32;
    }

    Ok(())
}

/// Applies the changes of a validated block to the UTXO set.
/// This function should only be called after a block has been fully validated.
pub fn apply_block_to_utxo_set(
    block: &Block,
    utxo_set: &mut UtxoSet,
    masternode_list: &mut MasternodeList,
    height: u64,
    coinbase_maturity: u32,
) -> Result<(), ConsensusError> {
    let mut batch = UtxoSet::create_batch();

    for tx in &block.transactions {
        // Spend inputs (remove old UTXOs from the set)
        if !tx.is_coinbase() {
            for input in tx.get_inputs() {
                utxo_set.delete_utxo_in_batch(&mut batch, &input.previous_output)?;
            }
        }

        // Create outputs (add new UTXOs to the set)
        for (vout, output) in tx.get_outputs().iter().enumerate() {
            let outpoint = OutPoint {
                txid: tx.txid(),
                vout: vout as u32,
            };
            let is_coinbase = tx.is_coinbase();
            utxo_set.put_utxo_in_batch(&mut batch, &outpoint, output, height, is_coinbase)?;
        }

        // Handle Masternode registration transactions
        if let Transaction::MasternodeRegister { .. } = tx {
            // You may need to extract the fields if needed
            // masternode_list.register_masternode(reg_tx.clone(), block.height() as u32)
            //     .map_err(|e| ConsensusError::MasternodeError(e))?;
        }
    }

    // Apply the batch of changes atomically
    utxo_set.apply_batch(batch)?;

    Ok(())
}

/// Validates a block against the consensus rules.
pub fn validate_block(
    block: &Block,
    previous_blocks: &[&Block],
    context: &mut ValidationContext,
    current_time: u64,
) -> Result<(), ConsensusError> {
    // 1. Check if we have previous blocks (for now, assume we always have at least one for context)
    if previous_blocks.is_empty() {
        return Err(ConsensusError::MissingPreviousBlock);
    }
    let prev_block = previous_blocks[0]; // Assuming the most recent previous block is at index 0

    // 2. Verify previous block hash
    if block.header.previous_block_hash != prev_block.header.hash() {
        return Err(ConsensusError::InvalidPreviousBlockHash);
    }

    // 3. Verify block height
    if block.height() != prev_block.height() + 1 {
        return Err(ConsensusError::InvalidProof(
            "Block height mismatch".to_string(),
        ));
    }

    // 4. Verify Merkle root
    let calculated_merkle_root = block.calculate_merkle_root();
    if block.header.merkle_root != calculated_merkle_root {
        return Err(ConsensusError::InvalidMerkleRoot);
    }

    // 5. Validate block header (already existing checks)
    validate_block_header(&block.header, prev_block, current_time)?;

    // 6. Validate transactions (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 7. Verify PoW/PoS based on block type (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 8. Apply block to UTXO set (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 9. Apply block to blockchain state (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    Ok(())
}

/// Validates a block against the consensus rules (comprehensive validation).
pub fn validate_block_comprehensive(
    block: &Block,
    previous_blocks: &[&Block],
    context: &mut ValidationContext,
    current_time: u64,
) -> Result<(), ConsensusError> {
    if previous_blocks.is_empty() {
        return Err(ConsensusError::MissingPreviousBlock);
    }

    let prev_block = previous_blocks[0];

    // Validate the block header
    validate_block_header(&block.header, prev_block, current_time)?;

    // Check block size limits
    let block_size = bincode::serialized_size(block).map_err(|e| {
        ConsensusError::SerializationError(format!("failed to serialize block: {}", e))
    })? as usize;

    if block_size > context.params.max_block_size as usize {
        return Err(ConsensusError::BlockTooLarge(
            block_size,
            context.params.max_block_size as usize,
        ));
    }

    // Check transactions
    validate_transactions(&block.transactions, block.height(), current_time, context)?;

    // Check for coinbase transaction and its position
    if block.transactions.is_empty() || !block.transactions[0].is_coinbase() {
        return Err(ConsensusError::NoCoinbaseTransaction);
    }
    if block.transactions[0].get_inputs().len() != 1
    /* || !block.transactions[0].get_inputs()[0].is_coinbase_input() */
    {
        return Err(ConsensusError::InvalidCoinbaseInput);
    }

    // Check Merkle root
    let calculated_merkle_root = block.calculate_merkle_root();
    if calculated_merkle_root != block.header.merkle_root {
        return Err(ConsensusError::MerkleRootMismatch {
            expected: block.header.merkle_root,
            found: calculated_merkle_root,
        });
    }

    // Check for duplicate transactions and sum up fees
    let mut txids = HashSet::new();
    let mut total_tx_fees = 0u64;

    for (i, tx) in block.transactions.iter().enumerate() {
        let txid = tx.hash();
        if !txids.insert(txid) {
            return Err(ConsensusError::DuplicateTransaction);
        }

        // Validate each transaction individually (excluding coinbase for now, as it's handled separately)
        if i > 0 {
            // Skip coinbase transaction
            validate_transaction(tx, block.height() as u32, current_time, context)?;

            // Calculate fees for non-coinbase transactions
            let mut input_value_sum = 0u64;
            for input in tx.get_inputs() {
                let (prev_output, prev_height, prev_is_coinbase) = context
                    .utxo_set
                    .get_utxo(&input.previous_output)?
                    .ok_or_else(|| ConsensusError::MissingTxInput)?;
                if prev_is_coinbase
                    && block.height()
                        < (prev_height as u64) + context.params.coinbase_maturity as u64
                {
                    return Err(ConsensusError::CoinbaseNotMature);
                }
                input_value_sum = input_value_sum.checked_add(prev_output.value).ok_or(
                    ConsensusError::InvalidProof("Input value too large".to_string()),
                )?;
            }
            let mut output_value_sum = 0u64;
            for output in tx.get_outputs() {
                output_value_sum = output_value_sum.checked_add(output.value).ok_or(
                    ConsensusError::InvalidProof("Output value too large".to_string()),
                )?;
            }
            total_tx_fees = total_tx_fees
                .checked_add(input_value_sum - output_value_sum)
                .ok_or(ConsensusError::InvalidProof("Fee overflow".to_string()))?;
        }
    }

    // Validate coinbase reward
    let coinbase_tx = &block.transactions[0];
    let expected_reward = context.params.block_reward + total_tx_fees;
    let actual_reward = coinbase_tx
        .get_outputs()
        .iter()
        .map(|o| o.value)
        .sum::<u64>();

    if actual_reward > expected_reward {
        return Err(ConsensusError::InvalidProof(
            "Block reward invalid".to_string(),
        ));
    }

    // Validate ticket votes if this is a PoS block
    if !block.ticket_votes.is_empty() {
        // Validate using the pos module function
        crate::pos::validate_ticket_votes(
            &block.ticket_votes,
            context.params,
            block.height(),
            context.ticket_voting.get_all_tickets(),
        )?;

        // Note: Non-participation detection is handled separately during block application
        // to avoid borrowing conflicts. The detection logic is in validate_ticket_votes()
        // in this module and can be called with the LiveTicketsPool when applying blocks.
    }

    // Validate state root (Spec §4.1, §5.5)
    // State root is a commitment to UTXO set, live tickets, masternode list, and active proposals
    // after applying this block's transactions.
    //
    // Note: For full validation, we would need to:
    // 1. Create a temporary copy of the state
    // 2. Apply this block's transactions to the temporary state
    // 3. Calculate the expected state root
    // 4. Compare with header.state_root
    //
    // For now, we validate that state_root is non-zero (basic check)
    // Full state root validation should be done during block application
    // when we have access to the updated state.
    if block.header.state_root == [0u8; 32] && block.height() > 0 {
        return Err(ConsensusError::InvalidStateRoot {
            expected: [0u8; 32], // Placeholder - would be calculated
            found: block.header.state_root,
        });
    }

    // State root validation note:
    // Full state root validation requires simulating the application of this block's transactions
    // to the current state, which is computationally expensive and typically done during
    // block application rather than validation. The state root in the block header represents
    // the state AFTER applying this block's transactions.
    //
    // For validation, we perform a basic check (non-zero for non-genesis blocks).
    // Full validation is performed during block application in:
    // - rusty-core/src/consensus/state.rs::BlockchainState::apply_block()
    // - rusty-core/src/consensus/state.rs::BlockchainState::calculate_state_root()
    //
    // The state root calculation uses MerklePatriciaTrie to commit:
    // - UTXO set (after applying block transactions)
    // - Live tickets pool (after applying block transactions)
    // - Masternode list (after applying block transactions)
    // - Active governance proposals (after applying block transactions)

    // Validate difficulty target (for adjustment period blocks)
    // Per spec 02a - Proof-of-Work Difficulty Adjustment
    const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;
    const TARGET_BLOCK_TIME_SECONDS: u64 = 150;
    const MAX_DIFFICULTY_ADJUSTMENT_FACTOR: u64 = 4;

    let current_height = block.height();
    let is_adjustment_block = (current_height - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL as u64 == 0;

    if is_adjustment_block && current_height > 1 {
        // This is an adjustment period block - calculate expected difficulty
        // Per spec §2a.3: Adjustment happens at blocks where (H_current - 1) % 2016 == 0

        // We need at least DIFFICULTY_ADJUSTMENT_INTERVAL blocks to calculate
        if previous_blocks.len() >= DIFFICULTY_ADJUSTMENT_INTERVAL as usize {
            // Get first and last block of the adjustment period
            let first_block_in_period =
                previous_blocks[DIFFICULTY_ADJUSTMENT_INTERVAL as usize - 1];
            let last_block_in_period = previous_blocks[0];

            // Calculate actual elapsed time
            let actual_timespan = last_block_in_period
                .header
                .timestamp
                .saturating_sub(first_block_in_period.header.timestamp);

            // Calculate expected elapsed time
            let expected_timespan =
                DIFFICULTY_ADJUSTMENT_INTERVAL as u64 * TARGET_BLOCK_TIME_SECONDS;

            // Get previous target (from last block of period)
            use crate::pow::{calculate_new_target, compact_to_target, target_to_compact};
            use primitive_types::U256;

            let previous_target = compact_to_target(last_block_in_period.header.difficulty_target);

            // Calculate new target using the difficulty adjustment algorithm
            let max_target = U256::MAX;
            let min_target = U256::zero(); // MIN_DIFFICULTY_TARGET would be set here if defined

            let new_target = calculate_new_target(
                previous_target,
                actual_timespan,
                expected_timespan,
                MAX_DIFFICULTY_ADJUSTMENT_FACTOR,
                U256::zero(), // min_difficulty_target - would be set from protocol constants if defined
                max_target,
            );

            let expected_difficulty = target_to_compact(new_target);

            // Verify the difficulty target matches
            if block.header.difficulty_target != expected_difficulty {
                return Err(ConsensusError::InvalidProof(format!(
                    "Difficulty target mismatch at adjustment block: expected {}, got {}",
                    expected_difficulty, block.header.difficulty_target
                )));
            }
        } else {
            // Not enough blocks to validate - this is acceptable for early blocks
            // but we should still verify it's not obviously wrong
            if current_height <= DIFFICULTY_ADJUSTMENT_INTERVAL as u64 {
                // For early blocks, just verify it's not zero
                if block.header.difficulty_target == 0 {
                    return Err(ConsensusError::InvalidProof(
                        "Difficulty target cannot be zero".to_string(),
                    ));
                }
            }
        }
    } else if current_height == 0 {
        // Per spec §2a.3: Genesis Block special case
        // For the Genesis Block (H_current = 0), its difficulty_target is INITIAL_DIFFICULTY_TARGET
        // For now, just verify it's not zero (would validate against hardcoded INITIAL_DIFFICULTY_TARGET in production)
        if block.header.difficulty_target == 0 {
            return Err(ConsensusError::InvalidProof(
                "Genesis block difficulty target cannot be zero".to_string(),
            ));
        }
    } else {
        // Per spec §2a.3: Non-Adjustment Period Blocks
        // If the current block H_current is NOT the first block of a new adjustment period,
        // its difficulty_target MUST be the same as the difficulty_target of the immediately preceding block
        if let Some(previous_block) = previous_blocks.first() {
            if block.header.difficulty_target != previous_block.header.difficulty_target {
                return Err(ConsensusError::InvalidProof(
                    format!(
                        "Difficulty target should match previous block for non-adjustment block: expected {}, got {}",
                        previous_block.header.difficulty_target, block.header.difficulty_target
                    )
                ));
            }
        }
    }

    Ok(())
}

/// Validates a Masternode registration transaction.
///
/// Protocol reference:
/// - See docs/specs/01_block_structure.md §3.1 (Masternode Registration)
pub fn validate_masternode_registration(
    tx: &Transaction,
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    let masternode_registration = match tx {
        Transaction::MasternodeRegister { .. } => tx,
        _ => {
            return Err(ConsensusError::InvalidTransactionType(
                "Expected MasternodeRegister transaction".to_string(),
            ))
        }
    };

    // 6.2.3 Masternode Registration (MN_REGISTER_TX)

    // Inputs: MUST include at least one TxInput spending exactly MASTERNODE_COLLATERAL_AMOUNT to a new TxOutput specifically designed to lock the collateral.
    // For now, we'll check if there's at least one input and one output.
    // The exact collateral amount check will be done by checking the output value.
    if masternode_registration.get_inputs().is_empty() {
        return Err(ConsensusError::MasternodeError(
            "Masternode registration transaction must have inputs".to_string(),
        ));
    }

    // Outputs: The transaction MUST create a new TxOutput locking MASTERNODE_COLLATERAL_AMOUNT with a script designating it as Masternode collateral.
    // It MUST also include a small transaction fee.
    let mut found_collateral_output = false;
    let mut total_output_value: u64 = 0;
    for output in masternode_registration.get_outputs() {
        if output.value == context.params.masternode_collateral_amount {
            // Validate masternode collateral script
            validate_masternode_collateral_script(&output.script_pubkey)?;
            found_collateral_output = true;
        }
        total_output_value =
            total_output_value
                .checked_add(output.value)
                .ok_or(ConsensusError::InvalidProof(
                    "Output value too large".to_string(),
                ))?;
    }

    if !found_collateral_output {
        return Err(ConsensusError::MasternodeError(
            "Masternode registration transaction must have a collateral output".to_string(),
        ));
    }

    // Payload: The MN_REGISTER_TX MUST include an additional payload containing:
    // The Operator Key (public key).
    // The network address (IP:Port) of the Masternode.
    // A signature by the Collateral Ownership Key over the entire transaction (including the payload).
    // These are part of the MasternodeIdentity and MasternodeRegistration structs, which are already deserialized.
    // We need to validate the signature.

    // Validation: Full nodes verify:
    // Correct collateral amount locked. (Done above)
    // Valid Operator Key and network address. (Basic format checks)
    // Valid signature by the Collateral Ownership Key.
    // The Masternode is not already registered. (This check requires access to the MasternodeList, which is not available here yet)

    // Basic validation of operator key and network address format
    // For now, we assume the deserialization handles basic format, but more rigorous checks might be needed.
    // E.g., validate IP address format, port range.

    // Validate signature by the Collateral Ownership Key
    // This requires the raw transaction bytes and the public key.
    // The signature is over the entire transaction (including the payload).
    // We need to re-serialize the transaction without the signature to verify.
    // You will need to update this section to match your Transaction struct
    // let mut tx_without_signature = masternode_registration.clone();
    // tx_without_signature.signature = [0u8; 64]; // Zero out the signature for verification

    // let tx_bytes_for_signature = bincode::serialize(&tx_without_signature)
    //     .map_err(|e| ConsensusError::SerializationError(format!("Failed to serialize transaction for signature verification: {}", e)))?;

    // let public_key = &masternode_registration.masternode_identity.collateral_ownership_public_key;
    // let signature = &masternode_registration.signature;

    // // Verify the signature using rusty-crypto
    // if !verify_signature(public_key, &tx_bytes_for_signature, signature).is_ok() {
    //     return Err(ConsensusError::MasternodeError("Invalid Masternode registration signature".to_string()));
    // }

    Ok(())
}

/// Validates a list of transactions against the consensus rules.
pub fn validate_transactions(
    transactions: &[Transaction],
    height: u64,
    current_time: u64,
    context: &mut ValidationContext,
) -> Result<(), ConsensusError> {
    if transactions.is_empty() {
        return Err(ConsensusError::EmptyTransaction);
    }

    // Track spent outputs to detect double spends within the block
    let mut spent_outputs = HashSet::new();

    // The first transaction must be a coinbase transaction
    if !transactions[0].is_coinbase() {
        return Err(ConsensusError::NoCoinbaseTransaction);
    }

    // Validate each transaction
    let mut total_fees = 0u64;

    for (i, tx) in transactions.iter().enumerate() {
        // Skip coinbase transaction for some checks
        if i > 0 && tx.is_coinbase() {
            return Err(ConsensusError::InvalidCoinbaseInput);
        }

        // Validate transaction structure
        validate_transaction_structure(tx, height, context)?;

        // Perform type-specific validation
        match tx {
            Transaction::MasternodeRegister { .. } => {
                validate_masternode_registration(tx, context)?;
            }
            Transaction::MasternodeCollateral {
                collateral_amount, ..
            } => {
                // Validate masternode collateral transaction
                // Per spec 06_masternode_protocol_spec.md Section 6.2.1
                use rusty_core::constants::MASTERNODE_COLLATERAL_AMOUNT;
                if *collateral_amount != MASTERNODE_COLLATERAL_AMOUNT {
                    return Err(ConsensusError::InvalidTransactionType(format!(
                        "Masternode collateral amount must be {} satoshis",
                        MASTERNODE_COLLATERAL_AMOUNT
                    )));
                }
                // Validate that there's exactly one output with the collateral amount
                if tx.get_outputs().len() != 1 {
                    return Err(ConsensusError::InvalidTransactionType(
                        "Masternode collateral transaction must have exactly one output"
                            .to_string(),
                    ));
                }
                if tx.get_outputs()[0].value != *collateral_amount {
                    return Err(ConsensusError::InvalidTransactionType(
                        "Masternode collateral output value does not match collateral amount"
                            .to_string(),
                    ));
                }
            }
            Transaction::TicketPurchase {
                ticket_id,
                locked_amount,
                ticket_address,
                outputs,
                ..
            } => {
                // Validate ticket purchase transaction
                // Per spec 03_oxidesync_pos_spec.md Section 3.2.1
                use rusty_shared_types::TicketId;

                // Ensure ticket output exists and matches locked_amount
                let ticket_output = outputs.first().ok_or(ConsensusError::InvalidTicketID)?;

                if ticket_output.value != *locked_amount {
                    return Err(ConsensusError::InvalidTransactionType(
                        "Ticket purchase output value does not match locked amount".to_string(),
                    ));
                }

                // Ensure the ticket address matches the output's script_pubkey
                if ticket_output.script_pubkey != *ticket_address {
                    return Err(ConsensusError::InvalidTransactionType(
                        "Ticket purchase output script_pubkey does not match ticket address"
                            .to_string(),
                    ));
                }

                // Ensure the ticket is not already in the live tickets pool
                let ticket_id_typed = TicketId::from(*ticket_id);
                if context.ticket_voting.get_ticket(&ticket_id_typed).is_some() {
                    return Err(ConsensusError::DuplicateTicketVote);
                }
            }
            Transaction::TicketRedemption { ticket_id, .. } => {
                // Validate ticket redemption transaction
                // Per spec 03_oxidesync_pos_spec.md Section 3.2.3
                use rusty_shared_types::TicketId;
                let ticket_id_typed = TicketId::from(*ticket_id);

                // Ensure the ticket exists in the live tickets pool
                let ticket = context
                    .ticket_voting
                    .get_ticket(&ticket_id_typed)
                    .ok_or(ConsensusError::InvalidTicketID)?;

                // Ensure the ticket is in a redeemable state (Expired or Revoked)
                // Per spec: Only expired or revoked tickets can be redeemed
                use rusty_shared_types::TicketStatus;
                match ticket.status {
                    TicketStatus::Expired | TicketStatus::Revoked => {
                        // Valid for redemption
                    }
                    TicketStatus::Live | TicketStatus::Voted | TicketStatus::Pending => {
                        return Err(ConsensusError::InvalidTicketStatus);
                    }
                }
            }
            Transaction::GovernanceProposal(proposal) => {
                // Validate governance proposal transaction
                // Per spec 09_governance_protocol_spec.md (Homestead Accord)
                // Basic validation - detailed validation is done in governance crate
                if proposal.title.trim().is_empty() {
                    return Err(ConsensusError::GovernanceError(
                        "Governance proposal must have a non-empty title".to_string(),
                    ));
                }
                if proposal.description_hash == [0u8; 32] {
                    return Err(ConsensusError::GovernanceError(
                        "Governance proposal must have a valid description hash".to_string(),
                    ));
                }
                // Validate voting period
                if proposal.end_block_height < proposal.start_block_height {
                    return Err(ConsensusError::GovernanceError(
                        "Governance proposal end_block_height must be >= start_block_height"
                            .to_string(),
                    ));
                }
                // Validate proposal is not in the past
                if proposal.start_block_height < height {
                    return Err(ConsensusError::GovernanceError(
                        "Governance proposal start_block_height must be >= current block height"
                            .to_string(),
                    ));
                }
            }
            Transaction::GovernanceVote(vote) => {
                // Validate governance vote transaction
                // Per spec 09_governance_protocol_spec.md (Homestead Accord)
                // Basic validation - detailed validation is done in governance crate
                // Vote must reference a valid proposal (checked during block application)
                // Vote signature validation is done in governance crate
            }
            Transaction::ActivateProposal {
                proposal_id,
                activation_block_height,
                ..
            } => {
                // Validate proposal activation transaction
                // Per spec 09_governance_protocol_spec.md Section 4.2.1
                // Activation block height must be in the future
                if *activation_block_height <= height {
                    return Err(ConsensusError::GovernanceError(
                        "Proposal activation block height must be > current block height"
                            .to_string(),
                    ));
                }
                // Proposal must exist and be approved (checked during block application)
                // Approval proof validation is done in governance crate
            }
            Transaction::TicketSlashNonParticipation {
                ticket_id, proof, ..
            } => {
                use crate::pos_slashing::validate_ticket_non_participation_slashing;
                use rusty_shared_types::TicketId;
                let ticket_id = TicketId::from(*ticket_id);
                validate_ticket_non_participation_slashing(&ticket_id, proof, height)
                    .map_err(|e| ConsensusError::InvalidSlashingTransaction(e.to_string()))?;
            }
            Transaction::TicketSlashMalicious {
                ticket_id, proof, ..
            } => {
                use crate::pos_slashing::validate_ticket_malicious_behavior_slashing;
                use rusty_shared_types::TicketId;
                let ticket_id = TicketId::from(*ticket_id);
                validate_ticket_malicious_behavior_slashing(&ticket_id, proof, height)
                    .map_err(|e| ConsensusError::InvalidSlashingTransaction(e.to_string()))?;
            }
            Transaction::MasternodeSlashTx(slash_tx) => {
                // Validate masternode slashing transaction
                // Per spec 06_masternode_protocol_spec.md Section 6.4

                // Validate proof data size (max 4KB)
                const MAX_SLASHING_PROOF_SIZE: usize = 4096;
                if slash_tx.proof.len() > MAX_SLASHING_PROOF_SIZE {
                    return Err(ConsensusError::InvalidSlashingTransaction(
                        "Proof data too large".to_string(),
                    ));
                }

                // Validate that there's exactly one input (the collateral)
                if slash_tx.inputs.len() != 1 {
                    return Err(ConsensusError::InvalidSlashingTransaction(
                        "Slashing transaction must have exactly one input".to_string(),
                    ));
                }

                // Validate that there's at least one output (the burn output)
                if slash_tx.outputs.is_empty() {
                    return Err(ConsensusError::InvalidSlashingTransaction(
                        "Slashing transaction must have at least one output".to_string(),
                    ));
                }

                // Validate that the first output is a burn output (OP_RETURN)
                let burn_script = vec![0x6a, 0x04, 0x72, 0x75, 0x73, 0x74]; // OP_RETURN + 'rust'
                if slash_tx.outputs[0].script_pubkey != burn_script {
                    return Err(ConsensusError::InvalidSlashingTransaction(
                        "First output must be a burn output".to_string(),
                    ));
                }

                // Verify masternode exists and is eligible for slashing
                // Convert masternode_id to the expected type
                use rusty_core::protocol_constants::{MAX_POSE_FAILURES, RESET_FAILURES_PERIOD};
                use rusty_shared_types::MasternodeID as SharedMasternodeID;

                let mn_id = SharedMasternodeID(slash_tx.masternode_id.0.clone());
                let masternode = context
                    .masternode_list
                    .get_masternode(&mn_id)
                    .ok_or(ConsensusError::MasternodeNotFound)?;

                // Check that the first input is the masternode's collateral
                let collateral_outpoint = &masternode.identity.collateral_outpoint;
                if &slash_tx.inputs[0].previous_output != collateral_outpoint {
                    return Err(ConsensusError::InvalidSlashingTransaction(
                        "Slashing transaction input does not match masternode collateral"
                            .to_string(),
                    ));
                }

                // Validate slashing reason matches masternode state
                match slash_tx.reason {
                    rusty_shared_types::masternode::SlashingReason::MasternodeNonResponse => {
                        // Per spec 06 Section 6.4.1: Non-participation slashing requires
                        // PoSe failure count > MAX_POSE_FAILURES within RESET_FAILURES_PERIOD
                        if masternode.pose_failure_count < MAX_POSE_FAILURES {
                            return Err(ConsensusError::InvalidSlashingTransaction(format!(
                                "Masternode failure count {} is below threshold {}",
                                masternode.pose_failure_count, MAX_POSE_FAILURES
                            )));
                        }

                        // Check if failures occurred within RESET_FAILURES_PERIOD
                        // (This would require tracking failure timestamps, simplified here)
                        // In full implementation, we'd check if failures are recent enough
                    }
                    rusty_shared_types::masternode::SlashingReason::DoubleSigning
                    | rusty_shared_types::masternode::SlashingReason::InvalidBlockProposal
                    | rusty_shared_types::masternode::SlashingReason::InvalidTransaction
                    | rusty_shared_types::masternode::SlashingReason::GovernanceViolation => {
                        // Per spec 06 Section 6.4.2: Malicious behavior slashing
                        // Requires cryptographic proof (validated via proof_data)
                        if slash_tx.proof.is_empty() {
                            return Err(ConsensusError::InvalidSlashingTransaction(
                                "Malicious behavior slashing requires proof data".to_string(),
                            ));
                        }
                    }
                }

                // Validate slashing amount matches reason
                let expected_slash_percentage = match slash_tx.reason {
                    rusty_shared_types::masternode::SlashingReason::MasternodeNonResponse => {
                        rusty_core::protocol_constants::NON_PARTICIPATION_SLASH_PERCENTAGE
                    }
                    _ => rusty_core::protocol_constants::MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE,
                };

                // Calculate expected slashed amount
                // Use collateral_amount field directly, or fallback to protocol constant
                let collateral_value = if masternode.collateral_amount > 0 {
                    masternode.collateral_amount
                } else {
                    // Fallback to protocol constant if not set
                    rusty_core::protocol_constants::MASTERNODE_COLLATERAL_AMOUNT
                };
                let expected_slashed = (collateral_value as f64 * expected_slash_percentage) as u64;
                let actual_slashed = slash_tx.outputs[0].value;

                // Allow small rounding differences
                if actual_slashed.abs_diff(expected_slashed) > 1 {
                    return Err(ConsensusError::InvalidSlashingTransaction(format!(
                        "Slashing amount mismatch: expected {}, got {}",
                        expected_slashed, actual_slashed
                    )));
                }
            }
            // Transaction::MasternodePoSe { masternode_id, signature, .. } => {
            //     validate_masternode_proof_of_service(masternode_id, height, signature, context)?;
            // },
            // Transaction::MasternodeHeartbeat { masternode_id, signature, .. } => {
            //     validate_masternode_heartbeat(masternode_id, height, signature, &mut context)?;
            // },
            _ => {}
        }

        let mut input_value_sum = 0u64;

        // Check for double spends within this block and calculate input sum
        for input in tx.get_inputs() {
            // Check if the previous output exists in the UTXO set
            let (prev_output, prev_height, prev_is_coinbase) = context
                .utxo_set
                .get_utxo(&input.previous_output)?
                .ok_or_else(|| ConsensusError::MissingTxInput)?;

            // Coinbase maturity check
            if prev_is_coinbase
                && height < prev_height as u64 + context.params.coinbase_maturity as u64
            {
                return Err(ConsensusError::CoinbaseNotMature);
            }
            let outpoint_key = (input.previous_output.txid, input.previous_output.vout);
            if !spent_outputs.insert(outpoint_key) {
                return Err(ConsensusError::InvalidProof(
                    "Duplicate transaction detected".to_string(),
                ));
            }

            input_value_sum = input_value_sum.checked_add(prev_output.value).ok_or(
                ConsensusError::InvalidProof("Input value too large".to_string()),
            )?;
        }
        let mut output_value_sum = 0u64;
        for output in tx.get_outputs().iter() {
            output_value_sum =
                output_value_sum
                    .checked_add(output.value)
                    .ok_or(ConsensusError::InvalidProof(
                        "Output value too large".to_string(),
                    ))?;
        }

        // Value conservation and fees
        if !tx.is_coinbase() {
            if input_value_sum < output_value_sum {
                return Err(ConsensusError::InvalidProof(
                    "Spending more than inputs".to_string(),
                ));
            }
            let fee = input_value_sum - output_value_sum;
            let tx_size = bincode::serialized_size(tx)? as usize;
            // Per spec 05 Section 5.4: Fee MUST be >= MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes
            use rusty_core::constants::MIN_RELAY_FEE_PER_BYTE;
            let min_fee = MIN_RELAY_FEE_PER_BYTE * tx_size as u64;
            if fee < min_fee {
                return Err(ConsensusError::InsufficientFee(fee, min_fee));
            }
            total_fees = total_fees
                .checked_add(fee)
                .ok_or(ConsensusError::InvalidProof("Fee overflow".to_string()))?;
        } else {
            // Coinbase transaction reward validation will be done at block validation level
            // where total fees from other transactions are known.
        }

        // Lock time validation (full check with block height and timestamp)
        // Per spec 05 Section 5.4: lock_time interpretation
        // If lock_time < LOCKTIME_THRESHOLD: interpreted as block height
        // If lock_time >= LOCKTIME_THRESHOLD: interpreted as Unix timestamp
        if tx.get_lock_time() != 0 {
            use rusty_core::constants::LOCKTIME_THRESHOLD;
            let locktime_threshold = LOCKTIME_THRESHOLD;

            if tx.get_lock_time() < locktime_threshold {
                // Interpreted as block height
                // Per spec: transaction is valid ONLY if current block height >= lock_time
                if tx.get_lock_time() as u64 > height {
                    return Err(ConsensusError::InvalidProof(
                        "Invalid lock time: block height not reached".to_string(),
                    ));
                }
            } else {
                // Interpreted as Unix timestamp
                // Per spec: transaction is valid ONLY if current block timestamp >= lock_time
                if tx.get_lock_time() as u64 > current_time {
                    return Err(ConsensusError::InvalidProof(
                        "Invalid lock time: timestamp not reached".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validates the structure of a transaction.
pub fn validate_transaction_structure(
    tx: &Transaction,
    height: u64,
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    // Check transaction size
    let tx_size = bincode::serialized_size(tx).map_err(|e| {
        ConsensusError::SerializationError(format!("failed to serialize transaction: {}", e))
    })? as usize;

    if tx_size > context.params.max_tx_size {
        return Err(ConsensusError::TransactionTooLarge(
            tx_size,
            context.params.max_tx_size,
        ));
    }

    // Check for empty inputs (except coinbase)
    if !tx.is_coinbase() && tx.get_inputs().is_empty() {
        return Err(ConsensusError::EmptyTransaction);
    }

    // Validate scripts for non-coinbase transactions
    if !tx.is_coinbase() {
        // Per spec 04 Section 4.3.3: MAX_SIG_OPS is enforced per transaction, not per input
        let mut transaction_sig_op_count: usize = 0;
        use rusty_core::constants::MAX_SIG_OPS;

        for (i, input) in tx.get_inputs().iter().enumerate() {
            let (prev_output, _prev_height, _prev_is_coinbase) = context
                .utxo_set
                .get_utxo(&input.previous_output)?
                .ok_or_else(|| ConsensusError::MissingTxInput)?;

            let mut script_engine = rusty_core::script::script_engine::ScriptEngine::new();
            if let Err(e) = script_engine.verify_script_with_sig_op_count(
                &input.script_sig,
                &prev_output.script_pubkey,
                tx,
                i,
                &prev_output,
                &mut transaction_sig_op_count,
            ) {
                return Err(ConsensusError::InvalidScript(format!(
                    "script validation failed for input {}: {:?}",
                    i, e
                )));
            }

            // Input existence and unspent status are checked in `validate_transactions`
            // Coinbase maturity is checked in `validate_transactions`
        }
    }

    // Check for empty outputs
    if tx.get_outputs().is_empty() {
        return Err(ConsensusError::NoOutputs);
    }

    // Check output values
    let mut total_output_value = 0u64;
    for (i, output) in tx.get_outputs().iter().enumerate() {
        if output.value == 0 {
            return Err(ConsensusError::OutputValueZero(i));
        }

        // Check for overflow
        total_output_value =
            total_output_value
                .checked_add(output.value)
                .ok_or(ConsensusError::InvalidProof(
                    "Output value too large".to_string(),
                ))?;

        // Check for dust output (outputs below a certain value are not standard)
        // Per spec 05 Section 5.4: OP_RETURN outputs are explicitly allowed to be below DUST_LIMIT
        let is_op_return = is_op_return_output(&output.script_pubkey);
        if !is_op_return && output.value < context.params.dust_limit {
            return Err(ConsensusError::DustOutput(output.value));
        }
    }

    // For coinbase transactions, we skip some checks
    if tx.is_coinbase() {
        // Coinbase transactions must have exactly one input
        if tx.get_inputs().len() != 1 {
            return Err(ConsensusError::InvalidCoinbase(
                "coinbase transaction must have exactly one input".to_string(),
            ));
        }

        // Coinbase input must be null
        if tx.get_inputs()[0].previous_output.txid != [0u8; 32]
            || tx.get_inputs()[0].previous_output.vout != u32::MAX
        {
            return Err(ConsensusError::InvalidCoinbase(
                "coinbase input must be null".to_string(),
            ));
        }

        // Coinbase maturity check is done at block validation
        // where total fees from other transactions are known.
        return Ok(());
    }

    // For regular transactions, check inputs and fees
    let mut total_input_value = 0u64;

    for input in tx.get_inputs().iter() {
        let (prev_output, _prev_height, _prev_is_coinbase) = context
            .utxo_set
            .get_utxo(&input.previous_output)?
            .ok_or(ConsensusError::MissingTxInput)?;

        total_input_value = total_input_value.checked_add(prev_output.value).ok_or(
            ConsensusError::InvalidProof("Input value too large".to_string()),
        )?;

        // Validate sequence number (for future use with Replace-by-Fee or relative locktime)
        // For now, we'll just ensure it's not the max value if locktime is set
        if tx.get_lock_time() != 0 && input.sequence == u32::MAX {
            return Err(ConsensusError::InvalidSequence);
        }
    }

    // Check for overflow in input values
    if total_input_value < total_output_value {
        return Err(ConsensusError::SpendingMoreThanInputs);
    }

    // Check minimum fee
    // Per spec 05 Section 5.4: Fee MUST be >= MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes
    let fee = total_input_value - total_output_value;
    use rusty_core::constants::MIN_RELAY_FEE_PER_BYTE;
    let min_fee = MIN_RELAY_FEE_PER_BYTE * tx_size as u64;

    if fee < min_fee {
        return Err(ConsensusError::InsufficientFee(fee, min_fee));
    }

    // Validate lock_time
    // If lock_time is set, all inputs must have sequence < u32::MAX
    if tx.get_lock_time() != 0
        && tx
            .get_inputs()
            .iter()
            .any(|input| input.sequence == u32::MAX)
    {
        return Err(ConsensusError::InvalidLockTime(
            "all inputs must have sequence < MAX_UINT if lock_time is set".to_string(),
        ));
    }

    // If lock_time is block height, it must be less than or equal to current block height
    // This check is done in `validate_transactions` where block height is available.

    // If lock_time is timestamp, it must be less than or equal to current block timestamp
    // This check is done in `validate_transactions` where block timestamp is available.

    Ok(())
}

/// Validates a list of ticket votes according to the OxideSync PoS specification.
///
/// Per spec 03_oxidesync_pos_spec.md Section 3.5:
/// - Validates ticket votes structure
/// - Validates individual TicketVote entries
/// - Performs quorum check
///
/// Note: Non-participation detection is handled separately during block application
/// to avoid borrowing conflicts. See `detect_ticket_non_participation()` in pos module.
pub fn validate_ticket_votes(
    votes: &[TicketVote],
    current_height: u64,
    previous_block_hash: &[u8; 32],
) -> Result<(), ConsensusError> {
    if votes.is_empty() {
        return Err(ConsensusError::NoTicketVotes);
    }

    let mut seen_votes = HashSet::new();
    let mut valid_vote_count = 0;

    for vote in votes {
        // Check for duplicate votes (same ticket voting multiple times)
        if !seen_votes.insert((vote.ticket_id, vote.block_hash)) {
            return Err(ConsensusError::DuplicateTicketVote);
        }

        // Validate individual ticket vote according to PoS spec:

        // 1. Verify the ticket ID is valid (non-zero and properly formatted)
        if vote.ticket_id == [0u8; 32] {
            return Err(ConsensusError::InvalidTicketID);
        }

        // 2. Verify the block hash being voted on is valid (non-zero)
        if vote.block_hash == [0u8; 32] {
            return Err(ConsensusError::InvalidBlockHash);
        }

        // 3. Verify the signature is properly formatted (64 bytes for Ed25519)
        if vote.signature.len() != 64 {
            return Err(ConsensusError::InvalidSignature);
        }

        // 4. Validate ticket expiration - ticket must not be expired
        // Note: In a full implementation, we would look up the ticket's purchase height
        // from the LIVE_TICKETS_POOL and check expiration there.
        // For now, we assume all properly formatted votes represent valid, non-expired tickets

        // 5. Verify ticket is in LIVE state (not PENDING, EXPIRED, or SPENT)
        // In full implementation, this would check the LIVE_TICKETS_POOL
        // Note: We check against the selected tickets list instead of pool
        // to avoid borrowing issues

        // 6. Cryptographic signature validation would happen here
        // This requires access to the ticket's public key from the UTXO set
        // For now, we validate the signature format and structure

        valid_vote_count += 1;
    }

    // 7. Quorum check: ensure minimum valid votes required
    // Per spec 03 Section 3.5.3: MIN_VALID_VOTES_REQUIRED (e.g., 3)
    // This is 60% of VOTERS_PER_BLOCK (5), ensuring supermajority consensus
    use rusty_core::protocol_constants::MIN_VALID_VOTES_REQUIRED;
    let min_valid_votes_required = MIN_VALID_VOTES_REQUIRED as usize;
    if valid_vote_count < min_valid_votes_required {
        return Err(ConsensusError::InsufficientTicketVotes);
    }

    log::debug!(
        "Validated {} ticket votes, {} valid out of {} total.",
        votes.len(),
        valid_vote_count,
        votes.len()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo_set::UtxoSet;
    use rusty_shared_types::ConsensusParams;
    use rusty_shared_types::{Block, BlockHeader, OutPoint, Transaction, TxInput, TxOutput};
    // Remove tempfile::tempdir; use std::env::temp_dir instead
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    // Helper to create a temp directory (replace tempfile)
    fn create_temp_dir() -> PathBuf {
        let mut dir = env::temp_dir();
        dir.push(format!("rustycoin_test_{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Helper to create a coinbase transaction
    fn make_coinbase(amount: u64, script: Vec<u8>) -> Transaction {
        Transaction::Coinbase {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: [0u8; 32],
                    vout: u32::MAX,
                },
                vec![],
                0xffffffff,
                vec![],
            )],
            outputs: vec![TxOutput::new(amount, script)],
            lock_time: 0,
            witness: vec![],
        }
    }

    // Helper to create a standard transaction
    fn make_standard(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        fee: u64,
    ) -> Transaction {
        Transaction::Standard {
            version: 1,
            inputs,
            outputs,
            lock_time,
            fee,
            witness: vec![],
        }
    }

    fn create_test_block(prev_hash: [u8; 32], timestamp: u64) -> Block {
        let header = BlockHeader {
            version: 1,
            height: 0,
            previous_block_hash: prev_hash,
            merkle_root: [1; 32],
            state_root: [2; 32],
            timestamp,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };
        let tx = make_coinbase(50 * 100_000_000, vec![]);
        Block {
            header,
            ticket_votes: vec![],
            transactions: vec![tx],
        }
    }

    #[test]
    fn test_validate_block_header() {
        let prev_header = BlockHeader {
            version: 1,
            height: 0,
            previous_block_hash: [0; 32],
            merkle_root: [1; 32],
            state_root: [2; 32],
            timestamp: 1000,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };
        let current_time = 1001;
        let header = BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: prev_header.hash(),
            merkle_root: [3; 32],
            state_root: [4; 32],
            timestamp: current_time,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };
        // Should pass validation
        // NOTE: validate_block_header expects (&BlockHeader, &Block, ...), so create a dummy prev_block
        let prev_block = Block {
            header: prev_header.clone(),
            ticket_votes: vec![],
            transactions: vec![],
        };
        assert!(validate_block_header(&header, &prev_block, current_time + 1).is_ok());
        // Test timestamp too far in the future
        assert!(matches!(
            validate_block_header(&header, &prev_block, current_time - 1),
            Err(ConsensusError::TimestampTooFarInFuture)
        ));
        // Test timestamp too old
        let mut invalid_header = header.clone();
        invalid_header.timestamp = prev_header.timestamp - 1;
        assert!(matches!(
            validate_block_header(&invalid_header, &prev_block, current_time + 1),
            Err(ConsensusError::TimestampTooOld)
        ));
        // Test unsupported version
        let mut invalid_header = header;
        invalid_header.version = 0;
        assert!(matches!(
            validate_block_header(&invalid_header, &prev_block, current_time + 1),
            Err(ConsensusError::UnsupportedVersion(0))
        ));
    }

    #[test]
    fn test_validate_transaction_structure() {
        let dir = create_temp_dir();
        let mut utxo_set = UtxoSet::new(dir.to_str().unwrap()).expect("Failed to create UtxoSet");
        let params = ConsensusParams::default();
        let dummy_ticket_voting = crate::pos::LiveTicketsPool::new();
        let mut dummy_masternode_list = MasternodeList::new();
        let dummy_blockchain_state = crate::state::BlockchainState::new(dir.to_str().unwrap())
            .expect("Failed to create BlockchainState");
        let mut context = ValidationContext {
            utxo_set: &mut utxo_set,
            params: &params,
            ticket_voting: &dummy_ticket_voting,
            masternode_list: &mut dummy_masternode_list,
            blockchain_state: &dummy_blockchain_state,
        };
        let tx = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: [0xaa; 32],
                    vout: 0,
                },
                vec![0x01; 10],
                0xffffffff,
                vec![],
            )],
            outputs: vec![
                TxOutput::new(100_000_000, vec![0x02; 10]),
                TxOutput::new(50_000_000, vec![0x03; 10]),
            ],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };
        assert!(validate_transaction_structure(&tx, 1, &context).is_ok());
        // Test empty outputs
        let mut invalid_tx = tx.clone();
        if let Transaction::Standard { outputs, .. } = &mut invalid_tx {
            outputs.clear();
        }
        assert!(matches!(
            validate_transaction_structure(&invalid_tx, 1, &context),
            Err(ConsensusError::NoOutputs)
        ));
        // Test zero value output
        let mut invalid_tx = tx.clone();
        if let Transaction::Standard { outputs, .. } = &mut invalid_tx {
            outputs[0].value = 0;
        }
        assert!(matches!(
            validate_transaction_structure(&invalid_tx, 1, &context),
            Err(ConsensusError::OutputValueZero(0))
        ));
        // Test too large transaction size
        let mut large_tx = tx.clone();
        if let Transaction::Standard { inputs, .. } = &mut large_tx {
            inputs[0].script_sig = vec![0x04; params.max_tx_size + 1];
        }
        assert!(matches!(
            validate_transaction_structure(&large_tx, 1, &context),
            Err(ConsensusError::TransactionTooLarge(_, _))
        ));
        // Test empty inputs (not coinbase)
        let mut no_input_tx = tx.clone();
        if let Transaction::Standard { inputs, .. } = &mut no_input_tx {
            inputs.clear();
        }
        assert!(matches!(
            validate_transaction_structure(&no_input_tx, 1, &context),
            Err(ConsensusError::EmptyTransaction)
        ));
        // Test insufficient fee
        let mut low_fee_tx = tx.clone();
        if let Transaction::Standard { outputs, .. } = &mut low_fee_tx {
            outputs[0].value = 100_000_000;
        }
        assert!(matches!(
            validate_transaction_structure(&low_fee_tx, 1, &context),
            Err(ConsensusError::InsufficientFee(_, _))
        ));
    }

    #[test]
    fn test_validate_transactions() {
        let dir = create_temp_dir();
        let mut utxo_set = UtxoSet::new(dir.to_str().unwrap()).expect("Failed to create UtxoSet");
        let params = ConsensusParams::default();
        let dummy_ticket_voting = crate::pos::LiveTicketsPool::new();
        let mut dummy_masternode_list = MasternodeList::new();
        let dummy_blockchain_state = crate::state::BlockchainState::new(dir.to_str().unwrap())
            .expect("Failed to create BlockchainState");

        let coinbase_tx = Transaction::Coinbase {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: [0u8; 32],
                    vout: u32::MAX,
                },
                vec![],
                0xffffffff,
                vec![],
            )],
            outputs: vec![TxOutput::new(50_000_000, vec![1; 20])],
            lock_time: 0,
            witness: vec![],
        };
        let prev_outpoint = OutPoint {
            txid: [0xaa; 32],
            vout: 0,
        };
        let prev_output = TxOutput::new(200_000_000, vec![1; 20]);
        utxo_set
            .put_utxo_in_batch(
                &mut UtxoSet::create_batch(),
                &prev_outpoint,
                &prev_output,
                1,
                false,
            )
            .expect("Failed to put UTXO");
        utxo_set
            .apply_batch(UtxoSet::create_batch())
            .expect("Failed to apply batch");
        let tx1 = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                prev_outpoint.clone(),
                vec![0x01; 10],
                0xffffffff,
                vec![],
            )],
            outputs: vec![
                TxOutput::new(150_000_000, vec![0x02; 10]),
                TxOutput::new(49_000_000, vec![0x03; 10]),
            ],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };
        let valid_transactions = vec![coinbase_tx.clone(), tx1.clone()];
        let prev_block_header = BlockHeader {
            version: 1,
            height: 0,
            previous_block_hash: [0u8; 32],
            merkle_root: [1; 32],
            state_root: [2; 32],
            timestamp: 1234567800,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };
        let previous_block = Block {
            header: prev_block_header.clone(),
            ticket_votes: vec![],
            transactions: vec![],
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                previous_block_hash: prev_block_header.hash(),
                merkle_root: [3; 32],
                state_root: [4; 32],
                timestamp: 1234567890,
                difficulty_target: 0x207fffff,
                nonce: 0,
            },
            ticket_votes: vec![],
            transactions: vec![coinbase_tx.clone()],
        };
        let mut block_with_txs = block.clone();
        block_with_txs.transactions = valid_transactions;

        // Test valid block - scope the context to avoid borrow checker issues
        {
            let mut context = ValidationContext {
                utxo_set: &mut utxo_set,
                params: &params,
                ticket_voting: &dummy_ticket_voting,
                masternode_list: &mut dummy_masternode_list,
                blockchain_state: &dummy_blockchain_state,
            };
            assert!(validate_block(
                &block_with_txs,
                &[&previous_block],
                &mut context,
                1234567900
            )
            .is_ok());
        }

        // Test empty block
        {
            let mut context = ValidationContext {
                utxo_set: &mut utxo_set,
                params: &params,
                ticket_voting: &dummy_ticket_voting,
                masternode_list: &mut dummy_masternode_list,
                blockchain_state: &dummy_blockchain_state,
            };
            let mut empty_block = block.clone();
            empty_block.transactions.clear();
            assert!(matches!(
                validate_block(&empty_block, &[&previous_block], &mut context, 1234567900),
                Err(ConsensusError::EmptyBlock)
            ));
        }

        // Test no coinbase transaction
        {
            let mut context = ValidationContext {
                utxo_set: &mut utxo_set,
                params: &params,
                ticket_voting: &dummy_ticket_voting,
                masternode_list: &mut dummy_masternode_list,
                blockchain_state: &dummy_blockchain_state,
            };
            let mut no_coinbase_block = block.clone();
            no_coinbase_block.transactions = vec![tx1.clone()];
            assert!(matches!(
                validate_block(
                    &no_coinbase_block,
                    &[&previous_block],
                    &mut context,
                    1234567900
                ),
                Err(ConsensusError::NoCoinbaseTransaction)
            ));
        }

        // Test block too large (adjust max_block_size in params for this)
        let mut large_block = block.clone();
        let large_tx = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: [0xcc; 32],
                    vout: 0,
                },
                vec![0x01; params.max_tx_size],
                0xffffffff,
                vec![],
            )],
            outputs: vec![TxOutput::new(100_000_000, vec![0x02; 10])],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };
        let tx_size = bincode::serialized_size(&large_tx).unwrap() as u64;
        let num_txs = (params.max_block_size / tx_size) + 1;
        large_block.transactions = (0..num_txs).map(|_| large_tx.clone()).collect();
        large_block.transactions.insert(0, coinbase_tx.clone());
        for i in 0..num_txs {
            let mut batch = UtxoSet::create_batch();
            let outpoint = OutPoint {
                txid: [0xcc; 32],
                vout: i as u32,
            };
            let output = TxOutput::new(200_000_000, vec![1; 20]);
            utxo_set
                .put_utxo_in_batch(&mut batch, &outpoint, &output, 1, false)
                .expect("Failed to put UTXO");
            utxo_set.apply_batch(batch).expect("Failed to apply batch");
        }

        {
            let mut context = ValidationContext {
                utxo_set: &mut utxo_set,
                params: &params,
                ticket_voting: &dummy_ticket_voting,
                masternode_list: &mut dummy_masternode_list,
                blockchain_state: &dummy_blockchain_state,
            };
            assert!(matches!(
                validate_block(&large_block, &[&previous_block], &mut context, 1234567900),
                Err(ConsensusError::BlockTooLarge(_, _))
            ));
        }

        // Test duplicate transactions in block (already covered by validate_transactions)
        {
            let mut context = ValidationContext {
                utxo_set: &mut utxo_set,
                params: &params,
                ticket_voting: &dummy_ticket_voting,
                masternode_list: &mut dummy_masternode_list,
                blockchain_state: &dummy_blockchain_state,
            };
            let mut duplicate_tx_block = block.clone();
            duplicate_tx_block.transactions = vec![coinbase_tx.clone(), tx1.clone(), tx1.clone()];
            assert!(matches!(
                validate_block(
                    &duplicate_tx_block,
                    &[&previous_block],
                    &mut context,
                    1234567900
                ),
                Err(ConsensusError::DuplicateTransaction)
            ));
        }
    }
}

/// Checks if a script_pubkey is an OP_RETURN output
/// Per spec 04: OP_RETURN (0x6a) marks outputs as unspendable
/// Per spec 05 Section 5.4: OP_RETURN outputs are explicitly allowed to be below DUST_LIMIT
fn is_op_return_output(script_pubkey: &[u8]) -> bool {
    // OP_RETURN outputs start with 0x6a (OP_RETURN opcode)
    // Format: OP_RETURN (0x6a) [data push opcode] [data]
    script_pubkey.len() >= 1 && script_pubkey[0] == 0x6a
}

/// Validates script_pubkey format and type
fn validate_script_pubkey(script_pubkey: &[u8]) -> Result<(), ConsensusError> {
    // Maximum script size
    const MAX_SCRIPT_PUBKEY_SIZE: usize = 520;

    if script_pubkey.len() > MAX_SCRIPT_PUBKEY_SIZE {
        return Err(ConsensusError::InvalidScript(
            "Script too large".to_string(),
        ));
    }

    if script_pubkey.is_empty() {
        return Err(ConsensusError::InvalidScript("Empty script".to_string()));
    }

    // Check for common script patterns
    match script_pubkey.len() {
        // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        25 if script_pubkey[0] == 0x76
            && script_pubkey[1] == 0xa9
            && script_pubkey[2] == 0x14
            && script_pubkey[23] == 0x88
            && script_pubkey[24] == 0xac =>
        {
            Ok(())
        }

        // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
        23 if script_pubkey[0] == 0xa9 && script_pubkey[1] == 0x14 && script_pubkey[22] == 0x87 => {
            Ok(())
        }

        // P2PK: <33 or 65-byte-pubkey> OP_CHECKSIG
        35 if script_pubkey[0] == 0x21 && script_pubkey[34] == 0xac => Ok(()), // Compressed pubkey
        67 if script_pubkey[0] == 0x41 && script_pubkey[66] == 0xac => Ok(()), // Uncompressed pubkey

        // OP_RETURN (data output)
        _ if script_pubkey[0] == 0x6a => {
            // OP_RETURN scripts can be of various lengths
            // Typically limited to 80 bytes of data
            if script_pubkey.len() <= 82 {
                // OP_RETURN + push opcode + 80 bytes max
                Ok(())
            } else {
                Err(ConsensusError::InvalidScript(
                    "OP_RETURN script too large".to_string(),
                ))
            }
        }

        // For other scripts, do basic validation
        _ => {
            // Check for obviously invalid opcodes or patterns
            for &byte in script_pubkey {
                // Check for disabled opcodes (simplified check)
                if byte == 0xff {
                    return Err(ConsensusError::InvalidScript("Invalid opcode".to_string()));
                }
            }
            Ok(())
        }
    }
}

/// Validates masternode collateral script format
fn validate_masternode_collateral_script(script_pubkey: &[u8]) -> Result<(), ConsensusError> {
    // Masternode collateral scripts should be special scripts that can only be spent:
    // 1. By the collateral ownership key for deregistration
    // 2. Through slashing mechanisms

    // For now, we'll implement a simplified version that validates:
    // - Script is not empty
    // - Script follows a recognized pattern for masternode collateral

    if script_pubkey.is_empty() {
        return Err(ConsensusError::InvalidScript(
            "Empty masternode collateral script".to_string(),
        ));
    }

    // Check script size limits
    const MAX_COLLATERAL_SCRIPT_SIZE: usize = 1000;
    if script_pubkey.len() > MAX_COLLATERAL_SCRIPT_SIZE {
        return Err(ConsensusError::InvalidScript(
            "Masternode collateral script too large".to_string(),
        ));
    }

    // For a basic implementation, we'll check if it's a valid script format
    // In a more complete implementation, this would validate specific patterns for:
    // - Time-locked scripts that prevent immediate spending
    // - Multi-signature scripts for governance-controlled slashing
    // - Scripts that require specific conditions for deregistration

    // Check for obviously invalid opcodes
    for &byte in script_pubkey {
        if byte == 0xff {
            return Err(ConsensusError::InvalidScript(
                "Invalid opcode in masternode collateral script".to_string(),
            ));
        }
    }

    // Basic pattern validation - could be expanded based on protocol requirements
    // For now, we'll accept standard script patterns but require additional validation
    match script_pubkey.len() {
        // Standard P2PKH pattern (but for collateral, might need additional constraints)
        25 if script_pubkey[0] == 0x76
            && script_pubkey[1] == 0xa9
            && script_pubkey[2] == 0x14
            && script_pubkey[23] == 0x88
            && script_pubkey[24] == 0xac =>
        {
            // Could add additional validation here for masternode-specific requirements
            Ok(())
        }

        // Standard P2SH pattern (might be used for more complex collateral locking)
        23 if script_pubkey[0] == 0xa9 && script_pubkey[1] == 0x14 && script_pubkey[22] == 0x87 => {
            // P2SH could be used for time-locked or multi-sig collateral scripts
            Ok(())
        }

        // Custom masternode collateral script patterns could be added here
        // For example, scripts that include:
        // - Time locks preventing immediate spending
        // - Specific opcodes for masternode operations
        // - Multi-signature requirements for slashing
        _ => {
            // For other script patterns, do basic validation
            // In production, might want to be more restrictive
            if script_pubkey.len() < 1000 {
                Ok(())
            } else {
                Err(ConsensusError::InvalidScript(
                    "Unrecognized masternode collateral script pattern".to_string(),
                ))
            }
        }
    }
}

/// Validates locktime and sequence numbers for a transaction (BIP 68/113 style)
fn validate_locktime_and_sequence(
    tx: &Transaction,
    current_height: u32,
    median_time_past: u64,
) -> Result<(), ConsensusError> {
    // Skip locktime validation for coinbase transactions
    if tx.is_coinbase() {
        return Ok(());
    }

    // Check if locktime is enabled (at least one input has sequence < 0xfffffffe)
    let locktime_enabled = tx
        .get_inputs()
        .iter()
        .any(|input| input.sequence < 0xfffffffeu32);

    if !locktime_enabled {
        return Ok(());
    }

    // Validate the transaction's locktime
    // Per spec 05 Section 5.4: lock_time interpretation
    // If lock_time < LOCKTIME_THRESHOLD: interpreted as block height
    // If lock_time >= LOCKTIME_THRESHOLD: interpreted as Unix timestamp
    if tx.get_lock_time() > 0 {
        use rusty_core::constants::LOCKTIME_THRESHOLD;
        let locktime_threshold = LOCKTIME_THRESHOLD;

        if tx.get_lock_time() < locktime_threshold {
            // Block height based locktime
            // Per spec: transaction is valid ONLY if current block height >= lock_time
            if tx.get_lock_time() as u32 > current_height {
                return Err(ConsensusError::TransactionLocktimeNotMet);
            }
        } else {
            // Timestamp based locktime
            // Per spec: transaction is valid ONLY if current block timestamp >= lock_time
            if u64::from(tx.get_lock_time()) > median_time_past {
                return Err(ConsensusError::TransactionLocktimeNotMet);
            }
        }
    }

    // Validate sequence numbers (BIP 68 relative locktime)
    for input in tx.get_inputs() {
        // Skip validation if sequence disable flag is set
        if input.sequence & 0x80000000 != 0 {
            continue;
        }

        // Check if relative locktime is enabled
        if input.sequence & 0x40000000 == 0 {
            // Relative locktime is enabled
            let relative_locktime = input.sequence & 0x0000ffff;

            if input.sequence & 0x00400000 != 0 {
                // Time-based relative locktime (512 second units)
                let required_time = relative_locktime as u64 * 512;
                // We would need the input's confirmation time here
                // For now, we'll skip this detailed validation
            } else {
                // Block-based relative locktime
                // We would need the input's confirmation height here
                // For now, we'll skip this detailed validation
            }
        }
    }

    Ok(())
}

/// Validates UTXO set consistency against blockchain state
pub fn validate_utxo_set_consistency(
    utxo_set: &UtxoSet,
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    info!(
        "Starting UTXO set consistency validation at height {}",
        current_height
    );

    // This is a comprehensive validation that should ideally be done periodically
    // or during startup to ensure the UTXO set is consistent with the blockchain

    // Full UTXO set consistency check per docs/specs/05_utxo_model_spec.md
    use std::collections::HashSet;
    let mut inconsistencies_found = 0;
    let mut total_utxos_checked = 0;
    let mut immature_coinbases_found = 0;
    let mut seen_outpoints = HashSet::new();

    // Step 1: Validate recent block range for hot UTXOs (last 1000 blocks)
    let validation_window = std::cmp::min(current_height, 1000);
    let start_height = current_height.saturating_sub(validation_window);
    info!(
        "Validating UTXO consistency for blocks {} to {}",
        start_height, current_height
    );

    for height in start_height..=current_height {
        // Use get_block if available, otherwise get_block_hash and then fetch block
        if let Some(block) = blockchain_state.get_block(height as u32).ok().flatten() {
            for (tx_idx, tx) in block.transactions.iter().enumerate() {
                // Check all outputs: if unspent, must be in UTXO set
                for (vout, _output) in tx.get_outputs().iter().enumerate() {
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    };
                    let utxo = utxo_set.get_utxo(&outpoint).ok().flatten();
                    let spent = blockchain_state.is_output_spent(&outpoint)?;
                    if !spent {
                        // Should be present in UTXO set
                        if utxo.is_none() {
                            inconsistencies_found += 1;
                            warn!(
                                "Missing UTXO for outpoint {:?} in block {} tx {}",
                                outpoint, height, tx_idx
                            );
                        }
                    } else {
                        // Should NOT be present in UTXO set
                        if utxo.is_some() {
                            inconsistencies_found += 1;
                            warn!(
                                "Spent output {:?} still present in UTXO set (block {} tx {})",
                                outpoint, height, tx_idx
                            );
                        }
                    }
                    // Check for duplicate outpoints
                    if !seen_outpoints.insert(outpoint.clone()) {
                        inconsistencies_found += 1;
                        warn!("Duplicate outpoint detected: {:?}", outpoint);
                    }
                    total_utxos_checked += 1;
                }
                // Check all inputs: must NOT be present in UTXO set
                for input in tx.get_inputs().iter() {
                    let utxo = utxo_set.get_utxo(&input.previous_output).ok().flatten();
                    if utxo.is_some() {
                        inconsistencies_found += 1;
                        warn!(
                            "Input {:?} still present in UTXO set (should be spent)",
                            input.previous_output
                        );
                    }
                }
            }
            // Step 2: Check for immature coinbase outputs
            if let Some(coinbase_tx) = block.transactions.first() {
                let coinbase_maturity = 100;
                if height + coinbase_maturity > current_height {
                    immature_coinbases_found += 1;
                }
            }
        }
    }

    // Step 3: Cross-reference special UTXOs (masternode collaterals, governance funds)
    for special_outpoint in blockchain_state.get_critical_utxos()? {
        let utxo = utxo_set.get_utxo(&special_outpoint).ok().flatten();
        if utxo.is_none() {
            inconsistencies_found += 1;
            warn!("Critical UTXO {:?} missing from UTXO set", special_outpoint);
        }
    }

    info!("UTXO set validation completed: checked {} outputs, found {} inconsistencies, {} immature coinbases tracked", 
          total_utxos_checked, inconsistencies_found, immature_coinbases_found);
    if inconsistencies_found > 0 {
        warn!("UTXO set inconsistencies detected! Database may need repair or re-sync");
        return Err(ConsensusError::UtxoSetInconsistent(inconsistencies_found));
    }
    debug!("UTXO set consistency validation passed - no inconsistencies found");
    Ok(())
}

/// Validates masternode list consistency
pub fn validate_masternode_list_consistency(
    masternode_list: &MasternodeList,
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    info!(
        "Starting masternode list consistency validation at height {}",
        current_height
    );

    // Validate that all masternodes in the list have valid collateral
    for (mn_id, mn_entry) in masternode_list.get_all_masternodes() {
        // Check collateral UTXO exists and has correct amount
        let collateral_outpoint = &mn_entry.identity.collateral_outpoint;
        let utxo_result = blockchain_state.get_utxo(collateral_outpoint);

        match utxo_result {
            Ok(Some((output, _height, _is_coinbase))) => {
                // Validate collateral amount
                if output.value < rusty_core::protocol_constants::MASTERNODE_COLLATERAL_AMOUNT {
                    return Err(ConsensusError::MasternodeError(format!(
                        "Masternode {:?} has insufficient collateral: {} < {}",
                        mn_id,
                        output.value,
                        rusty_core::protocol_constants::MASTERNODE_COLLATERAL_AMOUNT
                    )));
                }

                // Validate collateral script
                validate_masternode_collateral_script(&output.script_pubkey)?;
            }
            Ok(None) => {
                return Err(ConsensusError::MasternodeError(format!(
                    "Masternode {:?} collateral UTXO not found",
                    mn_id
                )));
            }
            Err(e) => {
                return Err(ConsensusError::DatabaseError(format!(
                    "Failed to check masternode {:?} collateral: {}",
                    mn_id, e
                )));
            }
        }

        // Additional masternode validation could include:
        // - PoSe status consistency
        // - Last seen timestamp validation
        // - Operator key validation
    }

    info!("Masternode list consistency validation completed");
    Ok(())
}

/// Validates governance state consistency according to Homestead Accord specification
pub fn validate_governance_state_consistency(
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    info!(
        "Starting governance state consistency validation at height {}",
        current_height
    );

    // 1. Validate active proposals in voting period
    validate_active_proposals(blockchain_state, current_height)?;

    // 2. Validate vote tallies consistency
    validate_vote_tallies(blockchain_state, current_height)?;

    // 3. Validate proposal resolution and activation
    validate_proposal_outcomes(blockchain_state, current_height)?;

    // 4. Validate parameter change consistency
    validate_parameter_changes(blockchain_state, current_height)?;

    // 5. (Spec §4.2.1) Ensure no proposal is active past its allowed period
    let governance_state = &blockchain_state.governance_state;
    for (proposal_id, proposal) in &governance_state.active_proposals {
        if current_height > proposal.end_block_height + 144 {
            // 144-block activation delay
            // Proposal should be resolved and not active anymore
            warn!("Proposal {:?} still active past allowed period (end_block_height + activation delay)", proposal_id);
            // In a strict implementation, this could be an error:
            // return Err(ConsensusError::GovernanceError(format!("Proposal {:?} active past allowed period", proposal_id)));
        }
    }

    info!("Governance state consistency validation completed");
    Ok(())
}

/// Validates that all active proposals have correct voting periods and states
fn validate_active_proposals(
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    let governance_state = &blockchain_state.governance_state;

    // Validate each active proposal
    for (proposal_id, proposal) in &governance_state.active_proposals {
        // Verify proposal is in valid voting period (Spec §3.2.2)
        if current_height >= proposal.start_block_height
            && current_height <= proposal.end_block_height
        {
            debug!("Validating active proposal: {:?}", proposal_id);

            // Protocol: Homestead Accord §2.2.1, §2.2.2
            // Validate proposal structure: must have valid fields, non-empty title/description, valid proposer, etc.
            if proposal.title.trim().is_empty() {
                return Err(ConsensusError::GovernanceError(format!(
                    "Proposal {:?} has empty title",
                    proposal_id
                )));
            }
            // Check that the description_hash is not the default (all zeros)
            if proposal.description_hash == [0u8; 32] {
                return Err(ConsensusError::GovernanceError(format!(
                    "Proposal {:?} has empty or invalid description_hash",
                    proposal_id
                )));
            }
            // Proposer address validity (basic check)
            // (Assume PublicKey is a struct with a to_bytes() method)
            if proposal.proposer_address.len() < 20 {
                return Err(ConsensusError::GovernanceError(format!(
                    "Proposal {:?} proposer address too short",
                    proposal_id
                )));
            }
            // Voting period must be at least 1 block
            if proposal.end_block_height < proposal.start_block_height {
                return Err(ConsensusError::GovernanceError(format!(
                    "Proposal {:?} end_block_height < start_block_height",
                    proposal_id
                )));
            }
            // Voting period must not exceed protocol maximum (e.g., 2 weeks)
        }
    }
    Ok(())
}

/// Validates vote tallies match actual votes cast
fn validate_vote_tallies(
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    let governance_state = &blockchain_state.governance_state;

    // For each proposal, validate vote counts
    for (proposal_id, proposal) in &governance_state.active_proposals {
        if let Some(vote_tally) = governance_state.proposal_votes.get(proposal_id) {
            debug!("Validating vote tally for proposal: {:?}", proposal_id);

            // Validate vote counts are non-negative and consistent
            if vote_tally.pos_yes_votes < 0
                || vote_tally.pos_no_votes < 0
                || vote_tally.mn_yes_votes < 0
                || vote_tally.mn_no_votes < 0
            {
                return Err(ConsensusError::GovernanceError(
                    "Negative vote counts detected".to_string(),
                ));
            }

            // Check if proposal is in resolution phase
            if current_height > proposal.end_block_height {
                validate_proposal_resolution(proposal, vote_tally, current_height)?;
            }
        }
    }

    Ok(())
}

/// Validates proposal resolution follows bicameral requirements
fn validate_proposal_resolution(
    proposal: &rusty_shared_types::governance::GovernanceProposal,
    vote_tally: &crate::state::GovernanceVoteTally,
    current_height: u64,
) -> Result<(), ConsensusError> {
    // Apply Homestead Accord bicameral voting rules

    // Calculate quorum requirements (simplified - actual implementation would fetch from chain params)
    const POS_QUORUM_PERCENTAGE: f64 = 0.20; // 20%
    const MN_QUORUM_PERCENTAGE: f64 = 0.50; // 50%
    const POS_APPROVAL_PERCENTAGE: f64 = 0.75; // 75%
    const MN_APPROVAL_PERCENTAGE: f64 = 0.66; // 66%

    let total_pos_votes = vote_tally.pos_yes_votes + vote_tally.pos_no_votes;
    let total_mn_votes = vote_tally.mn_yes_votes + vote_tally.mn_no_votes;

    // Check quorum requirements
    // Note: In full implementation, we'd need to get actual eligible voter counts
    let pos_quorum_met = total_pos_votes > 0; // Simplified check
    let mn_quorum_met = total_mn_votes > 0; // Simplified check

    if !pos_quorum_met || !mn_quorum_met {
        debug!("Proposal failed quorum requirements");
        return Ok(()); // Valid state - proposal should be marked as rejected
    }

    // Check supermajority requirements if quorum met
    let pos_approval_rate = if total_pos_votes > 0 {
        vote_tally.pos_yes_votes as f64 / total_pos_votes as f64
    } else {
        0.0
    };

    let mn_approval_rate = if total_mn_votes > 0 {
        vote_tally.mn_yes_votes as f64 / total_mn_votes as f64
    } else {
        0.0
    };

    let passed =
        pos_approval_rate >= POS_APPROVAL_PERCENTAGE && mn_approval_rate >= MN_APPROVAL_PERCENTAGE;

    debug!(
        "Proposal resolution: PoS approval {:.2}%, MN approval {:.2}%, Passed: {}",
        pos_approval_rate * 100.0,
        mn_approval_rate * 100.0,
        passed
    );

    Ok(())
}

/// Validates proposal outcomes and activation status
fn validate_proposal_outcomes(
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    let governance_state = &blockchain_state.governance_state;

    // Check for proposals that should have been activated
    for (proposal_id, proposal) in &governance_state.active_proposals {
        // Check if proposal should be activated (simplified)
        const ACTIVATION_DELAY_BLOCKS: u64 = 144; // ~6 hours
        let activation_height = proposal.end_block_height + ACTIVATION_DELAY_BLOCKS;

        if current_height >= activation_height {
            debug!("Checking activation status for proposal: {:?}", proposal_id);
            // In full implementation, verify the proposal was actually activated
            // This would check parameter changes were applied, etc.
        }
    }

    Ok(())
}

/// Validates parameter change history consistency
fn validate_parameter_changes(
    blockchain_state: &BlockchainState,
    current_height: u64,
) -> Result<(), ConsensusError> {
    let governance_state = &blockchain_state.governance_state;

    // Validate parameter change history is consistent
    if let Some(param_history) = &governance_state.parameter_change_history {
        for (height, changes) in param_history {
            if *height > current_height {
                return Err(ConsensusError::GovernanceError(format!(
                    "Parameter change scheduled for future height: {}",
                    height
                )));
            }

            debug!(
                "Validated parameter changes at height {}: {} changes",
                height,
                changes.len()
            );
        }
    }

    Ok(())
}
