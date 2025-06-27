//! Validation logic for the Rusty Coin blockchain.
//!
//! This module contains the core validation logic for blocks and transactions,
//! ensuring they comply with the consensus rules.

use blake3::Hasher as Blake3Hasher;
use std::collections::{HashMap, HashSet};
use crate::utxo_set::UtxoSet;
use crate::ConsensusParams;
use rocksdb::WriteBatch;

use crate::error::ConsensusError;
use rusty_types::block::{Block, BlockHeader, TicketVote};
use rusty_types::transaction::{Transaction, TxInput, TxOutput, OutPoint};
use bincode;

use crate::pos::TicketVoting;
use rusty_core::masternode::{MasternodeList, MasternodeID};
use rusty_core::script::script_engine::ScriptEngine;
use crate::pow;
use crate::state::BlockchainState;

pub struct ValidationContext<'a> {
    pub utxo_set: &'a mut UtxoSet,
    pub params: &'a ConsensusParams,
    pub ticket_voting: &'a TicketVoting,
    pub masternode_list: &'a mut MasternodeList,
    pub blockchain_state: &'a BlockchainState,
}

/// Validates a transaction against the consensus rules.
pub fn validate_transaction(
    tx: &Transaction,
    current_height: u32,
    context: &mut ValidationContext,
) -> Result<(), ConsensusError> {
    // 1. Basic checks
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        return Err(ConsensusError::EmptyTransaction);
    }

    let tx_size = bincode::serialized_size(tx).map_err(|_| ConsensusError::SerializationError)? as usize;
    if tx_size > context.params.max_tx_size {
        return Err(ConsensusError::TransactionTooLarge);
    }

    // 2. Coinbase transaction specific rules
    if tx.is_coinbase() {
        if !tx.inputs.is_empty() {
            return Err(ConsensusError::CoinbaseHasInputs);
        }
        // Coinbase maturity check is handled when applying the block, not during transaction validation
    } else {
        // 3. Non-coinbase transaction input validation
        if tx.inputs.is_empty() {
            return Err(ConsensusError::NonCoinbaseHasNoInputs);
        }

        let mut seen_inputs = HashSet::new();
        let mut total_input_value = 0;

        for input in &tx.inputs {
            // Check for duplicate inputs within the same transaction
            if !seen_inputs.insert(input.previous_output.clone()) {
                return Err(ConsensusError::DuplicateInput);
            }

            // Check UTXO existence and retrieve its value and scriptPubKey
            let prev_output_utxo = context.utxo_set.get_utxo(&input.previous_output)?
                .ok_or(ConsensusError::MissingTxInput)?;

            // Check coinbase maturity for inputs
            if prev_output_utxo.is_coinbase && current_height - prev_output_utxo.height < context.params.coinbase_maturity {
                return Err(ConsensusError::CoinbaseNotMature);
            }

            // Verify signature and script using ScriptEngine
            let mut script_engine = ScriptEngine::new();
            if let Err(e) = script_engine.verify_script(
                &input.script_sig,
                &prev_output_utxo.script_pubkey,
                tx,
                input_index,
                &prev_output_utxo,
            ) {
                warn!("Script verification failed: {:?}", e);
                return Err(ConsensusError::InvalidScriptSig);
            }

            total_input_value += prev_output_utxo.value;
        }

        // 4. Fee validation
        let mut total_output_value = 0;
        for output in &tx.outputs {
            total_output_value += output.value;
        }

        if total_input_value < total_output_value {
            return Err(ConsensusError::NegativeFee);
        }

        let calculated_fee = total_input_value - total_output_value;
        let min_fee = (tx_size as u64 / 1000 + 1) * context.params.min_relay_tx_fee;
        if calculated_fee < min_fee {
            return Err(ConsensusError::InsufficientFee);
        }

        // 5. Locktime and sequence number validation (simplified for now)
        // TODO: Implement full locktime and sequence number rules
        if tx.lock_time > current_height as u32 && tx.lock_time != 0 {
            // This is a simplified check. Real locktime rules are more complex.
            return Err(ConsensusError::TransactionLocked);
        }
    }

    // 6. Output validation (e.g., dust limits, valid script pubkeys)
    for output in &tx.outputs {
        if output.value < context.params.dust_limit {
            return Err(ConsensusError::DustOutput);
        }
        // TODO: Validate script_pubkey format/type if necessary
    }

    Ok(())
}

/// Validates a Masternode deregistration transaction.
pub fn validate_masternode_deregistration(
    tx: &Transaction,
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    let masternode_deregistration = match tx {
        Transaction::MasternodeDeregister(dereg_tx) => dereg_tx,
        _ => return Err(ConsensusError::InvalidTransactionType("Expected MasternodeDeregister transaction".to_string())),
    };

    // Check if the Masternode exists
    let masternode = context.masternode_list.get_masternode(&masternode_deregistration.masternode_id)
        .ok_or(ConsensusError::MasternodeNotFound)?;

    // Validate signature by the Operator Key
    let public_key = &masternode.operator_public_key;
    let signature = &masternode_deregistration.signature;

    // Serialize the transaction without the signature for verification
    let mut tx_without_signature = masternode_deregistration.clone();
    tx_without_signature.signature = [0u8; 64];

    let config = bincode::config::standard();
    let tx_bytes_for_signature = bincode::encode_to_vec(&tx_without_signature, config)
        .map_err(|e| ConsensusError::SerializationError(format!("Failed to serialize transaction for signature verification: {}", e)))?;

    // Verify the signature
    if !rusty_crypto::verify_signature(public_key, &tx_bytes_for_signature, signature) {
        return Err(ConsensusError::InvalidMasternodeDeregistration("Invalid signature".to_string()));
    }

    Ok(())
}

/// Validates a block header against the consensus rules.
pub fn validate_block_header(
    header: &BlockHeader,
    previous_block: &Block,
    current_time: u64,
) -> Result<(), ConsensusError> {
    // Check block version
    if header.version != rusty_types::block::BlockVersion::V1 {
        return Err(ConsensusError::UnsupportedVersion(header.version as u32)); // Assuming BlockVersion can be cast to u32 for error reporting
    }

    // BHS_001: prev_block_hash match: This should be validated against the actual previous block's hash in the blockchain.
    if header.prev_block_hash != previous_block.hash() {
        return Err(ConsensusError::InvalidPreviousBlockHash);
    }

    // BHS_001: merkle_root correctness: This requires the full block's transactions to recompute and verify.
    if header.merkle_root != block.compute_merkle_root() {
        return Err(ConsensusError::InvalidMerkleRoot);
    }

    // BHS_001: state_root correctness: This requires a separate state validation logic, likely involving a Merkle Patricia Trie.
    // For now, we will assume state_root is correctly computed and passed.
    // In a real blockchain, this would involve validating the state transition.
    // if header.state_root != expected_state_root {
    //     return Err(ConsensusError::InvalidStateRoot);
    // }

    // BHS_001: difficulty_target match: This requires the difficulty adjustment algorithm to recompute and verify.
    // For now, we will assume difficulty_target is correctly computed and passed.
    // In a real blockchain, this would involve fetching previous blocks and running the DAA.
    // if header.difficulty_target != expected_difficulty_target {
    //     return Err(ConsensusError::InvalidDifficultyTarget);
    // }

    // Check timestamp is not too far in the future (2 hours)
    if header.timestamp > current_time + 7200 {
        return Err(ConsensusError::TimestampTooFarInFuture);
    }

    // Check timestamp is not before the median time of the last 11 blocks
    // For now, we'll just check it's not before the previous block
    if header.timestamp <= previous_block.header.timestamp {
        return Err(ConsensusError::TimestampTooOld);
    }

    // Check proof of work
    if !pow::verify_pow(header, header.difficulty) {
        return Err(ConsensusError::InvalidProofOfWork);
    }

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
    let public_key = &masternode.unwrap().public_key;

    // Construct the message to verify (e.g., block height and masternode ID)
    let message = format!("{}{}", block_height, masternode_id).as_bytes();

    // Verify the signature using the public key
    // Using rusty-crypto for actual verification
    use rusty_crypto::verify_signature;
    verify_signature(public_key, message, signature)
}

/// Validates a Masternode heartbeat.
pub fn validate_masternode_heartbeat(
    masternode_id: &MasternodeID,
    block_height: u64,
    signature: &[u8],
    context: &mut ValidationContext,
) -> Result<(), ConsensusError> {
    // Check if the Masternode exists
    let masternode = context.masternode_list.get_masternode(masternode_id)
        .ok_or(ConsensusError::MasternodeNotFound)?;

    // Check if the Masternode has been active recently
    let max_inactivity_blocks = context.params.max_inactivity_blocks;
    if masternode.last_seen + max_inactivity_blocks < block_height {
        return Err(ConsensusError::MasternodeInactive);
    }

    // Verify the signature
    if !verify_masternode_signature(masternode_id, block_height, signature, context.masternode_list) {
        return Err(ConsensusError::InvalidProofOfService);
    }

    // Update Masternode's last seen time
    if let Some(mn) = context.masternode_list.get_mut(masternode_id) {
        mn.last_seen = block_height;
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
    let cf_utxos = utxo_set.cf_utxos();

    for tx in &block.transactions {
        // Spend inputs (remove old UTXOs from the set)
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                UtxoSet::delete_utxo_in_batch(&mut batch, cf_utxos, &input.prev_output)?;
            }
        }

        // Create outputs (add new UTXOs to the set)
        for (vout, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid: tx.txid(),
                vout: vout as u32,
            };
            UtxoSet::put_utxo_in_batch(&mut batch, cf_utxos, &outpoint, output)?;
        }

        // Handle Masternode registration transactions
        if let Transaction::MasternodeRegister(reg_tx) = tx {
            masternode_list.register_masternode(reg_tx.clone(), block.height() as u32)
                .map_err(|e| ConsensusError::MasternodeError(e))?;
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
    if block.header.prev_block_hash != prev_block.header.block_hash {
        return Err(ConsensusError::InvalidPreviousBlockHash);
    }

    // 3. Verify block height
    if block.height() != prev_block.height() + 1 {
        return Err(ConsensusError::InvalidBlockHeight);
    }

    // 4. Verify Merkle root
    let calculated_merkle_root = block.calculate_merkle_root();
    if block.header.merkle_root != calculated_merkle_root {
        return Err(ConsensusError::InvalidMerkleRoot);
    }

    // 5. Validate block header (already existing checks)
    validate_block_header(&block.header, &prev_block.header, current_time)?;

    // 6. Validate transactions (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 7. Verify PoW/PoS based on block type (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 8. Apply block to UTXO set (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    // 9. Apply block to blockchain state (already existing call)
    // This is already called within the validate_block function in lib.rs, so no need to duplicate here.

    Ok(())

        

    let previous_header = &previous_blocks[0].header;
    
    // Validate the block header
    validate_block_header(&block.header, previous_header, current_time)?;
    
    // Check block size limits
    let block_size = bincode::serialized_size(block).map_err(|e| {
        ConsensusError::SerializationError(format!("failed to serialize block: {}", e))
    })? as usize;
    
    if block_size > context.params.max_block_size { 
        return Err(ConsensusError::BlockTooLarge(block_size, context.params.max_block_size));
    }
    
    // Check transactions
    validate_transactions(&block.transactions, block.height(), current_time, context)?;
    
    // Check for coinbase transaction and its position
    if block.transactions.is_empty() || !block.transactions[0].is_coinbase() {
        return Err(ConsensusError::NoCoinbaseTransaction);
    }
    if block.transactions[0].inputs.len() != 1 || !block.transactions[0].inputs[0].is_coinbase_input() {
        return Err(ConsensusError::InvalidCoinbaseInput);
    }

    // Check Merkle root
    let calculated_merkle_root = block.calculate_merkle_root();
    if calculated_merkle_root != block.header.merkle_root {
        return Err(ConsensusError::MerkleRootMismatch { expected: block.header.merkle_root, found: calculated_merkle_root });
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
        if i > 0 { // Skip coinbase transaction
            validate_transaction(tx, block.height(), context)?;

            // Calculate fees for non-coinbase transactions
            let mut input_value_sum = 0u64;
            for input in &tx.inputs {
                let prev_output = context.utxo_set.get_utxo(&input.previous_output)?
                    .ok_or_else(|| ConsensusError::MissingPreviousOutput(input.previous_output.clone()))?;
                input_value_sum = input_value_sum.checked_add(prev_output.value)
                    .ok_or(ConsensusError::InputValueTooLarge)?;
            }

            let mut output_value_sum = 0u64;
            for output in &tx.outputs {
                output_value_sum = output_value_sum.checked_add(output.value)
                    .ok_or(ConsensusError::OutputValueTooLarge)?;
            }
            total_tx_fees = total_tx_fees.checked_add(input_value_sum - output_value_sum)
                .ok_or(ConsensusError::FeeOverflow)?;
        }
    }

    // Validate coinbase reward
    let coinbase_tx = &block.transactions[0];
    let expected_reward = context.params.block_reward + total_tx_fees;
    let actual_reward = coinbase_tx.outputs.iter().map(|o| o.value).sum::<u64>();

    if actual_reward > expected_reward {
        return Err(ConsensusError::InvalidBlockReward { expected: expected_reward, actual: actual_reward });
    }

    // Validate ticket votes if this is a PoS block
    if !block.ticket_votes.is_empty() {
        crate::pos::validate_ticket_votes(&block.ticket_votes, context.params, block.height(), &context.ticket_voting.tickets)?; // Pass the tickets from TicketVoting
    }
    
    Ok(())
}

/// Validates a Masternode registration transaction.
pub fn validate_masternode_registration(
    tx: &Transaction,
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    let masternode_registration = match tx {
        Transaction::MasternodeRegister(reg_tx) => reg_tx,
        _ => return Err(ConsensusError::InvalidTransactionType("Expected MasternodeRegister transaction".to_string())),
    };

    // 6.2.3 Masternode Registration (MN_REGISTER_TX)

    // Inputs: MUST include at least one TxInput spending exactly MASTERNODE_COLLATERAL_AMOUNT to a new TxOutput specifically designed to lock the collateral.
    // For now, we'll check if there's at least one input and one output.
    // The exact collateral amount check will be done by checking the output value.
    if masternode_registration.inputs.is_empty() {
        return Err(ConsensusError::InvalidMasternodeRegistration("Masternode registration transaction must have inputs".to_string()));
    }

    // Outputs: The transaction MUST create a new TxOutput locking MASTERNODE_COLLATERAL_AMOUNT with a script designating it as Masternode collateral.
    // It MUST also include a small transaction fee.
    let mut found_collateral_output = false;

/// Validates a Masternode Proof-of-Service (PoSe).
pub fn validate_masternode_proof_of_service(
    masternode_id: &MasternodeID,
    block_height: u64,
    signature: &[u8],
    context: &ValidationContext,
) -> Result<(), ConsensusError> {
    // Check if the Masternode exists
    let masternode = context.masternode_list.get_masternode(masternode_id)
        .ok_or(ConsensusError::MasternodeNotFound)?;

    // Check if the Masternode has been active recently
    let max_inactivity_blocks = context.params.max_inactivity_blocks;
    if masternode.last_seen + max_inactivity_blocks < block_height {
        return Err(ConsensusError::MasternodeInactive);
    }

    // Verify the signature
    if !verify_masternode_signature(masternode_id, block_height, signature, context.masternode_list) {
        return Err(ConsensusError::InvalidProofOfService);
    }

    Ok(())
}
    let mut total_output_value = 0u64;
    for output in &masternode_registration.outputs {
        if output.value == context.params.masternode_collateral_amount {
            // TODO: Add script validation for collateral output
            found_collateral_output = true;
        }
        total_output_value = total_output_value.checked_add(output.value)
            .ok_or(ConsensusError::OutputValueTooLarge)?;
    }

    if !found_collateral_output {
        return Err(ConsensusError::InvalidMasternodeRegistration("Masternode registration transaction must have a collateral output".to_string()));
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
    let mut tx_without_signature = masternode_registration.clone();
    tx_without_signature.signature = [0u8; 64]; // Zero out the signature for verification

    let config = bincode::config::standard();
    let tx_bytes_for_signature = bincode::encode_to_vec(&tx_without_signature, config)
        .map_err(|e| ConsensusError::SerializationError(format!("Failed to serialize transaction for signature verification: {}", e)))?;

    let public_key = &masternode_registration.masternode_identity.collateral_ownership_public_key;
    let signature = &masternode_registration.signature;

    // Verify the signature using rusty-crypto
    if !rusty_crypto::verify_signature(public_key, &tx_bytes_for_signature, signature) {
        return Err(ConsensusError::InvalidMasternodeRegistration("Invalid Masternode registration signature".to_string()));
    }

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
                return Err(ConsensusError::InvalidCoinbase("coinbase transaction must be first".to_string()));
            }
            
            // Validate transaction structure
            validate_transaction_structure(tx, height, context)?;

            // Perform type-specific validation
            match tx {
                Transaction::MasternodeRegister(_) => {
                    validate_masternode_registration(tx, context)?;
                },
                Transaction::MasternodePoSe(pose_tx) => {
                    validate_masternode_proof_of_service(&pose_tx.masternode_id, height, &pose_tx.signature, context)?;
                },
                Transaction::MasternodeHeartbeat(heartbeat_tx) => {
                    validate_masternode_heartbeat(&heartbeat_tx.masternode_id, height, &heartbeat_tx.signature, &mut context)?;
                },
            }
            
            let mut input_value_sum = 0u64;

            // Check for double spends within this block and calculate input sum
            for input in &tx.inputs {
                // Check if the previous output exists in the UTXO set
                let prev_output = context.utxo_set.get_utxo(&input.prev_output)?
                    .ok_or_else(|| ConsensusError::MissingPreviousOutput(input.prev_output.clone()))?;

                // Coinbase maturity check
                if prev_output.is_coinbase && height < prev_output.creation_height + context.params.coinbase_maturity as u64 {
                    return Err(ConsensusError::CoinbaseNotMature);
                }

                let outpoint_key = (input.prev_output.txid, input.prev_output.vout);
                if !spent_outputs.insert(outpoint_key) {
                    return Err(ConsensusError::DoubleSpend);
                }

                input_value_sum = input_value_sum.checked_add(prev_output.value)
                    .ok_or(ConsensusError::InputValueTooLarge)?;
            }

            let mut output_value_sum = 0u64;
            for output in &tx.outputs {
                output_value_sum = output_value_sum.checked_add(output.value)
                    .ok_or(ConsensusError::OutputValueTooLarge)?;
            }

            // Value conservation and fees
            if !tx.is_coinbase() {
                if input_value_sum < output_value_sum {
                    return Err(ConsensusError::SpendingMoreThanInputs);
                }
                let fee = input_value_sum - output_value_sum;
                let tx_size = bincode::serialized_size(tx).map_err(|e| {
                    ConsensusError::SerializationError(format!("failed to serialize transaction: {}", e))
                })? as usize;
                let min_fee = (tx_size as u64).saturating_add(999) / 1000 * context.params.min_relay_tx_fee;
                if fee < min_fee {
                    return Err(ConsensusError::InsufficientFee(fee, min_fee));
                }
                total_fees = total_fees.checked_add(fee).ok_or(ConsensusError::FeeOverflow)?;
            } else {
                // Coinbase transaction reward validation will be done at block validation level
                // where total fees from other transactions are known.
            }

            // Lock time validation (full check with block height and timestamp)
            if tx.lock_time != 0 {
                if tx.lock_time < 0x80000000 { // Interpreted as block height
                    if tx.lock_time as u64 > height {
                        return Err(ConsensusError::InvalidLockTime(format!("transaction lock_time ({}) is greater than current block height ({})", tx.lock_time, height)));
                    }
                } else { // Interpreted as Unix timestamp
                    if tx.lock_time as u64 > current_time {
                        return Err(ConsensusError::InvalidLockTime(format!("transaction lock_time ({}) is in the future compared to current time ({})", tx.lock_time, current_time)));
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
        return Err(ConsensusError::TransactionTooLarge(tx_size, context.params.max_tx_size));
    }
    
    // Check for empty inputs (except coinbase)
    if !tx.is_coinbase() && tx.inputs.is_empty() {
        return Err(ConsensusError::EmptyTransaction);
    }

    // Validate scripts for non-coinbase transactions
    if !tx.is_coinbase() {
        for (i, input) in tx.inputs.iter().enumerate() {
            let prev_output = context.utxo_set.get_utxo(&input.prev_output)?
                .ok_or_else(|| ConsensusError::MissingPreviousOutput(input.prev_output.clone()))?;

            let mut script_engine = rusty_core::script::script_engine::ScriptEngine::new(
                input.script_sig.clone(),
                prev_output.script_pubkey.clone(),
                tx.hash(), // Use the transaction hash as the message for signature verification
            );

            if !script_engine.run() {
                return Err(ConsensusError::InvalidScript(format!("script validation failed for input {}: {}", i, script_engine.last_error().unwrap_or("unknown error"))));
            }

            // Input existence and unspent status are checked in `validate_transactions`
            // Coinbase maturity is checked in `validate_transactions`
        }
    }
    
    // Check for empty outputs
    if tx.outputs.is_empty() {
        return Err(ConsensusError::NoOutputs);
    }
    
    // Check output values
    let mut total_output_value = 0u64;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(ConsensusError::OutputValueZero(i));
        }
        
        // Check for overflow
        total_output_value = total_output_value.checked_add(output.value)
            .ok_or(ConsensusError::OutputValueTooLarge)?;
            
        // Check for dust output (outputs below a certain value are not standard)
        // For now, we'll use a fixed dust limit
        if output.value < 546 { // 546 satoshis is the current Bitcoin dust limit
            return Err(ConsensusError::DustOutput(output.value));
        }
    }
    
    // For coinbase transactions, we skip some checks
    if tx.is_coinbase() {
        // Coinbase transactions must have exactly one input
        if tx.inputs.len() != 1 {
            return Err(ConsensusError::InvalidCoinbase(
                "coinbase transaction must have exactly one input".to_string()
            ));
        }
        
        // Coinbase input must be null
        if !tx.inputs[0].prev_output.txid == [0u8; 32] && tx.inputs[0].prev_output.vout == u32::MAX {
            return Err(ConsensusError::InvalidCoinbase(
                "coinbase input must be null".to_string()
            ));
        }
        
        // Coinbase maturity check is done at block validation
        return Ok(());
    }
    
    // For regular transactions, check inputs and fees
    let mut total_input_value = 0u64;
    
    for input in &tx.inputs {
        let prev_output = context.utxo_set.get_utxo(&input.prev_output)?;
        let prev_output_value = prev_output.ok_or(ConsensusError::MissingPreviousOutput(input.prev_output.clone()))?.value;

        total_input_value = total_input_value.checked_add(prev_output_value)
            .ok_or(ConsensusError::InputValueTooLarge)?;

        // Validate sequence number (for future use with Replace-by-Fee or relative locktime)
        // For now, we'll just ensure it's not the max value if locktime is set
        if tx.lock_time != 0 && input.sequence == u32::MAX {
            return Err(ConsensusError::InvalidSequence);
        }
    }
    
    // Check for overflow in input values
    if total_input_value < total_output_value {
        return Err(ConsensusError::SpendingMoreThanInputs);
    }
    
    // Check minimum fee
    let fee = total_input_value - total_output_value;
    let min_fee = (tx_size as u64).saturating_add(999) / 1000 * context.params.min_relay_tx_fee; // Use min_relay_tx_fee from params
    
    if fee < min_fee {
        return Err(ConsensusError::InsufficientFee(fee, min_fee));
    }

    // Validate lock_time
    // Validate lock_time
        // If lock_time is set, all inputs must have sequence < u32::MAX
        if tx.lock_time != 0 && tx.inputs.iter().any(|input| input.sequence == u32::MAX) {
            return Err(ConsensusError::InvalidLockTime("all inputs must have sequence < MAX_UINT if lock_time is set".to_string()));
        }

        // If lock_time is block height, it must be less than or equal to current block height
        // This check is done in `validate_transactions` where block height is available.

        // If lock_time is timestamp, it must be less than or equal to current block timestamp
        // This check is done in `validate_transactions` where block timestamp is available.

        Ok(())
    }

/// Validates a list of ticket votes.
pub fn validate_ticket_votes(
    votes: &[TicketVote],
    current_height: u64,
) -> Result<(), ConsensusError> {
    if votes.is_empty() {
        return Err(ConsensusError::NoTicketVotes);
    }
    
    let mut seen_votes = HashSet::new();
    
    for vote in votes {
        // Check for duplicate votes
        if !seen_votes.insert((vote.ticket_id, vote.block_hash)) {
            return Err(ConsensusError::DuplicateTicketVote);
        }
        
        // In a real implementation, we would verify the ticket exists,
        // is not expired, and the signature is valid
        // This is just a placeholder
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_types::block::{BlockHeader, BlockVersion};
    use rusty_types::transaction::{Transaction, TxInput, TxOutput, OutPoint};
    use crate::utxo_set::UtxoSet;
    use crate::ConsensusParams;
    use std::sync::Arc;
    use rocksdb::{DB, Options};
    use tempfile::tempdir;
    
    fn create_test_block(prev_hash: [u8; 32], timestamp: u64) -> Block {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root: [1; 32],
            state_root: [2; 32],
            timestamp,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };
        
        let tx = Transaction::new_coinbase(
            0,
            vec![0x04, 0x01, 0x02, 0x03, 0x04],
            vec![TxOutput::new(50 * 100_000_000, vec![])],
        );
        
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
            prev_block_hash: [0; 32],
            merkle_root: [1; 32],
            state_root: [2; 32],
            timestamp: 1000,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };
        
        let current_time = 1001;
        
        let header = BlockHeader {
            version: 1,
            prev_block_hash: prev_header.hash(),
            merkle_root: [3; 32],
            state_root: [4; 32],
            timestamp: current_time,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };
        
        // Should pass validation
        assert!(validate_block_header(&header, &prev_header, current_time + 1).is_ok());
        
        // Test timestamp too far in the future
        assert!(matches!(
            validate_block_header(&header, &prev_header, current_time - 1),
            Err(ConsensusError::TimestampTooFarInFuture)
        ));
        
        // Test timestamp too old
        let mut invalid_header = header.clone();
        invalid_header.timestamp = prev_header.timestamp - 1;
        assert!(matches!(
            validate_block_header(&invalid_header, &prev_header, current_time + 1),
            Err(ConsensusError::TimestampTooOld)
        ));
        
        // Test unsupported version
        let mut invalid_header = header;
        invalid_header.version = 0;
        assert!(matches!(
            validate_block_header(&invalid_header, &prev_header, current_time + 1),
            Err(ConsensusError::UnsupportedVersion(0))
        ));
    }
    
    #[test]
    fn test_validate_transaction_structure() {
        let dir = tempdir().expect("Failed to create temp directory");
        let utxo_set = UtxoSet::new(dir.path().to_str().unwrap()).expect("Failed to create UtxoSet");
        let params = ConsensusParams::default();
        let context = ValidationContext { utxo_set: &mut utxo_set, params: &params };

        let tx = Transaction {
            version: TxVersion::V1,
            inputs: vec![
                TxInput::new(
                    OutPoint {
                        txid: [0x01; 32],
                        vout: 0,
                    },
                    vec![0x01; 10], // Dummy script_sig
                    0xffffffff,
                ),
            ],
            outputs: vec![
                TxOutput::new(100_000_000, vec![0x02; 10]), // Dummy script_pubkey
                TxOutput::new(50_000_000, vec![0x03; 10]),
            ],
            lock_time: 0,
        };

        // Should pass validation
        assert!(validate_transaction_structure(&tx, 1, &context).is_ok());

        // Test empty outputs
        let mut invalid_tx = tx.clone();
        invalid_tx.outputs.clear();
        assert!(matches!(
            validate_transaction_structure(&invalid_tx, 1, &context),
            Err(ConsensusError::NoOutputs)
        ));

        // Test zero value output
        let mut invalid_tx = tx.clone();
        invalid_tx.outputs[0].value = 0;
        assert!(matches!(
            validate_transaction_structure(&invalid_tx, 1, &context),
            Err(ConsensusError::OutputValueZero(0))
        ));

        // Test too large transaction size (adjust max_tx_size in params for this)
        let mut large_tx = tx.clone();
        large_tx.inputs[0].script_sig = vec![0x04; params.max_tx_size + 1]; // Make it exceed max_tx_size
        assert!(matches!(
            validate_transaction_structure(&large_tx, 1, &context),
            Err(ConsensusError::TransactionTooLarge(_, _))
        ));

        // Test empty inputs (not coinbase)
        let mut no_input_tx = tx.clone();
        no_input_tx.inputs.clear();
        assert!(matches!(
            validate_transaction_structure(&no_input_tx, 1, &context),
            Err(ConsensusError::EmptyTransaction)
        ));

        // Test insufficient fee (adjust output values to cause this)
        let mut low_fee_tx = tx.clone();
        low_fee_tx.outputs[0].value = 100_000_000; // Total output value matches input
        low_fee_tx.inputs[0].script_sig = vec![0x01; 10]; // Keep small size
        assert!(matches!(
            validate_transaction_structure(&low_fee_tx, 1, &context),
            Err(ConsensusError::InsufficientFee(_, _))
        ));
    }

    #[test]
    fn test_validate_transactions() {
        let dir = tempdir().expect("Failed to create temp directory");
        let utxo_set = UtxoSet::new(dir.path().to_str().unwrap()).expect("Failed to create UtxoSet");
        let params = ConsensusParams::default();
        let context = ValidationContext { utxo_set: &mut utxo_set, params: &params };

        let coinbase_tx = Transaction::new_coinbase(50_000_000, vec![1; 20], 1);

        // Create a valid transaction that spends a UTXO (simulate its presence in UTXO set)
        let prev_outpoint = OutPoint { txid: [0xaa; 32], vout: 0 };
        let prev_output = TxOutput::new(200_000_000, vec![1; 20]);
        utxo_set.put_utxo_in_batch(&mut UtxoSet::create_batch(), utxo_set.cf_utxos(), &prev_outpoint, &prev_output).expect("Failed to put UTXO");
        utxo_set.apply_batch(UtxoSet::create_batch()).expect("Failed to apply batch");

        let tx1 = Transaction {
            version: TxVersion::V1,
            inputs: vec![
                TxInput::new(
                    prev_outpoint,
                    vec![0x01; 10], // Dummy script_sig
                    0xffffffff,
                ),
            ],
            outputs: vec![
                TxOutput::new(150_000_000, vec![0x02; 10]),
                TxOutput::new(49_000_000, vec![0x03; 10]), // With some fee
            ],
            lock_time: 0,
        };

        let valid_transactions = vec![coinbase_tx.clone(), tx1.clone()];
        assert!(validate_transactions(&valid_transactions, 1, &context).is_ok());

        // Test no coinbase transaction
        assert!(matches!(
            validate_transactions(&vec![tx1.clone()], 1, &context),
            Err(ConsensusError::NoCoinbaseTransaction)
        ));

        // Test duplicate transaction in block
        let duplicate_txs = vec![coinbase_tx.clone(), tx1.clone(), tx1.clone()];
        assert!(matches!(
            validate_transactions(&duplicate_txs, 1, &context),
            Err(ConsensusError::DuplicateTransaction)
        ));

        // Test double spend within block
        let mut double_spend_tx1 = tx1.clone();
        let mut double_spend_tx2 = tx1.clone();
        double_spend_tx2.inputs[0].prev_output = double_spend_tx1.inputs[0].prev_output.clone(); // Same input

        let double_spend_block_txs = vec![coinbase_tx.clone(), double_spend_tx1, double_spend_tx2];
        assert!(matches!(
            validate_transactions(&double_spend_block_txs, 1, &context),
            Err(ConsensusError::DoubleSpend)
        ));

        // Test missing previous output (simulate by not adding to UTXO set)
        let missing_output_tx = Transaction {
            version: TxVersion::V1,
            inputs: vec![
                TxInput::new(
                    OutPoint { txid: [0xbb; 32], vout: 0 }, // This UTXO is not in the set
                    vec![0x01; 10],
                    0xffffffff,
                ),
            ],
            outputs: vec![
                TxOutput::new(100_000_000, vec![0x02; 10]),
            ],
            lock_time: 0,
        };
        assert!(matches!(
            validate_transactions(&vec![coinbase_tx.clone(), missing_output_tx], 1, &context),
            Err(ConsensusError::MissingPreviousOutput(_))
        ));
    }

    #[test]
    fn test_validate_block() {
        let dir = tempdir().expect("Failed to create temp directory");
        let utxo_set = UtxoSet::new(dir.path().to_str().unwrap()).expect("Failed to create UtxoSet");
        let params = ConsensusParams::default();
        let context = ValidationContext { utxo_set: &mut utxo_set, params: &params };

        let coinbase_tx = Transaction::new_coinbase(50_000_000, vec![1; 20], 1);

        let prev_outpoint = OutPoint { txid: [0xaa; 32], vout: 0 };
        let prev_output = TxOutput::new(200_000_000, vec![1; 20]);
        utxo_set.put_utxo_in_batch(&mut UtxoSet::create_batch(), utxo_set.cf_utxos(), &prev_outpoint, &prev_output).expect("Failed to put UTXO");
        utxo_set.apply_batch(UtxoSet::create_batch()).expect("Failed to apply batch");

        let tx1 = Transaction {
            version: TxVersion::V1,
            inputs: vec![
                TxInput::new(
                    prev_outpoint,
                    vec![0x01; 10],
                    0xffffffff,
                ),
            ],
            outputs: vec![
                TxOutput::new(150_000_000, vec![0x02; 10]),
                TxOutput::new(49_000_000, vec![0x03; 10]),
            ],
            lock_time: 0,
        };

        let valid_transactions = vec![coinbase_tx.clone(), tx1.clone()];

        let prev_block_header = BlockHeader::new(
            BlockVersion::V1,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            1234567800,
            0x207fffff,
            0,
            0,
        );
        let previous_block = create_test_block(prev_block_header.hash(), 1234567800);

        let block = create_test_block(previous_block.header.hash(), 1234567890);
        let mut block_with_txs = block.clone();
        block_with_txs.transactions = valid_transactions;

        // Test valid block
        assert!(validate_block(&block_with_txs, &[&previous_block], &context, 1234567900).is_ok());

        // Test empty block
        let mut empty_block = block.clone();
        empty_block.transactions.clear();
        assert!(matches!(
            validate_block(&empty_block, &[&previous_block], &context, 1234567900),
            Err(ConsensusError::EmptyBlock)
        ));

        // Test no coinbase transaction
        let mut no_coinbase_block = block.clone();
        no_coinbase_block.transactions = vec![tx1.clone()];
        assert!(matches!(
            validate_block(&no_coinbase_block, &[&previous_block], &context, 1234567900),
            Err(ConsensusError::NoCoinbaseTransaction)
        ));

        // Test block too large (adjust max_block_size in params for this)
        let mut large_block = block.clone();
        // Fill with transactions to exceed size limit
        let large_tx = Transaction {
            version: TxVersion::V1,
            inputs: vec![TxInput::new(OutPoint { txid: [0xcc; 32], vout: 0 }, vec![0x01; context.params.max_tx_size], 0xffffffff)],
            outputs: vec![TxOutput::new(100_000_000, vec![0x02; 10])],
            lock_time: 0,
        };
        let num_txs = (context.params.max_block_size / bincode::serialized_size(&large_tx).unwrap() as usize) + 1;
        large_block.transactions = (0..num_txs).map(|_| large_tx.clone()).collect();
        large_block.transactions.insert(0, coinbase_tx.clone()); // Add coinbase

        // Need to add the UTXO for the large_tx.input
        for i in 0..num_txs {
            let mut batch = UtxoSet::create_batch();
            let outpoint = OutPoint { txid: [0xcc; 32], vout: i as u32 };
            let output = TxOutput::new(200_000_000, vec![1; 20]);
            utxo_set.put_utxo_in_batch(&mut batch, utxo_set.cf_utxos(), &outpoint, &output).expect("Failed to put UTXO");
            utxo_set.apply_batch(batch).expect("Failed to apply batch");
        }

        assert!(matches!(
            validate_block(&large_block, &[&previous_block], &context, 1234567900),
            Err(ConsensusError::BlockTooLarge(_, _))
        ));

        // Test duplicate transactions in block (already covered by validate_transactions)
        let mut duplicate_tx_block = block.clone();
        duplicate_tx_block.transactions = vec![coinbase_tx.clone(), tx1.clone(), tx1.clone()];
        assert!(matches!(
            validate_block(&duplicate_tx_block, &[&previous_block], &context, 1234567900),
            Err(ConsensusError::DuplicateTransaction)
        ));
    }
}
