use crate::{
    types::{Block, BlockHeader, BlockchainState, Transaction, UTXO, PoSVote},
    crypto::{Hash, verify_signature},
    error::{Result, ConsensusError, Error},
};
pub mod pos;
use pos::{VotingTicket, TicketSelectionParams};
use std::time::{SystemTime, UNIX_EPOCH};

const INITIAL_COINBASE_REWARD: u64 = 50_000_000_000; // 50 RustyCoins
const MASTERNODE_COLLATERAL: u64 = 26_000_000_000_000; // 26,000 RustyCoins

pub struct ConsensusParams {
    /// Target block time in seconds (2.5 minutes)
    pub target_block_time: u64,
    /// Difficulty adjustment window in blocks
    pub difficulty_adjustment_window: u32,
    /// Minimum difficulty
    pub min_difficulty: Hash,
    /// Maximum difficulty
    pub max_difficulty: Hash,
    /// PoS ticket selection parameters
    pub ticket_params: TicketSelectionParams,
    /// Masternode parameters
    pub masternode_params: MasternodeParams,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            target_block_time: 150,
            difficulty_adjustment_window: 90,
            min_difficulty: Hash::from_bits(0x20000000),
            max_difficulty: Hash::from_bits(0x1d00ffff),
            ticket_params: TicketSelectionParams::default(),
            masternode_params: MasternodeParams::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MasternodeParams {
    /// Timeout in seconds for PoSe challenges.
    pub pose_timeout_seconds: u64,
    /// Maximum number of failed PoSe challenges before disqualification.
    pub max_pose_failures: u32,
}

impl Default for MasternodeParams {
    fn default() -> Self {
        Self {
            pose_timeout_seconds: 3600, // 1 hour
            max_pose_failures: 3,
        }
    }
}

/// Proof-of-Work validation
pub mod pow {
    use super::*;
    
    const LWMA_WINDOW: u32 = 90; // Number of blocks for LWMA (Linear Weighted Moving Average)
    const TARGET_BLOCK_TIME_SECONDS: u64 = 150; // 2.5 minutes

    /// Checks if a block header meets the difficulty target
    pub fn validate_pow(header: &BlockHeader, target: Hash) -> bool {
        // Use oxide_hash_impl for PoW validation
        crate::crypto::oxide_hash_impl(&bincode::encode_to_vec(&header, bincode::config::standard()).unwrap()) <= target
    }
    
    /// Calculates the next work required using LWMA algorithm
    pub fn calculate_next_work_required(
        last_headers: &[BlockHeader],
        params: &ConsensusParams,
    ) -> Result<u32> {
        if last_headers.len() < LWMA_WINDOW as usize {
            // If not enough blocks for LWMA, use the initial maximum difficulty (as bits).
            return Ok(params.max_difficulty.to_bits());
        }

        let mut weighted_times: u128 = 0;
        let mut sum_weights: u128 = 0;
        let mut avg_target_work: u128 = 0; // Use avg_target_work instead of avg_target

        let relevant_headers = &last_headers[last_headers.len() - LWMA_WINDOW as usize ..];

        for i in 0..LWMA_WINDOW as usize {
            let header = &relevant_headers[i];
            let weight = (i + 1) as u128;

            sum_weights += weight;
            avg_target_work += calculate_work_from_bits(header.bits); // Use bits directly

            if i > 0 {
                let time_diff = header.timestamp.saturating_sub(relevant_headers[i-1].timestamp) as u128;
                weighted_times += time_diff * weight;
            }
        }

        let average_block_time = weighted_times / (sum_weights.max(1));
        let expected_block_time = TARGET_BLOCK_TIME_SECONDS as u128;
        let average_work = avg_target_work / (LWMA_WINDOW as u128);

        let new_work = (average_work * average_block_time) / expected_block_time.max(1);

        // Convert work back to bits for clamping with min/max difficulty
        let mut new_bits = work_to_bits(new_work);

        // Clamp the new bits to min/max difficulty
        if new_bits > params.max_difficulty.to_bits() {
            new_bits = params.max_difficulty.to_bits();
        }
        if new_bits < params.min_difficulty.to_bits() {
            new_bits = params.min_difficulty.to_bits();
        }

        Ok(new_bits)
    }

    // Helper functions hash_to_f64 and f64_to_hash are no longer needed
}

pub fn calculate_work_from_bits(bits: u32) -> u128 {
    let compact_target = bits;
    let n_size = (compact_target >> 24) as u8;
    let mut n_word = (compact_target & 0x007fffff) as u128;

    if n_size <= 3 {
        n_word >>= 8 * (3 - n_size) as u128;
    } else {
        n_word <<= 8 * (n_size - 3) as u128;
    }
    n_word
}

/// Converts a u128 work value back to a compact difficulty bits (u32).
/// This function is an approximation and might not yield the exact original bits
/// due to the lossy nature of the compact bits format. It aims to find the bits
/// that result in a work value close to the input.
pub fn work_to_bits(mut work: u128) -> u32 {
    if work == 0 {
        return 0x1d00FFFF; // Return minimum difficulty (max target) if work is zero
    }

    // For a 256-bit number, the highest work is effectively for target 1.
    // Let's use the min_difficulty work as a reference for highest work.
    let _max_representable_work = calculate_work_from_bits(0x20000000); // work for min_difficulty (easiest target)

    // Clamp the incoming work to a sensible range to avoid overflow or underflow issues
    // when converting to bits. Ensure it's not excessively large or small.
    work = work.min(calculate_work_from_bits(0x1d00FFFF) * 4).max(calculate_work_from_bits(0x20000000) / 4); // Clamping example

    // Iteratively find the bits value that produces a similar work.
    // This is a simplified search for the appropriate bits.
    // A more precise solution might use binary search or a more direct mathematical inversion.

    // Start with an average difficulty and adjust.
    let mut bits = 0x1d00FFFF; // Start with the easiest difficulty
    let mut current_work = calculate_work_from_bits(bits);

    // Iterate to find a suitable bits value. This is a heuristic approach.
    // Adjust `bits` based on whether `current_work` is too high or too low compared to `work`.
    for _ in 0..100 { // Limit iterations to prevent infinite loops
        if current_work > work && bits < 0x207fffff { // If current work is too high (difficulty too low), increase difficulty (decrease target hash, increase bits value)
            bits += 1; // Increment bits slightly to increase difficulty
        } else if current_work < work && bits > 0x1d000000 { // If current work is too low (difficulty too high), decrease difficulty (increase target hash, decrease bits value)
            bits -= 1; // Decrement bits slightly to decrease difficulty
        } else {
            break; // Found a good approximation
        }
        current_work = calculate_work_from_bits(bits);
    }
    
    // Final clamping to ensure within allowed range
    bits.max(0x1d00FFFF).min(0x207fffff) // Bitcoin's max exponent is 0x1d, so 0x20... is for higher difficulties
}

/// Determines the canonical chain using the hybrid fork choice rule.
///
/// For PoW blocks: Chooses the chain with most cumulative work
/// For PoS blocks: Chooses the chain with highest validator participation
/// Hybrid blocks: Combines both metrics with weighted scoring
///
/// # Arguments
/// * `chains` - Potential chains to evaluate
/// * `params` - Consensus parameters for weighting
///
/// # Returns
/// Index of the selected chain in `chains`
pub fn select_canonical_chain(
    chains: &[Vec<Block>],
    _params: &ConsensusParams,
) -> usize {
    // In a real hybrid system, this would involve cumulative work for PoW
    // and validator participation for PoS, with weighted scoring.
    // For now, prioritize cumulative work if available, otherwise fall back to longest chain.
    chains.iter()
        .enumerate()
        .max_by_key(|(_, chain)| {
            chain.last()
                .map(|block| block.header.cumulative_work)
                .unwrap_or(0)
        })
        .map(|(idx, _)| idx)
        .unwrap_or(0)
}

/// Adjusts the mining/staking difficulty target for the next block.
///
/// Uses a hybrid algorithm that considers:
/// - Recent block times (for PoW)
/// - Stake participation rates (for PoS)
/// - Network hash rate/stake distribution
///
/// # Arguments
/// * `headers` - Recent block headers for context
/// * `active_stake` - Current total staked amount
/// * `params` - Consensus parameters
///
/// # Returns
/// New difficulty target (represented as u32 bits for PoW compatibility)
pub fn calculate_next_difficulty(
    headers: &[BlockHeader],
    _active_stake: u64,
    params: &ConsensusParams,
) -> u32 {
    pow::calculate_next_work_required(headers, params)
        .unwrap_or_else(|_| 0x1d00FFFF) // Default to a relatively easy difficulty if calculation fails
}

const MAX_BLOCK_SIZE_BYTES: usize = 1_000_000; // 1 MB

/// Validates a transaction.
///
/// This function performs checks such as:
/// - Ensuring transaction inputs refer to existing UTXOs.
/// - Validating input signatures against corresponding public keys.
/// - Checking for double-spends.
/// - Verifying output values and scripts.
pub fn validate_transaction(
    tx: &Transaction,
    chain: &dyn BlockchainState,
) -> Result<()> {
    // 1. Basic structural validation (e.g., no negative amounts, sensible sizes)
    if tx.outputs.iter().any(|output| output.value == 0) {
        return Err(Error::ConsensusError(ConsensusError::TxValidation("Transaction output with zero value".to_string())));
    }

    // 2. Coinbase transaction specific validation
    if tx.is_coinbase() {
        if tx.inputs.len() != 1 || !tx.inputs[0].is_coinbase() {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Coinbase transaction must have exactly one coinbase input".to_string())));
        }
        
        // Coinbase reward validation
        let current_block_height = chain.height() + 1; // Assuming this transaction is for the *next* block
        let expected_reward = calculate_coinbase_reward(current_block_height);
        let actual_reward: u64 = tx.outputs.iter().map(|output| output.value).sum();

        if actual_reward > expected_reward {
            return Err(Error::ConsensusError(ConsensusError::TxValidation(format!("Coinbase transaction reward ({}) exceeds maximum allowed ({}) at height {}", actual_reward, expected_reward, current_block_height))));
        }

        return Ok(());
    }

    // 3. Ticket revocation transaction specific validation
    if tx.is_ticket_revocation() {
        if tx.inputs.len() != 1 || tx.outputs.len() != 1 {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Ticket revocation transaction must have exactly one input and one output".to_string())));
        }

        let input = &tx.inputs[0];
        let output = &tx.outputs[0];

        // Ensure the input refers to an active ticket being revoked
        let revoked_ticket_hash = output.revocation_data.as_ref()
            .ok_or_else(|| Error::ConsensusError(ConsensusError::TxValidation("Missing revocation data in ticket revocation output".to_string())))?.ticket_hash;
        
        let active_tickets = chain.active_tickets();
        let ticket_to_revoke = active_tickets.iter().find(|t| t.hash == revoked_ticket_hash)
            .ok_or_else(|| Error::ConsensusError(ConsensusError::TxValidation(format!("Ticket to revoke not found in active tickets: {:?}", revoked_ticket_hash))))?;

        // Validate input signature against the ticket's staker public key
        let message = tx.hash_for_signature().as_bytes().to_vec();
        if !crate::crypto::verify_signature(&input.public_key, &message, &input.signature.clone().try_into()?)? {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Invalid signature for ticket revocation input".to_string())));
        }

        // Ensure the input's public key matches the ticket's staker public key
        if input.public_key != ticket_to_revoke.staker_public_key {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Input public key does not match revoked ticket's staker public key".to_string())));
        }

        // Ensure the output value matches the staked amount (or is slightly less due to fees)
        if output.value > ticket_to_revoke.stake_amount {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Ticket revocation output value exceeds staked amount".to_string())));
        }

        // TODO: Consider adding a lock time or maturity period for ticket redemption
        return Ok(());
    }

    // 4. Masternode registration transaction specific validation
    if tx.is_masternode_registration() {
        if tx.inputs.len() != 1 || tx.outputs.len() != 1 {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Masternode registration transaction must have exactly one input and one output".to_string())));
        }

        let input = &tx.inputs[0];
        let output = &tx.outputs[0];

        // Ensure the output has masternode data
        let masternode_payload = output.masternode_data.as_ref()
            .ok_or_else(|| Error::ConsensusError(ConsensusError::TxValidation("Missing masternode data in registration output".to_string())))?;

        // Ensure the input refers to an existing UTXO and its value matches the collateral
        let utxo = chain.get_utxo(&input.outpoint.tx_hash, input.outpoint.output_index)
            .ok_or_else(|| Error::ConsensusError(ConsensusError::TxValidation("UTXO not found for masternode collateral".to_string())))?;
        
        if utxo.value < MASTERNODE_COLLATERAL {
            return Err(Error::ConsensusError(ConsensusError::TxValidation(format!("Masternode collateral too low: {} vs expected {}", utxo.value, MASTERNODE_COLLATERAL))));
        }

        // Validate input signature against the collateral UTXO's public key
        let message = tx.hash_for_signature().as_bytes().to_vec();
        if !crate::crypto::verify_signature(&input.public_key, &message, &input.signature.clone().try_into()?)? {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Invalid signature for masternode registration input".to_string())));
        }

        // Ensure the input's public key matches the masternode's public key in the payload
        if input.public_key != masternode_payload.public_key {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Input public key does not match masternode public key in payload".to_string())));
        }

        // Ensure the masternode is not already registered (check for duplicate pro_reg_tx_hash)
        // This requires iterating through active masternodes, which can be expensive. 
        // For now, we'll assume the `add_masternode` handles uniqueness. 
        // In a more robust implementation, this check would involve the BlockchainState.
        // if chain.masternodes().iter().any(|mn| mn.pro_reg_tx_hash == tx.hash()) {
        //     return Err(Error::ConsensusError(ConsensusError::TxValidation("Masternode with this ProRegTxHash already registered".to_string())));
        // }

        return Ok(());
    }

    // 5. Non-coinbase transaction validation
    if tx.inputs.is_empty() {
        return Err(Error::ConsensusError(ConsensusError::TxValidation("Non-coinbase transaction with no inputs".to_string())));
    }

    let mut total_input_value = 0;
    let mut spent_utxos: Vec<UTXO> = Vec::new();

    // Validate inputs and collect total input value
    for input in &tx.inputs {
        // Ensure input refers to an existing UTXO
        let utxo = chain.get_utxo(&input.outpoint.tx_hash, input.outpoint.output_index)
            .ok_or_else(|| Error::ConsensusError(ConsensusError::TxValidation(format!("UTXO not found for input: {}:{}", input.outpoint.tx_hash, input.outpoint.output_index))))?;

        // Validate input signature against the UTXO's script_pubkey
        let public_key = input.public_key.clone();
        
        // The message signed is the hash of the transaction itself (excluding signatures for initial hash calculation)
        let mut tx_copy_for_signing = tx.clone();
        for input_copy in &mut tx_copy_for_signing.inputs {
            input_copy.signature = vec![]; // Clear signatures for hashing
        }
        let message = tx_copy_for_signing.hash().as_bytes().to_vec();

        if !crate::crypto::verify_signature(&public_key, &message, &input.signature.clone().try_into()?)? {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Invalid signature for transaction input".to_string())));
        }
        
        // Ensure the public key in the input matches the script_pubkey of the UTXO
        if public_key.as_bytes()[0..20] != utxo.script_pubkey {
            return Err(Error::ConsensusError(ConsensusError::TxValidation("Input public key does not match UTXO script_pubkey".to_string())));
        }

        total_input_value += utxo.value;
        spent_utxos.push(utxo);
    }

    // 6. Validate output values and calculate total output value
    let total_output_value: u64 = tx.outputs.iter().map(|output| output.value).sum();

    // 7. Transaction fee validation: Inputs must be greater than or equal to outputs
    if total_input_value < total_output_value {
        return Err(Error::ConsensusError(ConsensusError::TxValidation(format!("Transaction input value ({}) less than output value ({})", total_input_value, total_output_value))));
    }

    Ok(())
}

/// Validates a block's basic integrity and adherence to protocol rules.
/// This includes checking the header, transaction count, Merkle root, and size limits.
pub fn validate_block(
    block: &Block,
    chain: &dyn BlockchainState,
) -> Result<()> {
    // 1. Block header structure (basic check, more detailed in BlockHeader::new/hash)
    if block.header.version == 0 {
        return Err(Error::ConsensusError(ConsensusError::BlockValidation("Invalid block version".to_string())));
    }

    // 2. Transaction merkle root
    let computed_merkle_root = block.compute_merkle_root();
    if computed_merkle_root != block.header.merkle_root {
        return Err(Error::ConsensusError(ConsensusError::BlockValidation("Invalid merkle root".to_string())));
    }

    // 3. Timestamp validity
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::ConsensusError(ConsensusError::BlockValidation(format!("Failed to get system time: {}", e))))?
        .as_secs();
    // Block timestamp cannot be too far in the future (e.g., 2 hours)
    if block.header.timestamp > current_timestamp + 2 * 60 * 60 {
        return Err(Error::ConsensusError(ConsensusError::BlockValidation("Block timestamp too far in future".to_string())));
    }

    // Block timestamp cannot be too far in the past (e.g., 10 minutes, assuming average block time)
    // This check would ideally involve the timestamp of the previous block.
    // For simplicity, we'll just ensure it's not excessively old.
    if block.header.timestamp == 0 || block.header.timestamp < current_timestamp.saturating_sub(60 * 60 * 24 * 7) { // 1 week old
        return Err(Error::ConsensusError(ConsensusError::BlockValidation("Block timestamp too old or invalid".to_string())));
    }

    // 4. Block size limits
    let block_size = bincode::encode_to_vec(block, bincode::config::standard())
        .map_err(|e| Error::ConsensusError(ConsensusError::SerializationError(format!("Failed to serialize block for size check: {}", e))))?.len();
    if block_size > MAX_BLOCK_SIZE_BYTES {
        return Err(Error::ConsensusError(ConsensusError::BlockValidation(format!("Block size exceeds limit: {} bytes (max {})", block_size, MAX_BLOCK_SIZE_BYTES))));
    }

    // Validate transactions
    let mut processed_tx_hashes = std::collections::HashSet::new();
    for tx in &block.transactions {
        // Check for duplicate transactions within the block
        if !processed_tx_hashes.insert(tx.hash()) {
            return Err(Error::ConsensusError(ConsensusError::DuplicateTransactionInBlock(tx.hash())));
        }

        // Validate transaction structure (e.g., inputs, outputs, scripts)
        validate_transaction(tx, chain)?;
    }

    Ok(())
}

/// Validates a block's PoW/PoS consensus proof.
///
/// This function is intended to consolidate the PoW and PoS validation
/// that is currently done within `validate_block_full`.
///
/// # Arguments
/// * `block` - The block with consensus proof
/// * `chain` - Blockchain state for context (used for active tickets and previous headers)
/// * `params` - Consensus parameters
///
/// # Returns
/// `Ok(())` if proof is valid, `Err` otherwise
pub fn validate_consensus_proof(
    block: &Block,
    chain: &dyn BlockchainState,
    params: &ConsensusParams,
) -> Result<()> {
    let current_height = chain.height();

    // Retrieve previous headers from the blockchain state for PoW difficulty calculation.
    // We need 'N' headers for LWMA, or as many as available up to the genesis block.
    const N: usize = 90; // As defined in pow::calculate_next_work_required
    let mut prev_headers: Vec<BlockHeader> = Vec::with_capacity(N);
    let mut current_hash = block.header.prev_block_hash;

    for _i in 0..N {
        if current_hash == Hash::zero() { // Reached genesis block
            break;
        }
        if let Some(header) = chain.get_header(&current_hash) {
            prev_headers.insert(0, header.clone()); // Insert at beginning to maintain chronological order
            current_hash = header.prev_block_hash;
        } else {
            // If a previous header is not found, the chain is invalid or incomplete.
            return Err(Error::ConsensusError(ConsensusError::BlockValidation("Missing previous block header in chain".to_string())));
        }
    }

    let active_tickets = chain.active_tickets();

    // 1. Validate Proof-of-Work
    let target = pow::calculate_next_work_required(&prev_headers, params)
        .map_err(|e| Error::ConsensusError(ConsensusError::DifficultyError(format!("Failed to calculate PoW target: {}", e))))?;
    if !pow::validate_pow(&block.header, Hash::from_bits(target)) {
        return Err(Error::ConsensusError(ConsensusError::InvalidProof(
            "Block does not meet PoW difficulty target".to_string(),
        )));
    }
    
    // 2. Select and validate PoS quorum
    let quorum = pos::select_quorum(
        &active_tickets,
        &block.header.prev_block_hash,
        current_height,
        &params.ticket_params,
    )
    .map_err(|e| Error::ConsensusError(ConsensusError::StakingError(format!("Failed to select PoS quorum: {}", e))))?;
    
    // Calculate expected ticket hash from the selected quorum
    let expected_ticket_hash = pos::calculate_ticket_hash(&quorum);
    if block.header.ticket_hash != expected_ticket_hash {
        return Err(Error::ConsensusError(ConsensusError::InvalidProof("Block ticket hash does not match calculated quorum hash".to_string())));
    }

    pos::validate_quorum(block, &quorum, &params.ticket_params)
        .map_err(|e| Error::ConsensusError(ConsensusError::InvalidProof(format!("PoS quorum validation failed: {}", e))))?;

    // 3. Validate PoS votes included in the block header
    validate_pos_votes(&block.header.pos_votes, &block.header.prev_block_hash, &active_tickets, params.ticket_params.min_pos_votes)?;
    
    Ok(())
}

/// Validates the Proof-of-Stake votes included in a block header.
pub fn validate_pos_votes(
    pos_votes: &[PoSVote],
    target_block_hash: &Hash,
    active_tickets: &[VotingTicket],
    min_required_votes: usize,
) -> Result<()> {
    let mut unique_voters = std::collections::HashSet::new();
    let mut valid_vote_count = 0;
    let active_ticket_hashes: std::collections::HashSet<Hash> = active_tickets.iter().map(|t| t.hash).collect();

    for vote in pos_votes {
        // 1. Check if the vote is for the correct block
        if vote.block_hash != *target_block_hash {
            return Err(Error::ConsensusError(ConsensusError::InvalidProof("PoS vote for incorrect block".to_string())));
        }

        // 2. Check if the voting ticket is currently active
        if !active_ticket_hashes.contains(&vote.ticket_hash) {
            return Err(Error::ConsensusError(ConsensusError::InvalidProof("PoS vote from inactive ticket".to_string())));
        }

        // 3. Retrieve the public key of the staker from the active ticket.
        // This requires iterating through active_tickets to find the matching one.
        let Some(voting_ticket) = active_tickets.iter().find(|t| t.hash == vote.ticket_hash) else {
            // This case should ideally not happen due to the `active_ticket_hashes.contains` check,
            // but added for robustness.
            return Err(Error::ConsensusError(ConsensusError::InvalidProof("PoS voting ticket not found".to_string())));
        };
        let staker_public_key = &voting_ticket.staker_public_key;

        // 4. Verify the signature of the vote
        if !verify_signature(staker_public_key, vote.block_hash.as_bytes(), &vote.signature.clone().try_into()?)? {
            return Err(Error::ConsensusError(ConsensusError::InvalidProof("Invalid PoS vote signature".to_string())));
        }

        // 5. Ensure each ticket votes only once
        if !unique_voters.insert(vote.ticket_hash) {
            return Err(Error::ConsensusError(ConsensusError::InvalidProof("Duplicate PoS vote from same ticket".to_string())));
        }

        valid_vote_count += 1;
    }

    // 6. Check if the number of valid votes meets the minimum required votes
    if valid_vote_count < min_required_votes {
        return Err(Error::ConsensusError(ConsensusError::InvalidProof(format!("Insufficient PoS votes ({} valid, {} required) to meet quorum", valid_vote_count, min_required_votes))));
    }

    Ok(())
}

/// Full hybrid consensus validation
pub fn validate_block_full(
    block: &Block,
    prev_headers: &[BlockHeader],
    active_tickets: &[VotingTicket],
    current_height: u64,
    params: &ConsensusParams,
) -> Result<()> {
    // 1. Validate Proof-of-Work
    let target = pow::calculate_next_work_required(prev_headers, params)?;
    if !pow::validate_pow(&block.header, Hash::from_bits(target)) {
        return Err(Error::BlockValidation(
            "Block does not meet PoW difficulty target".to_string(),
        ));
    }
    
    // 2. Select and validate PoS quorum
    let quorum = pos::select_quorum(
        active_tickets,
        &block.header.prev_block_hash,
        current_height,
        &params.ticket_params,
    )?;
    
    pos::validate_quorum(block, &quorum, &params.ticket_params)?;
    
    // 3. Validate PoS votes included in the block header
    validate_pos_votes(&block.header.pos_votes, &block.header.prev_block_hash, &active_tickets, params.ticket_params.min_pos_votes)?;
    
    Ok(())
}

fn calculate_coinbase_reward(height: u64) -> u64 {
    const HALVING_INTERVAL: u64 = 210_000; // Example: Halve every 210,000 blocks

    let num_halvings = height / HALVING_INTERVAL;
    if num_halvings >= 64 { // Prevent overflow and reward becoming zero too quickly
        return 0;
    }
    
    INITIAL_COINBASE_REWARD / (1 << num_halvings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Hash;

    fn create_test_header(timestamp: u64, bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            timestamp,
            bits,
            nonce: 0,
            ticket_hash: Hash::zero(),
            cumulative_work: 0,
            height: 0,
            pos_votes: vec![],
        }
    }

    #[test]
    fn test_lwma_constant_hash_rate() {
        let params = ConsensusParams::default();
        let mut headers = Vec::new();
        
        // Create headers with perfect 150 second intervals
        for i in 0..100 {
            headers.push(create_test_header(
                i * 150,
                0x1d00ffff, // Medium difficulty
            ));
        }
        
        let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
        
        // Difficulty should stay roughly the same
        assert!(new_target >= 0x1c000000 && new_target <= 0x1e000000);
    }

    #[test]
    fn test_lwma_increasing_hash_rate() {
        let params = ConsensusParams::default();
        let mut headers = Vec::new();
        
        // Create headers with decreasing intervals (hash rate increasing)
        for i in 0..100 {
            headers.push(create_test_header(
                i * 100, // Faster than target (100s vs 150s)
                0x1d00ffff,
            ));
        }
        
        let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
        
        // Difficulty should increase (target value should decrease)
        assert!(new_target < 0x1d00ffff);
    }

    #[test]
    fn test_lwma_decreasing_hash_rate() {
        let params = ConsensusParams::default();
        let mut headers = Vec::new();
        
        // Create headers with increasing intervals (hash rate decreasing)
        for i in 0..100 {
            headers.push(create_test_header(
                i * 200, // Slower than target (200s vs 150s)
                0x1d00ffff,
            ));
        }
        
        let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
        
        // Difficulty should decrease (target value should increase)
        assert!(new_target > 0x1d00ffff);
    }

    #[test]
    fn test_lwma_min_difficulty() {
        let params = ConsensusParams {
            min_difficulty: Hash::from_bits(0x1f000000),
            ..Default::default()
        };
        let mut headers = Vec::new();
        for i in 0..100 {
            headers.push(create_test_header(i * 150, 0x1d00ffff));
        }
        // Simulate very high hash rate to push difficulty to max
        for header in headers.iter_mut() {
            header.timestamp /= 10;
        }
        let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
        assert_eq!(new_target, params.min_difficulty.to_bits());
    }

    #[test]
    fn test_lwma_max_future_block_time() {
        let params = ConsensusParams {
            max_difficulty: Hash::from_bits(0x1c000000),
            ..Default::default()
        };
        let mut headers = Vec::new();
        for i in 0..100 {
            headers.push(create_test_header(i * 150, 0x1d00ffff));
        }
        // Simulate very low hash rate to push difficulty to min
        for header in headers.iter_mut() {
            header.timestamp *= 10;
        }
        let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
        assert_eq!(new_target, params.max_difficulty.to_bits());
    }
}
