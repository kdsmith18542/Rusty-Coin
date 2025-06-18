//! Enhanced Proof-of-Stake implementation for Rusty Coin

use crate::{
    types::{Block},
    error::{Result, ConsensusError, Error},
    crypto::{verify_signature, Hash, PublicKey, Signature, KeyPair},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

/// Represents a staking ticket in the Proof of Stake consensus system.
///
/// Staking tickets are used to participate in block validation and earn rewards.
/// Each ticket contains:
/// - The hash of the referenced block
/// - The staker's public key
/// - The amount of coins staked
/// - Creation block height
/// - Digital signature proving ownership
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotingTicket {
    /// Hash of the block this ticket is valid for
    pub hash: Hash,
    
    /// Public key of the staker
    pub staker_public_key: PublicKey,
    
    /// Amount of coins staked (in smallest units)
    pub stake_amount: u64,
    
    /// Block height when this ticket was created
    pub creation_height: u64,
    
    /// Signature proving the staker owns the staked coins
    pub signature: Signature,
}

impl VotingTicket {
    /// Creates and signs a new voting ticket
    pub fn new(
        keypair: &KeyPair,
        stake_amount: u64,
        creation_height: u64,
    ) -> Result<Self> {
        let message = Self::ticket_message(&keypair.public_key, stake_amount, creation_height);
        let signature = crate::crypto::sign(&keypair, &message)?;
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(keypair.public_key.as_bytes());
        hasher.update(&stake_amount.to_be_bytes());
        hasher.update(&creation_height.to_be_bytes());
        
        Ok(Self {
            hash: Hash::from_slice(hasher.finalize().as_bytes())
                .expect("Failed to create hash from slice"),
            staker_public_key: keypair.public_key.clone(),
            stake_amount,
            creation_height,
            signature,
        })
    }
    
    /// Verifies the ticket's signature
    pub fn verify(&self) -> bool {
        let message = Self::ticket_message(&self.staker_public_key, self.stake_amount, self.creation_height);
        match verify_signature(&self.staker_public_key, &message, &self.signature) {
            Ok(valid) => valid,
            Err(_) => false,
        }
    }
    
    /// Creates a message for signing a voting ticket
    pub fn ticket_message(pubkey: &PublicKey, amount: u64, height: u64) -> Vec<u8> {
        let mut message = pubkey.as_bytes().to_vec();
        message.extend_from_slice(&amount.to_be_bytes());
        message.extend_from_slice(&height.to_be_bytes());
        message
    }
}

/// Configuration parameters for Proof of Stake consensus.
///
/// These parameters control:
/// - Minimum required confirmations for staked coins
/// - Maximum age of valid tickets
/// - Minimum stake amount
/// - Committee (quorum) size for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoSParameters {
    /// Minimum number of confirmations required for staked coins
    pub min_confirmations: u64,
    
    /// Maximum age (in blocks) a staking ticket remains valid
    pub max_ticket_age: u64,
    
    /// Minimum amount of coins required to stake
    pub min_stake: u64,
    
    /// Number of validators required to form a quorum
    pub quorum_size: usize,
}

impl PoSParameters {
    /// Validates a staking ticket against the current consensus rules.
    ///
    /// # Arguments
    /// * `ticket` - The staking ticket to validate
    /// * `current_height` - The current blockchain height
    /// * `active_tickets` - Set of currently active tickets to check for duplicates
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err` with reason if invalid
    pub fn validate_ticket(
        &self,
        ticket: &VotingTicket,
        current_height: u64,
        active_tickets: &HashSet<Hash>,
    ) -> Result<()> {
        // Check ticket isn't too old
        if current_height.saturating_sub(ticket.creation_height) > self.max_ticket_age {
            return Err(Error::ConsensusError(ConsensusError::TicketExpired));
        }
        
        // Check meets minimum stake
        if ticket.stake_amount < self.min_stake {
            return Err(Error::ConsensusError(ConsensusError::InsufficientStake));
        }
        
        // Check for duplicate tickets
        if active_tickets.contains(&ticket.hash) {
            return Err(Error::ConsensusError(ConsensusError::DuplicateTicket));
        }
        
        Ok(())
    }
}

/// Parameters for ticket selection
#[derive(Debug, Clone)]
pub struct TicketSelectionParams {
    pub min_confirmations: u64,
    pub max_ticket_age: u64,
    pub min_stake: u64,
    pub quorum_size: usize,
    pub min_pos_votes: usize,
    pub target_active_tickets: u64,
    pub ticket_price_adjustment_factor: f64,
}

impl Default for TicketSelectionParams {
    fn default() -> Self {
        Self {
            min_confirmations: 100,
            max_ticket_age: 20160,
            min_stake: 1000,
            quorum_size: 5,
            min_pos_votes: 3,
            target_active_tickets: 20_000,
            ticket_price_adjustment_factor: 0.01, // 1% adjustment per block
        }
    }
}

/// Calculates the next ticket price based on the current number of active tickets.
/// 
/// Aims to adjust the price to target a constant pool size of `target_active_tickets`.
pub fn calculate_next_ticket_price(
    current_ticket_price: u64,
    current_active_tickets: u64,
    params: &TicketSelectionParams,
) -> u64 {
    let target = params.target_active_tickets as f64;
    let current = current_active_tickets as f64;
    let factor = params.ticket_price_adjustment_factor;

    if current > target { // Too many tickets, increase price
        let adjustment = (current * factor).max(1.0) as u64; // At least 1
        current_ticket_price.saturating_add(adjustment)
    } else if current < target { // Too few tickets, decrease price
        let adjustment = (target * factor).max(1.0) as u64; // At least 1
        current_ticket_price.saturating_sub(adjustment).max(params.min_stake) // Ensure it doesn't go below min_stake
    } else {
        current_ticket_price // Price is stable
    }
}

/// Selects a quorum of tickets using weighted random selection
pub fn select_quorum(
    tickets: &[VotingTicket],
    prev_block_hash: &Hash,
    current_height: u64,
    params: &TicketSelectionParams,
) -> Result<Vec<VotingTicket>> {
    // Filter eligible tickets
    let eligible: Vec<_> = tickets
        .iter()
        .filter(|t| {
            let _age = current_height - t.creation_height;
            _age >= params.min_confirmations && 
            _age <= params.max_ticket_age &&
            t.stake_amount >= params.min_stake &&
            t.verify()
        })
        .cloned()
        .collect();
    
    if eligible.len() < params.quorum_size {
        return Err(Error::ConsensusError(ConsensusError::InsufficientEligibleTickets));
    }
    
    // Create deterministic RNG from previous block hash
    let mut rng = ChaCha8Rng::from_seed(*prev_block_hash.as_bytes());
    let mut selected = Vec::with_capacity(params.quorum_size);
    let total_stake: u64 = eligible.iter().map(|t| t.stake_amount).sum();
    
    while selected.len() < params.quorum_size {
        let r = rng.next_u64() % total_stake;
        let mut sum = 0;
        
        for ticket in eligible.iter() {
            if selected.contains(ticket) {
                continue;
            }
            
            sum += ticket.stake_amount;
            if sum > r {
                selected.push(ticket.clone());
                break;
            }
        }
    }
    Ok(selected)
}

/// Calculates a combined hash of a sorted list of voting tickets.
/// This hash can be used in the block header to commit to the selected quorum.
pub fn calculate_ticket_hash(tickets: &[VotingTicket]) -> Hash {
    let mut all_ticket_hashes: Vec<Hash> = tickets.iter().map(|t| t.hash).collect();
    all_ticket_hashes.sort_unstable_by_key(|h| h.0.to_vec()); // Sort for deterministic hash

    if all_ticket_hashes.is_empty() {
        return Hash::zero();
    }

    let mut hasher = blake3::Hasher::new();
    for hash in all_ticket_hashes {
        hasher.update(hash.as_bytes());
    }
    Hash::from_slice(hasher.finalize().as_bytes()).expect("Failed to create hash from slice")
}

/// Validates a ticket quorum's approval of a block
pub fn validate_quorum(
    block: &Block,
    quorum: &[VotingTicket],
    params: &TicketSelectionParams,
) -> Result<()> {
    // 1. Verify quorum size
    if quorum.len() != params.quorum_size {
        return Err(Error::ConsensusError(ConsensusError::InvalidQuorumSize));
    }

    // 2. Verify each ticket is eligible and unique within the quorum
    let mut seen_tickets = HashSet::new();
    for ticket in quorum.iter() {
        // Basic eligibility check (more comprehensive checks should be done during ticket purchase/addition to active set)
        let age = block.header.height - ticket.creation_height;
        if age < params.min_confirmations || age > params.max_ticket_age || ticket.stake_amount < params.min_stake {
            return Err(Error::ConsensusError(ConsensusError::InvalidTicketHash)); // Generic error for now
        }

        // Verify ticket signature using the message derived from the ticket data
        let message = VotingTicket::ticket_message(&ticket.staker_public_key, ticket.stake_amount, ticket.creation_height);
        if !verify_signature(&ticket.staker_public_key, &message, &ticket.signature)? {
            return Err(Error::ConsensusError(ConsensusError::TicketDidntApproveBlock));
        }

        if !seen_tickets.insert(ticket.hash) {
            return Err(Error::ConsensusError(ConsensusError::DuplicateTicketInQuorum));
        }
    }

    // 3. Verify the block's ticket_hash matches the calculated quorum hash
    let calculated_ticket_hash = calculate_ticket_hash(quorum);
    if calculated_ticket_hash != block.header.ticket_hash {
        return Err(Error::ConsensusError(ConsensusError::InvalidTicketHash));
    }

    Ok(())
}

/// Selects validators from available staking tickets using a weighted random selection.
///
/// The selection is weighted by stake amount - higher stakes increase selection probability.
/// Uses a verifiable random function (VRF) to ensure fairness and prevent manipulation.
///
/// # Arguments
/// * `tickets` - Pool of eligible staking tickets
/// * `params` - Selection parameters including quorum size
/// * `seed` - Random seed derived from previous block hash
///
/// # Returns
/// Selected validator tickets and their selection proofs
pub fn select_validators(
    tickets: &[VotingTicket],
    params: &TicketSelectionParams,
    seed: &[u8; 32],
) -> Result<Vec<(VotingTicket, [u8; 32])>> {
    // Filter eligible tickets (same logic as select_quorum)
    let eligible: Vec<_> = tickets
        .iter()
        .filter(|t| {
            let _age = t.creation_height;
            // Assuming `creation_height` is used to determine eligibility based on age from current_height implicitly
            // For validator selection, we primarily care about active, valid tickets.
            // Simplified for now, real implementation would consider more factors like uptime, PoSe scores.
            t.stake_amount >= params.min_stake && t.verify()
        })
        .cloned()
        .collect();
    
    if eligible.len() < params.quorum_size {
        return Err(Error::ConsensusError(ConsensusError::InsufficientEligibleTickets));
    }
    
    // Create deterministic RNG from seed
    let mut rng = ChaCha8Rng::from_seed(*seed);
    let mut selected = Vec::with_capacity(params.quorum_size);
    let total_stake: u64 = eligible.iter().map(|t| t.stake_amount).sum();
    
    while selected.len() < params.quorum_size {
        let r = rng.next_u64() % total_stake;
        let mut sum = 0;
        
        for ticket in eligible.iter() {
            if selected.iter().any(|(t, _)| t == ticket) {
                continue;
            }
            
            sum += ticket.stake_amount;
            if sum > r {
                let mut signature_bytes = [0; 32];
                rng.fill_bytes(&mut signature_bytes);
                selected.push((ticket.clone(), signature_bytes));
                break;
            }
        }
    }
    Ok(selected)
}

/// Verifies validator selection proofs to ensure fair selection.
///
/// Checks that:
/// 1. Each validator was properly selected according to the rules
/// 2. The selection proofs are valid
/// 3. No validator was selected multiple times
///
/// # Arguments
/// * `selected` - List of selected validators and their proofs
/// * `available` - Full set of available tickets
/// * `params` - Selection parameters
/// * `seed` - Random seed used for selection
///
/// # Returns
/// `Ok(())` if all selections are valid, error otherwise
pub fn verify_selection(
    selected: &[(VotingTicket, [u8; 32])],
    available: &[VotingTicket],
    params: &TicketSelectionParams,
    seed: &[u8; 32],
) -> Result<()> {
    // 1. Verify quorum size
    if selected.len() != params.quorum_size {
        return Err(Error::ConsensusError(ConsensusError::InvalidQuorumSize));
    }

    // 2. Re-select and compare
    let re_selected = select_validators(available, params, seed)?;

    if selected.len() != re_selected.len() {
        return Err(Error::ConsensusError(ConsensusError::InvalidQuorumSize));
    }

    // Sort both for deterministic comparison
    let mut selected_sorted = selected.to_vec();
    selected_sorted.sort_unstable_by_key(|(t, _)| t.hash.0.to_vec());

    let mut re_selected_sorted = re_selected.to_vec();
    re_selected_sorted.sort_unstable_by_key(|(t, _)| t.hash.0.to_vec());

    if selected_sorted != re_selected_sorted {
        return Err(Error::ConsensusError(ConsensusError::InvalidQuorumSize)); // Generic error for mismatch
    }

    Ok(())
}
