// rusty-core/src/consensus/pos.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, SignatureError, PublicKey as VerifyingKey};
use rusty_shared_types::{BlockHeader, Ticket, TicketId, OutPoint, PublicKey, Hash};
use rusty_shared_types::masternode::{MasternodeList, PoSeChallenge, PoSeResponse};
use crate::consensus::error::ConsensusError;

pub fn validate_ticket_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, SignatureError> {
    let public_key = VerifyingKey::from_bytes(public_key_bytes).map_err(|_| SignatureError::new())?;
    let signature = Signature::from_bytes(signature_bytes).map_err(|_| SignatureError::new())?;
    match public_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false)
    }
}

// 3.2.1 Ticket Structure and Identification

// Remove inherent impl for Ticket, which is defined in another crate. Only traits can be implemented for external types

// 3.2.3 Live Tickets Pool
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LiveTicketsPool {
    pub tickets: HashMap<TicketId, Ticket>,
}

impl LiveTicketsPool {
    pub fn new() -> Self {
        LiveTicketsPool {
            tickets: HashMap::new(),
        }
    }

    pub fn add_ticket(&mut self, ticket: Ticket) -> Result<(), ConsensusError> {
        let _bytes = bincode::serialize(&ticket)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        self.tickets.insert(ticket.id.clone(), ticket);
        Ok(())
    }

    pub fn remove_ticket(&mut self, ticket_id: &TicketId) -> Result<Ticket, ConsensusError> {
        self.tickets.remove(ticket_id).ok_or(ConsensusError::InvalidTicket("Ticket not found in live pool.".to_string()))
    }

    pub fn get_ticket(&self, ticket_id: &TicketId) -> Option<&Ticket> {
        self.tickets.get(ticket_id)
    }

    pub fn get_live_ticket_count(&self) -> usize {
        self.tickets.len()
    }

    pub fn count_live_tickets(&self) -> usize {
        self.tickets.len()
    }

    pub fn get_all_tickets(&self) -> impl Iterator<Item = &Ticket> {
        self.tickets.values()
    }

    pub fn update_for_new_block(&mut self, block: &rusty_shared_types::Block, used_ticket_ids: &Vec<TicketId>) -> Result<(), ConsensusError> {
        for ticket_id in used_ticket_ids {
            self.tickets.remove(ticket_id);
        }

        for tx in &block.transactions {
            if let rusty_shared_types::Transaction::TicketPurchase { version: _, inputs: _, outputs, ticket_id: _tx_ticket_hash, locked_amount: _locked_amount, lock_time: _, fee: _, ticket_address, witness: _ } = tx {
                // Assuming the first output of a TicketPurchase transaction is the ticket output
                // and the value of this output is the locked_amount.
                let _ticket_output = outputs.get(0).ok_or(ConsensusError::InvalidTicket("Ticket purchase transaction has no output for ticket.".to_string()))?;
                let _outpoint = OutPoint { txid: tx.txid(), vout: 0 }; // Assuming vout 0 for the ticket output

                // Convert Vec<u8> ticket_address to PublicKey ([u8; 32])
                let public_key: PublicKey = ticket_address.as_slice().try_into()
                    .map_err(|_| ConsensusError::InvalidTicket("Invalid public key length in ticket address.".to_string()))?;

                // Commitment can be a hash of the public key or other relevant ticket data
                let commitment: Hash = blake3::hash(&public_key).into();

                let ticket = Ticket {
                    id: TicketId::from_bytes(commitment),  // Using commitment as the ID
                    pubkey: public_key.to_vec(),          // Convert PublicKey to Vec<u8>
                    height: block.header.height,         // Purchase block height
                    value: outputs.get(0).ok_or(
                        ConsensusError::InvalidTicket("Ticket purchase transaction has no output value.".to_string())
                    )?.value,
                    status: rusty_shared_types::TicketStatus::Live,  // New tickets are Live by default
                };
                self.add_ticket(ticket).expect("Failed to add ticket from purchase transaction");
            }
        }
        Ok(())
    }

    pub fn update_for_revert_block(&mut self, block: &rusty_shared_types::Block, used_ticket_ids: &Vec<TicketId>) {
        // Add back the used tickets
        for ticket_id in used_ticket_ids {
            self.tickets.remove(ticket_id);
        }

        for tx in &block.transactions {
            if let rusty_shared_types::Transaction::TicketPurchase { ticket_id, .. } = tx {
                // The ticket_id from the transaction is already the TicketId (Hash)
                let ticket_id = TicketId(*ticket_id);
                self.tickets.remove(&ticket_id);
            }
        }
    }

    pub fn get_ticket_ids_sorted(&self) -> Vec<TicketId> {
        let mut ticket_ids: Vec<TicketId> = self.tickets.keys().cloned().collect();
        ticket_ids.sort();
        ticket_ids
    }

    pub fn validate_non_participation_proof(&self, proof: &rusty_shared_types::masternode::MasternodeNonParticipationProof, masternode_list: &MasternodeList) -> Result<(), ConsensusError> {
        if masternode_list.get_masternode(&proof.masternode_id).is_none() {
            return Err(ConsensusError::MasternodeError("Masternode not found for non-participation proof.".to_string()));
        }
        Ok(())
    }

    pub fn validate_malicious_proof(&self, proof: &rusty_shared_types::masternode::MasternodeMaliciousProof, masternode_list: &MasternodeList) -> Result<(), ConsensusError> {
        if masternode_list.get_masternode(&proof.masternode_id).is_none() {
            return Err(ConsensusError::MasternodeError("Masternode not found for malicious proof.".to_string()));
        }
        Ok(())
    }
}

// 3.3 Ticket Price Adjustment Parameters (Example values)
pub const INITIAL_TICKET_PRICE: u64 = 100_000_000; // 1 RUST in satoshis
const TARGET_LIVE_TICKETS: usize = 20_000;
const TICKET_PRICE_ADJUSTMENT_PERIOD: u64 = 2016;
const K_P: f64 = 0.05;
const MAX_TICKET_PRICE: u64 = 1_000_000_000; // 10 RUST
const MIN_TICKET_PRICE: u64 = 10_000_000; // 0.1 RUST

pub fn calculate_new_ticket_price(
    current_block_height: u64,
    last_ticket_price: u64,
    avg_live_tickets_count: usize,
) -> u64 {
    if current_block_height == 0 {
        return INITIAL_TICKET_PRICE;
    }
    if current_block_height % TICKET_PRICE_ADJUSTMENT_PERIOD != 0 {
        return last_ticket_price;
    }

    let n_l = avg_live_tickets_count as f64;
    let t_g = TARGET_LIVE_TICKETS as f64;

    let p_new_f64 = last_ticket_price as f64 * (1.0 + (K_P * (n_l - t_g) / t_g));
    let mut p_new = p_new_f64.round() as u64;

    // Apply constraints
    if p_new > MAX_TICKET_PRICE {
        p_new = MAX_TICKET_PRICE;
    } else if p_new < MIN_TICKET_PRICE {
        p_new = MIN_TICKET_PRICE;
    }
    p_new
}

// 3.4 Voter Selection Parameters (Example values)
const VOTERS_PER_BLOCK: usize = 5;

    pub fn select_voters(
        prev_block_hash: &[u8; 32],
        live_tickets_pool: &LiveTicketsPool,
    ) -> Vec<TicketId> {
        let mut selected_voters: Vec<(u64, TicketId)> = Vec::new();

        for (ticket_id, _ticket) in &live_tickets_pool.tickets {
            let mut hasher = blake3::Hasher::new();
            hasher.update(prev_block_hash);
            hasher.update(&bincode::serialize(ticket_id).unwrap());
            let lottery_score_bytes: [u8; 32] = hasher.finalize().into();
            let lottery_score = u64::from_le_bytes(lottery_score_bytes[0..8].try_into().unwrap());
            selected_voters.push((lottery_score, ticket_id.clone()));
        }

        // Sort by lottery score, then by TicketId for tie-breaking
        selected_voters.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_ref().cmp(b.1.as_ref())));

        selected_voters
            .into_iter()
            .rev()
            .take(VOTERS_PER_BLOCK)
            .map(|(_, id)| id)
            .collect()
    }

// 3.5 Block Validation Parameters (Example values)
const MIN_VALID_VOTES_REQUIRED: usize = 3;

pub fn validate_pos_block(
    _block_header: &BlockHeader,
    prev_block_hash: &[u8; 32],
    live_tickets_pool: &LiveTicketsPool,
) -> bool {
    // 3.5.1 ticket_votes Structure Validation:
    // Commented out as block_header.ticket_votes is non-existent
    // TODO: This function should operate on a Block, not BlockHeader, to access ticket_votes.
    // For now, this logic is disabled.

    let _expected_voters = select_voters(prev_block_hash, live_tickets_pool);
    let valid_votes_count = 0;

    // Remove for ticket_vote in &block_header.ticket_votes { ... }
    // ...existing code...

    // 3.5.3 Quorum Check:
    if valid_votes_count < MIN_VALID_VOTES_REQUIRED {
        println!(
            "POS Validation Failed: Not enough valid votes. Required: {}, Found: {}.",
            MIN_VALID_VOTES_REQUIRED, valid_votes_count
        );
        return false;
    }

    true
}

pub fn calculate_pos_reward(_block_height: u32) -> u64 {
    // Placeholder for PoS reward calculation
    // This should be dynamic based on factors like block height, staking difficulty, etc.
    100000000 // Example: 1 coin (100,000,000 satoshis)
}

/// Parameters for the TicketVoting system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketVotingParams {
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
}
