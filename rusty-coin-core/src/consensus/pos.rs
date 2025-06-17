//! Enhanced Proof-of-Stake implementation for Rusty Coin

use crate::{
    crypto::{verify_signature, Hash, PublicKey, Signature, KeyPair},
    error::{Error, Result},
    types::Block,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashSet;

/// Voting ticket with enhanced security features
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotingTicket {
    pub hash: Hash,
    pub staker_public_key: PublicKey,
    pub stake_amount: u64,
    pub creation_height: u64,
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
        let signature = keypair.sign(&message)?;
        
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

/// Parameters for ticket selection
#[derive(Debug, Clone)]
pub struct TicketSelectionParams {
    pub min_confirmations: u64,
    pub max_ticket_age: u64,
    pub min_stake: u64,
    pub quorum_size: usize,
}

impl Default for TicketSelectionParams {
    fn default() -> Self {
        Self {
            min_confirmations: 100,
            max_ticket_age: 20160,
            min_stake: 1000,
            quorum_size: 5,
        }
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
            let age = current_height - t.creation_height;
            age >= params.min_confirmations && 
            age <= params.max_ticket_age &&
            t.stake_amount >= params.min_stake &&
            t.verify()
        })
        .cloned()
        .collect();
    
    if eligible.len() < params.quorum_size {
        return Err(Error::ConsensusError("Insufficient eligible tickets".into()));
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

/// Validates a ticket quorum's approval of a block
pub fn validate_quorum(
    block: &Block,
    quorum: &[VotingTicket],
    params: &TicketSelectionParams,
) -> Result<()> {
    if quorum.len() != params.quorum_size {
        return Err(Error::ConsensusError("Invalid quorum size".into()));
    }
    
    let block_hash = block.header.hash();
    let msg = block_hash.as_bytes();
    
    let mut seen = HashSet::new();
    
    for ticket in quorum {
        // Verify ticket was properly created
        let expected_msg = VotingTicket::ticket_message(
            &ticket.staker_public_key, 
            ticket.stake_amount, 
            ticket.creation_height
        );
        let expected_hash = Hash::blake3(&expected_msg);
        
        if ticket.hash != expected_hash {
            return Err(Error::ConsensusError("Invalid ticket hash".into()));
        }
        
        // Verify ticket approves this block
        match verify_signature(&ticket.staker_public_key, msg, &ticket.signature) {
            Ok(valid) => {
                if !valid {
                    return Err(Error::ConsensusError("Ticket didn't approve block".into()));
                }
            },
            Err(_) => return Err(Error::ConsensusError("Failed to verify ticket signature".into())),
        }
        
        if ticket.stake_amount < params.min_stake {
            return Err(Error::ConsensusError("Insufficient stake amount".into()));
        }
        
        if !seen.insert(ticket.hash) {
            return Err(Error::ConsensusError("Duplicate ticket in quorum".into()));
        }
    }
    
    Ok(())
}
