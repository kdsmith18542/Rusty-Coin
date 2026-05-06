//! Vote validation for governance system
//!
//! This module validates governance votes before they are accepted into the voting set.

use ed25519_dalek::{Verifier, VerifyingKey};
use rusty_core::consensus::pos::LiveTicketsPool;
use rusty_shared_types::masternode::{MasternodeList, MasternodeStatus};
use rusty_shared_types::{
    governance::{GovernanceVote, VoterType},
    PublicKey,
};

/// Validation errors for governance votes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteValidationError {
    /// Voter signature is invalid
    InvalidSignature,
    /// Voter is not eligible (not a valid masternode or PoS ticket holder)
    IneligibleVoter,
    /// Voter does not have sufficient stake
    InsufficientStake,
}

/// Validates governance votes
pub struct VoteValidator;

impl VoteValidator {
    /// Validate a governance vote (signature and eligibility)
    pub fn validate_vote(
        vote: &GovernanceVote,
        voter_pubkey: &PublicKey,
        live_tickets: &LiveTicketsPool,
        masternode_list: &MasternodeList,
        required_ticket_value: u64,
        required_mn_collateral: u64,
    ) -> Result<(), VoteValidationError> {
        // Eligibility and stake
        match vote.voter_type {
            VoterType::PosTicket => {
                // For PoS, voter_id is the ticket's public key
                let ticket = live_tickets
                    .tickets
                    .values()
                    .find(|t| t.pubkey == voter_pubkey.to_vec());
                if let Some(ticket) = ticket {
                    if ticket.value < required_ticket_value {
                        return Err(VoteValidationError::InsufficientStake);
                    }
                } else {
                    return Err(VoteValidationError::IneligibleVoter);
                }
            }
            VoterType::Masternode => {
                // For masternode, voter_id is the operator public key
                let mn = masternode_list
                    .map
                    .values()
                    .find(|entry| entry.identity.operator_public_key == voter_pubkey.to_vec());
                if let Some(mn) = mn {
                    if mn.status != MasternodeStatus::Active {
                        return Err(VoteValidationError::IneligibleVoter);
                    }
                    // Collateral validation enforced: masternode must meet required_mn_collateral
                    if let Some(collateral_amount) = mn.get_collateral_amount() {
                        if collateral_amount < required_mn_collateral {
                            return Err(VoteValidationError::InsufficientStake);
                        }
                    } else {
                        return Err(VoteValidationError::InsufficientStake);
                    }
                } else {
                    return Err(VoteValidationError::IneligibleVoter);
                }
            }
        }
        // Signature check (unchanged)
        let verifying_key = VerifyingKey::from_bytes(voter_pubkey)
            .map_err(|_| VoteValidationError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&vote.voter_signature.bytes);
        let mut vote_clone = vote.clone();
        vote_clone.voter_signature.bytes = [0u8; 64];
        let payload =
            bincode::serialize(&vote_clone).map_err(|_| VoteValidationError::InvalidSignature)?;
        verifying_key
            .verify(&payload, &sig)
            .map_err(|_| VoteValidationError::InvalidSignature)?;
        // Masternode collateral validation is now implemented above
        Ok(())
    }
}
