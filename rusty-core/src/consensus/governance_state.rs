//! Manages the state of active governance proposals and votes.

use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;
use tracing::{event, Level};

use crate::consensus::error::ConsensusError;
use rusty_shared_types::{
    Block, BlockHeader, Hash, MasternodeID, PublicKey, Ticket, TicketId, Transaction, TxInput
};
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote, VoteChoice, ProposalType};

/// Represents the state of active governance proposals and votes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveProposals {
    /// Maps proposal IDs to their corresponding proposal data and votes.
    pub proposals: HashMap<Hash, (GovernanceProposal, HashMap<Hash, GovernanceVote>)>,
}

impl ActiveProposals {
    pub fn new() -> Self {
        ActiveProposals {
            proposals: HashMap::new(),
        }
    }

    /// Adds a new governance proposal to the active list.
    pub fn add_proposal(&mut self, proposal: GovernanceProposal) -> Result<(), ConsensusError> {
        let proposal_id = proposal.proposal_id.clone();
        if self.proposals.contains_key(&proposal_id) {
            return Err(ConsensusError::ProposalAlreadyExists(proposal_id));
        }
        self.proposals.insert(proposal_id, (proposal, HashMap::new()));
        Ok(())
    }

    /// Records a vote for a given proposal.
    pub fn record_vote(&mut self, vote: GovernanceVote) -> Result<(), ConsensusError> {
        let proposal_id = vote.proposal_id.clone();
        let voter_id = vote.voter_id.clone();
        
        let (_, votes) = self.proposals.get_mut(&proposal_id)
            .ok_or_else(|| ConsensusError::ProposalNotFound(proposal_id.clone()))?;
            
        votes.insert(voter_id, vote);
        Ok(())
    }

    /// Retrieves an active proposal by its ID.
    pub fn get_proposal(&self, proposal_id: &Hash) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id).map(|(proposal, _)| proposal)
    }

    /// Retrieves votes for a specific proposal.
    pub fn get_votes_for_proposal(&self, proposal_id: &Hash) -> Option<&HashMap<Hash, GovernanceVote>> {
        self.proposals.get(proposal_id).map(|(_, votes)| votes)
    }

    /// Removes an expired or resolved proposal and its votes.
    pub fn remove_proposal(&mut self, proposal_id: &Hash) -> Result<(), ConsensusError> {
        if self.proposals.remove(proposal_id).is_none() {
            return Err(ConsensusError::ProposalNotFound(proposal_id.clone()));
        }
        Ok(())
    }

    /// Removes a specific vote for a given proposal and voter.
    pub fn remove_vote(&mut self, proposal_id: &Hash, voter_id: &Hash) -> Result<(), ConsensusError> {
        let (_, votes) = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ConsensusError::ProposalNotFound(proposal_id.clone()))?;
            
        if votes.remove(voter_id).is_none() {
            return Err(ConsensusError::VoteNotFound(proposal_id.clone(), voter_id.clone()));
        }
        Ok(())
    }

    // TODO: Implement quorum and supermajority check methods here, or in a governance-specific module
    // These methods would need access to the current block height, live tickets, and masternode list
    pub fn evaluate_proposal_at_height(&self, proposal_id: &Hash, current_height: u64, 
        live_tickets_count: u64, active_masternode_count: u64,
        pos_quorum_percentage: f64, mn_quorum_percentage: f64,
        pos_approval_percentage: f64, mn_approval_percentage: f64
    ) -> Result<ProposalOutcome, ConsensusError> {
        let proposal = self.get_proposal(proposal_id)
            .ok_or(ConsensusError::Internal("Proposal not found for evaluation.".to_string()))?;

        if current_height < proposal.start_block_height || current_height > proposal.end_block_height {
            return Ok(ProposalOutcome::InProgress); // Or Expired if past end_block_height
        }

        let votes = self.get_votes_for_proposal(proposal_id)
            .ok_or(ConsensusError::Internal("Votes not found for proposal.".to_string()))?;

        let (mut pos_yes, mut pos_no, mut pos_abstain) = (0, 0, 0);
        let (mut mn_yes, mut mn_no, mut mn_abstain) = (0, 0, 0);

        // This part needs real data for voter type, which is not in VoteChoice.
        // It should be passed in from the transaction during validation.
        // For now, assuming votes are correctly categorized externally.
        // A more robust solution would embed VoterType in GovernanceVote.

        // Dummy aggregation for now, will refine with actual voter types
        for (_voter_id, vote) in votes.iter() {
            // In a real scenario, you'd query the blockchain state to determine if _voter_id is PoS or MN
            // This would involve looking up the ticket or masternode entry.
            // For this example, we'll just randomly assign for demonstration.
            match rand::random::<bool>() { // Placeholder: replace with actual voter type check
                true => { // PoS
                    match vote.vote_choice {
                        VoteChoice::Yes => pos_yes += 1,
                        VoteChoice::No => pos_no += 1,
                        VoteChoice::Abstain => pos_abstain += 1,
                    }
                },
                false => { // Masternode
                    match vote.vote_choice {
                        VoteChoice::Yes => mn_yes += 1,
                        VoteChoice::No => mn_no += 1,
                        VoteChoice::Abstain => mn_abstain += 1,
                    }
                }
            }
        }

        let pos_total_cast = pos_yes + pos_no;
        let mn_total_cast = mn_yes + mn_no;

        // Quorum Check
        // Needs theoretical max live tickets and active masternodes, which are external inputs.
        // Assuming current_live_tickets and current_active_masternodes are passed in.
        // These values would come from the BlockchainState.
        let pos_quorum_met = (pos_total_cast as f64 / live_tickets_count as f64) >= pos_quorum_percentage;
        let mn_quorum_met = (mn_total_cast as f64 / active_masternode_count as f64) >= mn_quorum_percentage;

        if !pos_quorum_met || !mn_quorum_met {
            return Ok(ProposalOutcome::Rejected { reason: "Quorum not met".to_string() });
        }

        // Supermajority Check
        let pos_approval_met = (pos_yes as f64 / pos_total_cast as f64) >= pos_approval_percentage;
        let mn_approval_met = (mn_yes as f64 / mn_total_cast as f64) >= mn_approval_percentage;

        if pos_approval_met && mn_approval_met {
            Ok(ProposalOutcome::Passed)
        } else {
            Ok(ProposalOutcome::Rejected { reason: "Supermajority not met".to_string() })
        }
    }
}

/// Represents the outcome of a governance proposal.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOutcome {
    Passed,
    Rejected { reason: String },
    InProgress,
    Expired,
}

impl std::hash::Hash for ProposalOutcome {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            ProposalOutcome::Passed => 0u8.hash(state),
            ProposalOutcome::Rejected { reason } => {
                1u8.hash(state);
                reason.hash(state);
            }
            ProposalOutcome::InProgress => 2u8.hash(state),
            ProposalOutcome::Expired => 3u8.hash(state),
        }
    }
}
