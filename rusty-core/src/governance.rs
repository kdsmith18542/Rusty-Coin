use serde::{Deserialize, Serialize};
use rusty_shared_types::{Hash, PublicKey, OutPoint};
use std::collections::HashMap;
use rusty_shared_types::masternode::{MasternodeList, MasternodeID};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceState {
    pub active_proposals: HashMap<Hash, GovernanceProposalState>,
    // Add other fields as needed, e.g., treasury balance, past proposals
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposalState {
    pub proposal: GovernanceProposal,
    pub votes: HashMap<MasternodeID, GovernanceVote>,
    pub is_active: bool,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_votes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalOutcome {
    Approved,
    Rejected,
    Expired,
}

pub struct Governance<'a> {
    pub state: GovernanceState,
    pub masternode_list: &'a MasternodeList,
}

impl<'a> Governance<'a> {
    const GOVERNANCE_QUORUM: f64 = 0.6; // 60% minimum approval per spec

    pub fn new(masternode_list: &'a MasternodeList) -> Self {
        Self {
            state: GovernanceState {
                active_proposals: HashMap::new(),
            },
            masternode_list,
        }
    }

    pub fn process_proposal(&mut self, proposal: GovernanceProposal) -> Result<(), String> {
        // Validate proposal
        if proposal.start_block <= 0 {
            return Err("Proposal start block must be greater than 0".to_string());
        }
        if proposal.end_block <= proposal.start_block {
            return Err("Proposal end block must be after start block".to_string());
        }
        if self.state.active_proposals.contains_key(&proposal.hash) {
            return Err("Proposal with this ID already exists".to_string());
        }

        // Add to active_proposals
        let proposal_state = GovernanceProposalState {
            proposal: proposal.clone(),
            votes: HashMap::new(),
            is_active: true,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_votes: 0,
        };
        self.state.active_proposals.insert(proposal.hash, proposal_state);
        Ok(())
    }

    pub fn process_vote(&mut self, vote: GovernanceVote, current_block_height: u64) -> Result<(), String> {
        // Validate vote
        // Check if the voter is an active masternode
        let voter_mn_id: PublicKey = vote.voter;
        let mn_id = MasternodeID(OutPoint { txid: voter_mn_id, vout: 0 }); // Assuming vout 0 for MasternodeID from PublicKey
        if self.masternode_list.get_masternode(&mn_id).is_none() {
            return Err("Voter is not a registered masternode".to_string());
        }

        // Further validate vote (e.g., signature)

        // Update votes for the corresponding proposal
        if let Some(proposal_state) = self.state.active_proposals.get_mut(&vote.proposal_hash) {
            // Check if the proposal is active and within its voting period
            if !proposal_state.is_active || current_block_height < proposal_state.proposal.start_block || current_block_height > proposal_state.proposal.end_block {
                return Err("Proposal is not active or not within voting period".to_string());
            }
            // Fix: match on VoteType
            match vote.vote {
                VoteType::Yes => proposal_state.yes_votes += 1,
                VoteType::No => proposal_state.no_votes += 1,
                VoteType::Abstain => proposal_state.abstain_votes += 1,
            }
            proposal_state.total_votes += 1;
            proposal_state.votes.insert(mn_id, vote);
            Ok(())
        } else {
            Err("Proposal not found or not active".to_string())
        }
    }

    pub fn evaluate_proposals(&mut self, _current_block_height: u64) {
        let mut proposals_to_evaluate = Vec::new();
        for (proposal_hash, proposal_state) in self.state.active_proposals.iter() {
            if proposal_state.is_active /*&& current_block_height >= proposal_state.proposal.end_block*/ {
                proposals_to_evaluate.push(*proposal_hash);
            }
        }

        for proposal_hash in proposals_to_evaluate {
            if let Some(proposal_state) = self.state.active_proposals.get_mut(&proposal_hash) {
                proposal_state.is_active = false;

                // Simple majority rule for now
                if proposal_state.yes_votes > proposal_state.no_votes {
                    // proposal_state.outcome = Some(ProposalOutcome::Approved);
                } else if proposal_state.no_votes > proposal_state.yes_votes {
                    // proposal_state.outcome = Some(ProposalOutcome::Rejected);
                } else {
                    // Tie or no votes, consider it expired or rejected
                    // proposal_state.outcome = Some(ProposalOutcome::Expired);
                }
            }
        }
    }

    pub fn is_quorum_reached(&self, proposal_hash: &Hash) -> bool {
        let state = self.state.active_proposals.get(proposal_hash).unwrap();
        let total_voting_power = self.masternode_list.total_voting_power(); // Use the new method
        let approved_power = state.yes_votes;
        
        (approved_power as f64 / total_voting_power as f64) >= Self::GOVERNANCE_QUORUM
    }
}

// Note: MasternodeList methods should be implemented in rusty_shared_types
// to avoid orphan rule violations

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub hash: Hash,
    pub proposer: PublicKey,
    pub description: String,
    pub start_block: u64,
    pub end_block: u64,
    pub voting_power_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Yes = 0,
    No = 1,
    Abstain = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVote {
    pub hash: Hash,
    pub voter: PublicKey,
    pub proposal_hash: Hash,
    pub vote: VoteType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSystem {
    // This would typically interact with a database or a persistent store
    // For now, use in-memory for simplicity.
    proposals: std::collections::HashMap<Hash, GovernanceProposal>,
    votes: std::collections::HashMap<Hash, Vec<GovernanceVote>>,
}

impl GovernanceSystem {
    pub fn new() -> Self {
        GovernanceSystem {
            proposals: std::collections::HashMap::new(),
            votes: std::collections::HashMap::new(),
        }
    }

    pub fn submit_proposal(
        &mut self,
        proposal: GovernanceProposal,
    ) -> Result<(), String> {
        // In a real system, you'd verify the signature against the proposer's public key
        // and potentially check for a collateral deposit.
        if self.proposals.contains_key(&proposal.hash) {
            return Err("Proposal with this ID already exists".to_string());
        }
        self.proposals.insert(proposal.hash, proposal);
        Ok(())
    }

    pub fn cast_vote(
        &mut self,
        vote: GovernanceVote,
    ) -> Result<(), String> {
        // Verify the vote's signature
        // Check if the proposal exists and is in a voting state
        // Check if the voter is eligible (e.g., a masternode owner, ticket holder)
        if !self.proposals.contains_key(&vote.proposal_hash) {
            return Err("Proposal not found".to_string());
        }
        self.votes
            .entry(vote.proposal_hash)
            .or_default()
            .push(vote);
        Ok(())
    }

    pub fn get_proposal(&self, proposal_hash: Hash) -> Option<&GovernanceProposal> {
        self.proposals.get(&proposal_hash)
    }

    pub fn get_votes(&self, proposal_hash: Hash) -> Option<&Vec<GovernanceVote>> {
        self.votes.get(&proposal_hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVoteReceipt {
    pub proposal_hash: Hash,
    pub voter_id: PublicKey,
    pub vote: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVoteTally {
    pub proposal_hash: Hash,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_votes: u64,
}