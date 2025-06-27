//! Voting coordination for governance proposals
//! 
//! This module coordinates the voting process for governance proposals,
//! integrating with the stake burning system for failed proposals.

use std::collections::HashMap;
use log::{info, warn, error, debug};

use rusty_shared_types::{
    Hash, ConsensusParams,
    governance::{GovernanceProposal, GovernanceVote, VoteChoice, VoterType},
    masternode::{MasternodeList, MasternodeID},
};
use crate::stake_burning::{StakeBurningManager, StakeBurningReason};

/// Represents the current state of a proposal's voting
#[derive(Debug, Clone)]
pub struct ProposalVotingState {
    pub proposal: GovernanceProposal,
    pub votes: HashMap<Hash, GovernanceVote>, // voter_id -> vote
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_voting_power: u64,
    pub is_active: bool,
    pub outcome: Option<ProposalOutcome>,
}

/// Possible outcomes for a governance proposal
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOutcome {
    Approved,
    Rejected,
    Expired,
    InsufficientParticipation,
}

/// Configuration for voting coordination
#[derive(Debug, Clone)]
pub struct VotingConfig {
    /// Minimum participation threshold (0.0 to 1.0)
    pub min_participation_threshold: f64,
    /// Approval threshold for different proposal types
    pub approval_thresholds: HashMap<String, f64>,
    /// Grace period after voting ends before finalizing
    pub finalization_grace_period: u64,
}

impl Default for VotingConfig {
    fn default() -> Self {
        let mut approval_thresholds = HashMap::new();
        approval_thresholds.insert("ProtocolUpgrade".to_string(), 0.75);
        approval_thresholds.insert("ParameterChange".to_string(), 0.60);
        approval_thresholds.insert("TreasurySpend".to_string(), 0.66);

        Self {
            min_participation_threshold: 0.33,
            approval_thresholds,
            finalization_grace_period: 100, // ~4 hours
        }
    }
}

/// Coordinates voting for governance proposals
pub struct VotingCoordinator {
    config: VotingConfig,
    active_proposals: HashMap<Hash, ProposalVotingState>,
    finalized_proposals: HashMap<Hash, ProposalVotingState>,
    stake_burning_manager: StakeBurningManager,
}

impl VotingCoordinator {
    /// Create a new voting coordinator
    pub fn new(
        config: VotingConfig,
        stake_burning_manager: StakeBurningManager,
    ) -> Self {
        Self {
            config,
            active_proposals: HashMap::new(),
            finalized_proposals: HashMap::new(),
            stake_burning_manager,
        }
    }

    /// Add a new proposal to the voting system
    pub fn add_proposal(
        &mut self,
        proposal: GovernanceProposal,
        total_voting_power: u64,
    ) -> Result<(), String> {
        if self.active_proposals.contains_key(&proposal.proposal_id) {
            return Err("Proposal already exists".to_string());
        }

        let voting_state = ProposalVotingState {
            proposal,
            votes: HashMap::new(),
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_voting_power,
            is_active: true,
            outcome: None,
        };

        self.active_proposals.insert(voting_state.proposal.proposal_id, voting_state);
        info!("Added proposal {} to voting system", hex::encode(voting_state.proposal.proposal_id));
        Ok(())
    }

    /// Cast a vote for a proposal
    pub fn cast_vote(
        &mut self,
        vote: GovernanceVote,
        voter_power: u64,
    ) -> Result<(), String> {
        let proposal_state = self.active_proposals.get_mut(&vote.proposal_id)
            .ok_or("Proposal not found")?;

        if !proposal_state.is_active {
            return Err("Proposal is not active".to_string());
        }

        // Check if voter has already voted
        if proposal_state.votes.contains_key(&vote.voter_id) {
            return Err("Voter has already voted on this proposal".to_string());
        }

        // Update vote counts
        match vote.vote_choice {
            VoteChoice::Yes => proposal_state.yes_votes += voter_power,
            VoteChoice::No => proposal_state.no_votes += voter_power,
            VoteChoice::Abstain => proposal_state.abstain_votes += voter_power,
        }

        // Store the vote
        proposal_state.votes.insert(vote.voter_id, vote.clone());

        debug!("Vote cast for proposal {} by voter {}", 
               hex::encode(vote.proposal_id), hex::encode(vote.voter_id));
        Ok(())
    }

    /// Process proposals that have reached their end block
    pub fn process_ended_proposals(
        &mut self,
        current_block_height: u64,
        consensus_params: &ConsensusParams,
    ) -> Result<Vec<Hash>, String> {
        let ended_proposals: Vec<Hash> = self.active_proposals
            .iter()
            .filter(|(_, state)| {
                current_block_height >= state.proposal.end_block_height + self.config.finalization_grace_period
            })
            .map(|(id, _)| *id)
            .collect();

        let mut finalized_proposals = Vec::new();

        for proposal_id in ended_proposals {
            if let Some(mut proposal_state) = self.active_proposals.remove(&proposal_id) {
                // Determine outcome
                let outcome = self.determine_proposal_outcome(&proposal_state, consensus_params);
                proposal_state.outcome = Some(outcome.clone());
                proposal_state.is_active = false;

                // Handle stake burning if needed
                if self.should_burn_stake(&outcome) {
                    match self.stake_burning_manager.evaluate_proposal_for_burning(
                        &proposal_state.proposal,
                        current_block_height,
                        proposal_state.total_voting_power,
                        proposal_state.yes_votes,
                        proposal_state.no_votes,
                        proposal_state.yes_votes + proposal_state.no_votes + proposal_state.abstain_votes,
                        consensus_params,
                    ) {
                        Ok(Some(pending_burn)) => {
                            info!("Scheduled stake burn for proposal {} due to {:?}", 
                                  hex::encode(proposal_id), outcome);
                        }
                        Ok(None) => {
                            debug!("No stake burn needed for proposal {}", hex::encode(proposal_id));
                        }
                        Err(e) => {
                            error!("Failed to evaluate proposal for burning: {}", e);
                        }
                    }
                }

                self.finalized_proposals.insert(proposal_id, proposal_state);
                finalized_proposals.push(proposal_id);

                info!("Finalized proposal {} with outcome {:?}", hex::encode(proposal_id), outcome);
            }
        }

        Ok(finalized_proposals)
    }

    /// Determine the outcome of a proposal based on votes
    fn determine_proposal_outcome(
        &self,
        proposal_state: &ProposalVotingState,
        consensus_params: &ConsensusParams,
    ) -> ProposalOutcome {
        let total_votes = proposal_state.yes_votes + proposal_state.no_votes + proposal_state.abstain_votes;
        
        // Check participation threshold
        let participation_rate = if proposal_state.total_voting_power > 0 {
            total_votes as f64 / proposal_state.total_voting_power as f64
        } else {
            0.0
        };

        if participation_rate < self.config.min_participation_threshold {
            return ProposalOutcome::InsufficientParticipation;
        }

        // Get approval threshold for this proposal type
        let proposal_type_str = format!("{:?}", proposal_state.proposal.proposal_type);
        let approval_threshold = self.config.approval_thresholds
            .get(&proposal_type_str)
            .copied()
            .unwrap_or(0.60); // Default 60%

        // Calculate approval rate (excluding abstentions)
        let voting_votes = proposal_state.yes_votes + proposal_state.no_votes;
        if voting_votes == 0 {
            return ProposalOutcome::InsufficientParticipation;
        }

        let approval_rate = proposal_state.yes_votes as f64 / voting_votes as f64;

        if approval_rate >= approval_threshold {
            ProposalOutcome::Approved
        } else {
            ProposalOutcome::Rejected
        }
    }

    /// Check if stake should be burned for a given outcome
    fn should_burn_stake(&self, outcome: &ProposalOutcome) -> bool {
        matches!(outcome, 
            ProposalOutcome::Rejected | 
            ProposalOutcome::InsufficientParticipation
        )
    }

    /// Get voting statistics for a proposal
    pub fn get_proposal_stats(&self, proposal_id: &Hash) -> Option<ProposalVotingStats> {
        let state = self.active_proposals.get(proposal_id)
            .or_else(|| self.finalized_proposals.get(proposal_id))?;

        let total_votes = state.yes_votes + state.no_votes + state.abstain_votes;
        let participation_rate = if state.total_voting_power > 0 {
            total_votes as f64 / state.total_voting_power as f64
        } else {
            0.0
        };

        let approval_rate = if state.yes_votes + state.no_votes > 0 {
            state.yes_votes as f64 / (state.yes_votes + state.no_votes) as f64
        } else {
            0.0
        };

        Some(ProposalVotingStats {
            proposal_id: *proposal_id,
            yes_votes: state.yes_votes,
            no_votes: state.no_votes,
            abstain_votes: state.abstain_votes,
            total_votes,
            total_voting_power: state.total_voting_power,
            participation_rate,
            approval_rate,
            is_active: state.is_active,
            outcome: state.outcome.clone(),
        })
    }

    /// Get all active proposals
    pub fn get_active_proposals(&self) -> Vec<&GovernanceProposal> {
        self.active_proposals.values()
            .map(|state| &state.proposal)
            .collect()
    }

    /// Get proposals by outcome
    pub fn get_proposals_by_outcome(&self, outcome: &ProposalOutcome) -> Vec<&GovernanceProposal> {
        self.finalized_proposals.values()
            .filter(|state| state.outcome.as_ref() == Some(outcome))
            .map(|state| &state.proposal)
            .collect()
    }

    /// Execute pending stake burns
    pub fn execute_pending_burns(
        &mut self,
        current_block_height: u64,
        blockchain_state: &mut rusty_core::consensus::state::BlockchainState,
    ) -> Result<Vec<rusty_shared_types::Transaction>, String> {
        self.stake_burning_manager.execute_pending_burns(current_block_height, blockchain_state)
    }

    /// Get overall voting system statistics
    pub fn get_system_stats(&self) -> VotingSystemStats {
        let total_active = self.active_proposals.len();
        let total_finalized = self.finalized_proposals.len();
        
        let outcomes_count = self.finalized_proposals.values()
            .fold(HashMap::new(), |mut acc, state| {
                if let Some(ref outcome) = state.outcome {
                    *acc.entry(outcome.clone()).or_insert(0) += 1;
                }
                acc
            });

        let stake_burn_stats = self.stake_burning_manager.get_burn_statistics();

        VotingSystemStats {
            total_active_proposals: total_active,
            total_finalized_proposals: total_finalized,
            outcomes_count,
            total_burned_amount: stake_burn_stats.total_amount_burned,
            pending_burns: stake_burn_stats.pending_burns,
        }
    }
}

/// Statistics for a specific proposal's voting
#[derive(Debug, Clone)]
pub struct ProposalVotingStats {
    pub proposal_id: Hash,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_votes: u64,
    pub total_voting_power: u64,
    pub participation_rate: f64,
    pub approval_rate: f64,
    pub is_active: bool,
    pub outcome: Option<ProposalOutcome>,
}

/// Statistics for the overall voting system
#[derive(Debug, Clone)]
pub struct VotingSystemStats {
    pub total_active_proposals: usize,
    pub total_finalized_proposals: usize,
    pub outcomes_count: HashMap<ProposalOutcome, usize>,
    pub total_burned_amount: u64,
    pub pending_burns: usize,
}
