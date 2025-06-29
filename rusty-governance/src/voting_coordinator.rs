//! Voting coordination for governance proposals
//! 
//! This module coordinates the voting process for governance proposals,
//! integrating with the stake burning system for failed proposals.

use log::{info, warn, error, debug};

use rusty_shared_types::{
    Hash, Transaction, ConsensusParams, PublicKey,
    governance::{GovernanceProposal, GovernanceVote, VoteChoice, VoterType},
    masternode::{MasternodeList, MasternodeID},
};
use rusty_core::consensus::state::BlockchainState;

use crate::stake_burning::{StakeBurningManager, StakeBurningConfig, StakeBurningReason};
use crate::proposal_validation::ProposalValidationError;
use std::collections::HashMap;
use std::time::Instant;

/// Represents the current state of a proposal's voting
#[derive(Debug, Clone)]
pub struct ProposalVotingState {
    pub proposal: GovernanceProposal,
    pub votes: HashMap<PublicKey, GovernanceVote>, // voter_id -> vote (using PublicKey)
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_voting_power: u64,
    pub is_active: bool,
    pub outcome: Option<ProposalOutcome>,
}

/// Possible outcomes for a governance proposal
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        approval_thresholds.insert("BugFix".to_string(), 0.80);
        approval_thresholds.insert("CommunityFund".to_string(), 0.70);

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
        current_block_height: u64,
    ) -> Result<(), String> {
        if self.active_proposals.contains_key(&proposal.proposal_id) {
            return Err("Proposal already exists".to_string());
        }

        // Ensure proposal is not already ended or started
        if current_block_height >= proposal.end_block_height {
            return Err("Cannot add a proposal that has already ended".to_string());
        }
        if current_block_height >= proposal.start_block_height {
            return Err("Cannot add a proposal that has already started voting".to_string());
        }

        let voting_state = ProposalVotingState {
            proposal: proposal.clone(),
            votes: HashMap::new(),
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_voting_power: 0, // This will be calculated when votes are cast
            is_active: true,
            outcome: None,
        };

        let proposal_id = voting_state.proposal.proposal_id;
        self.active_proposals.insert(proposal_id, voting_state);
        info!("Added proposal {} to voting system", hex::encode(proposal_id));
        Ok(())
    }

    /// Record a vote for a proposal
    pub fn record_vote(
        &mut self,
        vote: GovernanceVote,
        voter_power: u64,
    ) -> Result<(), String> {
        let proposal_state = self.active_proposals.get_mut(&vote.proposal_id)
            .ok_or("Proposal not found or not active")?;

        if !proposal_state.is_active {
            return Err("Proposal is not active".to_string());
        }

        // Check if voter has already voted
        if proposal_state.votes.contains_key(&vote.voter_id) {
            return Err("Voter has already voted on this proposal".to_string());
        }

        // Update vote counts and total voting power for the proposal
        match vote.vote_choice {
            VoteChoice::Yes => proposal_state.yes_votes += voter_power,
            VoteChoice::No => proposal_state.no_votes += voter_power,
            VoteChoice::Abstain => proposal_state.abstain_votes += voter_power,
        }
        proposal_state.total_voting_power += voter_power;

        // Store the vote
        proposal_state.votes.insert(vote.voter_id, vote.clone());

        info!("Vote recorded for proposal {} by voter {}", 
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
                let outcome = self.determine_proposal_outcome(&proposal_state, current_block_height, consensus_params);
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
                        Ok(Some(_pending_burn)) => {
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

    /// Determine the final outcome of a proposal
    fn determine_proposal_outcome(
        &self,
        proposal_state: &ProposalVotingState,
        current_block_height: u64,
        consensus_params: &ConsensusParams,
    ) -> ProposalOutcome {
        let total_votes_cast = proposal_state.yes_votes + proposal_state.no_votes + proposal_state.abstain_votes;
        let required_participation = (proposal_state.total_voting_power as f64) * self.config.min_participation_threshold;

        if total_votes_cast < required_participation as u64 {
            return ProposalOutcome::InsufficientParticipation;
        }

        // Check if voting period has actually ended
        if current_block_height < proposal_state.proposal.end_block_height {
            return ProposalOutcome::Expired; // Should not happen if filtered correctly
        }

        let proposal_type_str = format!("{:?}", proposal_state.proposal.proposal_type);
        let approval_threshold = self.config.approval_thresholds
            .get(&proposal_type_str)
            .copied()
            .unwrap_or(0.60); // Default to 60% if not specified

        if proposal_state.yes_votes as f64 >= (total_votes_cast as f64 * approval_threshold) {
            ProposalOutcome::Approved
        } else {
            ProposalOutcome::Rejected
        }
    }

    /// Check if stake should be burned based on proposal outcome
    fn should_burn_stake(&self, outcome: &ProposalOutcome) -> bool {
        match outcome {
            ProposalOutcome::Rejected | ProposalOutcome::InsufficientParticipation => true,
            _ => false,
        }
    }

    /// Get current voting statistics for a proposal
    pub fn get_proposal_stats(&self, proposal_id: &Hash) -> Option<ProposalVotingStats> {
        self.active_proposals.get(proposal_id)
            .or_else(|| self.finalized_proposals.get(proposal_id))
            .map(|state| {
                let total_votes_cast = state.yes_votes + state.no_votes + state.abstain_votes;
                let participation_rate = if state.total_voting_power > 0 {
                    total_votes_cast as f64 / state.total_voting_power as f64
                } else {
                    0.0
                };
                let approval_rate = if total_votes_cast > 0 {
                    state.yes_votes as f64 / total_votes_cast as f64
                } else {
                    0.0
                };

                ProposalVotingStats {
                    proposal_id: *proposal_id,
                    yes_votes: state.yes_votes,
                    no_votes: state.no_votes,
                    abstain_votes: state.abstain_votes,
                    total_votes: total_votes_cast,
                    total_voting_power: state.total_voting_power,
                    participation_rate,
                    approval_rate,
                    is_active: state.is_active,
                    outcome: state.outcome.clone(),
                }
            })
    }

    /// Get all currently active proposals
    pub fn get_active_proposals(&self) -> Vec<&GovernanceProposal> {
        self.active_proposals.values()
            .filter(|state| state.is_active)
            .map(|state| &state.proposal)
            .collect()
    }

    /// Get proposals by their outcome
    pub fn get_proposals_by_outcome(&self, outcome: &ProposalOutcome) -> Vec<&GovernanceProposal> {
        self.finalized_proposals.values()
            .filter(|state| state.outcome.as_ref() == Some(outcome))
            .map(|state| &state.proposal)
            .collect()
    }

    /// Execute pending stake burns for finalized proposals
    pub fn execute_pending_burns(
        &mut self,
        current_block_height: u64,
        blockchain_state: &mut BlockchainState,
    ) -> Result<Vec<Transaction>, String> {
        self.stake_burning_manager.execute_pending_burns(current_block_height, blockchain_state)
    }

    /// Get system-wide voting statistics
    pub fn get_system_stats(&self) -> VotingSystemStats {
        let mut outcomes_count = HashMap::new();
        for state in self.finalized_proposals.values() {
            if let Some(outcome) = &state.outcome {
                *outcomes_count.entry(outcome.clone()).or_insert(0) += 1;
            }
        }

        VotingSystemStats {
            total_active_proposals: self.active_proposals.len(),
            total_finalized_proposals: self.finalized_proposals.len(),
            outcomes_count,
            total_burned_amount: self.stake_burning_manager.get_burn_statistics().total_amount_burned,
            pending_burns: self.stake_burning_manager.get_burn_statistics().pending_burns,
        }
    }
}

/// Detailed statistics for a single proposal's voting progress
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

/// System-wide voting statistics
#[derive(Debug, Clone)]
pub struct VotingSystemStats {
    pub total_active_proposals: usize,
    pub total_finalized_proposals: usize,
    pub outcomes_count: HashMap<ProposalOutcome, usize>,
    pub total_burned_amount: u64,
    pub pending_burns: usize,
}
