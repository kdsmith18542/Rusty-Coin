//! Voting coordination for governance proposals
//!
//! This module coordinates the voting process for governance proposals,
//! integrating with the stake burning system for failed proposals.

use log::{debug, error, info};

use crate::vote_validation::VoteValidator;
use rusty_core::consensus::state::BlockchainState;
use rusty_shared_types::{
    governance::{GovernanceProposal, GovernanceVote, VoteChoice},
    ConsensusParams, Hash, PublicKey, Transaction,
};

use crate::stake_burning::StakeBurningManager;
use std::collections::HashMap;

/// Represents the current state of a proposal's voting
/// Per spec 08_json_rpc_spec.md (Homestead Accord) - Bicameral governance
#[derive(Debug, Clone)]
pub struct ProposalVotingState {
    pub proposal: GovernanceProposal,
    pub votes: HashMap<PublicKey, GovernanceVote>, // voter_id -> vote (using PublicKey)

    // Combined vote counts (for backward compatibility)
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_voting_power: u64,

    // Bicameral vote counts - PoS Chamber
    pub pos_yes_votes: u64,
    pub pos_no_votes: u64,
    pub pos_abstain_votes: u64,
    pub pos_total_votes: u64,

    // Bicameral vote counts - Masternode Chamber
    pub mn_yes_votes: u64,
    pub mn_no_votes: u64,
    pub mn_abstain_votes: u64,
    pub mn_total_votes: u64,

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
    pub fn new(config: VotingConfig, stake_burning_manager: StakeBurningManager) -> Self {
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
            // Bicameral vote counts - initialized to 0
            pos_yes_votes: 0,
            pos_no_votes: 0,
            pos_abstain_votes: 0,
            pos_total_votes: 0,
            mn_yes_votes: 0,
            mn_no_votes: 0,
            mn_abstain_votes: 0,
            mn_total_votes: 0,
            is_active: true,
            outcome: None,
        };

        let proposal_id = voting_state.proposal.proposal_id;
        self.active_proposals.insert(proposal_id, voting_state);
        info!(
            "Added proposal {} to voting system",
            hex::encode(proposal_id)
        );
        Ok(())
    }

    /// Record a vote for a proposal
    pub fn record_vote(
        &mut self,
        vote: GovernanceVote,
        voter_power: u64,
        live_tickets: &rusty_core::consensus::pos::LiveTicketsPool,
        masternode_list: &rusty_shared_types::masternode::MasternodeList,
        required_ticket_value: u64,
        required_mn_collateral: u64,
    ) -> Result<(), String> {
        let proposal_state = self
            .active_proposals
            .get_mut(&vote.proposal_id)
            .ok_or("Proposal not found or not active")?;

        if !proposal_state.is_active {
            return Err("Proposal is not active".to_string());
        }

        // Check if voter has already voted
        if proposal_state.votes.contains_key(&vote.voter_id) {
            return Err("Voter has already voted on this proposal".to_string());
        }

        // --- NEW: Validate vote signature and eligibility ---
        let voter_pubkey = &vote.voter_id;
        VoteValidator::validate_vote(
            &vote,
            voter_pubkey,
            live_tickets,
            masternode_list,
            required_ticket_value,
            required_mn_collateral,
        )
        .map_err(|e| format!("Vote validation failed: {:?}", e))?;
        // --- END NEW ---

        // Update vote counts and total voting power for the proposal
        // Per spec: Separate tracking for PoS and Masternode chambers (bicameral)
        match vote.vote_choice {
            VoteChoice::Yes => {
                proposal_state.yes_votes += voter_power;
                match vote.voter_type {
                    rusty_shared_types::governance::VoterType::PosTicket => {
                        proposal_state.pos_yes_votes += 1; // Each ticket = 1 vote
                    }
                    rusty_shared_types::governance::VoterType::Masternode => {
                        proposal_state.mn_yes_votes += 1; // Each masternode = 1 vote
                    }
                }
            }
            VoteChoice::No => {
                proposal_state.no_votes += voter_power;
                match vote.voter_type {
                    rusty_shared_types::governance::VoterType::PosTicket => {
                        proposal_state.pos_no_votes += 1;
                    }
                    rusty_shared_types::governance::VoterType::Masternode => {
                        proposal_state.mn_no_votes += 1;
                    }
                }
            }
            VoteChoice::Abstain => {
                proposal_state.abstain_votes += voter_power;
                match vote.voter_type {
                    rusty_shared_types::governance::VoterType::PosTicket => {
                        proposal_state.pos_abstain_votes += 1;
                    }
                    rusty_shared_types::governance::VoterType::Masternode => {
                        proposal_state.mn_abstain_votes += 1;
                    }
                }
            }
        }
        proposal_state.total_voting_power += voter_power;

        // Update chamber-specific totals
        match vote.voter_type {
            rusty_shared_types::governance::VoterType::PosTicket => {
                proposal_state.pos_total_votes += 1;
            }
            rusty_shared_types::governance::VoterType::Masternode => {
                proposal_state.mn_total_votes += 1;
            }
        }

        // Store the vote
        proposal_state.votes.insert(vote.voter_id, vote.clone());

        info!(
            "Vote recorded for proposal {} by voter {}",
            hex::encode(vote.proposal_id),
            hex::encode(vote.voter_id)
        );
        Ok(())
    }

    /// Process proposals that have reached their end block
    /// Per spec 08_json_rpc_spec.md Section 8.3.3 - requires counts of eligible voters for quorum checks
    pub fn process_ended_proposals(
        &mut self,
        current_block_height: u64,
        consensus_params: &ConsensusParams,
        live_tickets_count: u32,
        active_masternodes_count: u32,
    ) -> Result<Vec<Hash>, String> {
        let ended_proposals: Vec<Hash> = self
            .active_proposals
            .iter()
            .filter(|(_, state)| {
                current_block_height
                    >= state.proposal.end_block_height + self.config.finalization_grace_period
            })
            .map(|(id, _)| *id)
            .collect();

        let mut finalized_proposals = Vec::new();

        for proposal_id in ended_proposals {
            if let Some(mut proposal_state) = self.active_proposals.remove(&proposal_id) {
                // Determine outcome with actual voter counts for quorum checks
                let outcome = self.determine_proposal_outcome(
                    &proposal_state,
                    current_block_height,
                    consensus_params,
                    live_tickets_count,
                    active_masternodes_count,
                );
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
                        proposal_state.yes_votes
                            + proposal_state.no_votes
                            + proposal_state.abstain_votes,
                        consensus_params,
                    ) {
                        Ok(Some(_pending_burn)) => {
                            info!(
                                "Scheduled stake burn for proposal {} due to {:?}",
                                hex::encode(proposal_id),
                                outcome
                            );
                        }
                        Ok(None) => {
                            debug!(
                                "No stake burn needed for proposal {}",
                                hex::encode(proposal_id)
                            );
                        }
                        Err(e) => {
                            error!("Failed to evaluate proposal for burning: {}", e);
                        }
                    }
                }

                self.finalized_proposals.insert(proposal_id, proposal_state);
                finalized_proposals.push(proposal_id);

                info!(
                    "Finalized proposal {} with outcome {:?}",
                    hex::encode(proposal_id),
                    outcome
                );
            }
        }

        Ok(finalized_proposals)
    }

    /// Determine the final outcome of a proposal
    /// Per spec 08_json_rpc_spec.md Section 8.3.3 - Bicameral Quorum and Supermajority Check
    fn determine_proposal_outcome(
        &self,
        proposal_state: &ProposalVotingState,
        current_block_height: u64,
        consensus_params: &ConsensusParams,
        live_tickets_count: u32,
        active_masternodes_count: u32,
    ) -> ProposalOutcome {
        // Check if voting period has actually ended
        if current_block_height < proposal_state.proposal.end_block_height {
            return ProposalOutcome::Expired; // Should not happen if filtered correctly
        }

        // Bicameral Quorum Check (Section 8.3.3)
        // PoS Quorum: YES + NO votes from PoS tickets >= POS_VOTING_QUORUM_PERCENTAGE of LIVE tickets
        // Masternode Quorum: YES + NO votes from Masternodes >= MN_VOTING_QUORUM_PERCENTAGE of ACTIVE Masternodes

        let pos_votes_cast = proposal_state.pos_yes_votes + proposal_state.pos_no_votes;
        let mn_votes_cast = proposal_state.mn_yes_votes + proposal_state.mn_no_votes;

        // Calculate required quorum thresholds
        let pos_quorum_required = (live_tickets_count as f64
            * consensus_params.pos_voting_quorum_percentage)
            .ceil() as u64;
        let mn_quorum_required = (active_masternodes_count as f64
            * consensus_params.mn_voting_quorum_percentage)
            .ceil() as u64;

        // Check if quorums are met (Section 8.3.3: "If EITHER quorum fails, the proposal is REJECTED")
        let pos_quorum_met = pos_votes_cast >= pos_quorum_required;
        let mn_quorum_met = mn_votes_cast >= mn_quorum_required;

        if !pos_quorum_met || !mn_quorum_met {
            // Quorum not met - proposal is REJECTED per spec
            return ProposalOutcome::InsufficientParticipation;
        }

        // Both quorums are met - proceed to supermajority check (Section 8.3.3)
        // Bicameral Supermajority Check: Both chambers must meet their respective approval thresholds

        // PoS Approval: YES votes / (YES + NO) >= POS_APPROVAL_PERCENTAGE (e.g., 75%)
        let pos_approval = if pos_votes_cast > 0 {
            (proposal_state.pos_yes_votes as f64 / pos_votes_cast as f64)
                >= consensus_params.pos_approval_percentage
        } else {
            false // No PoS votes cast (shouldn't happen if quorum is met)
        };

        // Masternode Approval: YES votes / (YES + NO) >= MN_APPROVAL_PERCENTAGE (e.g., 66%)
        let mn_approval = if mn_votes_cast > 0 {
            (proposal_state.mn_yes_votes as f64 / mn_votes_cast as f64)
                >= consensus_params.mn_approval_percentage
        } else {
            false // No masternode votes cast (shouldn't happen if quorum is met)
        };

        // Proposal is APPROVED only if BOTH chambers approve (Section 8.3.3)
        if pos_approval && mn_approval {
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
        self.active_proposals
            .get(proposal_id)
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
        self.active_proposals
            .values()
            .filter(|state| state.is_active)
            .map(|state| &state.proposal)
            .collect()
    }

    /// Get proposals by their outcome
    pub fn get_proposals_by_outcome(&self, outcome: &ProposalOutcome) -> Vec<&GovernanceProposal> {
        self.finalized_proposals
            .values()
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
        self.stake_burning_manager
            .execute_pending_burns(current_block_height, blockchain_state)
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
            total_burned_amount: self
                .stake_burning_manager
                .get_burn_statistics()
                .total_amount_burned,
            pending_burns: self
                .stake_burning_manager
                .get_burn_statistics()
                .pending_burns,
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
