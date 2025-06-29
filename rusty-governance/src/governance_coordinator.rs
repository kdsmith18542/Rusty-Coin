//! Comprehensive governance coordinator that integrates all governance components
//! 
//! This module provides a unified interface for managing the entire governance
//! lifecycle from proposal submission to activation.

use log::{info, error};

use rusty_shared_types::{
    Hash, Transaction, ConsensusParams,
    governance::{GovernanceProposal, GovernanceVote, ApprovalProof, ProposalType},
};
use rusty_core::consensus::state::BlockchainState;

use crate::{
    stake_burning::{StakeBurningManager, StakeBurningConfig},
    proposal_validation::{ProposalValidator, ProposalValidationConfig, ProposalValidationError},
    voting_coordinator::{VotingCoordinator, VotingConfig, ProposalOutcome},
    proposal_activation::{ProposalActivationManager, ActivationConfig, ActivateProposalTx},
    parameter_manager::{ParameterManager, ParameterChange},
};


/// Configuration for the governance coordinator
#[derive(Debug, Clone)]
pub struct GovernanceCoordinatorConfig {
    pub stake_burning: StakeBurningConfig,
    pub proposal_validation: ProposalValidationConfig,
    pub voting: VotingConfig,
    pub activation: ActivationConfig,
}

impl Default for GovernanceCoordinatorConfig {
    fn default() -> Self {
        Self {
            stake_burning: StakeBurningConfig::default(),
            proposal_validation: ProposalValidationConfig::default(),
            voting: VotingConfig::default(),
            activation: ActivationConfig::default(),
        }
    }
}

/// Comprehensive governance coordinator
pub struct GovernanceCoordinator {
    config: GovernanceCoordinatorConfig,
    stake_burning_manager: StakeBurningManager,
    proposal_validator: ProposalValidator,
    voting_coordinator: VotingCoordinator,
    activation_manager: ProposalActivationManager,
    parameter_manager: ParameterManager,
}

impl GovernanceCoordinator {
    /// Create a new governance coordinator
    pub fn new(config: GovernanceCoordinatorConfig) -> Self {
        let stake_burning_manager = StakeBurningManager::new(config.stake_burning.clone());
        let proposal_validator = ProposalValidator::new(config.proposal_validation.clone());
        let voting_coordinator = VotingCoordinator::new(
            config.voting.clone(),
            StakeBurningManager::new(config.stake_burning.clone()),
        );
        let activation_manager = ProposalActivationManager::new(config.activation.clone());
        let parameter_manager = ParameterManager::new();

        Self {
            config,
            stake_burning_manager,
            proposal_validator,
            voting_coordinator,
            activation_manager,
            parameter_manager,
        }
    }

    /// Process a new governance proposal
    pub fn process_governance_proposal(
        &mut self,
        proposal: GovernanceProposal,
        current_block_height: u64,
        existing_proposals: &[Hash],
        consensus_params: &ConsensusParams,
        total_voting_power: u64,
    ) -> Result<(), String> {
        self.proposal_validator.validate_proposal(&proposal, current_block_height, existing_proposals, consensus_params)?;
        self.voting_coordinator.add_proposal(proposal, current_block_height)
    }

    /// Process a new governance vote
    pub fn process_governance_vote(
        &mut self,
        vote: GovernanceVote,
        voter_power: u64,
    ) -> Result<(), String> {
        self.voting_coordinator.record_vote(vote, voter_power)
    }

    /// Process proposals that have ended and handle activation/burning
    pub fn process_ended_proposals(
        &mut self,
        current_block_height: u64,
        consensus_params: &ConsensusParams,
    ) -> Result<GovernanceProcessingResult, String> {
        // Process ended proposals
        let finalized_proposals = self.voting_coordinator.process_ended_proposals(
            current_block_height,
            consensus_params,
        )?;

        let mut approved_proposals = Vec::new();
        let mut rejected_proposals = Vec::new();

        // Handle approved and rejected proposals
        for proposal_id in &finalized_proposals {
            if let Some(stats) = self.voting_coordinator.get_proposal_stats(&proposal_id) {
                match stats.outcome {
                    Some(ProposalOutcome::Approved) => {
                        // Schedule for activation
                        if let Some(proposal) = self.get_proposal_by_id(proposal_id) {
                            let approval_proof = ApprovalProof {
                                total_voting_power: stats.total_voting_power,
                                yes_votes: stats.yes_votes,
                                no_votes: stats.no_votes,
                                abstain_votes: stats.abstain_votes,
                                approval_percentage_bp: Self::f64_to_u64_bp(stats.approval_rate),
                                required_threshold_bp: Self::f64_to_u64_bp(self.get_required_threshold(&proposal)),
                                voting_end_height: current_block_height,
                                voting_state_hash: self.calculate_voting_state_hash(&stats),
                            };

                            // For parameter changes, validate and schedule the parameter change
                            if proposal.proposal_type == ProposalType::ParameterChange {
                                match self.parameter_manager.validate_parameter_change(&proposal) {
                                    Ok(parameter_change) => {
                                        let activation_height = current_block_height + consensus_params.activation_delay_blocks;
                                        self.parameter_manager.schedule_parameter_change(parameter_change, activation_height)?;
                                        info!("Scheduled parameter change for proposal {}", hex::encode(*proposal_id));
                                    }
                                    Err(e) => {
                                        error!("Failed to validate parameter change for proposal {}: {}", hex::encode(*proposal_id), e);
                                    }
                                }
                            }

                            // Clone proposal to avoid borrow conflicts
                            let proposal_clone = proposal.clone();

                            self.activation_manager.schedule_activation(
                                proposal_clone,
                                approval_proof,
                                current_block_height,
                            )?;

                            approved_proposals.push(*proposal_id);
                        }
                    }
                    Some(ProposalOutcome::Rejected) |
                    Some(ProposalOutcome::InsufficientParticipation) => {
                        rejected_proposals.push(*proposal_id);
                    }
                    _ => {}
                }
            }
        }

        Ok(GovernanceProcessingResult {
            finalized_proposals,
            approved_proposals,
            rejected_proposals,
        })
    }

    /// Process an activation transaction
    pub fn process_activation_transaction(
        &mut self,
        activation_tx: &ActivateProposalTx,
        blockchain_state: &mut BlockchainState,
    ) -> Result<(), String> {
        self.activation_manager.process_activation(activation_tx, blockchain_state)
    }

    /// Apply pending parameter changes at the current block height
    pub fn apply_parameter_changes(
        &mut self,
        current_block_height: u64,
        consensus_params: &mut rusty_shared_types::ConsensusParams,
    ) -> Result<Vec<ParameterChange>, String> {
        self.parameter_manager.apply_pending_changes(current_block_height, consensus_params)
    }

    /// Execute pending stake burns
    pub fn execute_pending_burns(
        &mut self,
        current_block_height: u64,
        blockchain_state: &mut BlockchainState,
    ) -> Result<Vec<Transaction>, String> {
        self.voting_coordinator.execute_pending_burns(current_block_height, blockchain_state)
    }

    /// Get proposals that can be activated at current height
    pub fn get_activatable_proposals(&self, current_block_height: u64) -> Vec<Hash> {
        self.activation_manager.get_activatable_proposals(current_block_height)
    }

    /// Create an activation transaction for a proposal
    pub fn create_activation_transaction(
        &self,
        proposal_id: &Hash,
        activator_private_key: &ed25519_dalek::SigningKey,
        current_block_height: u64,
        fee_input: rusty_shared_types::TxInput,
        change_output: Option<rusty_shared_types::TxOutput>,
    ) -> Result<ActivateProposalTx, String> {
        self.activation_manager.create_activation_transaction(
            proposal_id,
            activator_private_key,
            current_block_height,
            fee_input,
            change_output,
        )
    }

    /// Get comprehensive governance statistics
    pub fn get_governance_stats(&self) -> GovernanceStats {
        let voting_stats = self.voting_coordinator.get_system_stats();
        let burn_stats = self.stake_burning_manager.get_burn_statistics();
        let activation_stats = self.activation_manager.get_activation_stats();
        let validation_stats = self.proposal_validator.get_validation_stats();
        let parameter_stats = self.parameter_manager.get_stats();

        GovernanceStats {
            active_proposals: voting_stats.total_active_proposals,
            finalized_proposals: voting_stats.total_finalized_proposals,
            pending_activations: activation_stats.pending_activations,
            activated_proposals: activation_stats.activated_proposals,
            total_burned_amount: burn_stats.total_amount_burned,
            pending_burns: burn_stats.pending_burns,
            validation_config: validation_stats,
            parameter_stats,
        }
    }

    /// Get proposal by ID (helper method)
    fn get_proposal_by_id(&self, _proposal_id: &Hash) -> Option<GovernanceProposal> {
        // This would need to be implemented to retrieve proposals from storage
        // For now, return None as a placeholder
        None
    }

    /// Get required threshold for a proposal type
    fn get_required_threshold(&self, proposal: &GovernanceProposal) -> f64 {
        let proposal_type_str = format!("{:?}", proposal.proposal_type);
        self.config.voting.approval_thresholds
            .get(&proposal_type_str)
            .copied()
            .unwrap_or(0.60)
    }

    /// Helper to convert f64 threshold to u64 basis points for comparison
    fn f64_to_u64_bp(value: f64) -> u64 {
        (value * 10_000.0).round() as u64
    }

    /// Calculate voting state hash
    fn calculate_voting_state_hash(&self, stats: &crate::voting_coordinator::ProposalVotingStats) -> Hash {
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&stats.proposal_id);
        hash_data.extend_from_slice(&stats.yes_votes.to_le_bytes());
        hash_data.extend_from_slice(&stats.no_votes.to_le_bytes());
        hash_data.extend_from_slice(&stats.abstain_votes.to_le_bytes());
        hash_data.extend_from_slice(&stats.total_voting_power.to_le_bytes());
        blake3::hash(&hash_data).into()
    }

    /// Check if a proposal has been activated
    pub fn is_proposal_activated(&self, proposal_id: &Hash) -> bool {
        self.activation_manager.is_proposal_activated(proposal_id)
    }

    /// Check if a proposal has been burned
    pub fn is_proposal_burned(&self, proposal_id: &Hash) -> bool {
        self.stake_burning_manager.is_proposal_burned(proposal_id)
    }

    /// Get active proposals
    pub fn get_active_proposals(&self) -> Vec<&GovernanceProposal> {
        self.voting_coordinator.get_active_proposals()
    }

    /// Get proposals by outcome
    pub fn get_proposals_by_outcome(&self, outcome: &ProposalOutcome) -> Vec<&GovernanceProposal> {
        self.voting_coordinator.get_proposals_by_outcome(outcome)
    }

    /// Validate an activation transaction
    pub fn validate_activation_transaction(
        &self,
        activation_tx: &ActivateProposalTx,
        current_block_height: u64,
    ) -> Result<(), String> {
        self.activation_manager.validate_activation_transaction(activation_tx, current_block_height)
    }

    /// Get activation details for a proposal
    pub fn get_activation_details(&self, proposal_id: &Hash) -> Option<&crate::proposal_activation::ActivatedProposal> {
        self.activation_manager.get_activation_details(proposal_id)
    }

    /// Get burn details for a proposal
    pub fn get_burn_details(&self, proposal_id: &Hash) -> Option<&crate::stake_burning::ExecutedBurn> {
        self.stake_burning_manager.get_burn_details(proposal_id)
    }

    /// Get parameter metadata
    pub fn get_parameter_metadata(&self, parameter_name: &str) -> Option<&crate::parameter_manager::ParameterMetadata> {
        self.parameter_manager.get_parameter_metadata(parameter_name)
    }

    /// Get all registered parameters
    pub fn get_all_parameters(&self) -> Vec<&crate::parameter_manager::ParameterMetadata> {
        self.parameter_manager.get_all_parameters()
    }

    /// Get parameters by category
    pub fn get_parameters_by_category(&self, category: &crate::parameter_manager::ParameterCategory) -> Vec<&crate::parameter_manager::ParameterMetadata> {
        self.parameter_manager.get_parameters_by_category(category)
    }

    /// Get pending parameter changes
    pub fn get_pending_parameter_changes(&self) -> &std::collections::HashMap<Hash, ParameterChange> {
        self.parameter_manager.get_pending_changes()
    }

    /// Get parameter change history
    pub fn get_parameter_change_history(&self) -> &[ParameterChange] {
        self.parameter_manager.get_change_history()
    }
}

/// Result of processing ended proposals
#[derive(Debug, Clone)]
pub struct GovernanceProcessingResult {
    pub finalized_proposals: Vec<Hash>,
    pub approved_proposals: Vec<Hash>,
    pub rejected_proposals: Vec<Hash>,
}

/// Comprehensive governance statistics
#[derive(Debug, Clone)]
pub struct GovernanceStats {
    pub active_proposals: usize,
    pub finalized_proposals: usize,
    pub pending_activations: usize,
    pub activated_proposals: usize,
    pub total_burned_amount: u64,
    pub pending_burns: usize,
    pub validation_config: crate::proposal_validation::ProposalValidationStats,
    pub parameter_stats: crate::parameter_manager::ParameterManagerStats,
}
