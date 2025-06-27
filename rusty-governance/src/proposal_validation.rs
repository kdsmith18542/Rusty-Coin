//! Proposal validation for governance system
//! 
//! This module validates governance proposals before they are accepted
//! into the active proposal set, preventing malicious or invalid proposals.

use log::{info, warn, error, debug};
use rusty_shared_types::{
    Hash, ConsensusParams,
    governance::{GovernanceProposal, ProposalType},
};

/// Validation errors for governance proposals
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalValidationError {
    /// Proposal ID is invalid or already exists
    InvalidProposalId,
    /// Proposer signature is invalid
    InvalidSignature,
    /// Voting period is invalid (too short, too long, or malformed)
    InvalidVotingPeriod,
    /// Proposal type is not supported
    UnsupportedProposalType,
    /// Required fields are missing for the proposal type
    MissingRequiredFields,
    /// Proposal content violates protocol rules
    ProtocolViolation,
    /// Insufficient collateral provided
    InsufficientCollateral,
    /// Proposal title or description is invalid
    InvalidContent,
    /// Parameter change proposal has invalid target or value
    InvalidParameterChange,
    /// Treasury spend proposal exceeds available funds
    InsufficientTreasuryFunds,
    /// Proposal conflicts with existing active proposals
    ConflictingProposal,
}

/// Configuration for proposal validation
#[derive(Debug, Clone)]
pub struct ProposalValidationConfig {
    /// Minimum voting period in blocks
    pub min_voting_period: u64,
    /// Maximum voting period in blocks
    pub max_voting_period: u64,
    /// Minimum title length
    pub min_title_length: usize,
    /// Maximum title length
    pub max_title_length: usize,
    /// Required collateral amount
    pub required_collateral: u64,
    /// Maximum number of active proposals per proposer
    pub max_proposals_per_proposer: usize,
}

impl Default for ProposalValidationConfig {
    fn default() -> Self {
        Self {
            min_voting_period: 1000,    // ~2.5 days
            max_voting_period: 100000,  // ~250 days
            min_title_length: 10,
            max_title_length: 128,
            required_collateral: 1000_000_000, // 1000 RUST
            max_proposals_per_proposer: 3,
        }
    }
}

/// Validates governance proposals
pub struct ProposalValidator {
    config: ProposalValidationConfig,
}

impl ProposalValidator {
    /// Create a new proposal validator
    pub fn new(config: ProposalValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a governance proposal
    pub fn validate_proposal(
        &self,
        proposal: &GovernanceProposal,
        current_block_height: u64,
        existing_proposals: &[Hash],
        consensus_params: &ConsensusParams,
    ) -> Result<(), ProposalValidationError> {
        // Validate proposal ID uniqueness
        if existing_proposals.contains(&proposal.proposal_id) {
            return Err(ProposalValidationError::InvalidProposalId);
        }

        // Validate voting period
        self.validate_voting_period(proposal, current_block_height)?;

        // Validate proposal content
        self.validate_content(proposal)?;

        // Validate proposal type specific requirements
        self.validate_type_specific_requirements(proposal, consensus_params)?;

        // Validate collateral
        self.validate_collateral(proposal)?;

        // Validate signature (simplified - would use actual crypto verification)
        self.validate_signature(proposal)?;

        info!("Proposal {} passed validation", hex::encode(proposal.proposal_id));
        Ok(())
    }

    /// Validate voting period constraints
    fn validate_voting_period(
        &self,
        proposal: &GovernanceProposal,
        current_block_height: u64,
    ) -> Result<(), ProposalValidationError> {
        // Check that start block is in the future
        if proposal.start_block_height <= current_block_height {
            return Err(ProposalValidationError::InvalidVotingPeriod);
        }

        // Check that end block is after start block
        if proposal.end_block_height <= proposal.start_block_height {
            return Err(ProposalValidationError::InvalidVotingPeriod);
        }

        // Check voting period length
        let voting_period = proposal.end_block_height - proposal.start_block_height;
        if voting_period < self.config.min_voting_period || voting_period > self.config.max_voting_period {
            return Err(ProposalValidationError::InvalidVotingPeriod);
        }

        Ok(())
    }

    /// Validate proposal content
    fn validate_content(&self, proposal: &GovernanceProposal) -> Result<(), ProposalValidationError> {
        // Validate title length
        if proposal.title.len() < self.config.min_title_length || 
           proposal.title.len() > self.config.max_title_length {
            return Err(ProposalValidationError::InvalidContent);
        }

        // Check for valid characters in title
        if !proposal.title.chars().all(|c| c.is_ascii() && (c.is_alphanumeric() || c.is_whitespace() || ".,!?-_()[]{}".contains(c))) {
            return Err(ProposalValidationError::InvalidContent);
        }

        // Validate description hash is not empty
        if proposal.description_hash == [0u8; 32] {
            return Err(ProposalValidationError::InvalidContent);
        }

        Ok(())
    }

    /// Validate type-specific requirements
    fn validate_type_specific_requirements(
        &self,
        proposal: &GovernanceProposal,
        _consensus_params: &ConsensusParams,
    ) -> Result<(), ProposalValidationError> {
        match proposal.proposal_type {
            ProposalType::ProtocolUpgrade => {
                // Protocol upgrades should have code change hash
                if proposal.code_change_hash.is_none() {
                    return Err(ProposalValidationError::MissingRequiredFields);
                }
            }
            ProposalType::ParameterChange => {
                // Parameter changes should specify target parameter and new value
                if proposal.target_parameter.is_none() || proposal.new_value.is_none() {
                    return Err(ProposalValidationError::MissingRequiredFields);
                }

                // Validate parameter change is reasonable
                self.validate_parameter_change(proposal)?;
            }
            ProposalType::TreasurySpend => {
                // Treasury spends should have reasonable amounts
                // This would check against actual treasury balance in a real implementation
                if let Some(ref value_str) = proposal.new_value {
                    if let Ok(amount) = value_str.parse::<u64>() {
                        if amount == 0 || amount > 1_000_000_000_000 { // Max 1M RUST
                            return Err(ProposalValidationError::InsufficientTreasuryFunds);
                        }
                    } else {
                        return Err(ProposalValidationError::InvalidContent);
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate parameter change proposals
    fn validate_parameter_change(&self, proposal: &GovernanceProposal) -> Result<(), ProposalValidationError> {
        let target_param = proposal.target_parameter.as_ref().unwrap();
        let new_value = proposal.new_value.as_ref().unwrap();

        match target_param.as_str() {
            "block_time" => {
                if let Ok(time) = new_value.parse::<u64>() {
                    if time < 60 || time > 3600 { // 1 minute to 1 hour
                        return Err(ProposalValidationError::InvalidParameterChange);
                    }
                } else {
                    return Err(ProposalValidationError::InvalidParameterChange);
                }
            }
            "max_block_size" => {
                if let Ok(size) = new_value.parse::<u64>() {
                    if size < 1_000_000 || size > 100_000_000 { // 1MB to 100MB
                        return Err(ProposalValidationError::InvalidParameterChange);
                    }
                } else {
                    return Err(ProposalValidationError::InvalidParameterChange);
                }
            }
            "difficulty_adjustment_window" => {
                if let Ok(window) = new_value.parse::<u64>() {
                    if window < 10 || window > 10000 { // 10 to 10000 blocks
                        return Err(ProposalValidationError::InvalidParameterChange);
                    }
                } else {
                    return Err(ProposalValidationError::InvalidParameterChange);
                }
            }
            "masternode_collateral" => {
                if let Ok(collateral) = new_value.parse::<u64>() {
                    if collateral < 100_000_000 || collateral > 100_000_000_000 { // 100 to 100k RUST
                        return Err(ProposalValidationError::InvalidParameterChange);
                    }
                } else {
                    return Err(ProposalValidationError::InvalidParameterChange);
                }
            }
            _ => {
                // Unknown parameter
                return Err(ProposalValidationError::InvalidParameterChange);
            }
        }

        Ok(())
    }

    /// Validate collateral requirements
    fn validate_collateral(&self, proposal: &GovernanceProposal) -> Result<(), ProposalValidationError> {
        // Check that proposal has inputs (collateral)
        if proposal.inputs.is_empty() {
            return Err(ProposalValidationError::InsufficientCollateral);
        }

        // Calculate total input value (simplified - would need UTXO lookup)
        let total_collateral = proposal.outputs.iter()
            .map(|output| output.value)
            .sum::<u64>();

        if total_collateral < self.config.required_collateral {
            return Err(ProposalValidationError::InsufficientCollateral);
        }

        Ok(())
    }

    /// Validate proposal signature
    fn validate_signature(&self, _proposal: &GovernanceProposal) -> Result<(), ProposalValidationError> {
        // In a real implementation, this would verify the Ed25519 signature
        // against the proposer's public key and the proposal content
        
        // For now, just check that signature is not empty
        if _proposal.proposer_signature.is_empty() {
            return Err(ProposalValidationError::InvalidSignature);
        }

        Ok(())
    }

    /// Check for conflicting proposals
    pub fn check_conflicts(
        &self,
        proposal: &GovernanceProposal,
        active_proposals: &[GovernanceProposal],
    ) -> Result<(), ProposalValidationError> {
        for active in active_proposals {
            // Check for parameter change conflicts
            if proposal.proposal_type == ProposalType::ParameterChange &&
               active.proposal_type == ProposalType::ParameterChange {
                if proposal.target_parameter == active.target_parameter {
                    return Err(ProposalValidationError::ConflictingProposal);
                }
            }

            // Check for overlapping voting periods on similar proposals
            let proposal_period = proposal.start_block_height..=proposal.end_block_height;
            let active_period = active.start_block_height..=active.end_block_height;
            
            if proposal_period.start() <= active_period.end() && 
               proposal_period.end() >= active_period.start() {
                // Overlapping periods - check if proposals are similar
                if self.are_proposals_similar(proposal, active) {
                    return Err(ProposalValidationError::ConflictingProposal);
                }
            }
        }

        Ok(())
    }

    /// Check if two proposals are similar enough to conflict
    fn are_proposals_similar(&self, proposal1: &GovernanceProposal, proposal2: &GovernanceProposal) -> bool {
        // Same type and same target parameter
        if proposal1.proposal_type == proposal2.proposal_type {
            match proposal1.proposal_type {
                ProposalType::ParameterChange => {
                    proposal1.target_parameter == proposal2.target_parameter
                }
                ProposalType::ProtocolUpgrade => {
                    // Protocol upgrades are always conflicting if overlapping
                    true
                }
                ProposalType::TreasurySpend => {
                    // Treasury spends might conflict if they exceed available funds
                    // For simplicity, assume they don't conflict unless identical
                    proposal1.new_value == proposal2.new_value
                }
            }
        } else {
            false
        }
    }

    /// Get validation statistics
    pub fn get_validation_stats(&self) -> ProposalValidationStats {
        ProposalValidationStats {
            min_voting_period: self.config.min_voting_period,
            max_voting_period: self.config.max_voting_period,
            required_collateral: self.config.required_collateral,
            max_proposals_per_proposer: self.config.max_proposals_per_proposer,
        }
    }
}

/// Statistics about proposal validation
#[derive(Debug, Clone)]
pub struct ProposalValidationStats {
    pub min_voting_period: u64,
    pub max_voting_period: u64,
    pub required_collateral: u64,
    pub max_proposals_per_proposer: usize,
}
