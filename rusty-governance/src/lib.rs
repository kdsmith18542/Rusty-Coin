//! Rusty Coin Governance System
//!
//! This crate implements the governance protocol for Rusty Coin, including
//! proposal management, voting mechanisms, and stake burning for failed proposals.

pub mod governance_coordinator;
pub mod parameter_manager;
pub mod proposal_activation;
pub mod proposal_validation;
pub mod stake_burning;
pub mod vote_validation;
pub mod voting_coordinator;

pub use governance_coordinator::{
    GovernanceCoordinator, GovernanceCoordinatorConfig, GovernanceProcessingResult, GovernanceStats,
};
pub use parameter_manager::{
    ParameterCategory, ParameterChange, ParameterManager, ParameterManagerStats, ParameterMetadata,
    ParameterType, ParameterValue,
};
pub use proposal_activation::{
    ActivateProposalTx, ActivationConfig, ActivationStats, ProposalActivationManager,
};
pub use proposal_validation::{
    ProposalValidationConfig, ProposalValidationError, ProposalValidator,
};
pub use stake_burning::{
    StakeBurnStatistics, StakeBurningConfig, StakeBurningManager, StakeBurningReason,
};
pub use voting_coordinator::{
    ProposalOutcome, ProposalVotingStats, VotingConfig, VotingCoordinator, VotingSystemStats,
};

// Re-export commonly used types
pub use rusty_shared_types::governance::*;

mod vote_validation_tests;
