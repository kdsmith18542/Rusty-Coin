//! Rusty Coin Governance System
//!
//! This crate implements the governance protocol for Rusty Coin, including
//! proposal management, voting mechanisms, and stake burning for failed proposals.

pub mod stake_burning;
pub mod proposal_validation;
pub mod voting_coordinator;
pub mod proposal_activation;
pub mod governance_coordinator;
pub mod parameter_manager;

pub use stake_burning::{StakeBurningManager, StakeBurningConfig, StakeBurningReason, StakeBurnStatistics};
pub use proposal_validation::{ProposalValidator, ProposalValidationConfig, ProposalValidationError};
pub use voting_coordinator::{VotingCoordinator, VotingConfig, ProposalOutcome, ProposalVotingStats, VotingSystemStats};
pub use proposal_activation::{ProposalActivationManager, ActivationConfig, ActivateProposalTx, ActivationStats};
pub use governance_coordinator::{GovernanceCoordinator, GovernanceCoordinatorConfig, GovernanceProcessingResult, GovernanceStats};
pub use parameter_manager::{ParameterManager, ParameterChange, ParameterValue, ParameterType, ParameterCategory, ParameterMetadata, ParameterManagerStats};

// Re-export commonly used types
pub use rusty_shared_types::governance::*;
