//! Sidechain implementation
//!
//! This module provides comprehensive sidechain functionality including
//! federation management, fraud proofs, cross-chain transfers, validation,
//! and full integration with mainchain consensus.

pub mod cross_chain_communication;
pub mod cross_chain_processor;
pub mod federation_integrator;
pub mod federation_manager;
pub mod fraud_proofs;
pub mod inter_sidechain_transfer;
pub mod mainchain_validator;
pub mod proof_validation;
pub mod sidechain_consensus;
pub mod two_way_peg;
pub mod types;

// Re-export commonly used types and modules
pub use types::*;
pub use cross_chain_communication::CrossChainCommunication;
pub use cross_chain_processor::{CrossChainProcessor, MainchainInterface};
pub use federation_integrator::FederationIntegrator;
pub use federation_manager::FederationManager;
pub use mainchain_validator::MainchainValidator;
pub use sidechain_consensus::SidechainConsensus;
pub use two_way_peg::TwoWayPegManager;