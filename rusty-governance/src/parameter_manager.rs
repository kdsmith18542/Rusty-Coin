//! Runtime parameter change management for governance proposals
//!
//! This module implements the system for applying parameter changes through
//! governance proposals, including validation, scheduling, and runtime updates.
//! Now integrated with live blockchain consensus state for real-time parameter values.

use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use rusty_shared_types::{
    governance::{GovernanceProposal, ProposalType},
    ConsensusParams, Hash,
};

use rusty_core::consensus::state::BlockchainState;

/// Represents a parameter change that can be applied to the system
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterChange {
    pub parameter_name: String,
    pub old_value: ParameterValue,
    pub new_value: ParameterValue,
    pub proposal_id: Hash,
    pub activation_height: u64,
}

/// Represents different types of parameter values
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterValue {
    U64(u64),
    U32(u32),
    F64(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

impl ParameterValue {
    /// Parse a string value into the appropriate parameter type
    pub fn parse_from_string(value: &str, param_type: &ParameterType) -> Result<Self, String> {
        match param_type {
            ParameterType::U64 => value
                .parse::<u64>()
                .map(ParameterValue::U64)
                .map_err(|_| format!("Invalid u64 value: {}", value)),
            ParameterType::U32 => value
                .parse::<u32>()
                .map(ParameterValue::U32)
                .map_err(|_| format!("Invalid u32 value: {}", value)),
            ParameterType::F64 => value
                .parse::<f64>()
                .map(ParameterValue::F64)
                .map_err(|_| format!("Invalid f64 value: {}", value)),
            ParameterType::Bool => value
                .parse::<bool>()
                .map(ParameterValue::Bool)
                .map_err(|_| format!("Invalid bool value: {}", value)),
            ParameterType::String => Ok(ParameterValue::String(value.to_string())),
            ParameterType::Bytes => hex::decode(value)
                .map(ParameterValue::Bytes)
                .map_err(|_| format!("Invalid hex bytes: {}", value)),
        }
    }

    /// Convert parameter value to string representation
    pub fn to_string(&self) -> String {
        match self {
            ParameterValue::U64(v) => v.to_string(),
            ParameterValue::U32(v) => v.to_string(),
            ParameterValue::F64(v) => v.to_string(),
            ParameterValue::Bool(v) => v.to_string(),
            ParameterValue::String(v) => v.clone(),
            ParameterValue::Bytes(v) => hex::encode(v),
        }
    }
}

/// Parameter type information
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterType {
    U64,
    U32,
    F64,
    Bool,
    String,
    Bytes,
}

/// Parameter metadata including validation rules
#[derive(Debug, Clone)]
pub struct ParameterMetadata {
    pub name: String,
    pub param_type: ParameterType,
    pub description: String,
    pub min_value: Option<ParameterValue>,
    pub max_value: Option<ParameterValue>,
    pub requires_restart: bool,
    pub category: ParameterCategory,
}

/// Categories of parameters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterCategory {
    Consensus,
    Economic,
    Network,
    Governance,
    Security,
    Performance,
}

/// Manages runtime parameter changes with live blockchain consensus state integration
pub struct ParameterManager {
    /// Registry of all known parameters
    parameter_registry: HashMap<String, ParameterMetadata>,
    /// Pending parameter changes scheduled for future activation
    pending_changes: HashMap<Hash, ParameterChange>,
    /// History of applied parameter changes
    change_history: Vec<ParameterChange>,
    /// Mapping of block height to parameter changes applied at that height
    changes_by_height: HashMap<u64, Vec<ParameterChange>>,
    /// Live reference to blockchain state for real-time parameter values
    blockchain_state: Option<Arc<rusty_core::consensus::state::BlockchainState>>,
    /// Live reference to consensus parameters
    consensus_params: Option<Arc<ConsensusParams>>,
}

impl ParameterManager {
    /// Create a new parameter manager
    pub fn new() -> Self {
        let mut manager = Self {
            parameter_registry: HashMap::new(),
            pending_changes: HashMap::new(),
            change_history: Vec::new(),
            changes_by_height: HashMap::new(),
            blockchain_state: None,
            consensus_params: None,
        };

        // Register all known parameters
        manager.register_consensus_parameters();
        manager.register_economic_parameters();
        manager.register_network_parameters();
        manager.register_governance_parameters();
        manager.register_security_parameters();

        manager
    }

    /// Create a parameter manager connected to live blockchain state
    pub fn new_with_blockchain_state(
        blockchain_state: Arc<BlockchainState>,
        consensus_params: Arc<ConsensusParams>,
    ) -> Self {
        let mut manager = Self::new();
        manager.blockchain_state = Some(blockchain_state);
        manager.consensus_params = Some(consensus_params);
        manager
    }

    /// Connect parameter manager to live blockchain state
    pub fn connect_to_blockchain_state(
        &mut self,
        blockchain_state: Arc<BlockchainState>,
        consensus_params: Arc<ConsensusParams>,
    ) {
        self.blockchain_state = Some(blockchain_state);
        self.consensus_params = Some(consensus_params);
    }

    /// Update consensus parameters reference
    pub fn update_consensus_params(&mut self, consensus_params: Arc<ConsensusParams>) {
        self.consensus_params = Some(consensus_params);
    }

    /// Register consensus-related parameters
    fn register_consensus_parameters(&mut self) {
        self.register_parameter(ParameterMetadata {
            name: "min_block_time".to_string(),
            param_type: ParameterType::U64,
            description: "Minimum time between blocks in seconds".to_string(),
            min_value: Some(ParameterValue::U64(30)),
            max_value: Some(ParameterValue::U64(3600)),
            requires_restart: false,
            category: ParameterCategory::Consensus,
        });

        self.register_parameter(ParameterMetadata {
            name: "difficulty_adjustment_window".to_string(),
            param_type: ParameterType::U32,
            description: "Number of blocks for difficulty adjustment".to_string(),
            min_value: Some(ParameterValue::U32(10)),
            max_value: Some(ParameterValue::U32(10000)),
            requires_restart: false,
            category: ParameterCategory::Consensus,
        });

        self.register_parameter(ParameterMetadata {
            name: "halving_interval".to_string(),
            param_type: ParameterType::U64,
            description: "Block interval for reward halving".to_string(),
            min_value: Some(ParameterValue::U64(50000)),
            max_value: Some(ParameterValue::U64(1000000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "max_block_size".to_string(),
            param_type: ParameterType::U64,
            description: "Maximum block size in bytes".to_string(),
            min_value: Some(ParameterValue::U64(1_000_000)),
            max_value: Some(ParameterValue::U64(100_000_000)),
            requires_restart: false,
            category: ParameterCategory::Network,
        });

        self.register_parameter(ParameterMetadata {
            name: "max_tx_size".to_string(),
            param_type: ParameterType::U64,
            description: "Maximum transaction size in bytes".to_string(),
            min_value: Some(ParameterValue::U64(1000)),
            max_value: Some(ParameterValue::U64(10_000_000)),
            requires_restart: false,
            category: ParameterCategory::Network,
        });

        self.register_parameter(ParameterMetadata {
            name: "coinbase_maturity".to_string(),
            param_type: ParameterType::U32,
            description: "Coinbase maturity period in blocks".to_string(),
            min_value: Some(ParameterValue::U32(1)),
            max_value: Some(ParameterValue::U32(1000)),
            requires_restart: false,
            category: ParameterCategory::Consensus,
        });

        self.register_parameter(ParameterMetadata {
            name: "dust_limit".to_string(),
            param_type: ParameterType::U64,
            description: "Minimum value for transaction outputs in satoshis".to_string(),
            min_value: Some(ParameterValue::U64(1)),
            max_value: Some(ParameterValue::U64(100_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "grace_period_blocks".to_string(),
            param_type: ParameterType::U64,
            description: "Grace period before non-participating tickets can be slashed".to_string(),
            min_value: Some(ParameterValue::U64(10)),
            max_value: Some(ParameterValue::U64(10000)),
            requires_restart: false,
            category: ParameterCategory::Consensus,
        });

        self.register_parameter(ParameterMetadata {
            name: "slash_forgiveness_period".to_string(),
            param_type: ParameterType::U64,
            description: "Period for repeated non-participation penalties".to_string(),
            min_value: Some(ParameterValue::U64(100)),
            max_value: Some(ParameterValue::U64(100000)),
            requires_restart: false,
            category: ParameterCategory::Consensus,
        });

        self.register_parameter(ParameterMetadata {
            name: "malicious_behavior_slash_percentage".to_string(),
            param_type: ParameterType::F64,
            description: "Percentage of ticket value burned for malicious behavior".to_string(),
            min_value: Some(ParameterValue::F64(0.1)),
            max_value: Some(ParameterValue::F64(1.0)),
            requires_restart: false,
            category: ParameterCategory::Security,
        });
    }

    /// Register economic parameters
    fn register_economic_parameters(&mut self) {
        self.register_parameter(ParameterMetadata {
            name: "ticket_price".to_string(),
            param_type: ParameterType::U64,
            description: "Base ticket price for PoS voting".to_string(),
            min_value: Some(ParameterValue::U64(100_000)),
            max_value: Some(ParameterValue::U64(1_000_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "min_stake".to_string(),
            param_type: ParameterType::U64,
            description: "Required collateral for masternode registration".to_string(),
            min_value: Some(ParameterValue::U64(100_000_000)),
            max_value: Some(ParameterValue::U64(100_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "pos_reward_ratio".to_string(),
            param_type: ParameterType::F64,
            description: "Percentage of block reward for PoS stakers".to_string(),
            min_value: Some(ParameterValue::F64(0.1)),
            max_value: Some(ParameterValue::F64(0.9)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "initial_block_reward".to_string(),
            param_type: ParameterType::U64,
            description: "Initial block reward in satoshis".to_string(),
            min_value: Some(ParameterValue::U64(1_000_000)),
            max_value: Some(ParameterValue::U64(100_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "ticket_maturity".to_string(),
            param_type: ParameterType::U32,
            description: "Ticket maturity period in blocks".to_string(),
            min_value: Some(ParameterValue::U32(1)),
            max_value: Some(ParameterValue::U32(1000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "ticket_expiry".to_string(),
            param_type: ParameterType::U32,
            description: "Ticket expiry period in blocks".to_string(),
            min_value: Some(ParameterValue::U32(1000)),
            max_value: Some(ParameterValue::U32(100000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "max_ticket_price".to_string(),
            param_type: ParameterType::U64,
            description: "Maximum allowed ticket price".to_string(),
            min_value: Some(ParameterValue::U64(1_000_000)),
            max_value: Some(ParameterValue::U64(10_000_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });

        self.register_parameter(ParameterMetadata {
            name: "min_ticket_price".to_string(),
            param_type: ParameterType::U64,
            description: "Minimum allowed ticket price".to_string(),
            min_value: Some(ParameterValue::U64(1000)),
            max_value: Some(ParameterValue::U64(1_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Economic,
        });
    }

    /// Register network parameters
    fn register_network_parameters(&mut self) {
        self.register_parameter(ParameterMetadata {
            name: "max_connections".to_string(),
            param_type: ParameterType::U32,
            description: "Maximum number of peer connections".to_string(),
            min_value: Some(ParameterValue::U32(8)),
            max_value: Some(ParameterValue::U32(1000)),
            requires_restart: true,
            category: ParameterCategory::Network,
        });
    }

    /// Register governance parameters
    fn register_governance_parameters(&mut self) {
        self.register_parameter(ParameterMetadata {
            name: "proposal_stake_amount".to_string(),
            param_type: ParameterType::U64,
            description: "Required stake for governance proposals".to_string(),
            min_value: Some(ParameterValue::U64(1_000_000_000)),
            max_value: Some(ParameterValue::U64(100_000_000_000)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "voting_period_blocks".to_string(),
            param_type: ParameterType::U64,
            description: "Duration of governance voting period in blocks".to_string(),
            min_value: Some(ParameterValue::U64(1000)),
            max_value: Some(ParameterValue::U64(100000)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "activation_delay_blocks".to_string(),
            param_type: ParameterType::U64,
            description: "Delay between approval and activation".to_string(),
            min_value: Some(ParameterValue::U64(100)),
            max_value: Some(ParameterValue::U64(10000)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "pos_voting_quorum_percentage".to_string(),
            param_type: ParameterType::F64,
            description: "Required PoS voting quorum percentage".to_string(),
            min_value: Some(ParameterValue::F64(0.1)),
            max_value: Some(ParameterValue::F64(1.0)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "mn_voting_quorum_percentage".to_string(),
            param_type: ParameterType::F64,
            description: "Required masternode voting quorum percentage".to_string(),
            min_value: Some(ParameterValue::F64(0.1)),
            max_value: Some(ParameterValue::F64(1.0)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "pos_approval_percentage".to_string(),
            param_type: ParameterType::F64,
            description: "Required PoS approval percentage".to_string(),
            min_value: Some(ParameterValue::F64(0.5)),
            max_value: Some(ParameterValue::F64(1.0)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });

        self.register_parameter(ParameterMetadata {
            name: "mn_approval_percentage".to_string(),
            param_type: ParameterType::F64,
            description: "Required masternode approval percentage".to_string(),
            min_value: Some(ParameterValue::F64(0.5)),
            max_value: Some(ParameterValue::F64(1.0)),
            requires_restart: false,
            category: ParameterCategory::Governance,
        });
    }

    /// Register security parameters
    fn register_security_parameters(&mut self) {
        self.register_parameter(ParameterMetadata {
            name: "pose_challenge_period_blocks".to_string(),
            param_type: ParameterType::U64,
            description: "Period between PoSe challenges".to_string(),
            min_value: Some(ParameterValue::U64(10)),
            max_value: Some(ParameterValue::U64(1000)),
            requires_restart: false,
            category: ParameterCategory::Security,
        });

        self.register_parameter(ParameterMetadata {
            name: "max_pose_failures".to_string(),
            param_type: ParameterType::U32,
            description: "Maximum PoSe failures before slashing".to_string(),
            min_value: Some(ParameterValue::U32(1)),
            max_value: Some(ParameterValue::U32(10)),
            requires_restart: false,
            category: ParameterCategory::Security,
        });
    }

    /// Register a parameter in the registry
    fn register_parameter(&mut self, metadata: ParameterMetadata) {
        self.parameter_registry
            .insert(metadata.name.clone(), metadata);
    }

    /// Validate a parameter change proposal
    pub fn validate_parameter_change(
        &self,
        proposal: &GovernanceProposal,
        consensus_params: &ConsensusParams,
    ) -> Result<ParameterChange, String> {
        if proposal.proposal_type != ProposalType::ParameterChange {
            return Err("Not a parameter change proposal".to_string());
        }

        let parameter_name = proposal
            .target_parameter
            .as_ref()
            .ok_or("Missing target parameter")?;
        let new_value_str = proposal.new_value.as_ref().ok_or("Missing new value")?;

        // Check if parameter exists
        let metadata = self
            .parameter_registry
            .get(parameter_name)
            .ok_or_else(|| format!("Unknown parameter: {}", parameter_name))?;

        // Parse new value
        let new_value = ParameterValue::parse_from_string(new_value_str, &metadata.param_type)?;

        // Validate value range
        if let Some(ref min_val) = metadata.min_value {
            if !self.is_value_greater_or_equal(&new_value, min_val) {
                return Err(format!(
                    "Value {} is below minimum {}",
                    new_value.to_string(),
                    min_val.to_string()
                ));
            }
        }

        if let Some(ref max_val) = metadata.max_value {
            if !self.is_value_less_or_equal(&new_value, max_val) {
                return Err(format!(
                    "Value {} is above maximum {}",
                    new_value.to_string(),
                    max_val.to_string()
                ));
            }
        }

        // Get current value from live consensus parameters or provided fallback
        let old_value = self.get_current_parameter_value_from_consensus(parameter_name, consensus_params)?;

        Ok(ParameterChange {
            parameter_name: parameter_name.clone(),
            old_value,
            new_value,
            proposal_id: proposal.proposal_id,
            activation_height: 0, // Will be set when scheduled
        })
    }

    /// Schedule a parameter change for activation
    pub fn schedule_parameter_change(
        &mut self,
        mut change: ParameterChange,
        activation_height: u64,
    ) -> Result<(), String> {
        change.activation_height = activation_height;

        // Check for conflicts with existing pending changes
        for (_, pending) in &self.pending_changes {
            if pending.parameter_name == change.parameter_name
                && pending.activation_height == activation_height
            {
                return Err(format!(
                    "Conflicting parameter change for {} at height {}",
                    change.parameter_name, activation_height
                ));
            }
        }

        self.pending_changes
            .insert(change.proposal_id, change.clone());

        info!(
            "Scheduled parameter change: {} = {} at height {}",
            change.parameter_name,
            change.new_value.to_string(),
            activation_height
        );

        Ok(())
    }

    /// Apply pending parameter changes at the current block height
    pub fn apply_pending_changes(
        &mut self,
        current_height: u64,
        consensus_params: &mut ConsensusParams,
    ) -> Result<Vec<ParameterChange>, String> {
        let ready_changes: Vec<Hash> = self
            .pending_changes
            .iter()
            .filter(|(_, change)| change.activation_height <= current_height)
            .map(|(id, _)| *id)
            .collect();

        let mut applied_changes = Vec::new();

        for proposal_id in ready_changes {
            if let Some(change) = self.pending_changes.remove(&proposal_id) {
                self.apply_parameter_change(&change, consensus_params)?;
                self.change_history.push(change.clone());
                applied_changes.push(change.clone());

                // Track changes by height for rollback purposes
                self.changes_by_height
                    .entry(current_height)
                    .or_insert_with(Vec::new)
                    .push(change);
            }
        }

        if !applied_changes.is_empty() {
            info!(
                "Applied {} parameter changes at height {}",
                applied_changes.len(),
                current_height
            );
        }

        Ok(applied_changes)
    }

    /// Apply a single parameter change to consensus parameters
    fn apply_parameter_change(
        &self,
        change: &ParameterChange,
        consensus_params: &mut ConsensusParams,
    ) -> Result<(), String> {
        match change.parameter_name.as_str() {
            "min_block_time" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.min_block_time = value;
                } else {
                    return Err("Invalid value type for min_block_time".to_string());
                }
            }
            "difficulty_adjustment_window" => {
                if let ParameterValue::U32(value) = change.new_value {
                    consensus_params.difficulty_adjustment_window = value;
                } else {
                    return Err("Invalid value type for difficulty_adjustment_window".to_string());
                }
            }
            "halving_interval" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.halving_interval = value;
                } else {
                    return Err("Invalid value type for halving_interval".to_string());
                }
            }
            "max_block_size" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.max_block_size = value;
                } else {
                    return Err("Invalid value type for max_block_size".to_string());
                }
            }
            "max_tx_size" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.max_tx_size = value as usize;
                } else {
                    return Err("Invalid value type for max_tx_size".to_string());
                }
            }
            "coinbase_maturity" => {
                if let ParameterValue::U32(value) = change.new_value {
                    consensus_params.coinbase_maturity = value;
                } else {
                    return Err("Invalid value type for coinbase_maturity".to_string());
                }
            }
            "dust_limit" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.dust_limit = value;
                } else {
                    return Err("Invalid value type for dust_limit".to_string());
                }
            }
            "grace_period_blocks" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.grace_period_blocks = value;
                } else {
                    return Err("Invalid value type for grace_period_blocks".to_string());
                }
            }
            "slash_forgiveness_period" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.slash_forgiveness_period = value;
                } else {
                    return Err("Invalid value type for slash_forgiveness_period".to_string());
                }
            }
            "malicious_behavior_slash_percentage" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.malicious_behavior_slash_percentage = value;
                } else {
                    return Err(
                        "Invalid value type for malicious_behavior_slash_percentage".to_string()
                    );
                }
            }
            "ticket_price" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.ticket_price = value;
                } else {
                    return Err("Invalid value type for ticket_price".to_string());
                }
            }
            "min_stake" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.min_stake = value;
                } else {
                    return Err("Invalid value type for min_stake".to_string());
                }
            }
            "pos_reward_ratio" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.pos_reward_ratio = value;
                } else {
                    return Err("Invalid value type for pos_reward_ratio".to_string());
                }
            }
            "initial_block_reward" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.initial_block_reward = value;
                } else {
                    return Err("Invalid value type for initial_block_reward".to_string());
                }
            }
            "ticket_maturity" => {
                if let ParameterValue::U32(value) = change.new_value {
                    consensus_params.ticket_maturity = value;
                } else {
                    return Err("Invalid value type for ticket_maturity".to_string());
                }
            }
            "ticket_expiry" => {
                if let ParameterValue::U32(value) = change.new_value {
                    consensus_params.ticket_expiry = value;
                } else {
                    return Err("Invalid value type for ticket_expiry".to_string());
                }
            }
            "max_ticket_price" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.max_ticket_price = value;
                } else {
                    return Err("Invalid value type for max_ticket_price".to_string());
                }
            }
            "min_ticket_price" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.min_ticket_price = value;
                } else {
                    return Err("Invalid value type for min_ticket_price".to_string());
                }
            }
            "proposal_stake_amount" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.proposal_stake_amount = value;
                } else {
                    return Err("Invalid value type for proposal_stake_amount".to_string());
                }
            }
            "voting_period_blocks" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.voting_period_blocks = value;
                } else {
                    return Err("Invalid value type for voting_period_blocks".to_string());
                }
            }
            "activation_delay_blocks" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.activation_delay_blocks = value;
                } else {
                    return Err("Invalid value type for activation_delay_blocks".to_string());
                }
            }
            "pos_voting_quorum_percentage" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.pos_voting_quorum_percentage = value;
                } else {
                    return Err("Invalid value type for pos_voting_quorum_percentage".to_string());
                }
            }
            "mn_voting_quorum_percentage" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.mn_voting_quorum_percentage = value;
                } else {
                    return Err("Invalid value type for mn_voting_quorum_percentage".to_string());
                }
            }
            "pos_approval_percentage" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.pos_approval_percentage = value;
                } else {
                    return Err("Invalid value type for pos_approval_percentage".to_string());
                }
            }
            "mn_approval_percentage" => {
                if let ParameterValue::F64(value) = change.new_value {
                    consensus_params.mn_approval_percentage = value;
                } else {
                    return Err("Invalid value type for mn_approval_percentage".to_string());
                }
            }
            "pose_challenge_period_blocks" => {
                if let ParameterValue::U64(value) = change.new_value {
                    consensus_params.pose_challenge_period_blocks = value;
                } else {
                    return Err("Invalid value type for pose_challenge_period_blocks".to_string());
                }
            }
            "max_pose_failures" => {
                if let ParameterValue::U32(value) = change.new_value {
                    consensus_params.max_pose_failures = value;
                } else {
                    return Err("Invalid value type for max_pose_failures".to_string());
                }
            }
            _ => {
                return Err(format!("Unknown parameter: {}", change.parameter_name));
            }
        }

        info!(
            "Applied parameter change: {} = {}",
            change.parameter_name,
            change.new_value.to_string()
        );

        Ok(())
    }

    /// Get current value of a parameter from live blockchain consensus state
    /// This is the enhanced version that reads from actual blockchain state
    pub fn get_current_parameter_value(&self, parameter_name: &str) -> Result<ParameterValue, String> {
        // First try to get from live consensus parameters if available
        if let Some(ref consensus_params) = self.consensus_params {
            return self.get_current_parameter_value_from_live_consensus(parameter_name, consensus_params);
        }

        // Fallback to error if not connected to live state
        Err(format!(
            "Parameter manager not connected to live blockchain state. Cannot get current value for parameter: {}",
            parameter_name
        ))
    }

    /// Get current parameter value from live consensus parameters
    fn get_current_parameter_value_from_live_consensus(
        &self,
        parameter_name: &str,
        consensus_params: &ConsensusParams,
    ) -> Result<ParameterValue, String> {
        // Get the actual current value from the live consensus params
        match parameter_name {
            "min_block_time" => Ok(ParameterValue::U64(consensus_params.min_block_time)),
            "difficulty_adjustment_window" => Ok(ParameterValue::U32(
                consensus_params.difficulty_adjustment_window,
            )),
            "halving_interval" => Ok(ParameterValue::U64(consensus_params.halving_interval)),
            "max_block_size" => Ok(ParameterValue::U64(consensus_params.max_block_size)),
            "max_tx_size" => Ok(ParameterValue::U64(consensus_params.max_tx_size as u64)),
            "coinbase_maturity" => Ok(ParameterValue::U32(consensus_params.coinbase_maturity)),
            "dust_limit" => Ok(ParameterValue::U64(consensus_params.dust_limit)),
            "grace_period_blocks" => Ok(ParameterValue::U64(consensus_params.grace_period_blocks)),
            "slash_forgiveness_period" => Ok(ParameterValue::U64(
                consensus_params.slash_forgiveness_period,
            )),
            "malicious_behavior_slash_percentage" => Ok(ParameterValue::F64(
                consensus_params.malicious_behavior_slash_percentage,
            )),
            "ticket_price" => Ok(ParameterValue::U64(consensus_params.ticket_price)),
            "min_stake" => Ok(ParameterValue::U64(consensus_params.min_stake)),
            "pos_reward_ratio" => Ok(ParameterValue::F64(consensus_params.pos_reward_ratio)),
            "initial_block_reward" => {
                Ok(ParameterValue::U64(consensus_params.initial_block_reward))
            }
            "ticket_maturity" => Ok(ParameterValue::U32(consensus_params.ticket_maturity)),
            "ticket_expiry" => Ok(ParameterValue::U32(consensus_params.ticket_expiry)),
            "max_ticket_price" => Ok(ParameterValue::U64(consensus_params.max_ticket_price)),
            "min_ticket_price" => Ok(ParameterValue::U64(consensus_params.min_ticket_price)),
            "proposal_stake_amount" => {
                Ok(ParameterValue::U64(consensus_params.proposal_stake_amount))
            }
            "voting_period_blocks" => {
                Ok(ParameterValue::U64(consensus_params.voting_period_blocks))
            }
            "activation_delay_blocks" => Ok(ParameterValue::U64(
                consensus_params.activation_delay_blocks,
            )),
            "pos_voting_quorum_percentage" => Ok(ParameterValue::F64(
                consensus_params.pos_voting_quorum_percentage,
            )),
            "mn_voting_quorum_percentage" => Ok(ParameterValue::F64(
                consensus_params.mn_voting_quorum_percentage,
            )),
            "pos_approval_percentage" => Ok(ParameterValue::F64(
                consensus_params.pos_approval_percentage,
            )),
            "mn_approval_percentage" => {
                Ok(ParameterValue::F64(consensus_params.mn_approval_percentage))
            }
            "pose_challenge_period_blocks" => Ok(ParameterValue::U64(
                consensus_params.pose_challenge_period_blocks,
            )),
            "max_pose_failures" => Ok(ParameterValue::U32(consensus_params.max_pose_failures)),
            _ => Err(format!("Unknown parameter: {}", parameter_name)),
        }
    }

    /// Get current parameter value from provided consensus parameters (fallback method)
    fn get_current_parameter_value_from_consensus(
        &self,
        parameter_name: &str,
        consensus_params: &ConsensusParams,
    ) -> Result<ParameterValue, String> {
        self.get_current_parameter_value_from_live_consensus(parameter_name, consensus_params)
    }

    /// Compare parameter values for validation
    fn is_value_greater_or_equal(&self, value: &ParameterValue, min: &ParameterValue) -> bool {
        match (value, min) {
            (ParameterValue::U64(v), ParameterValue::U64(m)) => v >= m,
            (ParameterValue::U32(v), ParameterValue::U32(m)) => v >= m,
            (ParameterValue::F64(v), ParameterValue::F64(m)) => v >= m,
            _ => false,
        }
    }

    fn is_value_less_or_equal(&self, value: &ParameterValue, max: &ParameterValue) -> bool {
        match (value, max) {
            (ParameterValue::U64(v), ParameterValue::U64(m)) => v <= m,
            (ParameterValue::U32(v), ParameterValue::U32(m)) => v <= m,
            (ParameterValue::F64(v), ParameterValue::F64(m)) => v <= m,
            _ => false,
        }
    }

    /// Get parameter metadata
    pub fn get_parameter_metadata(&self, parameter_name: &str) -> Option<&ParameterMetadata> {
        self.parameter_registry.get(parameter_name)
    }

    /// Get all registered parameters
    pub fn get_all_parameters(&self) -> Vec<&ParameterMetadata> {
        self.parameter_registry.values().collect()
    }

    /// Get parameters by category
    pub fn get_parameters_by_category(
        &self,
        category: &ParameterCategory,
    ) -> Vec<&ParameterMetadata> {
        self.parameter_registry
            .values()
            .filter(|meta| meta.category == *category)
            .collect()
    }

    /// Get pending changes
    pub fn get_pending_changes(&self) -> &HashMap<Hash, ParameterChange> {
        &self.pending_changes
    }

    /// Get change history
    pub fn get_change_history(&self) -> &[ParameterChange] {
        &self.change_history
    }

    /// Get statistics about parameter management
    pub fn get_stats(&self) -> ParameterManagerStats {
        ParameterManagerStats {
            total_parameters: self.parameter_registry.len(),
            pending_changes: self.pending_changes.len(),
            applied_changes: self.change_history.len(),
            changes_by_height_count: self.changes_by_height.len(),
            earliest_change_height: self.changes_by_height.keys().min().copied(),
            latest_change_height: self.changes_by_height.keys().max().copied(),
            parameters_by_category: self.parameter_registry.values().fold(
                HashMap::new(),
                |mut acc, meta| {
                    *acc.entry(meta.category.clone()).or_insert(0) += 1;
                    acc
                },
            ),
            is_connected_to_blockchain_state: self.blockchain_state.is_some() && self.consensus_params.is_some(),
        }
    }

    /// Rollback parameter changes from a specific block height and above
    /// This is used when blocks are reverted/reorganized
    pub fn rollback_changes_from_height(
        &mut self,
        from_height: u64,
        consensus_params: &mut ConsensusParams,
    ) -> Result<Vec<ParameterChange>, String> {
        let mut reverted_changes = Vec::new();
        let mut heights_to_remove = Vec::new();

        // Find all changes at or above the specified height
        for (&height, changes) in &self.changes_by_height {
            if height >= from_height {
                heights_to_remove.push(height);
                for change in changes {
                    // Revert the change by applying the old value
                    let revert_change = ParameterChange {
                        parameter_name: change.parameter_name.clone(),
                        old_value: change.new_value.clone(),
                        new_value: change.old_value.clone(),
                        proposal_id: change.proposal_id,
                        activation_height: height,
                    };

                    self.apply_parameter_change(&revert_change, consensus_params)?;
                    reverted_changes.push(change.clone());
                }
            }
        }

        // Remove the reverted changes from tracking
        for height in heights_to_remove {
            self.changes_by_height.remove(&height);
        }

        // Remove reverted changes from history
        self.change_history
            .retain(|change| change.activation_height < from_height);

        if !reverted_changes.is_empty() {
            info!(
                "Reverted {} parameter changes from height {} and above",
                reverted_changes.len(),
                from_height
            );
        }

        Ok(reverted_changes)
    }

    /// Cancel a pending parameter change by proposal ID
    pub fn cancel_pending_change(&mut self, proposal_id: Hash) -> Option<ParameterChange> {
        let removed = self.pending_changes.remove(&proposal_id);
        if removed.is_some() {
            info!(
                "Cancelled pending parameter change for proposal: {:?}",
                proposal_id
            );
        }
        removed
    }

    /// Get changes applied at a specific height
    pub fn get_changes_at_height(&self, height: u64) -> Option<&Vec<ParameterChange>> {
        self.changes_by_height.get(&height)
    }

    /// Get all changes applied at or after a specific height
    pub fn get_changes_from_height(&self, from_height: u64) -> Vec<&ParameterChange> {
        self.changes_by_height
            .iter()
            .filter(|(&height, _)| height >= from_height)
            .flat_map(|(_, changes)| changes.iter())
            .collect()
    }

    /// Get the height range of applied changes
    pub fn get_change_height_range(&self) -> Option<(u64, u64)> {
        if self.changes_by_height.is_empty() {
            return None;
        }

        let min_height = *self.changes_by_height.keys().min().unwrap();
        let max_height = *self.changes_by_height.keys().max().unwrap();
        Some((min_height, max_height))
    }

    /// Check if parameter manager is connected to live blockchain state
    pub fn is_connected_to_blockchain_state(&self) -> bool {
        self.blockchain_state.is_some() && self.consensus_params.is_some()
    }

    /// Get current blockchain height from live state
    pub fn get_current_block_height(&self) -> Option<u64> {
        self.blockchain_state
            .as_ref()
            .and_then(|state| state.get_current_block_height().ok())
    }
}

/// Statistics about parameter management
#[derive(Debug, Clone)]
pub struct ParameterManagerStats {
    pub total_parameters: usize,
    pub pending_changes: usize,
    pub applied_changes: usize,
    pub changes_by_height_count: usize,
    pub earliest_change_height: Option<u64>,
    pub latest_change_height: Option<u64>,
    pub parameters_by_category: HashMap<ParameterCategory, usize>,
    pub is_connected_to_blockchain_state: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::{ConsensusParams, Hash};

    fn create_test_hash(id: u8) -> Hash {
        let mut hash = [0u8; 32];
        hash[0] = id;
        hash
    }

    #[test]
    fn test_parameter_rollback() {
        let mut manager = ParameterManager::new();
        let mut consensus_params = ConsensusParams::default();

        // Create a parameter change
        let change1 = ParameterChange {
            parameter_name: "min_block_time".to_string(),
            old_value: ParameterValue::U64(150),
            new_value: ParameterValue::U64(200),
            proposal_id: create_test_hash(1),
            activation_height: 100,
        };

        let change2 = ParameterChange {
            parameter_name: "difficulty_adjustment_window".to_string(),
            old_value: ParameterValue::U32(2016),
            new_value: ParameterValue::U32(4032),
            proposal_id: create_test_hash(2),
            activation_height: 150,
        };

        // Schedule and apply changes
        manager
            .schedule_parameter_change(change1.clone(), 100)
            .unwrap();
        manager
            .schedule_parameter_change(change2.clone(), 150)
            .unwrap();

        // Apply changes at height 100
        let applied1 = manager
            .apply_pending_changes(100, &mut consensus_params)
            .unwrap();
        assert_eq!(applied1.len(), 1);
        assert_eq!(consensus_params.min_block_time, 200);

        // Apply changes at height 150
        let applied2 = manager
            .apply_pending_changes(150, &mut consensus_params)
            .unwrap();
        assert_eq!(applied2.len(), 1);
        assert_eq!(consensus_params.difficulty_adjustment_window, 4032);

        // Verify both changes are tracked
        assert_eq!(manager.changes_by_height.len(), 2);
        assert!(manager.changes_by_height.contains_key(&100));
        assert!(manager.changes_by_height.contains_key(&150));

        // Rollback changes from height 120 and above (should only affect change2)
        let reverted = manager
            .rollback_changes_from_height(120, &mut consensus_params)
            .unwrap();
        assert_eq!(reverted.len(), 1);
        assert_eq!(reverted[0].parameter_name, "difficulty_adjustment_window");

        // Verify rollback worked
        assert_eq!(consensus_params.difficulty_adjustment_window, 2016); // Back to original
        assert_eq!(consensus_params.min_block_time, 200); // Still changed

        // Verify tracking updated
        assert_eq!(manager.changes_by_height.len(), 1);
        assert!(manager.changes_by_height.contains_key(&100));
        assert!(!manager.changes_by_height.contains_key(&150));
    }

    #[test]
    fn test_parameter_validation() {
        let manager = ParameterManager::new();

        // Test valid parameter
        let metadata = manager.get_parameter_metadata("min_block_time").unwrap();
        assert_eq!(metadata.param_type, ParameterType::U64);

        // Test invalid parameter
        assert!(manager
            .get_parameter_metadata("nonexistent_param")
            .is_none());
    }

    #[test]
    fn test_parameter_categories() {
        let manager = ParameterManager::new();

        let consensus_params = manager.get_parameters_by_category(&ParameterCategory::Consensus);
        let economic_params = manager.get_parameters_by_category(&ParameterCategory::Economic);
        let governance_params = manager.get_parameters_by_category(&ParameterCategory::Governance);

        assert!(!consensus_params.is_empty());
        assert!(!economic_params.is_empty());
        assert!(!governance_params.is_empty());

        // Verify specific parameters are in correct categories
        assert!(consensus_params.iter().any(|p| p.name == "min_block_time"));
        assert!(economic_params.iter().any(|p| p.name == "ticket_price"));
        assert!(governance_params
            .iter()
            .any(|p| p.name == "voting_period_blocks"));
    }

    #[test]
    fn test_pending_change_cancellation() {
        let mut manager = ParameterManager::new();

        let change = ParameterChange {
            parameter_name: "min_block_time".to_string(),
            old_value: ParameterValue::U64(150),
            new_value: ParameterValue::U64(200),
            proposal_id: create_test_hash(1),
            activation_height: 100,
        };

        // Schedule change
        manager
            .schedule_parameter_change(change.clone(), 100)
            .unwrap();
        assert_eq!(manager.pending_changes.len(), 1);

        // Cancel change
        let cancelled = manager.cancel_pending_change(create_test_hash(1));
        assert!(cancelled.is_some());
        assert_eq!(manager.pending_changes.len(), 0);

        // Try to cancel non-existent change
        let not_found = manager.cancel_pending_change(create_test_hash(2));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_parameter_manager_stats() {
        let mut manager = ParameterManager::new();
        let mut consensus_params = ConsensusParams::default();

        let stats_initial = manager.get_stats();
        assert!(stats_initial.total_parameters > 0);
        assert_eq!(stats_initial.pending_changes, 0);
        assert_eq!(stats_initial.applied_changes, 0);
        assert!(!stats_initial.is_connected_to_blockchain_state);

        // Add and apply a change
        let change = ParameterChange {
            parameter_name: "min_block_time".to_string(),
            old_value: ParameterValue::U64(150),
            new_value: ParameterValue::U64(200),
            proposal_id: create_test_hash(1),
            activation_height: 100,
        };

        manager.schedule_parameter_change(change, 100).unwrap();
        manager
            .apply_pending_changes(100, &mut consensus_params)
            .unwrap();

        let stats_after = manager.get_stats();
        assert_eq!(stats_after.pending_changes, 0);
        assert_eq!(stats_after.applied_changes, 1);
        assert_eq!(stats_after.changes_by_height_count, 1);
        assert_eq!(stats_after.earliest_change_height, Some(100));
        assert_eq!(stats_after.latest_change_height, Some(100));
    }

    #[test]
    fn test_live_blockchain_state_integration() {
        let blockchain_state = Arc::new(BlockchainState::new());
        let consensus_params = Arc::new(ConsensusParams::default());
        
        let mut manager = ParameterManager::new();
        assert!(!manager.is_connected_to_blockchain_state());

        // Connect to blockchain state
        manager.connect_to_blockchain_state(blockchain_state.clone(), consensus_params.clone());
        assert!(manager.is_connected_to_blockchain_state());

        // Test getting current parameter value from live state
        let current_value = manager.get_current_parameter_value("min_block_time").unwrap();
        assert_eq!(current_value, ParameterValue::U64(150)); // Default value from ConsensusParams

        // Test stats reflect connection
        let stats = manager.get_stats();
        assert!(stats.is_connected_to_blockchain_state);

        // Test updating consensus parameters
        manager.update_consensus_params(Arc::new(ConsensusParams::regtest()));
        let current_value_after_update = manager.get_current_parameter_value("min_block_time").unwrap();
        assert_eq!(current_value_after_update, ParameterValue::U64(1)); // regtest value
    }
}
