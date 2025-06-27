//! Runtime parameter change management for governance proposals
//! 
//! This module implements the system for applying parameter changes through
//! governance proposals, including validation, scheduling, and runtime updates.

use std::collections::HashMap;
use log::{info, warn, error, debug};

use rusty_shared_types::{
    Hash, ConsensusParams,
    governance::{GovernanceProposal, ProposalType},
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
            ParameterType::U64 => {
                value.parse::<u64>()
                    .map(ParameterValue::U64)
                    .map_err(|_| format!("Invalid u64 value: {}", value))
            }
            ParameterType::U32 => {
                value.parse::<u32>()
                    .map(ParameterValue::U32)
                    .map_err(|_| format!("Invalid u32 value: {}", value))
            }
            ParameterType::F64 => {
                value.parse::<f64>()
                    .map(ParameterValue::F64)
                    .map_err(|_| format!("Invalid f64 value: {}", value))
            }
            ParameterType::Bool => {
                value.parse::<bool>()
                    .map(ParameterValue::Bool)
                    .map_err(|_| format!("Invalid bool value: {}", value))
            }
            ParameterType::String => Ok(ParameterValue::String(value.to_string())),
            ParameterType::Bytes => {
                hex::decode(value)
                    .map(ParameterValue::Bytes)
                    .map_err(|_| format!("Invalid hex bytes: {}", value))
            }
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

/// Manages runtime parameter changes
pub struct ParameterManager {
    /// Registry of all known parameters
    parameter_registry: HashMap<String, ParameterMetadata>,
    /// Pending parameter changes scheduled for future activation
    pending_changes: HashMap<Hash, ParameterChange>,
    /// History of applied parameter changes
    change_history: Vec<ParameterChange>,
}

impl ParameterManager {
    /// Create a new parameter manager
    pub fn new() -> Self {
        let mut manager = Self {
            parameter_registry: HashMap::new(),
            pending_changes: HashMap::new(),
            change_history: Vec::new(),
        };

        // Register all known parameters
        manager.register_consensus_parameters();
        manager.register_economic_parameters();
        manager.register_network_parameters();
        manager.register_governance_parameters();
        manager.register_security_parameters();

        manager
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
        self.parameter_registry.insert(metadata.name.clone(), metadata);
    }

    /// Validate a parameter change proposal
    pub fn validate_parameter_change(
        &self,
        proposal: &GovernanceProposal,
    ) -> Result<ParameterChange, String> {
        if proposal.proposal_type != ProposalType::ParameterChange {
            return Err("Not a parameter change proposal".to_string());
        }

        let parameter_name = proposal.target_parameter.as_ref()
            .ok_or("Missing target parameter")?;
        let new_value_str = proposal.new_value.as_ref()
            .ok_or("Missing new value")?;

        // Check if parameter exists
        let metadata = self.parameter_registry.get(parameter_name)
            .ok_or_else(|| format!("Unknown parameter: {}", parameter_name))?;

        // Parse new value
        let new_value = ParameterValue::parse_from_string(new_value_str, &metadata.param_type)?;

        // Validate value range
        if let Some(ref min_val) = metadata.min_value {
            if !self.is_value_greater_or_equal(&new_value, min_val) {
                return Err(format!("Value {} is below minimum {}", 
                                 new_value.to_string(), min_val.to_string()));
            }
        }

        if let Some(ref max_val) = metadata.max_value {
            if !self.is_value_less_or_equal(&new_value, max_val) {
                return Err(format!("Value {} is above maximum {}", 
                                 new_value.to_string(), max_val.to_string()));
            }
        }

        // Get current value (placeholder - would need actual current value)
        let old_value = self.get_current_parameter_value(parameter_name)?;

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
            if pending.parameter_name == change.parameter_name &&
               pending.activation_height == activation_height {
                return Err(format!("Conflicting parameter change for {} at height {}", 
                                 change.parameter_name, activation_height));
            }
        }

        self.pending_changes.insert(change.proposal_id, change.clone());
        
        info!("Scheduled parameter change: {} = {} at height {}", 
              change.parameter_name, change.new_value.to_string(), activation_height);

        Ok(())
    }

    /// Apply pending parameter changes at the current block height
    pub fn apply_pending_changes(
        &mut self,
        current_height: u64,
        consensus_params: &mut ConsensusParams,
    ) -> Result<Vec<ParameterChange>, String> {
        let ready_changes: Vec<Hash> = self.pending_changes
            .iter()
            .filter(|(_, change)| change.activation_height <= current_height)
            .map(|(id, _)| *id)
            .collect();

        let mut applied_changes = Vec::new();

        for proposal_id in ready_changes {
            if let Some(change) = self.pending_changes.remove(&proposal_id) {
                self.apply_parameter_change(&change, consensus_params)?;
                self.change_history.push(change.clone());
                applied_changes.push(change);
            }
        }

        if !applied_changes.is_empty() {
            info!("Applied {} parameter changes at height {}", applied_changes.len(), current_height);
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

        info!("Applied parameter change: {} = {}", 
              change.parameter_name, change.new_value.to_string());

        Ok(())
    }

    /// Get current value of a parameter (placeholder implementation)
    fn get_current_parameter_value(&self, parameter_name: &str) -> Result<ParameterValue, String> {
        // This would get the actual current value from consensus params
        // For now, return default values
        match parameter_name {
            "min_block_time" => Ok(ParameterValue::U64(150)),
            "difficulty_adjustment_window" => Ok(ParameterValue::U32(2016)),
            "halving_interval" => Ok(ParameterValue::U64(210_000)),
            "ticket_price" => Ok(ParameterValue::U64(100_000_000)),
            "min_stake" => Ok(ParameterValue::U64(100_000_000_000)),
            "pos_reward_ratio" => Ok(ParameterValue::F64(0.6)),
            "proposal_stake_amount" => Ok(ParameterValue::U64(10_000_000_000)),
            "voting_period_blocks" => Ok(ParameterValue::U64(4032)),
            "activation_delay_blocks" => Ok(ParameterValue::U64(1008)),
            "pose_challenge_period_blocks" => Ok(ParameterValue::U64(60)),
            "max_pose_failures" => Ok(ParameterValue::U32(3)),
            _ => Err(format!("Unknown parameter: {}", parameter_name)),
        }
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
    pub fn get_parameters_by_category(&self, category: &ParameterCategory) -> Vec<&ParameterMetadata> {
        self.parameter_registry.values()
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
            parameters_by_category: self.parameter_registry.values()
                .fold(HashMap::new(), |mut acc, meta| {
                    *acc.entry(meta.category.clone()).or_insert(0) += 1;
                    acc
                }),
        }
    }
}

/// Statistics about parameter management
#[derive(Debug, Clone)]
pub struct ParameterManagerStats {
    pub total_parameters: usize,
    pub pending_changes: usize,
    pub applied_changes: usize,
    pub parameters_by_category: HashMap<ParameterCategory, usize>,
}
