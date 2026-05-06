// rusty-core/src/consensus/mod.rs

pub mod blockchain;
pub mod error;
pub mod governance_state;
pub mod pos;
pub mod pow;
pub mod state;
pub mod threshold_signatures;
pub mod utxo_set;

use crate::constants::*;
use log::{info, warn};

/// Consensus configuration parameters per docs/specs/02_oxidehash_pow_spec.md and 03_oxidesync_pos_spec.md
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Block time target in seconds
    pub target_block_time: u64,
    /// Difficulty adjustment period in blocks
    pub difficulty_adjustment_period: u64,
    /// Maximum difficulty adjustment factor
    pub max_difficulty_adjustment: u64,
    /// Minimum masternode count for network security
    pub min_masternode_count: usize,
    /// Ticket pool size for PoS
    pub ticket_pool_size: usize,
    /// Coinbase maturity period
    pub coinbase_maturity: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            target_block_time: 60,             // 1 minute blocks
            difficulty_adjustment_period: 144, // Adjust every 144 blocks (~2.4 hours)
            max_difficulty_adjustment: 4,      // Max 4x difficulty change
            min_masternode_count: 10,
            ticket_pool_size: 8192,
            coinbase_maturity: 100,
        }
    }
}

/// Initialize consensus subsystem with proper parameter validation
pub fn init_consensus() -> Result<ConsensusConfig, String> {
    info!("Initializing Rusty Coin consensus subsystem...");

    let config = ConsensusConfig::default();

    // Validate consensus parameters per specifications
    if config.target_block_time == 0 {
        return Err("Invalid target block time: must be > 0".to_string());
    }

    if config.difficulty_adjustment_period == 0 {
        return Err("Invalid difficulty adjustment period: must be > 0".to_string());
    }

    if config.max_difficulty_adjustment < 2 {
        warn!(
            "Low maximum difficulty adjustment factor: {}",
            config.max_difficulty_adjustment
        );
    }

    if config.min_masternode_count < 3 {
        return Err("Insufficient minimum masternode count for security".to_string());
    }

    if config.ticket_pool_size < 1000 {
        warn!(
            "Small ticket pool size may affect PoS security: {}",
            config.ticket_pool_size
        );
    }

    // Initialize subsystems
    info!("Consensus configuration validated:");
    info!("  Target block time: {} seconds", config.target_block_time);
    info!(
        "  Difficulty adjustment: every {} blocks",
        config.difficulty_adjustment_period
    );
    info!(
        "  Max difficulty adjustment: {}x",
        config.max_difficulty_adjustment
    );
    info!("  Minimum masternodes: {}", config.min_masternode_count);
    info!("  Ticket pool size: {}", config.ticket_pool_size);
    info!("  Coinbase maturity: {} blocks", config.coinbase_maturity);

    info!("Rusty Coin consensus subsystem initialized successfully");
    Ok(config)
}

/// Initialize consensus for testing with custom parameters
pub fn init_consensus_with_config(config: ConsensusConfig) -> Result<ConsensusConfig, String> {
    info!("Initializing consensus with custom configuration...");

    // Basic validation
    if config.target_block_time == 0 {
        return Err("Invalid target block time".to_string());
    }

    info!("Custom consensus configuration loaded successfully");
    Ok(config)
}
