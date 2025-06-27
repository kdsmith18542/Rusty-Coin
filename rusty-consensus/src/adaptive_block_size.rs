//! Adaptive Block Size Algorithm Implementation
//! 
//! This module implements the adaptive block size algorithm as specified in
//! docs/specs/12_adaptive_block_size_spec.md. It dynamically adjusts the maximum
//! allowed block size based on observed median block sizes over previous periods.

use std::collections::VecDeque;
use serde::{Serialize, Deserialize};
use rusty_shared_types::Block;
use crate::error::ConsensusError;

/// Algorithm parameters for adaptive block size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveBlockSizeParams {
    /// Maximum allowed block size at network genesis (2 MB)
    pub initial_max_block_size_bytes: u64,
    /// Number of past blocks used to calculate median (2016 blocks)
    pub median_calculation_period_blocks: u64,
    /// Maximum percentage increase per period (10%)
    pub block_size_growth_factor_percentage: f64,
    /// Maximum percentage decrease per period (5%)
    pub block_size_shrink_factor_percentage: f64,
    /// Absolute hard maximum block size (64 MB)
    pub absolute_hard_max_block_size_bytes: u64,
    /// Minimum maximum block size (1 MB)
    pub min_max_block_size_bytes: u64,
    /// Signature operations cost in bytes per sigop (20 bytes/sigop)
    pub sig_ops_byte_cost: u64,
}

impl Default for AdaptiveBlockSizeParams {
    fn default() -> Self {
        Self {
            initial_max_block_size_bytes: 2_000_000,        // 2 MB
            median_calculation_period_blocks: 2016,         // ~3.5 days at 2.5 min/block
            block_size_growth_factor_percentage: 0.10,      // 10%
            block_size_shrink_factor_percentage: 0.05,      // 5%
            absolute_hard_max_block_size_bytes: 64_000_000, // 64 MB
            min_max_block_size_bytes: 1_000_000,            // 1 MB
            sig_ops_byte_cost: 20,                          // 20 bytes per sigop
        }
    }
}

/// Adaptive block size calculator
#[derive(Debug, Clone)]
pub struct AdaptiveBlockSizeCalculator {
    params: AdaptiveBlockSizeParams,
    block_sizes: VecDeque<u64>,
    current_adaptive_max_size: u64,
}

impl AdaptiveBlockSizeCalculator {
    /// Create a new adaptive block size calculator
    pub fn new(params: AdaptiveBlockSizeParams) -> Self {
        let current_adaptive_max_size = params.initial_max_block_size_bytes;
        Self {
            params,
            block_sizes: VecDeque::new(),
            current_adaptive_max_size,
        }
    }

    /// Add a new block size to the calculation
    pub fn add_block_size(&mut self, block_size: u64) {
        self.block_sizes.push_back(block_size);
        
        // Keep only the required number of blocks for median calculation
        while self.block_sizes.len() > self.params.median_calculation_period_blocks as usize {
            self.block_sizes.pop_front();
        }
    }

    /// Calculate the adaptive maximum block size for a given block height
    pub fn calculate_adaptive_max_block_size(&mut self, block_height: u64) -> u64 {
        // Check if this is an adjustment period
        if block_height == 0 {
            return self.params.initial_max_block_size_bytes;
        }

        if block_height % self.params.median_calculation_period_blocks != 0 {
            return self.current_adaptive_max_size;
        }

        // Calculate median of collected block sizes
        let median_actual_size = self.calculate_median_block_size();

        // Calculate potential new limit
        let potential_limit = self.calculate_potential_limit(median_actual_size);

        // Apply hard limits
        let new_adaptive_max_size = self.apply_hard_limits(potential_limit);

        self.current_adaptive_max_size = new_adaptive_max_size;
        new_adaptive_max_size
    }

    /// Calculate median block size from collected sizes
    fn calculate_median_block_size(&self) -> u64 {
        if self.block_sizes.is_empty() {
            return self.params.initial_max_block_size_bytes;
        }

        let mut sorted_sizes: Vec<u64> = self.block_sizes.iter().cloned().collect();
        sorted_sizes.sort_unstable();

        let len = sorted_sizes.len();
        if len % 2 == 0 {
            // Even number of elements - average of two middle values
            (sorted_sizes[len / 2 - 1] + sorted_sizes[len / 2]) / 2
        } else {
            // Odd number of elements - middle value
            sorted_sizes[len / 2]
        }
    }

    /// Calculate potential new limit based on median
    fn calculate_potential_limit(&self, median_actual_size: u64) -> u64 {
        let current_max = self.current_adaptive_max_size;

        if median_actual_size > current_max {
            // Increase limit
            let growth_factor = 1.0 + self.params.block_size_growth_factor_percentage;
            (median_actual_size as f64 * growth_factor) as u64
        } else if median_actual_size < current_max {
            // Decrease limit
            let shrink_factor = 1.0 - self.params.block_size_shrink_factor_percentage;
            (median_actual_size as f64 * shrink_factor) as u64
        } else {
            // No change
            current_max
        }
    }

    /// Apply hard limits to the potential limit
    fn apply_hard_limits(&self, potential_limit: u64) -> u64 {
        potential_limit
            .max(self.params.min_max_block_size_bytes)
            .min(self.params.absolute_hard_max_block_size_bytes)
    }

    /// Get current adaptive maximum block size
    pub fn get_current_adaptive_max_size(&self) -> u64 {
        self.current_adaptive_max_size
    }

    /// Calculate maximum signature operations per block
    pub fn calculate_max_sig_ops_per_block(&self) -> u64 {
        self.current_adaptive_max_size / self.params.sig_ops_byte_cost
    }

    /// Validate a block against adaptive size limits
    pub fn validate_block_size(&self, block: &Block) -> Result<(), ConsensusError> {
        let block_size = self.calculate_block_size(block)?;
        
        if block_size > self.current_adaptive_max_size {
            return Err(ConsensusError::BlockTooLarge(
                block_size as usize,
                self.current_adaptive_max_size as usize,
            ));
        }

        Ok(())
    }

    /// Calculate the serialized size of a block
    fn calculate_block_size(&self, block: &Block) -> Result<u64, ConsensusError> {
        bincode::serialize(block)
            .map(|bytes| bytes.len() as u64)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    /// Update calculator with a new block
    pub fn update_with_block(&mut self, block: &Block, block_height: u64) -> Result<(), ConsensusError> {
        let block_size = self.calculate_block_size(block)?;
        self.add_block_size(block_size);
        
        // Recalculate adaptive max size if needed
        self.calculate_adaptive_max_block_size(block_height);
        
        Ok(())
    }

    /// Get algorithm parameters
    pub fn get_params(&self) -> &AdaptiveBlockSizeParams {
        &self.params
    }

    /// Get collected block sizes for debugging
    pub fn get_block_sizes(&self) -> &VecDeque<u64> {
        &self.block_sizes
    }
}

/// Utility functions for adaptive block size
impl AdaptiveBlockSizeCalculator {
    /// Create calculator from existing block history
    pub fn from_block_history(
        params: AdaptiveBlockSizeParams,
        blocks: &[Block],
        current_height: u64,
    ) -> Result<Self, ConsensusError> {
        let mut calculator = Self::new(params);
        
        // Add block sizes from history
        for (i, block) in blocks.iter().enumerate() {
            let block_height = current_height.saturating_sub(blocks.len() as u64 - 1 - i as u64);
            calculator.update_with_block(block, block_height)?;
        }
        
        Ok(calculator)
    }

    /// Reset calculator to initial state
    pub fn reset(&mut self) {
        self.block_sizes.clear();
        self.current_adaptive_max_size = self.params.initial_max_block_size_bytes;
    }

    /// Get statistics about current state
    pub fn get_statistics(&self) -> AdaptiveBlockSizeStats {
        let median = if !self.block_sizes.is_empty() {
            self.calculate_median_block_size()
        } else {
            0
        };

        let average = if !self.block_sizes.is_empty() {
            self.block_sizes.iter().sum::<u64>() / self.block_sizes.len() as u64
        } else {
            0
        };

        AdaptiveBlockSizeStats {
            current_adaptive_max_size: self.current_adaptive_max_size,
            median_block_size: median,
            average_block_size: average,
            blocks_collected: self.block_sizes.len(),
            max_sig_ops_per_block: self.calculate_max_sig_ops_per_block(),
        }
    }
}

/// Statistics about adaptive block size state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveBlockSizeStats {
    pub current_adaptive_max_size: u64,
    pub median_block_size: u64,
    pub average_block_size: u64,
    pub blocks_collected: usize,
    pub max_sig_ops_per_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::{BlockHeader, Transaction, TxVersion};

    fn create_test_block(size_hint: u64) -> Block {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty_target: 0,
            nonce: 0,
            height: 0,
            state_root: [0; 32],
        };

        // Create transactions to approximate desired size
        let mut transactions = vec![];
        let mut current_size = bincode::serialize(&header)
            .unwrap().len() as u64;

        while current_size < size_hint {
            let tx = Transaction {
                version: TxVersion::V1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            };
            let tx_size = bincode::serialize(&tx)
                .unwrap().len() as u64;
            transactions.push(tx);
            current_size += tx_size;
        }

        Block {
            header,
            ticket_votes: vec![],
            transactions,
        }
    }

    #[test]
    fn test_adaptive_block_size_basic() {
        let params = AdaptiveBlockSizeParams::default();
        let mut calculator = AdaptiveBlockSizeCalculator::new(params);

        // Initial size should be the initial max
        assert_eq!(calculator.get_current_adaptive_max_size(), 2_000_000);

        // Add some block sizes
        calculator.add_block_size(1_000_000);
        calculator.add_block_size(1_500_000);
        calculator.add_block_size(1_200_000);

        // Calculate median
        let median = calculator.calculate_median_block_size();
        assert_eq!(median, 1_200_000);
    }

    #[test]
    fn test_adaptive_adjustment() {
        let params = AdaptiveBlockSizeParams::default();
        let mut calculator = AdaptiveBlockSizeCalculator::new(params);

        // Fill with blocks at 1.5MB (below initial 2MB limit)
        for _ in 0..2016 {
            calculator.add_block_size(1_500_000);
        }

        // At adjustment period, should decrease
        let new_size = calculator.calculate_adaptive_max_block_size(2016);
        assert!(new_size < 2_000_000);
    }

    #[test]
    fn test_hard_limits() {
        let params = AdaptiveBlockSizeParams::default();
        let calculator = AdaptiveBlockSizeCalculator::new(params);

        // Test minimum limit
        let min_limited = calculator.apply_hard_limits(500_000);
        assert_eq!(min_limited, 1_000_000); // Should be clamped to minimum

        // Test maximum limit
        let max_limited = calculator.apply_hard_limits(100_000_000);
        assert_eq!(max_limited, 64_000_000); // Should be clamped to maximum
    }
}
