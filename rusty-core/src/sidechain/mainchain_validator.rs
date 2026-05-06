//! Mainchain validation for sidechain operations
//!
//! This module provides validation logic to ensure sidechain operations
//! are consistent with mainchain state, including block validation,
//! transaction validation, and state consistency checks.

use crate::sidechain::types::*;
use rusty_shared_types::{BlockHeader, Hash};
use std::collections::HashMap;

/// Mainchain state snapshot for validation
#[derive(Debug, Clone)]
pub struct MainchainStateSnapshot {
    /// Mainchain block height
    pub height: u64,
    /// Mainchain block hash
    pub block_hash: Hash,
    /// Mainchain state root
    pub state_root: Hash,
    /// Active federation members
    pub federation_members: Vec<Vec<u8>>,
    /// Federation threshold
    pub federation_threshold: u32,
    /// Federation epoch
    pub federation_epoch: u64,
}

/// Mainchain validator for sidechain operations
pub struct MainchainValidator {
    /// Current mainchain state snapshots by sidechain
    state_snapshots: HashMap<Hash, MainchainStateSnapshot>,
    /// Mainchain block headers cache
    block_headers: HashMap<Hash, BlockHeader>,
    /// Maximum allowed mainchain reorg depth
    max_reorg_depth: u64,
}

impl MainchainValidator {
    /// Create a new mainchain validator
    pub fn new(max_reorg_depth: u64) -> Self {
        Self {
            state_snapshots: HashMap::new(),
            block_headers: HashMap::new(),
            max_reorg_depth,
        }
    }

    /// Update mainchain state snapshot for a sidechain
    pub fn update_mainchain_state(
        &mut self,
        sidechain_id: Hash,
        snapshot: MainchainStateSnapshot,
    ) {
        self.state_snapshots.insert(sidechain_id, snapshot);
    }

    /// Cache a mainchain block header
    pub fn cache_block_header(&mut self, block_hash: Hash, header: BlockHeader) {
        self.block_headers.insert(block_hash, header);
    }

    /// Validate sidechain block header against mainchain state
    pub fn validate_sidechain_block_header(
        &self,
        sidechain_header: &SidechainBlockHeader,
    ) -> Result<(), String> {
        // Get mainchain state snapshot for this sidechain
        let mainchain_state = self.state_snapshots.get(&sidechain_header.sidechain_id)
            .ok_or("No mainchain state snapshot available for sidechain")?;

        // Validate mainchain anchor height is not too old
        let current_mainchain_height = mainchain_state.height;
        if sidechain_header.mainchain_anchor_height > current_mainchain_height {
            return Err("Sidechain anchor height is in the future".to_string());
        }

        // Check anchor height is not too far behind (prevent deep reorgs)
        let height_diff = current_mainchain_height.saturating_sub(sidechain_header.mainchain_anchor_height);
        if height_diff > self.max_reorg_depth {
            return Err(format!(
                "Sidechain anchor height too old: {} blocks behind current height {}",
                height_diff, current_mainchain_height
            ));
        }

        // Validate mainchain anchor hash matches known header
        if let Some(cached_header) = self.block_headers.get(&sidechain_header.mainchain_anchor_hash) {
            if cached_header.height != sidechain_header.mainchain_anchor_height {
                return Err("Mainchain anchor hash height mismatch".to_string());
            }
        } else {
            return Err("Mainchain anchor hash not found in cache".to_string());
        }

        // Validate federation epoch matches mainchain state
        if sidechain_header.federation_epoch != mainchain_state.federation_epoch {
            return Err(format!(
                "Federation epoch mismatch: sidechain {}, mainchain {}",
                sidechain_header.federation_epoch, mainchain_state.federation_epoch
            ));
        }

        Ok(())
    }

    /// Validate cross-chain transaction against mainchain state
    pub fn validate_cross_chain_transaction(
        &self,
        cross_chain_tx: &CrossChainTransaction,
        sidechain_id: &Hash,
    ) -> Result<(), String> {
        // Get mainchain state snapshot
        let mainchain_state = self.state_snapshots.get(sidechain_id)
            .ok_or("No mainchain state snapshot available for sidechain")?;

        // Validate federation signatures
        self.validate_federation_signatures(
            &cross_chain_tx.federation_signatures,
            mainchain_state,
            &cross_chain_tx.hash(),
        )?;

        // Validate transaction amount is reasonable (not dust, not too large)
        if cross_chain_tx.amount == 0 {
            return Err("Cross-chain transaction amount cannot be zero".to_string());
        }

        // Additional validation would include:
        // - Checking if source chain has sufficient funds
        // - Validating recipient address format
        // - Checking transaction hasn't been processed before

        Ok(())
    }

    /// Validate sidechain block against mainchain state
    pub fn validate_sidechain_block(
        &self,
        sidechain_block: &SidechainBlock,
    ) -> Result<(), String> {
        // Validate block header
        self.validate_sidechain_block_header(&sidechain_block.header)?;

        // Validate cross-chain transactions
        for cross_chain_tx in &sidechain_block.cross_chain_transactions {
            self.validate_cross_chain_transaction(cross_chain_tx, &sidechain_block.header.sidechain_id)?;
        }

        // Validate federation signature on block
        if let Some(ref fed_sig) = sidechain_block.federation_signature {
            let mainchain_state = self.state_snapshots.get(&sidechain_block.header.sidechain_id)
                .ok_or("No mainchain state snapshot available for sidechain")?;

            self.validate_federation_signatures(
                &[fed_sig.clone()],
                mainchain_state,
                &sidechain_block.hash(),
            )?;
        } else {
            return Err("Sidechain block missing federation signature".to_string());
        }

        Ok(())
    }

    /// Validate federation signatures against mainchain state
    fn validate_federation_signatures(
        &self,
        signatures: &[FederationSignature],
        mainchain_state: &MainchainStateSnapshot,
        message_hash: &Hash,
    ) -> Result<(), String> {
        if signatures.is_empty() {
            return Err("No federation signatures provided".to_string());
        }

        // Check threshold is met
        let max_signers = signatures.iter()
            .map(|sig| sig.count_signers())
            .max()
            .unwrap_or(0);

        if max_signers < mainchain_state.federation_threshold {
            return Err(format!(
                "Federation signature threshold not met: {} < {}",
                max_signers, mainchain_state.federation_threshold
            ));
        }

        // Validate each signature's epoch matches mainchain state
        for sig in signatures {
            if sig.epoch != mainchain_state.federation_epoch {
                return Err(format!(
                    "Federation signature epoch mismatch: {} != {}",
                    sig.epoch, mainchain_state.federation_epoch
                ));
            }

            // Validate message hash
            if sig.message_hash != *message_hash {
                return Err("Federation signature message hash mismatch".to_string());
            }

            // Additional BLS signature validation would go here
            // For now, we assume the signature is valid if other checks pass
        }

        Ok(())
    }

    /// Check if a mainchain reorg affects sidechain validation
    pub fn check_reorg_impact(
        &self,
        sidechain_id: &Hash,
        new_mainchain_height: u64,
        new_mainchain_hash: Hash,
    ) -> Result<ReorgImpact, String> {
        let current_state = self.state_snapshots.get(sidechain_id)
            .ok_or("No mainchain state snapshot available for sidechain")?;

        let height_diff = new_mainchain_height as i64 - current_state.height as i64;

        if height_diff > 0 {
            // New blocks added
            Ok(ReorgImpact::NewBlocks(height_diff as u64))
        } else if height_diff < 0 {
            // Reorg occurred
            let reorg_depth = (-height_diff) as u64;
            if reorg_depth > self.max_reorg_depth {
                Ok(ReorgImpact::DeepReorg(reorg_depth))
            } else {
                Ok(ReorgImpact::ShallowReorg(reorg_depth))
            }
        } else {
            // Same height, check if hash changed
            if current_state.block_hash != new_mainchain_hash {
                Ok(ReorgImpact::SameHeightReorg)
            } else {
                Ok(ReorgImpact::NoImpact)
            }
        }
    }

    /// Get mainchain state snapshot for a sidechain
    pub fn get_mainchain_state(&self, sidechain_id: &Hash) -> Option<&MainchainStateSnapshot> {
        self.state_snapshots.get(sidechain_id)
    }

    /// Get cached block header
    pub fn get_block_header(&self, block_hash: &Hash) -> Option<&BlockHeader> {
        self.block_headers.get(block_hash)
    }
}

/// Impact of mainchain reorg on sidechain validation
#[derive(Debug, Clone, PartialEq)]
pub enum ReorgImpact {
    /// No impact
    NoImpact,
    /// New blocks added to mainchain
    NewBlocks(u64),
    /// Shallow reorg within allowed depth
    ShallowReorg(u64),
    /// Deep reorg exceeding allowed depth
    DeepReorg(u64),
    /// Reorg at same height (different hash)
    SameHeightReorg,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainchain_validator_creation() {
        let validator = MainchainValidator::new(100);
        assert!(validator.state_snapshots.is_empty());
        assert!(validator.block_headers.is_empty());
    }

    #[test]
    fn test_state_snapshot_update() {
        let mut validator = MainchainValidator::new(100);

        let sidechain_id = [1u8; 32];
        let snapshot = MainchainStateSnapshot {
            height: 1000,
            block_hash: [2u8; 32],
            state_root: [3u8; 32],
            federation_members: vec![vec![1u8; 48], vec![2u8; 48]],
            federation_threshold: 2,
            federation_epoch: 1,
        };

        validator.update_mainchain_state(sidechain_id, snapshot.clone());

        let retrieved = validator.get_mainchain_state(&sidechain_id).unwrap();
        assert_eq!(retrieved.height, 1000);
        assert_eq!(retrieved.federation_threshold, 2);
    }

    #[test]
    fn test_sidechain_block_header_validation() {
        let mut validator = MainchainValidator::new(100);

        let sidechain_id = [1u8; 32];
        let snapshot = MainchainStateSnapshot {
            height: 1000,
            block_hash: [2u8; 32],
            state_root: [3u8; 32],
            federation_members: vec![vec![1u8; 48], vec![2u8; 48]],
            federation_threshold: 2,
            federation_epoch: 1,
        };

        validator.update_mainchain_state(sidechain_id, snapshot);

        // Cache mainchain block header
        let block_header = BlockHeader {
            version: 1,
            height: 950,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };
        let block_hash = [4u8; 32];
        validator.cache_block_header(block_hash, block_header);

        // Valid sidechain header
        let sidechain_header = SidechainBlockHeader::new(
            [5u8; 32], // previous_block_hash
            [6u8; 32], // merkle_root
            [7u8; 32], // cross_chain_merkle_root
            [8u8; 32], // state_root
            100,       // height
            sidechain_id,
            950,       // mainchain_anchor_height
            block_hash, // mainchain_anchor_hash
            1,         // federation_epoch
        );

        assert!(validator.validate_sidechain_block_header(&sidechain_header).is_ok());

        // Invalid: anchor height too old
        let mut invalid_header = sidechain_header.clone();
        invalid_header.mainchain_anchor_height = 800; // More than 100 blocks behind
        assert!(validator.validate_sidechain_block_header(&invalid_header).is_err());
    }

    #[test]
    fn test_reorg_impact_detection() {
        let validator = MainchainValidator::new(100);

        let sidechain_id = [1u8; 32];

        // No impact (same height, same hash)
        let impact = validator.check_reorg_impact(&sidechain_id, 1000, [1u8; 32]);
        assert!(matches!(impact, Err(_))); // No state snapshot

        // Add state snapshot
        let mut validator = MainchainValidator::new(100);
        let snapshot = MainchainStateSnapshot {
            height: 1000,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            federation_members: vec![],
            federation_threshold: 2,
            federation_epoch: 1,
        };
        validator.update_mainchain_state(sidechain_id, snapshot);

        // No impact
        let impact = validator.check_reorg_impact(&sidechain_id, 1000, [1u8; 32]).unwrap();
        assert_eq!(impact, ReorgImpact::NoImpact);

        // New blocks
        let impact = validator.check_reorg_impact(&sidechain_id, 1010, [2u8; 32]).unwrap();
        assert_eq!(impact, ReorgImpact::NewBlocks(10));

        // Shallow reorg
        let impact = validator.check_reorg_impact(&sidechain_id, 990, [3u8; 32]).unwrap();
        assert_eq!(impact, ReorgImpact::ShallowReorg(10));

        // Deep reorg
        let impact = validator.check_reorg_impact(&sidechain_id, 800, [4u8; 32]).unwrap();
        assert_eq!(impact, ReorgImpact::DeepReorg(200));
    }
}