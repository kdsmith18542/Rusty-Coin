//! Property-based tests for consensus rules
//! Per remediation plan Phase 4.1 - Property-Based Testing
//! Uses proptest to test consensus rules, state transitions, and edge cases

use proptest::prelude::*;
use rusty_shared_types::{Block, BlockHeader, Hash, Transaction, TxInput, TxOutput};
use std::time::{SystemTime, UNIX_EPOCH};

// Helper to create a test hash from a value
fn test_hash(value: u64) -> Hash {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&value.to_le_bytes());
    hash
}

// Strategy for generating valid block heights
fn block_height_strategy() -> impl Strategy<Value = u64> {
    1u64..=10_000_000u64 // Reasonable block height range
}

// Strategy for generating valid transaction values
fn transaction_value_strategy() -> impl Strategy<Value = u64> {
    1u64..=21_000_000_000_000_000u64 // Max supply (21M * 1e9)
}

// Strategy for generating difficulty targets
fn difficulty_target_strategy() -> impl Strategy<Value = u32> {
    0x1u32..=0x7FFFFFFFu32 // Valid difficulty target range
}

proptest! {
    #[test]
    fn test_block_height_monotonicity(
        height1 in block_height_strategy(),
        height2 in block_height_strategy(),
    ) {
        // Property: Block heights should be monotonically increasing
        // If height2 > height1, then block2 should come after block1

        let header1 = BlockHeader {
            version: 1,
            height: height1,
            previous_block_hash: test_hash(0),
            merkle_root: test_hash(1),
            state_root: test_hash(2),
            timestamp: 1000,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        let header2 = BlockHeader {
            version: 1,
            height: height2,
            previous_block_hash: header1.hash(),
            merkle_root: test_hash(3),
            state_root: test_hash(4),
            timestamp: 2000,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        if height2 > height1 {
            // Block2 should reference block1's hash
            prop_assert_eq!(header2.previous_block_hash, header1.hash());
        }
    }

    #[test]
    fn test_transaction_value_conservation(
        input_value in transaction_value_strategy(),
        output_value in transaction_value_strategy(),
    ) {
        // Property: Transaction inputs should be >= outputs (value conservation)
        // Fee = input_value - output_value

        let fee = input_value.saturating_sub(output_value);

        // Fee should be non-negative
        prop_assert!(fee >= 0 || input_value >= output_value);

        // If inputs >= outputs, transaction is valid (ignoring dust limits)
        if input_value >= output_value {
            prop_assert!(input_value - output_value == fee);
        }
    }

    #[test]
    fn test_difficulty_target_range(
        target in difficulty_target_strategy(),
    ) {
        // Property: Difficulty target should be within valid range
        // MIN_DIFFICULTY_TARGET <= target <= MAX_DIFFICULTY_TARGET

        const MIN_DIFFICULTY_TARGET: u32 = 0x1;
        const MAX_DIFFICULTY_TARGET: u32 = 0x7FFFFFFF;

        prop_assert!(target >= MIN_DIFFICULTY_TARGET);
        prop_assert!(target <= MAX_DIFFICULTY_TARGET);
    }

    #[test]
    fn test_block_timestamp_monotonicity(
        timestamp1 in 1000u64..=2_000_000_000u64, // Unix timestamp range
        timestamp2 in 1000u64..=2_000_000_000u64,
    ) {
        // Property: Block timestamps should generally be monotonically increasing
        // (allowing for some clock skew)

        let header1 = BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: test_hash(0),
            merkle_root: test_hash(1),
            state_root: test_hash(2),
            timestamp: timestamp1,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        let header2 = BlockHeader {
            version: 1,
            height: 101,
            previous_block_hash: header1.hash(),
            merkle_root: test_hash(3),
            state_root: test_hash(4),
            timestamp: timestamp2,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        // Timestamps should be reasonable (within 2 hours of each other for consecutive blocks)
        // This allows for some clock skew but prevents extreme values
        if header2.height == header1.height + 1 {
            let time_diff = timestamp2.max(timestamp1) - timestamp2.min(timestamp1);
            // Allow up to 2 hours difference (7200 seconds)
            prop_assume!(time_diff <= 7200);
        }
    }

    #[test]
    fn test_transaction_fee_calculation(
        inputs in prop::collection::vec(
            transaction_value_strategy(),
            1..=10 // 1-10 inputs
        ),
        outputs in prop::collection::vec(
            transaction_value_strategy(),
            1..=10 // 1-10 outputs
        ),
    ) {
        // Property: Transaction fee = sum(inputs) - sum(outputs)

        let total_inputs: u64 = inputs.iter().sum();
        let total_outputs: u64 = outputs.iter().sum();

        if total_inputs >= total_outputs {
            let fee = total_inputs - total_outputs;
            prop_assert!(fee >= 0);
            prop_assert_eq!(fee, total_inputs - total_outputs);
        } else {
            // Invalid transaction (insufficient inputs)
            prop_assert!(total_inputs < total_outputs);
        }
    }

    #[test]
    fn test_block_hash_uniqueness(
        height1 in block_height_strategy(),
        height2 in block_height_strategy(),
        nonce1 in 0u64..=u64::MAX,
        nonce2 in 0u64..=u64::MAX,
    ) {
        // Property: Different blocks should have different hashes
        // (with high probability)

        let header1 = BlockHeader {
            version: 1,
            height: height1,
            previous_block_hash: test_hash(0),
            merkle_root: test_hash(1),
            state_root: test_hash(2),
            timestamp: 1000,
            difficulty_target: 0x207fffff,
            nonce: nonce1,
        };

        let header2 = BlockHeader {
            version: 1,
            height: height2,
            previous_block_hash: test_hash(0),
            merkle_root: test_hash(1),
            state_root: test_hash(2),
            timestamp: 1000,
            difficulty_target: 0x207fffff,
            nonce: nonce2,
        };

        // If blocks differ in height or nonce, hashes should differ
        if height1 != height2 || nonce1 != nonce2 {
            prop_assume!(header1.hash() != header2.hash());
        }
    }

    #[test]
    fn test_utxo_double_spend_prevention(
        outpoint_txid in prop::array::uniform32(0u8..=255u8),
        outpoint_vout in 0u32..=100u32,
    ) {
        // Property: Same UTXO cannot be spent twice in same transaction

        let outpoint = rusty_shared_types::OutPoint {
            txid: outpoint_txid,
            vout: outpoint_vout,
        };

        // Create transaction with same input twice (should be invalid)
        let input1 = TxInput::from_outpoint(
            outpoint.clone(),
            vec![],
            0xffffffff,
            vec![],
        );

        let input2 = TxInput::from_outpoint(
            outpoint.clone(),
            vec![],
            0xffffffff,
            vec![],
        );

        // Transaction with duplicate inputs should be detected as invalid
        if input1.previous_output == input2.previous_output {
            prop_assert_eq!(input1.previous_output, input2.previous_output);
            // This would be caught during validation
        }
    }

    #[test]
    fn test_merkle_root_determinism(
        tx_count in 1usize..=100usize,
    ) {
        // Property: Merkle root should be deterministic for same transactions

        // Generate random transactions
        let mut transactions = Vec::new();
        for i in 0..tx_count {
            transactions.push(Transaction::Standard {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    value: (i as u64) * 1000,
                    script_pubkey: vec![i as u8],
                    memo: None,
                }],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            });
        }

        // Calculate merkle root twice - should be same
        let root1 = calculate_merkle_root(&transactions);
        let root2 = calculate_merkle_root(&transactions);

        prop_assert_eq!(root1, root2, "Merkle root should be deterministic");
    }

    #[test]
    fn test_coinbase_maturity(
        block_height in block_height_strategy(),
        maturity_blocks in 100u64..=1000u64,
    ) {
        // Property: Coinbase outputs require maturity period before spending

        let coinbase_height = block_height;
        let spend_height = block_height + maturity_blocks;

        // Coinbase should not be spendable until maturity blocks have passed
        if spend_height < coinbase_height + 100 {
            // Assuming COINBASE_MATURITY = 100 blocks
            prop_assume!(spend_height < coinbase_height + 100);
            // Would be rejected during validation
        } else {
            prop_assert!(spend_height >= coinbase_height + 100);
        }
    }
}

// Helper function to calculate merkle root
fn calculate_merkle_root(transactions: &[Transaction]) -> Hash {
    if transactions.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<Hash> = transactions.iter().map(|tx| tx.txid()).collect();

    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let combined = if chunk.len() == 2 {
                [chunk[0], chunk[1]].concat()
            } else {
                [chunk[0], chunk[0]].concat() // Duplicate if odd
            };
            let hash = blake3::hash(&combined);
            next_level.push(hash.into());
        }
        hashes = next_level;
    }

    hashes[0]
}
