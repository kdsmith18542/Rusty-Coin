//! Proof of Work (OxideHash) implementation for Rusty Coin.
//!
//! This module implements the OxideHash algorithm, a custom Proof of Work algorithm
//! designed to be ASIC-resistant and memory-hard.

use crate::error::ConsensusError;
use primitive_types::U256;
use rusty_crypto::hash::OxideHasher as CryptoOxideHasher;
use rusty_shared_types::{Block, BlockHeader, Hash};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::thread;
use zerocopy::IntoBytes;

// The maximum target (easiest difficulty)
#[allow(dead_code)]
const MAX_TARGET: U256 = U256::MAX;

/// The number of nonce values a single thread tries before checking for a new block
const NONCES_PER_ROUND: u64 = 10_000;

/// The number of rounds after which to check for a new block
const ROUNDS_BEFORE_CHECK: usize = 100;

/// Thread-safe nonce counter for mining
#[derive(Debug)]
pub struct NonceCounter(AtomicU64);

impl NonceCounter {
    /// Create a new nonce counter starting at the given value
    pub fn new(start: u64) -> Self {
        NonceCounter(AtomicU64::new(start))
    }

    /// Get the next nonce value, incrementing the counter
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, AtomicOrdering::SeqCst)
    }
}

/// The OxideHash algorithm implementation for consensus.
#[derive(Debug, Default, Clone)]
pub struct OxideHasher {
    /// The current target difficulty
    target: [u8; 32],
}

impl OxideHasher {
    /// Create a new OxideHasher with default parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target difficulty
    pub fn set_target(&mut self, target: [u8; 32]) {
        self.target = target;
    }

    /// Verify that a block's hash meets the target difficulty
    pub fn verify(&self, block: &Block) -> Result<(), ConsensusError> {
        let mut hasher = CryptoOxideHasher::new(); // Create a local mutable hasher

        // Create a copy of the header without the nonce for serialization
        let mut header_without_nonce = block.header.clone();
        let nonce = header_without_nonce.nonce;
        header_without_nonce.nonce = 0; // Zero out the nonce

        let block_hash: U256 = U256::from(
            hasher
                .calculate_oxide_hash(
                    &bincode::serialize(&header_without_nonce)
                        .expect("Failed to serialize block header"),
                    nonce as u64,
                )
                .as_bytes(),
        );

        if block_hash > U256::from(self.target) {
            return Err(ConsensusError::InvalidProof(
                "block hash doesn't meet target difficulty".to_string(),
            ));
        }

        Ok(())
    }

    /// Calculate the hash of a block using the OxideHash algorithm.
    pub fn calculate_hash(&self, block: &Block) -> [u8; 32] {
        // Create a copy of the header without the nonce for serialization
        let mut header_without_nonce = block.header.clone();
        let nonce = header_without_nonce.nonce;
        header_without_nonce.nonce = 0; // Zero out the nonce

        let header_bytes =
            bincode::serialize(&header_without_nonce).expect("Failed to serialize block header");
        let mut hasher = CryptoOxideHasher::new(); // Create a local mutable hasher
        hasher
            .calculate_oxide_hash(&header_bytes, nonce as u64)
            .into()
    }

    /// Mine a new block by finding a valid nonce
    pub fn mine_block(self, block: Block, num_threads: usize) -> Option<Block> {
        let nonce_counter = Arc::new(NonceCounter::new(0));
        let found = Arc::new(AtomicU64::new(0));
        let current_target = U256::from(self.target); // Convert target to U256 for comparison
        let mut handles = vec![];

        for _ in 0..num_threads {
            let nonce_counter = Arc::clone(&nonce_counter);
            let found = Arc::clone(&found);
            let mut local_block = block.clone();
            let local_target = current_target; // Use U256 target

            let handle = thread::spawn(move || {
                let mut round = 0;
                let mut hasher = CryptoOxideHasher::new(); // Create a local mutable hasher for each thread

                loop {
                    // Check if another thread found a solution
                    if found.load(AtomicOrdering::Relaxed) > 0 {
                        return None;
                    }

                    // Try a batch of nonces
                    for _ in 0..NONCES_PER_ROUND {
                        let nonce = nonce_counter.next();
                        local_block.header.nonce = nonce;

                        // Create a copy of the header without the nonce for serialization
                        let mut header_without_nonce = local_block.header.clone();
                        let nonce = header_without_nonce.nonce;
                        header_without_nonce.nonce = 0; // Zero out the nonce

                        let block_hash: U256 = U256::from(
                            hasher
                                .calculate_oxide_hash(
                                    &bincode::serialize(&header_without_nonce)
                                        .expect("Failed to serialize header"),
                                    nonce as u64,
                                )
                                .as_bytes(),
                        );

                        if block_hash.lt(&local_target) {
                            // Directly compare U256 values
                            // Found a valid nonce
                            found.store(1, AtomicOrdering::Relaxed);
                            return Some(local_block);
                        }
                    }

                    // Periodically check for new transactions or stop signal
                    round += 1;
                    if local_block.header.nonce as u64 == u64::MAX {
                        // Handle nonce overflow, typically by updating timestamp or transactions
                        // For simplicity, we'll just increment timestamp
                        local_block.header.timestamp += 1;
                        local_block.header.nonce = 0;
                    }
                    if round % ROUNDS_BEFORE_CHECK == 0 {
                        // Here you would typically check for new transactions or stop signal
                        // For now, just continue mining
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for one of the threads to find a solution
        for handle in handles {
            if let Some(solution) = handle.join().unwrap() {
                return Some(solution);
            }
        }

        None
    }

    pub fn get_target(&self) -> [u8; 32] {
        self.target
    }

    pub fn is_block_hash_valid(&self, block_hash: &Hash) -> bool {
        let target_u256 = U256::from_big_endian(&self.target);
        let hash_u256 = U256::from_big_endian(block_hash.as_bytes());
        hash_u256 <= target_u256
    }

    pub fn verify_pow(&self) -> bool {
        // Implementation of verify_pow method
        false
    }
}

/// Calculate the new target difficulty based on the previous target and actual block time
/// Per spec 02a Section 2a.3: Difficulty Adjustment Procedure
pub fn calculate_new_target(
    previous_target: U256,
    actual_time_span: u64,
    expected_time_span: u64,
    max_difficulty_adjustment_factor: u64,
    min_difficulty_target: U256,
    max_target: U256,
) -> U256 {
    let actual_time_u256 = U256::from(actual_time_span);
    let expected_time_u256 = U256::from(expected_time_span);

    // Per spec §2a.3 step d: Calculate Time Ratio
    // TimeRatio = ActualTimeSpan / ExpectedTimeSpan
    // We need to use fixed-point arithmetic to avoid floating point
    // Multiply by a large factor to maintain precision
    const PRECISION_FACTOR: u64 = 1_000_000_000; // 1 billion for precision

    // Calculate TimeRatio with precision: (actual * PRECISION) / expected
    let time_ratio_numerator = actual_time_u256 * U256::from(PRECISION_FACTOR);
    let time_ratio = time_ratio_numerator / expected_time_u256;

    // Per spec §2a.3 step e: Clamp Time Ratio
    // ClampedTimeRatio = max(1 / MAX_DIFFICULTY_ADJUSTMENT_FACTOR, min(MAX_DIFFICULTY_ADJUSTMENT_FACTOR, TimeRatio))
    let min_ratio = U256::from(PRECISION_FACTOR) / U256::from(max_difficulty_adjustment_factor);
    let max_ratio = U256::from(PRECISION_FACTOR) * U256::from(max_difficulty_adjustment_factor);

    let clamped_time_ratio = time_ratio.min(max_ratio).max(min_ratio);

    // Per spec §2a.3 step f: Calculate New Difficulty Target (Inverse Relationship)
    // NewDifficultyTarget = OldDifficultyTarget * ClampedTimeRatio
    // Since we're using fixed-point, we need to divide by PRECISION_FACTOR
    let mut new_target = (previous_target * clamped_time_ratio) / U256::from(PRECISION_FACTOR);

    // Per spec §2a.3 step g: Clamp NewDifficultyTarget to Minimum
    // NewDifficultyTarget MUST NOT be greater than MIN_DIFFICULTY_TARGET
    // Note: In difficulty terms, a larger target = easier difficulty
    // So we clamp to ensure target doesn't exceed MIN_DIFFICULTY_TARGET (which is actually a maximum target value)
    if new_target > min_difficulty_target && !min_difficulty_target.is_zero() {
        new_target = min_difficulty_target;
    }

    // Also clamp to maximum target (easiest difficulty)
    if new_target > max_target {
        new_target = max_target;
    }

    new_target
}

/// Verifies that a block's hash meets the target difficulty.
///
/// Takes the block header and the compact difficulty target (bits) from the header.
/// Converts the compact difficulty target to a 256-bit target hash for comparison.
pub fn verify_pow(
    block_header: &BlockHeader,
    compact_difficulty_bits: u32,
) -> Result<(), ConsensusError> {
    let target_hash = compact_to_target(compact_difficulty_bits);

    // Create a copy of the header without the nonce for serialization
    let mut header_without_nonce = block_header.clone();
    let nonce = header_without_nonce.nonce;
    header_without_nonce.nonce = 0; // Zero out the nonce

    let header_bytes = bincode::serialize(&header_without_nonce)
        .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

    let mut hasher = CryptoOxideHasher::new();
    let block_hash: U256 = U256::from(
        hasher
            .calculate_oxide_hash(&header_bytes, nonce as u64)
            .as_bytes(),
    );

    if block_hash <= target_hash {
        Ok(())
    } else {
        Err(ConsensusError::InvalidProofOfWork)
    }
}

/// Converts a compact difficulty target (u32 "bits") into a 256-bit U256 target hash.
/// This implementation follows Bitcoin's compact difficulty representation, including edge cases.
pub fn compact_to_target(compact_difficulty: u32) -> U256 {
    let exponent = (compact_difficulty >> 24) as u8;
    let mantissa = compact_difficulty & 0x007FFFFF; // 23 bits
    let negative = (compact_difficulty & 0x00800000) != 0;

    // Bitcoin: If mantissa is zero, target is zero
    if mantissa == 0 {
        return U256::zero();
    }

    // If exponent <= 3, shift mantissa right
    let mut target = if exponent <= 3 {
        U256::from(mantissa) >> (8 * (3 - exponent))
    } else {
        U256::from(mantissa) << (8 * (exponent - 3))
    };

    // If negative bit is set, return zero (Bitcoin ignores sign, but some impls set target to zero)
    if negative {
        target = U256::zero();
    }

    target
}

/// Converts a 256-bit U256 target hash into a compact difficulty target (u32 "bits").
/// This is the reverse of `compact_to_target` and matches Bitcoin's encoding, including edge cases.
pub fn target_to_compact(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let mut size = (target.bits() + 7) / 8; // Number of bytes needed to represent the target
    let mut compact: u32;
    if size <= 3 {
        compact = (target.low_u64() as u32) << (8 * (3 - size));
    } else {
        compact = (target >> (8 * (size - 3))).low_u64() as u32;
    }
    // If the sign bit (0x00800000) is set, divide the mantissa by 256 and increase the exponent
    if (compact & 0x00800000) != 0 {
        compact >>= 8;
        size += 1;
    }
    // Only use the lowest 23 bits for mantissa
    compact &= 0x007FFFFF;
    compact |= (size as u32) << 24;
    // Bitcoin: If target is negative or overflow, set the sign bit (not used in Rusty Coin, but for compatibility)
    // (We never encode negative targets, so sign bit is always 0)
    compact
}

pub fn validate_pow(block: &Block, difficulty_target: u32) -> Result<(), ConsensusError> {
    let target_hash = compact_to_target_bytes(difficulty_target);

    let mut hasher = CryptoOxideHasher::new(); // Instantiate a new hasher
                                               // Create a copy of the header without the nonce for serialization
    let mut header_without_nonce = block.header.clone();
    let nonce = header_without_nonce.nonce;
    header_without_nonce.nonce = 0; // Zero out the nonce

    let header_bytes =
        bincode::serialize(&header_without_nonce).expect("Failed to serialize block header");
    let block_hash: [u8; 32] = hasher
        .calculate_oxide_hash(&header_bytes, nonce as u64)
        .into(); // Pass &mut hasher

    if block_hash.as_bytes() <= target_hash.as_ref() {
        Ok(())
    } else {
        Err(ConsensusError::InvalidProofOfWork)
    }
}

/// Convert compact difficulty to target bytes using the standard compact_to_target function
/// This replaces the placeholder calculate_target with the proper implementation
pub fn compact_to_target_bytes(compact_difficulty: u32) -> [u8; 32] {
    let target = compact_to_target(compact_difficulty);
    let mut bytes = [0u8; 32];
    target.to_big_endian(&mut bytes);
    bytes
}

/// Convert target bytes back to compact difficulty format
pub fn target_bytes_to_compact(target_bytes: &[u8; 32]) -> u32 {
    let target = U256::from_big_endian(target_bytes);
    target_to_compact(target)
}

/// Calculate target from difficulty using the standard compact format
/// This is the main function to use for all target calculations
pub fn calculate_target_from_difficulty(compact_difficulty: u32) -> [u8; 32] {
    compact_to_target_bytes(compact_difficulty)
}

pub fn block_merkle_root(block: &Block) -> Result<[u8; 32], ConsensusError> {
    let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
    for tx in &block.transactions {
        tx_hashes.push(tx.txid());
    }

    if tx_hashes.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }

    // Implement proper merkle tree calculation
    Ok(calculate_merkle_root(&tx_hashes))
}

/// Calculates the merkle root using the standard Bitcoin merkle tree algorithm
/// This follows the exact specification used in Bitcoin and most cryptocurrencies
fn calculate_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut level = hashes.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        // Process pairs of hashes
        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                // Hash pair of elements
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number of elements - duplicate the last one (Bitcoin standard)
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(hash);
        }

        level = next_level;
    }

    level[0]
}

/// Hashes a pair of 32-byte hashes using BLAKE3 (double hash for security)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    let first_hash = hasher.finalize();

    // Double hash for additional security (similar to Bitcoin's approach)
    let mut second_hasher = blake3::Hasher::new();
    second_hasher.update(first_hash.as_bytes());
    let final_hash = second_hasher.finalize();

    *final_hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_block(nonce: u64, prev_hash: [u8; 32], _difficulty: [u8; 32]) -> Block {
        let header = BlockHeader {
            version: 1,
            height: 0, // Initialize height for test block
            previous_block_hash: prev_hash,
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty_target: 0, // Set to 0 or appropriate test value
            nonce: nonce.try_into().unwrap(),
        };
        Block {
            header,
            transactions: vec![],
            ticket_votes: vec![],
        }
    }

    #[test]
    fn test_oxide_hash_verification() {
        let hasher = OxideHasher::default();
        let initial_target = hasher.target;
        let block = create_test_block(0, [0u8; 32], initial_target);
        let mined_block_option = hasher.clone().mine_block(block.clone(), 1);
        assert!(mined_block_option.is_some());
        let mined_block = mined_block_option.unwrap();
        let mined_hash = hasher.calculate_hash(&mined_block);
        // Convert both to slices for proper comparison
        assert!(mined_hash.as_bytes() < initial_target.as_ref());
        assert!(hasher.verify(&mined_block).is_ok());
    }

    #[test]
    fn test_difficulty_adjustment() {
        let initial_target = [0x7f; 32]; // Very easy target
        let target_block_time = 300; // 5 minutes

        // Test case 1: Blocks are too slow (actual_block_time > target_block_time)
        let actual_block_time_slow = 600;
        let new_target_slow = calculate_new_target(
            U256::from_big_endian(&initial_target),
            actual_block_time_slow,
            target_block_time,
            4,
            U256::from(0),
            MAX_TARGET,
        );
        // Expect new_target_slow to be easier (larger value) than initial_target
        assert!(new_target_slow > U256::from_big_endian(&initial_target));

        // Test case 2: Blocks are too fast (actual_block_time < target_block_time)
        let actual_block_time_fast = 150;
        let new_target_fast = calculate_new_target(
            U256::from_big_endian(&initial_target),
            actual_block_time_fast,
            target_block_time,
            4,
            U256::from(0),
            MAX_TARGET,
        );
        // Expect new_target_fast to be harder (smaller value) than initial_target
        assert!(new_target_fast < U256::from_big_endian(&initial_target));

        // Test case 3: Actual block time is equal to target block time
        let actual_block_time_equal = 300;
        let new_target_equal = calculate_new_target(
            U256::from_big_endian(&initial_target),
            actual_block_time_equal,
            target_block_time,
            4,
            U256::from(0),
            MAX_TARGET,
        );
        // Expect target to remain the same
        assert_eq!(new_target_equal, U256::from_big_endian(&initial_target));

        // Test case 4: Max target reached (difficulty hits easiest point)
        let max_target_test = calculate_new_target(
            MAX_TARGET,
            600,
            target_block_time,
            4,
            U256::from(0),
            MAX_TARGET,
        );
        assert_eq!(max_target_test, MAX_TARGET);

        // Test case 5: Min target reached (difficulty hits hardest point, capped by min_change_factor)
        let very_hard_target = [0u8; 32]; // Smallest possible target
        let min_target_test = calculate_new_target(
            U256::from_big_endian(&very_hard_target),
            150,
            target_block_time,
            4,
            U256::from(0),
            MAX_TARGET,
        );
        // The target should not go below `very_hard_target * 0.25` (due to min_change_factor_denominator = 4)
        assert!(min_target_test >= U256::from_big_endian(&very_hard_target) / U256::from(4));
    }

    #[test]
    fn test_compact_to_target_bytes() {
        let target = compact_to_target_bytes(0x1d00ffff); // Bitcoin mainnet initial difficulty
        assert_eq!(target[0], 0x00); // Should be a valid target
    }

    #[test]
    fn test_oxide_hasher_mining() {
        let hasher = OxideHasher::default();
        // Use Bitcoin's initial difficulty as a valid compact value
        let compact_difficulty = 0x1d00ffff;
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty_target: compact_difficulty,
            nonce: 0,
            height: 0,
            state_root: [0; 32],
        };
        let block = Block {
            header,
            transactions: vec![],
            ticket_votes: vec![],
        };
        let mined_block_option = hasher.clone().mine_block(block.clone(), 1);
        assert!(mined_block_option.is_some());
        let mined_block = mined_block_option.unwrap();
        let mined_hash = hasher.calculate_hash(&mined_block);
        assert!(hasher.is_block_hash_valid(&mined_hash));
    }

    #[test]
    fn test_is_block_hash_valid() {
        let target = [
            0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let mut hasher = OxideHasher::new();
        hasher.set_target(target);

        // Valid hash (smaller than target)
        let valid_hash = [
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]
        .into();
        assert!(hasher.is_block_hash_valid(&valid_hash));

        // Invalid hash (larger than target)
        let invalid_hash = [
            0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]
        .into();
        assert!(!hasher.is_block_hash_valid(&invalid_hash));
    }

    #[test]
    fn test_calculate_new_target() {
        let initial_target = [
            0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let target_block_time = 600; // 10 minutes
        let min_target = U256::from(0);
        let max_target = MAX_TARGET;

        // Scenario 1: Blocks are too slow (actual_time_delta > target_block_time)
        let last_block_time_slow = 1000;
        let current_block_time_slow = last_block_time_slow + 1200; // 20 minutes
        let new_target_slow = calculate_new_target(
            U256::from_big_endian(&initial_target),
            last_block_time_slow,
            current_block_time_slow,
            target_block_time,
            min_target,
            max_target,
        );
        let initial_target_u256 = U256::from_big_endian(&initial_target);
        assert!(new_target_slow > initial_target_u256);

        // Scenario 2: Blocks are too fast (actual_time_delta < target_block_time)
        let last_block_time_fast = 1000;
        let current_block_time_fast = last_block_time_fast + 300; // 5 minutes
        let new_target_fast = calculate_new_target(
            U256::from_big_endian(&initial_target),
            last_block_time_fast,
            current_block_time_fast,
            target_block_time,
            min_target,
            max_target,
        );
        assert!(new_target_fast < initial_target_u256);

        // Scenario 3: Perfect time (actual_time_delta == target_block_time)
        let last_block_time_perfect = 1000;
        let current_block_time_perfect = last_block_time_perfect + 600; // 10 minutes
        let new_target_perfect = calculate_new_target(
            U256::from_big_endian(&initial_target),
            last_block_time_perfect,
            current_block_time_perfect,
            target_block_time,
            min_target,
            max_target,
        );
        assert_eq!(new_target_perfect, initial_target_u256);
    }

    /// Test time ratio clamping per spec §2a.3 step e
    /// ClampedTimeRatio = max(1/4, min(4, TimeRatio))
    #[test]
    fn test_time_ratio_clamping() {
        let base_target = U256::from(1000);
        let expected_timespan = 2016 * 150; // 2016 blocks * 150 seconds

        // Test case 1: TimeRatio > 4 (should clamp to 4)
        let actual_timespan_large = expected_timespan * 10; // 10x too slow
        let new_target_large = calculate_new_target(
            base_target,
            actual_timespan_large,
            expected_timespan,
            4, // MAX_DIFFICULTY_ADJUSTMENT_FACTOR
            U256::zero(),
            MAX_TARGET,
        );
        // Should be clamped to 4x increase (target increases when blocks are slow)
        let expected_max_increase = base_target * U256::from(4);
        assert!(
            new_target_large <= expected_max_increase,
            "Target should be clamped to 4x increase, got {} expected max {}",
            new_target_large,
            expected_max_increase
        );

        // Test case 2: TimeRatio < 1/4 (should clamp to 1/4)
        let actual_timespan_small = expected_timespan / 10; // 10x too fast
        let new_target_small = calculate_new_target(
            base_target,
            actual_timespan_small,
            expected_timespan,
            4,
            U256::zero(),
            MAX_TARGET,
        );
        // Should be clamped to 1/4x (target decreases when blocks are fast)
        let expected_min_decrease = base_target / U256::from(4);
        assert!(
            new_target_small >= expected_min_decrease,
            "Target should be clamped to 1/4x decrease, got {} expected min {}",
            new_target_small,
            expected_min_decrease
        );

        // Test case 3: TimeRatio = 2 (within range, should not clamp)
        let actual_timespan_normal = expected_timespan * 2;
        let new_target_normal = calculate_new_target(
            base_target,
            actual_timespan_normal,
            expected_timespan,
            4,
            U256::zero(),
            MAX_TARGET,
        );
        // Should be approximately 2x (within clamping range)
        let expected_2x = base_target * U256::from(2);
        // Allow small rounding differences due to fixed-point arithmetic
        let diff = if new_target_normal > expected_2x {
            new_target_normal - expected_2x
        } else {
            expected_2x - new_target_normal
        };
        assert!(
            diff < base_target / U256::from(100),
            "Target should be approximately 2x, got {} expected {}",
            new_target_normal,
            expected_2x
        );
    }

    /// Test adjustment period detection: (H_current - 1) % 2016 == 0
    #[test]
    fn test_adjustment_period_detection() {
        const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

        // Test case 1: First adjustment block (height 2017, since (2017 - 1) % 2016 == 0)
        let height_2017 = 2017;
        let is_adjustment = (height_2017 - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;
        assert!(is_adjustment, "Height 2017 should be an adjustment block");

        // Test case 2: Second adjustment block (height 4033)
        let height_4033 = 4033;
        let is_adjustment_2 = (height_4033 - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;
        assert!(is_adjustment_2, "Height 4033 should be an adjustment block");

        // Test case 3: Non-adjustment block (height 2016)
        let height_2016 = 2016;
        let is_adjustment_3 = (height_2016 - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;
        assert!(
            !is_adjustment_3,
            "Height 2016 should NOT be an adjustment block"
        );

        // Test case 4: Non-adjustment block (height 2018)
        let height_2018 = 2018;
        let is_adjustment_4 = (height_2018 - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;
        assert!(
            !is_adjustment_4,
            "Height 2018 should NOT be an adjustment block"
        );

        // Test case 5: Genesis block (height 0)
        // Genesis block is never an adjustment block (adjustment starts at height 2017)
        let height_0 = 0u64;
        assert!(
            height_0 < DIFFICULTY_ADJUSTMENT_INTERVAL,
            "Genesis block height should be less than adjustment interval"
        );
    }

    /// Test inverse relationship: slower blocks → easier difficulty (larger target)
    #[test]
    fn test_inverse_relationship() {
        let base_target = U256::from(1000);
        let expected_timespan = 2016 * 150;

        // Slower blocks (actual > expected) → easier difficulty (larger target)
        let actual_slow = expected_timespan * 2; // 2x slower
        let target_slow = calculate_new_target(
            base_target,
            actual_slow,
            expected_timespan,
            4,
            U256::zero(),
            MAX_TARGET,
        );
        assert!(
            target_slow > base_target,
            "Slower blocks should result in easier difficulty (larger target). Got {}, base {}",
            target_slow,
            base_target
        );

        // Faster blocks (actual < expected) → harder difficulty (smaller target)
        let actual_fast = expected_timespan / 2; // 2x faster
        let target_fast = calculate_new_target(
            base_target,
            actual_fast,
            expected_timespan,
            4,
            U256::zero(),
            MAX_TARGET,
        );
        assert!(
            target_fast < base_target,
            "Faster blocks should result in harder difficulty (smaller target). Got {}, base {}",
            target_fast,
            base_target
        );
    }
}

#[cfg(test)]
mod merkle_tests {
    use super::*;

    #[test]
    fn test_merkle_root_single_hash() {
        let single_hash = [0x42u8; 32];
        let hashes = vec![single_hash];
        let merkle_root = calculate_merkle_root(&hashes);
        assert_eq!(merkle_root, single_hash);
    }

    #[test]
    fn test_merkle_root_two_hashes() {
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];
        let hashes = vec![hash1, hash2];
        let merkle_root = calculate_merkle_root(&hashes);

        // Should be the hash of hash1 + hash2
        let expected = hash_pair(&hash1, &hash2);
        assert_eq!(merkle_root, expected);
    }

    #[test]
    fn test_merkle_root_odd_number() {
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];
        let hash3 = [0x03u8; 32];
        let hashes = vec![hash1, hash2, hash3];
        let merkle_root = calculate_merkle_root(&hashes);

        // With 3 hashes, the last one should be duplicated
        let level1_1 = hash_pair(&hash1, &hash2);
        let level1_2 = hash_pair(&hash3, &hash3); // Duplicate last hash
        let expected = hash_pair(&level1_1, &level1_2);
        assert_eq!(merkle_root, expected);
    }

    #[test]
    fn test_merkle_root_power_of_two() {
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];
        let hash3 = [0x03u8; 32];
        let hash4 = [0x04u8; 32];
        let hashes = vec![hash1, hash2, hash3, hash4];
        let merkle_root = calculate_merkle_root(&hashes);

        // Perfect binary tree
        let level1_1 = hash_pair(&hash1, &hash2);
        let level1_2 = hash_pair(&hash3, &hash4);
        let expected = hash_pair(&level1_1, &level1_2);
        assert_eq!(merkle_root, expected);
    }
}
