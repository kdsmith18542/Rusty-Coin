//! Proof of Work (OxideHash) implementation for Rusty Coin.
//!
//! This module implements the OxideHash algorithm, a custom Proof of Work algorithm
//! designed to be ASIC-resistant and memory-hard.

use primitive_types::U256;
use rusty_shared_types::{Block, BlockHeader, Hash};
use crate::error::ConsensusError;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::thread;
use rusty_crypto::hash::OxideHasher as CryptoOxideHasher;
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
        let block_hash: U256 = U256::from(hasher.calculate_oxide_hash(&bincode::serialize(&block.header).expect("Failed to serialize block header"), block.header.nonce as u64).as_bytes());
        
        if block_hash > U256::from(self.target) {
            return Err(ConsensusError::InvalidProof(
                "block hash doesn't meet target difficulty".to_string(),
            ));
        }
        
        Ok(())
    }

    /// Calculate the hash of a block using the OxideHash algorithm.
    pub fn calculate_hash(&self, block: &Block) -> [u8; 32] {
        let header_bytes = bincode::serialize(&block.header).expect("Failed to serialize block header");
        let mut hasher = CryptoOxideHasher::new(); // Create a local mutable hasher
        hasher.calculate_oxide_hash(&header_bytes, block.header.nonce as u64).into()
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
                        
                        let block_hash: U256 = U256::from(hasher.calculate_oxide_hash(
                            &bincode::serialize(&local_block.header).expect("Failed to serialize header"),
                            local_block.header.nonce as u64,
                        ).as_bytes());
                        
                        if block_hash.lt(&local_target) { // Directly compare U256 values
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
}

/// Calculate the new target difficulty based on the previous target and actual block time
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

    // Clamp TimeRatio between 1 / MAX_DIFFICULTY_ADJUSTMENT_FACTOR and MAX_DIFFICULTY_ADJUSTMENT_FACTOR
    // This effectively means the new target can only change by a factor of MAX_DIFFICULTY_ADJUSTMENT_FACTOR
    // from the previous target, but it's based on the ratio, not a direct clamp of the target itself.

    let _clamped_time_ratio_numerator = actual_time_u256.min(expected_time_u256 * U256::from(max_difficulty_adjustment_factor));
    let _clamped_time_ratio_denominator = expected_time_u256.max(actual_time_u256 / U256::from(max_difficulty_adjustment_factor));

    // If clamping for minimum (difficulty increase, target decrease)
    let min_ratio_val = expected_time_u256 / U256::from(max_difficulty_adjustment_factor);
    let max_ratio_val = expected_time_u256 * U256::from(max_difficulty_adjustment_factor);

    let actual_time_clamped = actual_time_u256.min(max_ratio_val).max(min_ratio_val);

    let mut new_target = (previous_target * actual_time_clamped) / expected_time_u256;

    // Clamp NewDifficultyTarget to Minimum (hardest difficulty, lowest numerical value)
    if new_target < min_difficulty_target {
        new_target = min_difficulty_target;
    }

    // Clamp NewDifficultyTarget to Maximum (easiest difficulty, highest numerical value)
    if new_target > max_target {
        new_target = max_target;
    }

    new_target
}

/// Verifies that a block's hash meets the target difficulty.
///
/// Takes the block header and the compact difficulty target (bits) from the header.
/// Converts the compact difficulty target to a 256-bit target hash for comparison.
pub fn verify_pow(block_header: &BlockHeader, compact_difficulty_bits: u32) -> Result<(), ConsensusError> {
    let target_hash = compact_to_target(compact_difficulty_bits);
    let header_bytes = bincode::serialize(block_header)
        .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

    let mut hasher = CryptoOxideHasher::new();
    let block_hash: U256 = U256::from(hasher.calculate_oxide_hash(&header_bytes, block_header.nonce as u64).as_bytes());

    if block_hash <= target_hash {
        Ok(())
    } else {
        Err(ConsensusError::InvalidProofOfWork)
    }
}

/// Converts a compact difficulty target (u32 "bits") into a 256-bit U256 target hash.
/// This implementation follows Bitcoin's compact difficulty representation.
pub fn compact_to_target(compact_difficulty: u32) -> U256 {
    let exponent = (compact_difficulty >> 24) as u8;
    let mantissa = compact_difficulty & 0x007FFFFF; // 23 bits, removed mut

    let mut target = U256::from(mantissa);

    if exponent <= 3 {
        target = target >> (8 * (3 - exponent));
    } else {
        target = target << (8 * (exponent - 3));
    }

    target
}

/// Converts a 256-bit U256 target hash into a compact difficulty target (u32 "bits").
/// This is the reverse of `compact_to_target`.
pub fn target_to_compact(target: U256) -> u32 {
    let mut size = (target.bits() + 7) / 8; // Number of bytes needed to represent the target

    let mut compact = if size <= 3 {
        (target.low_u64() as u32) << (8 * (3 - size))
    } else {
        (target >> (8 * (size - 3))).low_u64() as u32
    };

    if (compact & 0x00800000) != 0 { // If highest bit is set, increment size and shift right
        compact >>= 8;
        size += 1;
    }

    compact |= (size as u32) << 24;

    compact
}

pub fn validate_pow(block: &Block, difficulty_target: u32) -> Result<(), ConsensusError> {
    let target_hash = calculate_target(difficulty_target);
    let header_bytes = bincode::serialize(&block.header)
        .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

    let mut hasher = CryptoOxideHasher::new(); // Instantiate a new hasher
    let block_hash: [u8; 32] = hasher.calculate_oxide_hash(&header_bytes, block.header.nonce as u64).into(); // Pass &mut hasher

    if block_hash.as_bytes() <= target_hash.as_ref() {
        Ok(())
    } else {
        Err(ConsensusError::InvalidProofOfWork)
    }
}

pub fn calculate_target(difficulty: u32) -> [u8; 32] {
    // This is a placeholder for a more complex difficulty adjustment algorithm.
    // For now, it simply converts the u32 difficulty to a 32-byte target.
    // A higher difficulty means a smaller target value.
    let mut target = [0u8; 32];
    if difficulty == 0 { return target; } // Handle extreme case

    let mut difficulty_bytes = difficulty.to_le_bytes().to_vec();
    difficulty_bytes.resize(32, 0);
    target.copy_from_slice(&difficulty_bytes);
    target
}

pub fn block_merkle_root(block: &Block) -> Result<[u8; 32], ConsensusError> {
    let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
    for tx in &block.transactions {
        tx_hashes.push(tx.txid());
    }

    if tx_hashes.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }

    // Simple merkle root for now, replace with proper merkle tree implementation
    // For a single transaction, the merkle root is just its hash.
    // For multiple, a simple XOR or concatenation can be a placeholder.
    if tx_hashes.len() == 1 {
        Ok(tx_hashes[0])
    } else {
        let mut combined_hash = [0u8; 32];
        for hash in tx_hashes {
            for i in 0..32 {
                combined_hash[i] ^= hash[i];
            }
        }
        Ok(combined_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_test_block(nonce: u64, prev_hash: [u8; 32], difficulty: [u8; 32]) -> Block {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: prev_hash,
            merkle_root: [0u8; 32],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            bits: 0,
            nonce: nonce.try_into().unwrap(),
            height: 0, // Initialize height for test block
        };
        Block { header, transactions: vec![], ticket_votes: vec![] }
    }

    #[test]
    fn test_oxide_hash_verification() {
        let mut hasher = OxideHasher::default();
        let initial_target = hasher.target;

        // Create a block that meets the default target
        let block = create_test_block(0, [0u8; 32], initial_target);

        // Find a valid nonce for the block
        let mined_block_option = hasher.mine_block(block.clone(), 1);
        assert!(mined_block_option.is_some());

        let mined_block = mined_block_option.unwrap();
        let mined_hash = hasher.calculate_hash(&mined_block);

        assert!(mined_hash.as_bytes().lt(&initial_target));
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
        assert!(U256::from_big_endian(&new_target_slow) > U256::from_big_endian(&initial_target));

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
        assert!(U256::from_big_endian(&new_target_fast) < U256::from_big_endian(&initial_target));

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
        assert!(U256::from_big_endian(&min_target_test) >= U256::from_big_endian(&very_hard_target) / U256::from(4));
    }

    #[test]
    fn test_calculate_target() {
        let target = calculate_target(100);
        assert_eq!(target[0], 100); // Simple assertion for now
    }

    #[test]
    fn test_oxide_hasher_mining() {
        let mut hasher = OxideHasher::default();
        let block = BlockHeader {
            version: 1,
            previous_block_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 0,
            difficulty_target: hasher.get_target(),
            nonce: 0,
            height: 0,
            state_root: [0; 32],
        };
        let mined_block_option = hasher.mine_block(block.clone(), 100000);
        assert!(mined_block_option.is_some());
        let mined_block = mined_block_option.unwrap();
        let mined_hash = hasher.calculate_hash(&mined_block);
        assert!(hasher.is_block_hash_valid(&mined_hash));
    }

    #[test]
    fn test_is_block_hash_valid() {
        let target = [0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let hasher = OxideHasher::new(target);

        // Valid hash (smaller than target)
        let valid_hash = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
        assert!(hasher.is_block_hash_valid(&valid_hash));

        // Invalid hash (larger than target)
        let invalid_hash = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into();
        assert!(!hasher.is_block_hash_valid(&invalid_hash));
    }

    #[test]
    fn test_calculate_new_target() {
        let initial_target = [0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let target_block_time = 600; // 10 minutes

        // Scenario 1: Blocks are too slow (actual_time_delta > target_block_time)
        let last_block_time_slow = 1000;
        let current_block_time_slow = last_block_time_slow + 1200; // 20 minutes
        let new_target_slow = calculate_new_target(initial_target, last_block_time_slow, current_block_time_slow, target_block_time);
        let initial_target_u256 = U256::from_big_endian(&initial_target);
        let new_target_slow_u256 = U256::from_big_endian(&new_target_slow);
        assert!(new_target_slow_u256 > initial_target_u256);

        // Scenario 2: Blocks are too fast (actual_time_delta < target_block_time)
        let last_block_time_fast = 1000;
        let current_block_time_fast = last_block_time_fast + 300; // 5 minutes
        let new_target_fast = calculate_new_target(initial_target, last_block_time_fast, current_block_time_fast, target_block_time);
        let new_target_fast_u256 = U256::from_big_endian(&new_target_fast);
        assert!(new_target_fast_u256 < initial_target_u256);

        // Scenario 3: Perfect time (actual_time_delta == target_block_time)
        let last_block_time_perfect = 1000;
        let current_block_time_perfect = last_block_time_perfect + 600; // 10 minutes
        let new_target_perfect = calculate_new_target(initial_target, last_block_time_perfect, current_block_time_perfect, target_block_time);
        let new_target_perfect_u256 = U256::from_big_endian(&new_target_perfect);
        assert_eq!(new_target_perfect_u256, initial_target_u256);
    }
}
