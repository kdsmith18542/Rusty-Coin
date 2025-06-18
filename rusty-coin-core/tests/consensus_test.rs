use rusty_coin_core::{
    consensus::{self, pow},
    crypto::Hash,
    types::BlockHeader,
};

fn create_test_header(timestamp: u64, bits: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: Hash::zero(),
        merkle_root: Hash::zero(),
        timestamp,
        bits,
        nonce: 0,
        ticket_hash: Hash::zero(),
        cumulative_work: 0,
        height: 0,
        pos_votes: Vec::new(),
    }
}

#[test]
fn test_lwma_constant_hash_rate() {
    let params = consensus::ConsensusParams::default();
    let mut headers = Vec::new();
    
    // Create headers with perfect 150 second intervals (target block time)
    for i in 0..100 {
        headers.push(create_test_header(
            i * 150,
            0x1d00ffff, // Medium difficulty
        ));
    }
    
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    
    // Difficulty should stay roughly the same
    assert!(new_target.as_bytes()[0] >= 0x1c && new_target.as_bytes()[0] <= 0x1e);
}

#[test]
fn test_lwma_increasing_hash_rate() {
    let params = consensus::ConsensusParams::default();
    let mut headers = Vec::new();
    
    // Create headers with decreasing intervals (hash rate increasing)
    for i in 0..100 {
        headers.push(create_test_header(
            i * 100, // Faster than target (100s vs 150s)
            0x1d00ffff,
        ));
    }
    
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    
    // Difficulty should increase (target value decreases)
    assert!(new_target < Hash([0x1d; 32]));
}

#[test]
fn test_lwma_decreasing_hash_rate() {
    let params = consensus::ConsensusParams::default();
    let mut headers = Vec::new();
    
    // Create headers with increasing intervals (hash rate decreasing)
    for i in 0..100 {
        headers.push(create_test_header(
            i * 200, // Slower than target (200s vs 150s)
            0x1d00ffff,
        ));
    }
    
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    
    // Difficulty should decrease (target value increases)
    assert!(new_target > Hash([0x1d; 32]));
}

#[test]
fn test_lwma_min_difficulty() {
    let mut params = consensus::ConsensusParams::default();
    params.min_difficulty = Hash([0x1f; 32]); // Set high min difficulty
    
    let mut headers = Vec::new();
    
    // Create headers with extremely fast mining
    for i in 0..100 {
        headers.push(create_test_header(
            i * 10, // Very fast mining
            0x1d00ffff,
        ));
    }
    
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    
    // Should hit minimum difficulty
    assert_eq!(new_target, params.min_difficulty);
}

#[test]
fn test_lwma_max_future_block_time() {
    let params = consensus::ConsensusParams::default();
    let mut headers = Vec::new();
    
    // Create headers with one extremely long interval
    headers.push(create_test_header(0, 0x1d00ffff));
    headers.push(create_test_header(2 * 60 * 60 + 1, 0x1d00ffff)); // 2 hours + 1 second
    
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    
    // Should cap at 2 hours for calculation
    assert!(new_target > Hash([0x1d; 32])); // Difficulty should decrease
}

#[test]
fn test_lwma_empty_headers() {
    let params = consensus::ConsensusParams::default();
    let headers = Vec::new();
    
    // With no headers, should return max difficulty
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    assert_eq!(new_target, params.max_difficulty);
}

#[test]
fn test_lwma_single_header() {
    let params = consensus::ConsensusParams::default();
    let headers = vec![create_test_header(0, 0x1d00ffff)];
    
    // With single header, should return max difficulty (can't calculate rate)
    let new_target = pow::calculate_next_work_required(&headers, &params).unwrap();
    assert_eq!(new_target, params.max_difficulty);
}
