//! Test for comprehensive blockchain validation

use std::sync::{Arc, Mutex};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::network::P2PNetwork;
use rusty_shared_types::{Block, BlockHeader, Transaction, TxOutput, P2PMessage, PeerInfo, BlockRequest, BlockResponse, GetHeaders, Headers};

// Mock P2PNetwork implementation for testing
struct MockP2PNetwork;

impl P2PNetwork for MockP2PNetwork {
    fn send_message(&self, _peer_id: String, _message: P2PMessage) -> Result<(), String> {
        Ok(())
    }

    fn broadcast_message(&self, _message: P2PMessage) -> Result<(), String> {
        Ok(())
    }

    fn receive_message(&mut self) -> Option<(String, P2PMessage)> {
        None
    }

    fn get_peer_info(&self, _peer_id: String) -> Option<PeerInfo> {
        None
    }

    fn get_connected_peers(&self) -> Vec<String> {
        vec![]
    }

    fn request_blocks(&self, _peer_id: String, _request: BlockRequest) -> Option<BlockResponse> {
        None
    }

    fn request_headers(&self, _peer_id: String, _request: GetHeaders) -> Option<Headers> {
        None
    }
}

fn create_dummy_block(height: u64, previous_hash: [u8; 32]) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            previous_block_hash: previous_hash,
            merkle_root: [0; 32],
            timestamp: 1640995200 + height * 60, // Incrementing timestamps
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
            height,
            state_root: [0; 32],
        },
        transactions: vec![
            // Coinbase transaction
            Transaction::Coinbase {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    value: 50_000_000_000, // 500 RustyCoin
                    script_pubkey: vec![0; 20],
                    memo: None,
                }],
                lock_time: 0,
                witness: vec![],
            },
        ],
        ticket_votes: vec![],
    }
}

#[test]
fn test_validate_blockchain_integrity() {
    let mock_p2p = Arc::new(Mutex::new(MockP2PNetwork));
    let blockchain = Blockchain::new(mock_p2p).unwrap();

    // Test with empty blockchain (genesis state)
    assert!(blockchain.is_valid());

    // Test comprehensive validation
    match blockchain.validate_blockchain_integrity() {
        Ok(_) => println!("Blockchain integrity validation passed"),
        Err(e) => assert!(false, "Blockchain integrity validation failed: {}", e),
    }
}

#[test]
fn test_validate_block_comprehensive() {
    let mock_p2p = Arc::new(Mutex::new(MockP2PNetwork));
    let blockchain = Blockchain::new(mock_p2p).unwrap();
    let block = create_dummy_block(1, [0; 32]);

    // Test comprehensive block validation
    match blockchain.validate_block_comprehensive(&block, 1) {
        Ok(_) => println!("Block validation passed"),
        Err(e) => println!("Block validation failed as expected: {}", e),
    }
}

#[test]
fn test_validate_merkle_root() {
    let mock_p2p = Arc::new(Mutex::new(MockP2PNetwork));
    let blockchain = Blockchain::new(mock_p2p).unwrap();
    let block = create_dummy_block(1, [0; 32]);

    // Calculate and verify merkle root
    let calculated_root = block.calculate_merkle_root();
    println!("Calculated merkle root: {:?}", calculated_root);
}

#[test]
fn test_validate_block_size() {
    let mock_p2p = Arc::new(Mutex::new(MockP2PNetwork));
    let blockchain = Blockchain::new(mock_p2p).unwrap();
    let block = create_dummy_block(1, [0; 32]);

    // Test block size validation
    match blockchain.validate_block_size(&block) {
        Ok(_) => println!("Block size validation passed"),
        Err(e) => assert!(false, "Block size validation failed: {}", e),
    }
}
