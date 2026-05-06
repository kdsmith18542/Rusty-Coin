use rusty_shared_types::{Block, BlockHeader, OutPoint, Transaction, TxInput, TxOutput};

#[test]
fn test_merkle_root_calculation() {
    // Create some test transactions
    let tx1 = Transaction::Coinbase {
        version: 1,
        inputs: vec![], // Coinbase has no real inputs
        outputs: vec![TxOutput {
            value: 50_0000_0000,          // 50 RUST
            script_pubkey: vec![0u8; 25], // Placeholder script
            memo: None,
        }],
        lock_time: 0,
        witness: vec![],
    };

    let tx2 = Transaction::Standard {
        version: 1,
        inputs: vec![TxInput::from_outpoint(
            OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            vec![],
            0xffffffff,
            vec![],
        )],
        outputs: vec![TxOutput {
            value: 25_0000_0000,
            script_pubkey: vec![0u8; 25],
            memo: None,
        }],
        lock_time: 0,
        fee: 1000,
        witness: vec![],
    };

    // Create a block with these transactions
    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [0u8; 32], // Will be calculated
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        },
        ticket_votes: vec![],
        transactions: vec![tx1, tx2],
    };

    // Calculate merkle root
    let calculated_root = block.calculate_merkle_root();

    // Verify it's not all zeros (which would indicate an error)
    assert_ne!(calculated_root, [0u8; 32]);

    // Verify consistency - calculating twice should give the same result
    let calculated_root_2 = block.calculate_merkle_root();
    assert_eq!(calculated_root, calculated_root_2);

    println!("Merkle root: {}", hex::encode(calculated_root));
}

#[test]
fn test_empty_block_merkle_root() {
    // Test with an empty block (no transactions)
    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        },
        ticket_votes: vec![],
        transactions: vec![],
    };

    let calculated_root = block.calculate_merkle_root();
    assert_eq!(calculated_root, [0u8; 32]); // Empty block should have all-zero root
}

#[test]
fn test_single_transaction_merkle_root() {
    // Test with a single transaction
    let tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 50_0000_0000,
            script_pubkey: vec![0u8; 25],
            memo: None,
        }],
        lock_time: 0,
        witness: vec![],
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        },
        ticket_votes: vec![],
        transactions: vec![tx.clone()],
    };

    let calculated_root = block.calculate_merkle_root();
    let tx_hash = tx.hash();

    // For a single transaction, the merkle root should be the transaction hash
    assert_eq!(calculated_root, tx_hash);
}
