use rusty_shared_types::{Transaction, TxInput, TxOutput, OutPoint, Hash, MasternodeSlashTx};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::error::ConsensusError;
use rusty_core::consensus::validation::{validate_transaction, validate_block};
use rusty_core::consensus::state::{BlockchainState, UtxoSet};
use std::sync::{Arc, Mutex};
use rusty_core::mempool::Mempool;
use rusty_core::masternode::{MasternodeList, MasternodeEntry, MasternodeStatus};
use rusty_core::script::ScriptEngine;
use rusty_core::constants::{MAX_BLOCK_SIZE_BYTES, MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_TX_IO_COUNT, COINBASE_MATURITY};
use rusty_shared_types::BlockHeader;

// Helper function to create a dummy hash
fn dummy_hash(seed: u8) -> Hash {
    [seed; 32]
}

// Helper function to create a dummy OutPoint
fn dummy_outpoint(txid_seed: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: dummy_hash(txid_seed),
        vout,
    }
}

// Helper function to create a basic TxInput
fn dummy_tx_input(txid_seed: u8, vout: u32) -> TxInput {
    TxInput {
        previous_output: dummy_outpoint(txid_seed, vout),
        script_sig: vec![],
        sequence: 0xFFFFFFFF,
        witness: vec![],
    }
}

// Helper function to create a basic TxOutput
fn dummy_tx_output(value: u64) -> TxOutput {
    TxOutput {
        value,
        script_pubkey: vec![1, 2, 3], // Dummy script pubkey
        memo: None,
    }
}

// Helper function to create a basic Standard Transaction
fn create_dummy_transaction(
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    fee: u64,
) -> Transaction {
    Transaction::Standard {
        version: 1,
        inputs,
        outputs,
        lock_time: 0,
        fee,
        witness: vec![],
    }
}

// Helper function to initialize a minimal Blockchain for testing
fn create_test_blockchain() -> Blockchain {
    let utxo_set = Arc::new(Mutex::new(UtxoSet::new()));
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let masternode_list = Arc::new(Mutex::new(MasternodeList::new()));
    let script_engine = Arc::new(Mutex::new(ScriptEngine::new()));

    // Populate with some initial UTXOs for testing double spends
    let mut utxo_guard = utxo_set.lock().unwrap();
    utxo_guard.add_utxo(
        dummy_outpoint(100, 0),
        rusty_shared_types::Utxo {
            output: dummy_tx_output(1000),
            is_coinbase: false,
            creation_height: 1,
        },
    );
    utxo_guard.add_utxo(
        dummy_outpoint(101, 0),
        rusty_shared_types::Utxo {
            output: dummy_tx_output(2000),
            is_coinbase: false,
            creation_height: 1,
        },
    );
    drop(utxo_guard); // Release the lock

    Blockchain::new(utxo_set, mempool, masternode_list, script_engine)
}

#[test]
fn test_double_spend_detection_utxo_set() {
    let blockchain = create_test_blockchain();

    // Create a transaction that attempts to double-spend an existing UTXO
    let inputs = vec![
        dummy_tx_input(100, 0), // This UTXO is in the initial utxo_set
        dummy_tx_input(102, 0), // This UTXO is NOT in the initial utxo_set
    ];
    let outputs = vec![dummy_tx_output(500)];
    let double_spend_tx = create_dummy_transaction(inputs, outputs, 10);

    // This should result in a DoubleSpend error because dummy_tx_input(102,0) is not present
    let result = validate_transaction(&blockchain, &double_spend_tx, 10);
    assert!(
        matches!(result, Err(ConsensusError::MissingPreviousOutput(_))),
        "Expected MissingPreviousOutput error for double-spend, got {:?}",
        result
    );
}

#[test]
fn test_double_spend_detection_mempool() {
    let blockchain = create_test_blockchain();
    let mut mempool = blockchain.mempool.lock().unwrap();

    // Add a transaction to the mempool that spends a UTXO
    let mempool_tx_input = dummy_tx_input(101, 0);
    let mempool_tx_output = dummy_tx_output(1500);
    let mempool_tx = create_dummy_transaction(vec![mempool_tx_input.clone()], vec![mempool_tx_output], 10);
    mempool.add_transaction(mempool_tx.clone());
    drop(mempool); // Release the lock

    // Create a new transaction that attempts to spend the same UTXO already in the mempool
    let double_spend_tx_inputs = vec![
        dummy_tx_input(100, 0), // Valid input
        mempool_tx_input,       // Double-spend input
    ];
    let double_spend_tx_outputs = vec![dummy_tx_output(2000)];
    let double_spend_tx = create_dummy_transaction(double_spend_tx_inputs, double_spend_tx_outputs, 20);

    // This should result in a DoubleSpend error due to the mempool conflict
    let result = validate_transaction(&blockchain, &double_spend_tx, 10);
    assert!(
        matches!(result, Err(ConsensusError::DoubleSpend)),
        "Expected DoubleSpend error for mempool conflict, got {:?}",
        result
    );
}

#[test]
fn test_invalid_merkle_root_detection() {
    let blockchain = create_test_blockchain();
    let mut context = rusty_core::consensus::validation::ValidationContext {
        utxo_set: &mut blockchain.utxo_set.lock().unwrap(),
        params: &rusty_shared_types::ConsensusParams::default(),
        ticket_voting: &mut blockchain.ticket_voting.lock().unwrap(),
        masternode_list: &mut blockchain.masternode_list.lock().unwrap(),
        blockchain_state: &blockchain.blockchain_state.lock().unwrap(),
    };

    // Create a dummy block with a valid header but manipulate the transactions
    // to cause a Merkle root mismatch.
    let header = BlockHeader {
        version: 1,
        previous_block_hash: dummy_hash(1),
        merkle_root: dummy_hash(99), // Intentionally wrong Merkle root
        timestamp: 1000,
        nonce: 0,
        difficulty_target: 0x207fffff,
        height: 10,
        state_root: dummy_hash(1),
    };
    let transactions = vec![
        create_dummy_transaction(vec![dummy_tx_input(100, 0)], vec![dummy_tx_output(990)], 10),
    ];
    // Correctly instantiate Block struct
    let block = rusty_shared_types::Block {
        header,
        transactions,
        ticket_votes: vec![],
    };

    // Calculate the correct Merkle root to confirm our dummy_hash(99) is indeed wrong
    let correct_merkle_root = block.calculate_merkle_root();
    assert_ne!(block.header.merkle_root, correct_merkle_root, "Precondition failed: Merkle root is accidentally correct.");

    // Attempt to validate the block, expecting an InvalidMerkleRoot error
    let previous_block_header = BlockHeader {
        version: 1,
        previous_block_hash: dummy_hash(0),
        merkle_root: dummy_hash(0),
        timestamp: 999,
        nonce: 0,
        difficulty_target: 0x207fffff,
        height: 9,
        state_root: dummy_hash(0),
    };
    // Correctly instantiate prev_block as Block struct
    let prev_block = rusty_shared_types::Block {
        header: previous_block_header,
        transactions: vec![], // Empty transactions for previous block in this test context
        ticket_votes: vec![],
    };

    let result = validate_block(&block, &[&prev_block], &mut context, 1000);
    assert!(
        matches!(result, Err(ConsensusError::InvalidMerkleRoot)),
        "Expected InvalidMerkleRoot error, got {:?}",
        result
    );
} 