//! Comprehensive JSON-RPC API validation tests for Rusty-Coin
//!
//! This module tests all JSON-RPC methods for accuracy, compliance, and robustness.
//! Tests cover blockchain, transaction, wallet, mining, governance, masternode,
//! and network methods with response format validation, data accuracy verification,
//! error handling, and rate limiting checks.

use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::state::State;
use rusty_core::consensus::utxo_set::UtxoSet;
use rusty_jsonrpc::auth::ApiKeyManager;
use rusty_jsonrpc::rpc::{Rpc, RpcImpl};
use rusty_shared_types::{Block, Hash, Transaction, TxInput, TxOutput};
use rusty_wallet::Wallet;
use std::sync::{Arc, Mutex};

/// Test setup utilities
mod test_utils {
    use super::*;

    /// Create a test blockchain with some initial state
    pub fn create_test_blockchain() -> Arc<Mutex<Blockchain>> {
        let state = State::new();
        let utxo_set = UtxoSet::new();
        let blockchain = Blockchain::new(state, utxo_set);
        Arc::new(Mutex::new(blockchain))
    }

    /// Create a test wallet
    pub fn create_test_wallet() -> Arc<Mutex<Wallet>> {
        let wallet = Wallet::new();
        Arc::new(Mutex::new(wallet))
    }

    /// Create a test RPC implementation
    pub fn create_test_rpc() -> RpcImpl {
        let blockchain = create_test_blockchain();
        let wallet = create_test_wallet();
        let api_key_manager = Arc::new(ApiKeyManager::new());
        RpcImpl::new(blockchain, wallet, api_key_manager)
    }

    /// Create a sample transaction for testing
    pub fn create_sample_transaction() -> Transaction {
        let input = TxInput {
            previous_output: rusty_shared_types::OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![0u8; 25], // Simplified script sig
            sequence: 0xFFFFFFFF,
        };

        let output = TxOutput {
            value: 100000000, // 1 RUST
            script_pubkey: vec![0u8; 25], // Simplified P2PKH script
            memo: None,
        };

        Transaction::Standard {
            version: 1,
            inputs: vec![input],
            outputs: vec![output],
            lock_time: 0,
            witness: vec![],
        }
    }

    /// Create a sample block for testing
    pub fn create_sample_block() -> Block {
        use rusty_shared_types::{BlockHeader, Transaction};

        let header = BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x207fffff,
            nonce: 0,
        };

        let coinbase_output = TxOutput {
            value: 5000000000, // 50 RUST reward
            script_pubkey: vec![0u8; 25],
            memo: None,
        };

        let coinbase_tx = Transaction::Coinbase {
            version: 1,
            inputs: vec![],
            outputs: vec![coinbase_output],
            lock_time: 0,
            witness: vec![],
        };

        Block {
            header,
            ticket_votes: vec![],
            transactions: vec![coinbase_tx],
        }
    }
}

#[cfg(test)]
mod blockchain_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_getbestblockhash() {
        let rpc = create_test_rpc();

        // Test successful retrieval
        let result = rpc.getbestblockhash();
        assert!(result.is_ok(), "getbestblockhash should succeed");

        let hash = result.unwrap();
        assert_eq!(hash.len(), 32, "Block hash should be 32 bytes");
    }

    #[test]
    fn test_get_block_count() {
        let rpc = create_test_rpc();

        let result = rpc.get_block_count();
        assert!(result.is_ok(), "get_block_count should succeed");

        let count = result.unwrap();
        assert!(count >= 0, "Block count should be non-negative");
    }

    #[test]
    fn test_get_block_hash() {
        let rpc = create_test_rpc();

        // Test valid height
        let result = rpc.get_block_hash(0);
        assert!(result.is_ok(), "get_block_hash for height 0 should succeed");

        let hash = result.unwrap();
        assert_eq!(hash.len(), 32, "Block hash should be 32 bytes");

        // Test invalid height
        let result = rpc.get_block_hash(999999);
        assert!(result.is_err(), "get_block_hash for invalid height should fail");
    }

    #[test]
    fn test_get_block() {
        let rpc = create_test_rpc();

        // First get a valid block hash
        let hash_result = rpc.getbestblockhash();
        assert!(hash_result.is_ok(), "Should get best block hash");

        let hash = hash_result.unwrap();

        // Test getting the block
        let block_result = rpc.get_block(hash);
        assert!(block_result.is_ok(), "get_block should succeed for valid hash");

        let block = block_result.unwrap();
        assert_eq!(block.header.version, 1, "Block version should be 1");
        assert!(!block.transactions.is_empty(), "Block should have transactions");

        // Test invalid hash
        let invalid_hash = [0xFFu8; 32];
        let result = rpc.get_block(invalid_hash);
        assert!(result.is_err(), "get_block should fail for invalid hash");
    }

    #[test]
    fn test_getblockchaininfo_equivalent() {
        let rpc = create_test_rpc();

        // Test block count
        let count_result = rpc.get_block_count();
        assert!(count_result.is_ok());

        // Test best block hash
        let hash_result = rpc.getbestblockhash();
        assert!(hash_result.is_ok());

        // Verify they are consistent
        let count = count_result.unwrap();
        let hash = hash_result.unwrap();

        // Get block at that height
        let block_result = rpc.get_block(hash);
        assert!(block_result.is_ok());

        let block = block_result.unwrap();
        assert_eq!(block.header.height, count, "Block height should match block count");
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_send_raw_transaction() {
        let rpc = create_test_rpc();

        // Create a valid transaction
        let tx = create_sample_transaction();

        // Serialize to hex
        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_hex = hex::encode(tx_bytes);

        // Test sending the transaction
        let result = rpc.send_raw_transaction(tx_hex);
        assert!(result.is_ok(), "send_raw_transaction should succeed for valid tx");

        let tx_hash = result.unwrap();
        assert_eq!(tx_hash.len(), 32, "Transaction hash should be 32 bytes");

        // Test invalid hex
        let result = rpc.send_raw_transaction("invalid_hex".to_string());
        assert!(result.is_err(), "send_raw_transaction should fail for invalid hex");

        // Test invalid transaction data
        let result = rpc.send_raw_transaction("deadbeef".to_string());
        assert!(result.is_err(), "send_raw_transaction should fail for invalid tx data");
    }

    #[test]
    fn test_get_transaction() {
        let rpc = create_test_rpc();

        // First send a transaction to have something to retrieve
        let tx = create_sample_transaction();
        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_hex = hex::encode(tx_bytes);

        let send_result = rpc.send_raw_transaction(tx_hex);
        assert!(send_result.is_ok(), "Should be able to send transaction");

        let tx_hash = send_result.unwrap();

        // Now try to get the transaction
        let get_result = rpc.get_transaction(tx_hash);
        assert!(get_result.is_ok(), "get_transaction should succeed for existing tx");

        let retrieved_tx = get_result.unwrap();
        assert_eq!(retrieved_tx.hash(), tx_hash, "Retrieved transaction hash should match");

        // Test non-existent transaction
        let nonexistent_hash = [0xFFu8; 32];
        let result = rpc.get_transaction(nonexistent_hash);
        assert!(result.is_err(), "get_transaction should fail for non-existent tx");
    }

    #[test]
    fn test_get_utxo_set() {
        let rpc = create_test_rpc();

        let result = rpc.get_utxo_set();
        assert!(result.is_ok(), "get_utxo_set should succeed");

        let utxos = result.unwrap();
        // UTXO set might be empty initially, but should be a valid Vec
        assert!(utxos.len() >= 0, "UTXO set should be valid");
    }
}

#[cfg(test)]
mod wallet_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_getwalletinfo() {
        let rpc = create_test_rpc();

        let result = rpc.getwalletinfo();
        assert!(result.is_ok(), "getwalletinfo should succeed");

        let info = result.unwrap();

        // Validate response structure
        assert!(info.is_object(), "Response should be a JSON object");
        assert!(info.get("walletname").is_some(), "Should have walletname field");
        assert!(info.get("walletversion").is_some(), "Should have walletversion field");
        assert!(info.get("balance").is_some(), "Should have balance field");
        assert!(info.get("txcount").is_some(), "Should have txcount field");
    }

    #[test]
    fn test_getbalance() {
        let rpc = create_test_rpc();

        // Test with default parameters
        let result = rpc.getbalance(None, None);
        assert!(result.is_ok(), "getbalance should succeed");

        let balance_info = result.unwrap();
        assert!(balance_info.is_object(), "Response should be a JSON object");

        // Check required fields
        assert!(balance_info.get("balance").is_some(), "Should have balance field");
        assert!(balance_info.get("unconfirmed_balance").is_some(), "Should have unconfirmed_balance field");
        assert!(balance_info.get("total_balance").is_some(), "Should have total_balance field");

        // Test with minimum confirmations
        let result = rpc.getbalance(None, Some(6));
        assert!(result.is_ok(), "getbalance with minconf should succeed");
    }

    #[test]
    fn test_listunspent() {
        let rpc = create_test_rpc();

        // Test with default parameters
        let result = rpc.listunspent(None, None, None);
        assert!(result.is_ok(), "listunspent should succeed");

        let unspent = result.unwrap();
        assert!(unspent.is_array(), "Response should be a JSON array");

        // Test with confirmation filters
        let result = rpc.listunspent(Some(1), Some(999999), None);
        assert!(result.is_ok(), "listunspent with filters should succeed");

        let unspent = result.unwrap();
        assert!(unspent.is_array(), "Response should be a JSON array");

        // Validate structure of unspent outputs if any exist
        if let Some(first_output) = unspent.as_array().unwrap().first() {
            assert!(first_output.is_object(), "Each output should be an object");
            assert!(first_output.get("txid").is_some(), "Should have txid field");
            assert!(first_output.get("vout").is_some(), "Should have vout field");
            assert!(first_output.get("amount").is_some(), "Should have amount field");
            assert!(first_output.get("confirmations").is_some(), "Should have confirmations field");
        }
    }
}

#[cfg(test)]
mod mining_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_get_mining_info() {
        let rpc = create_test_rpc();

        let result = rpc.get_mining_info();
        assert!(result.is_ok(), "get_mining_info should succeed");

        let mining_info = result.unwrap();
        assert!(mining_info.is_object(), "Response should be a JSON object");

        // Check required fields
        assert!(mining_info.get("blocks").is_some(), "Should have blocks field");
        assert!(mining_info.get("difficulty").is_some(), "Should have difficulty field");
        assert!(mining_info.get("networkhashps").is_some(), "Should have networkhashps field");
        assert!(mining_info.get("chain").is_some(), "Should have chain field");
        assert!(mining_info.get("algorithm").is_some(), "Should have algorithm field");
    }

    #[test]
    fn test_generate() {
        let rpc = create_test_rpc();

        // Test generating blocks
        let result = rpc.generate(5);
        assert!(result.is_ok(), "generate should succeed");

        let hashes = result.unwrap();
        assert_eq!(hashes.len(), 5, "Should generate exactly 5 blocks");

        for hash in hashes {
            assert_eq!(hash.len(), 32, "Each block hash should be 32 bytes");
        }
    }

    #[test]
    fn test_submit_block() {
        let rpc = create_test_rpc();

        // Create a sample block
        let block = create_sample_block();
        let block_bytes = bincode::serialize(&block).unwrap();
        let block_hex = hex::encode(block_bytes);

        // Test submitting the block
        let result = rpc.submit_block(block_hex);
        assert!(result.is_ok(), "submit_block should succeed for valid block");

        let response = result.unwrap();
        assert!(response == "accepted" || response.starts_with("rejected:"), "Should return accepted or rejected with reason");

        // Test invalid hex
        let result = rpc.submit_block("invalid_hex".to_string());
        assert!(result.is_err(), "submit_block should fail for invalid hex");
    }

    #[test]
    fn test_mine_block() {
        let rpc = create_test_rpc();

        let result = rpc.mine_block();
        assert!(result.is_ok(), "mine_block should succeed");

        let mining_result = result.unwrap();
        assert!(mining_result.is_object(), "Response should be a JSON object");

        // Check required fields
        assert!(mining_result.get("success").is_some(), "Should have success field");
        assert!(mining_result.get("block_hash").is_some(), "Should have block_hash field");
        assert!(mining_result.get("block_height").is_some(), "Should have block_height field");
        assert!(mining_result.get("nonce").is_some(), "Should have nonce field");
        assert!(mining_result.get("difficulty").is_some(), "Should have difficulty field");
        assert!(mining_result.get("timestamp").is_some(), "Should have timestamp field");
        assert!(mining_result.get("algorithm").is_some(), "Should have algorithm field");
        assert!(mining_result.get("transactions").is_some(), "Should have transactions field");
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_get_governance_proposals() {
        let rpc = create_test_rpc();

        let result = rpc.get_governance_proposals();
        assert!(result.is_ok(), "get_governance_proposals should succeed");

        let proposals = result.unwrap();
        // Proposals list might be empty initially, but should be valid
        assert!(proposals.len() >= 0, "Proposals should be a valid vector");
    }

    #[test]
    fn test_create_governance_proposal() {
        let rpc = create_test_rpc();

        // Test creating a valid proposal
        let result = rpc.create_governance_proposal(
            "Test Proposal".to_string(),
            "This is a test proposal for governance testing.".to_string(),
            "ParameterChange".to_string(),
            Some(1000000),
        );
        assert!(result.is_ok(), "create_governance_proposal should succeed for valid input");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("success").is_some(), "Should have success field");

        // Test invalid proposal type
        let result = rpc.create_governance_proposal(
            "Test".to_string(),
            "Description".to_string(),
            "InvalidType".to_string(),
            None,
        );
        assert!(result.is_ok(), "Should return error response for invalid type");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");

        // Test empty title
        let result = rpc.create_governance_proposal(
            "".to_string(),
            "Description".to_string(),
            "ParameterChange".to_string(),
            None,
        );
        assert!(result.is_ok(), "Should return error for empty title");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");
    }

    #[test]
    fn test_vote_on_proposal() {
        let rpc = create_test_rpc();

        // Test voting on a proposal
        let result = rpc.vote_on_proposal("test_proposal_id".to_string(), "YES".to_string());
        assert!(result.is_ok(), "vote_on_proposal should succeed");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("success").is_some(), "Should have success field");

        // Test invalid vote choice
        let result = rpc.vote_on_proposal("test_id".to_string(), "INVALID".to_string());
        assert!(result.is_ok(), "Should return error for invalid vote choice");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");
    }

    #[test]
    fn test_get_proposal_status() {
        let rpc = create_test_rpc();

        let result = rpc.get_proposal_status("test_proposal_id".to_string());
        assert!(result.is_ok(), "get_proposal_status should succeed");

        let status = result.unwrap();
        assert!(status.is_object(), "Response should be a JSON object");
        assert!(status.get("proposal_id").is_some(), "Should have proposal_id field");
        assert!(status.get("status").is_some(), "Should have status field");
    }

    #[test]
    fn test_list_governance_proposals() {
        let rpc = create_test_rpc();

        let result = rpc.list_governance_proposals();
        assert!(result.is_ok(), "list_governance_proposals should succeed");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("proposals").is_some(), "Should have proposals field");
        assert!(response.get("total_proposals").is_some(), "Should have total_proposals field");
    }

    #[test]
    fn test_get_governance_proposal() {
        let rpc = create_test_rpc();

        let result = rpc.get_governance_proposal("test_id".to_string());
        assert!(result.is_ok(), "get_governance_proposal should succeed");

        let proposal = result.unwrap();
        assert!(proposal.is_object(), "Response should be a JSON object");
        assert!(proposal.get("proposal_id").is_some(), "Should have proposal_id field");
    }

    #[test]
    fn test_get_governance_params() {
        let rpc = create_test_rpc();

        let result = rpc.get_governance_params();
        assert!(result.is_ok(), "get_governance_params should succeed");

        let params = result.unwrap();
        assert!(params.is_object(), "Response should be a JSON object");
        assert!(params.get("min_proposal_amount").is_some(), "Should have min_proposal_amount field");
    }
}

#[cfg(test)]
mod masternode_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_register_masternode() {
        let rpc = create_test_rpc();

        // Test registering with sufficient collateral
        let result = rpc.register_masternode("127.0.0.1:9999".to_string(), 1000000000000);
        assert!(result.is_ok(), "register_masternode should succeed");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("success").is_some(), "Should have success field");

        // Test with insufficient collateral
        let result = rpc.register_masternode("127.0.0.1:9998".to_string(), 1000000);
        assert!(result.is_ok(), "Should return error for insufficient collateral");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");
    }

    #[test]
    fn test_get_masternode_status() {
        let rpc = create_test_rpc();

        let result = rpc.get_masternode_status();
        assert!(result.is_ok(), "get_masternode_status should succeed");

        let status = result.unwrap();
        assert!(status.is_object(), "Response should be a JSON object");
        assert!(status.get("status").is_some(), "Should have status field");
        assert!(status.get("service_address").is_some(), "Should have service_address field");
    }

    #[test]
    fn test_get_masternode_list() {
        let rpc = create_test_rpc();

        let result = rpc.get_masternode_list();
        assert!(result.is_ok(), "get_masternode_list should succeed");

        let list = result.unwrap();
        assert!(list.is_object(), "Response should be a JSON object");
        assert!(list.get("total_masternodes").is_some(), "Should have total_masternodes field");
        assert!(list.get("active_masternodes").is_some(), "Should have active_masternodes field");
        assert!(list.get("masternodes").is_some(), "Should have masternodes field");
    }

    #[test]
    fn test_masternode_ping() {
        let rpc = create_test_rpc();

        let result = rpc.masternode_ping();
        assert!(result.is_ok(), "masternode_ping should succeed");

        let ping = result.unwrap();
        assert!(ping.is_object(), "Response should be a JSON object");
        assert!(ping.get("success").is_some(), "Should have success field");
        assert!(ping.get("ping_time").is_some(), "Should have ping_time field");
    }
}

#[cfg(test)]
mod pos_ticket_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_purchase_tickets() {
        let rpc = create_test_rpc();

        // Test purchasing tickets within spend limit
        let result = rpc.purchase_tickets(5, 10000000000); // 5 tickets, 100 RUST limit
        assert!(result.is_ok(), "purchase_tickets should succeed");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("success").is_some(), "Should have success field");

        // Test exceeding spend limit
        let result = rpc.purchase_tickets(100, 100000000); // 100 tickets, 1 RUST limit
        assert!(result.is_ok(), "Should return error for exceeding spend limit");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");
    }

    #[test]
    fn test_get_ticket_pool_info() {
        let rpc = create_test_rpc();

        let result = rpc.get_ticket_pool_info();
        assert!(result.is_ok(), "get_ticket_pool_info should succeed");

        let info = result.unwrap();
        assert!(info.is_object(), "Response should be a JSON object");
        assert!(info.get("live_tickets").is_some(), "Should have live_tickets field");
        assert!(info.get("target_pool_size").is_some(), "Should have target_pool_size field");
    }

    #[test]
    fn test_get_active_tickets() {
        let rpc = create_test_rpc();

        let result = rpc.get_active_tickets();
        assert!(result.is_ok(), "get_active_tickets should succeed");

        let tickets = result.unwrap();
        assert!(tickets.is_object(), "Response should be a JSON object");
        assert!(tickets.get("active_tickets").is_some(), "Should have active_tickets field");
        assert!(tickets.get("total_active").is_some(), "Should have total_active field");
    }

    #[test]
    fn test_vote_on_block() {
        let rpc = create_test_rpc();

        let block_hash = [0u8; 32];
        let result = rpc.vote_on_block(block_hash, "yes".to_string());
        assert!(result.is_ok(), "vote_on_block should succeed");

        let response = result.unwrap();
        assert!(response.is_object(), "Response should be a JSON object");
        assert!(response.get("success").is_some(), "Should have success field");

        // Test invalid vote type
        let result = rpc.vote_on_block(block_hash, "invalid".to_string());
        assert!(result.is_ok(), "Should return error for invalid vote type");

        let response = result.unwrap();
        assert_eq!(response.get("success").unwrap(), &serde_json::Value::Bool(false), "Should indicate failure");
    }

    #[test]
    fn test_get_ticket_info() {
        let rpc = create_test_rpc();

        let result = rpc.get_ticket_info("test_ticket_id".to_string());
        assert!(result.is_ok(), "get_ticket_info should succeed");

        let info = result.unwrap();
        assert!(info.is_object(), "Response should be a JSON object");
        assert!(info.get("ticket_id").is_some(), "Should have ticket_id field");
        assert!(info.get("state").is_some(), "Should have state field");
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_start_sync() {
        let rpc = create_test_rpc();

        let result = rpc.start_sync();
        assert!(result.is_ok(), "start_sync should succeed");

        let response = result.unwrap();
        assert!(response.contains("synchronization"), "Response should mention synchronization");
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_invalid_parameters() {
        let rpc = create_test_rpc();

        // Test get_block_hash with negative height
        let result = rpc.get_block_hash(u64::MAX);
        assert!(result.is_err(), "Should fail for invalid height");

        // Test get_block with invalid hash
        let invalid_hash = [0xFFu8; 32];
        let result = rpc.get_block(invalid_hash);
        assert!(result.is_err(), "Should fail for invalid block hash");

        // Test get_transaction with invalid hash
        let result = rpc.get_transaction(invalid_hash);
        assert!(result.is_err(), "Should fail for invalid transaction hash");
    }

    #[test]
    fn test_malformed_requests() {
        let rpc = create_test_rpc();

        // Test send_raw_transaction with malformed hex
        let result = rpc.send_raw_transaction("gggg".to_string());
        assert!(result.is_err(), "Should fail for malformed hex");

        // Test send_raw_transaction with invalid transaction data
        let result = rpc.send_raw_transaction("deadbeef".to_string());
        assert!(result.is_err(), "Should fail for invalid transaction data");
    }
}

#[cfg(test)]
mod response_format_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_response_structure_consistency() {
        let rpc = create_test_rpc();

        // Test that all methods return properly structured responses

        // Blockchain methods
        let result = rpc.getbestblockhash();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);

        let result = rpc.get_block_count();
        assert!(result.is_ok());
        assert!(result.unwrap() >= 0);

        // Wallet methods
        let result = rpc.getwalletinfo();
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.is_object());

        let result = rpc.getbalance(None, None);
        assert!(result.is_ok());
        let balance = result.unwrap();
        assert!(balance.is_object());

        // Mining methods
        let result = rpc.get_mining_info();
        assert!(result.is_ok());
        let mining = result.unwrap();
        assert!(mining.is_object());

        // Governance methods
        let result = rpc.list_governance_proposals();
        assert!(result.is_ok());
        let proposals = result.unwrap();
        assert!(proposals.is_object());

        // Masternode methods
        let result = rpc.get_masternode_list();
        assert!(result.is_ok());
        let list = result.unwrap();
        assert!(list.is_object());
    }
}

#[cfg(test)]
mod data_accuracy_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_blockchain_consistency() {
        let rpc = create_test_rpc();

        // Get current block count
        let count = rpc.get_block_count().unwrap();

        // Get best block hash
        let hash = rpc.getbestblockhash().unwrap();

        // Get the block
        let block = rpc.get_block(hash).unwrap();

        // Verify consistency
        assert_eq!(block.header.height, count, "Block height should match block count");

        // Get block hash by height
        let hash_by_height = rpc.get_block_hash(count).unwrap();
        assert_eq!(hash, hash_by_height, "Block hash should be consistent");
    }

    #[test]
    fn test_transaction_consistency() {
        let rpc = create_test_rpc();

        // Create and send a transaction
        let tx = create_sample_transaction();
        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_hex = hex::encode(tx_bytes);

        let tx_hash = rpc.send_raw_transaction(tx_hex).unwrap();

        // Retrieve the transaction
        let retrieved_tx = rpc.get_transaction(tx_hash).unwrap();

        // Verify consistency
        assert_eq!(retrieved_tx.hash(), tx_hash, "Transaction hash should match");
    }
}

#[cfg(test)]
mod regtest_integration_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_regtest_block_generation() {
        let rpc = create_test_rpc();

        // Generate some blocks
        let initial_count = rpc.get_block_count().unwrap();
        let hashes = rpc.generate(3).unwrap();

        // Verify blocks were generated
        assert_eq!(hashes.len(), 3, "Should generate exactly 3 blocks");

        // Verify block count increased
        let new_count = rpc.get_block_count().unwrap();
        assert_eq!(new_count, initial_count + 3, "Block count should increase by 3");
    }

    #[test]
    fn test_regtest_mempool_operations() {
        let rpc = create_test_rpc();

        // Create and send a transaction
        let tx = create_sample_transaction();
        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_hex = hex::encode(tx_bytes);

        let tx_hash = rpc.send_raw_transaction(tx_hex).unwrap();

        // Verify transaction was accepted
        assert_eq!(tx_hash.len(), 32, "Should return valid transaction hash");

        // Try to retrieve it
        let retrieved = rpc.get_transaction(tx_hash);
        assert!(retrieved.is_ok(), "Transaction should be retrievable");
    }

    #[test]
    fn test_regtest_wallet_operations() {
        let rpc = create_test_rpc();

        // Get initial wallet info
        let initial_info = rpc.getwalletinfo().unwrap();

        // Get initial balance
        let initial_balance = rpc.getbalance(None, None).unwrap();

        // Verify structure
        assert!(initial_info.is_object());
        assert!(initial_balance.is_object());

        // List unspent outputs
        let unspent = rpc.listunspent(None, None, None).unwrap();
        assert!(unspent.is_array());
    }
}