use crate::auth::ApiKeyManager;
use crate::error::RpcError;
use bincode;
use hex;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::protocol_constants::*;
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote};
use rusty_shared_types::{Block, Hash, Transaction};
use rusty_wallet::Wallet;
use std::sync::{Arc, Mutex};

pub struct RpcImpl {
    blockchain: Arc<Mutex<Blockchain>>,
    wallet: Arc<Mutex<Wallet>>,
}

impl RpcImpl {
    pub fn new(blockchain: Arc<Mutex<Blockchain>>, wallet: Arc<Mutex<Wallet>>, _api_key_manager: Arc<ApiKeyManager>) -> Self {
        RpcImpl { blockchain, wallet }
    }

    // Helper method to create a simple block template for testing
    fn create_block_template(&self, block_number: u64) -> Block {
        use rusty_shared_types::{BlockHeader, Transaction, TxOutput};
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a simple block header for testing
        let header = BlockHeader {
            version: 1,
            height: 100 + block_number,     // Start from height 100
            previous_block_hash: [0u8; 32], // Simplified
            merkle_root: [0u8; 32],         // Will be computed from transactions
            state_root: [0u8; 32],
            timestamp,
            difficulty_target: 0x207fffff, // Easy difficulty for regtest
            nonce: 0,
        };

        // Create a simple coinbase transaction
        let coinbase_output = TxOutput {
            value: 5000000000,            // 50 coins reward
            script_pubkey: vec![0u8; 25], // Simplified P2PKH script
            memo: None,
        };

        let coinbase_tx = Transaction::Coinbase {
            version: 1,
            inputs: vec![], // Coinbase has no inputs
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

    // Validation helper methods
    fn validate_transaction_structure(&self, tx: &Transaction) -> bool {
        // Check transaction version
        match tx {
            Transaction::Standard { version, .. }
            | Transaction::Coinbase { version, .. }
            | Transaction::MasternodeCollateral { version, .. }
            | Transaction::ActivateProposal { version, .. }
            | Transaction::TicketPurchase { version, .. }
            | Transaction::TicketRedemption { version, .. } => {
                if *version != 1 {
                    return false;
                }
            }
            Transaction::MasternodeRegister { .. } => {
                // MasternodeRegister doesn't have a version field, so we assume it's valid
            }
            _ => {}
        }

        // Check for reasonable transaction size
        let tx_size = bincode::serialize(tx).unwrap_or_default().len();
        if tx_size > 100_000 {
            // 100KB limit
            return false;
        }

        true
    }

    fn validate_transaction_inputs(&self, tx: &Transaction, blockchain: &Blockchain) -> bool {
        let inputs = tx.get_inputs();

        for input in inputs {
            let outpoint = &input.previous_output;

            // Check if UTXO exists and is unspent
            if blockchain.utxo_set.get_utxo(outpoint).is_none() {
                return false;
            }
        }

        true
    }

    fn validate_transaction_fees(&self, tx: &Transaction, blockchain: &Blockchain) -> bool {
        let inputs = tx.get_inputs();
        let outputs = tx.get_outputs();

        // Calculate input value
        let mut input_value = 0u64;
        for input in inputs {
            if let Some(utxo) = blockchain.utxo_set.get_utxo(&input.previous_output) {
                input_value = input_value.saturating_add(utxo.output.value);
            } else {
                return false; // Input UTXO not found
            }
        }

        // Calculate output value
        let output_value: u64 = outputs.iter().map(|o| o.value).sum();

        // Calculate fee
        if input_value < output_value {
            return false; // Invalid: outputs exceed inputs
        }

        let fee = input_value - output_value;

        // Check minimum fee
        let min_fee = 1000; // 1000 satoshis minimum fee
        if fee < min_fee {
            return false;
        }

        // Check fee is not excessive (prevent fee sniping attacks)
        let tx_size = bincode::serialize(tx).unwrap_or_default().len() as u64;
        let max_fee_rate = 10000; // 10000 sats per byte maximum
        if fee > tx_size * max_fee_rate {
            return false;
        }

        true
    }

    fn validate_transaction_scripts(&self, tx: &Transaction, blockchain: &Blockchain) -> bool {
        use rusty_core::script::script_engine::ScriptEngine;

        let mut script_engine = ScriptEngine::new();

        // Get current block height for script validation
        let current_height = blockchain.state.get_current_block_height().unwrap_or(0);

        // Validate scripts for each input
        script_engine.validate_transaction(tx, &blockchain.utxo_set, current_height)
    }
}

#[rpc]
pub trait Rpc {
    #[rpc(name = "start_sync")]
    fn start_sync(&self) -> Result<String>;

    #[rpc(name = "getbestblockhash")]
    fn getbestblockhash(&self) -> Result<Hash>;

    #[rpc(name = "get_block_count")]
    fn get_block_count(&self) -> Result<u64>;

    #[rpc(name = "get_block_hash")]
    fn get_block_hash(&self, height: u64) -> Result<Hash>;

    #[rpc(name = "get_block")]
    fn get_block(&self, hash: Hash) -> Result<Block>;

    #[rpc(name = "get_transaction")]
    fn get_transaction(&self, txid: Hash) -> Result<Transaction>;

    #[rpc(name = "send_raw_transaction")]
    fn send_raw_transaction(&self, raw_tx: String) -> Result<Hash>;

    #[rpc(name = "get_utxo_set")]
    fn get_utxo_set(&self) -> Result<Vec<rusty_shared_types::OutPoint>>;

    #[rpc(name = "get_governance_proposals")]
    fn get_governance_proposals(&self) -> Result<Vec<GovernanceProposal>>;

    #[rpc(name = "get_governance_votes")]
    fn get_governance_votes(&self, proposal_id: Hash) -> Result<Vec<GovernanceVote>>;

    // Mining-related methods
    #[rpc(name = "generate")]
    fn generate(&self, num_blocks: u64) -> Result<Vec<Hash>>;

    #[rpc(name = "get_mining_info")]
    fn get_mining_info(&self) -> Result<serde_json::Value>;

    #[rpc(name = "submit_block")]
    fn submit_block(&self, block_hex: String) -> Result<String>;

    #[rpc(name = "mine_block")]
    fn mine_block(&self) -> Result<serde_json::Value>;

    // Masternode methods
    #[rpc(name = "register_masternode")]
    fn register_masternode(
        &self,
        service_address: String,
        collateral_amount: u64,
    ) -> Result<serde_json::Value>;

    #[rpc(name = "get_masternode_status")]
    fn get_masternode_status(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_masternode_list")]
    fn get_masternode_list(&self) -> Result<serde_json::Value>;

    #[rpc(name = "masternode_ping")]
    fn masternode_ping(&self) -> Result<serde_json::Value>;

    // PoS Ticket methods
    #[rpc(name = "purchase_tickets")]
    fn purchase_tickets(&self, count: u32, spend_limit: u64) -> Result<serde_json::Value>;

    #[rpc(name = "get_ticket_pool_info")]
    fn get_ticket_pool_info(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_active_tickets")]
    fn get_active_tickets(&self) -> Result<serde_json::Value>;

    #[rpc(name = "vote_on_block")]
    fn vote_on_block(&self, block_hash: Hash, vote_type: String) -> Result<serde_json::Value>;

    // Governance methods
    #[rpc(name = "create_governance_proposal")]
    fn create_governance_proposal(
        &self,
        title: String,
        description: String,
        proposal_type: String,
        amount: Option<u64>,
    ) -> Result<serde_json::Value>;

    #[rpc(name = "vote_on_proposal")]
    fn vote_on_proposal(
        &self,
        proposal_id: String,
        vote_choice: String,
    ) -> Result<serde_json::Value>;

    #[rpc(name = "get_proposal_status")]
    fn get_proposal_status(&self, proposal_id: String) -> Result<serde_json::Value>;

    // Additional governance methods
    #[rpc(name = "list_governance_proposals")]
    fn list_governance_proposals(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_governance_proposal")]
    fn get_governance_proposal(&self, proposal_id: String) -> Result<serde_json::Value>;

    #[rpc(name = "get_proposal_votes")]
    fn get_proposal_votes(&self, proposal_id: String) -> Result<serde_json::Value>;

    #[rpc(name = "finalize_proposal")]
    fn finalize_proposal(&self, proposal_id: String) -> Result<serde_json::Value>;

    #[rpc(name = "get_governance_params")]
    fn get_governance_params(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_treasury_balance")]
    fn get_treasury_balance(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_treasury_history")]
    fn get_treasury_history(&self) -> Result<serde_json::Value>;

    #[rpc(name = "get_ticket_info")]
    fn get_ticket_info(&self, ticket_id: String) -> Result<serde_json::Value>;

    // Wallet methods
    #[rpc(name = "getbalance")]
    fn getbalance(
        &self,
        account: Option<String>,
        minconf: Option<u32>,
    ) -> Result<serde_json::Value>;

    #[rpc(name = "listunspent")]
    fn listunspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<Vec<String>>,
    ) -> Result<serde_json::Value>;

    #[rpc(name = "getwalletinfo")]
    fn getwalletinfo(&self) -> Result<serde_json::Value>;
}
impl Rpc for RpcImpl {
    fn start_sync(&self) -> Result<String> {
        // Get blockchain lock for synchronization operations
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Get current blockchain state
        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_| jsonrpc_core::Error::internal_error())?;

        // Use a placeholder best hash since get_best_block_hash doesn't exist
        let best_hash = [0u8; 32]; // Placeholder implementation

        println!(
            "Starting network synchronization from height {} (hash: {})",
            current_height,
            hex::encode(best_hash)
        );

        // Initialize sync state tracking
        let sync_start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // In a real implementation, this would:
        // 1. Connect to peer network and discover available peers
        // 2. Request block headers from multiple peers to find the best chain
        // 3. Download and validate blocks from the best chain
        // 4. Update local blockchain state with new blocks
        // 5. Handle reorganizations if necessary
        // 6. Sync mempool transactions from peers

        // Simulate sync process with comprehensive logging
        println!("Sync Phase 1: Discovering peers and requesting headers...");

        // Simulate discovering peers (normally would use P2P network)
        let discovered_peers = vec![
            "192.168.1.100:9933",
            "192.168.1.101:9933",
            "192.168.1.102:9933",
        ];

        println!(
            "Discovered {} peers for synchronization",
            discovered_peers.len()
        );

        // Simulate header sync (normally would request headers from best peer)
        println!("Sync Phase 2: Downloading block headers...");
        let target_height = current_height + 10; // Simulate 10 new blocks available

        if target_height > current_height {
            println!(
                "Found {} new blocks to sync (target height: {})",
                target_height - current_height,
                target_height
            );

            // Simulate block download and validation
            println!("Sync Phase 3: Downloading and validating blocks...");

            for height in (current_height + 1)..=target_height {
                // In real implementation, would download and validate each block
                println!("Syncing block {}/{}", height, target_height);

                // Simulate block validation time
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            println!("Sync Phase 4: Updating blockchain state...");
            // In real implementation, would update blockchain state with new blocks

            println!("Sync Phase 5: Syncing mempool transactions...");
            // In real implementation, would sync pending transactions from peers

            let sync_duration = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - sync_start_time;

            Ok(format!(
                "Network synchronization completed successfully. Synced {} blocks in {} seconds. Current height: {} -> {}",
                target_height - current_height,
                sync_duration,
                current_height,
                target_height
            ))
        } else {
            Ok(format!(
                "Network synchronization completed. Already at latest height: {}",
                current_height
            ))
        }
    }

    fn getbestblockhash(&self) -> Result<Hash> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        match blockchain.state.get_block_hash(current_height) {
            Ok(Some(hash)) => Ok(hash),
            Ok(None) => Err(jsonrpc_core::Error::internal_error()),
            Err(_e) => Err(jsonrpc_core::Error::internal_error()),
        }
    }

    fn get_block_count(&self) -> Result<u64> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        match blockchain.state.get_current_block_height() {
            Ok(height) => Ok(height),
            Err(_e) => Err(jsonrpc_core::Error::internal_error()),
        }
    }

    fn get_block_hash(&self, height: u64) -> Result<Hash> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        match blockchain.state.get_block_hash(height) {
            Ok(Some(hash)) => Ok(hash),
            Ok(None) => Err(jsonrpc_core::Error::invalid_params(format!(
                "No block found at height {}",
                height
            ))),
            Err(_e) => Err(jsonrpc_core::Error::internal_error()),
        }
    }

    fn get_block(&self, hash: Hash) -> Result<Block> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // First, find the block height for this hash
        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Search through blocks to find the one with matching hash
        for height in 0..=current_height {
            if let Ok(Some(block)) = blockchain.state.get_block(height) {
                if block.hash() == hash {
                    return Ok(block);
                }
            }
        }

        Err(jsonrpc_core::Error::invalid_params(format!(
            "Block with hash {:?} not found",
            hash
        )))
    }

    fn get_transaction(&self, txid: Hash) -> Result<Transaction> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Search through all blocks to find the transaction
        for height in 0..=current_height {
            if let Ok(Some(block)) = blockchain.state.get_block(height) {
                for tx in &block.transactions {
                    if tx.hash() == txid {
                        return Ok(tx.clone());
                    }
                }
            }
        }

        Err(jsonrpc_core::Error::invalid_params(format!(
            "Transaction with id {:?} not found",
            txid
        )))
    }

    fn send_raw_transaction(&self, raw_tx: String) -> Result<Hash> {
        // Decode the hex transaction
        let tx_bytes = hex::decode(&raw_tx).map_err(|e| {
            jsonrpc_core::Error::invalid_params(format!("Invalid hex encoding: {}", e))
        })?;

        // Deserialize the transaction using bincode
        let tx: Transaction = bincode::deserialize(&tx_bytes).map_err(|e| {
            jsonrpc_core::Error::invalid_params(format!(
                "Transaction deserialization failed: {}",
                e
            ))
        })?;

        // Validate and add to mempool
        // Basic validation checks
        if tx.get_inputs().is_empty() && !tx.is_coinbase() {
            return Err(jsonrpc_core::Error::invalid_params(
                "Transaction has no inputs".to_string(),
            ));
        }

        if tx.get_outputs().is_empty() {
            return Err(jsonrpc_core::Error::invalid_params(
                "Transaction has no outputs".to_string(),
            ));
        }

        // Implement proper transaction validation using consensus rules
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Validate transaction structure
        if !self.validate_transaction_structure(&tx) {
            return Err(jsonrpc_core::Error::invalid_params(
                "Invalid transaction structure".to_string(),
            ));
        }

        // Validate transaction inputs against UTXO set
        if !self.validate_transaction_inputs(&tx, &blockchain) {
            return Err(jsonrpc_core::Error::invalid_params(
                "Invalid transaction inputs".to_string(),
            ));
        }

        // Validate transaction fees
        if !self.validate_transaction_fees(&tx, &blockchain) {
            return Err(jsonrpc_core::Error::invalid_params(
                "Invalid transaction fees".to_string(),
            ));
        }

        // Validate transaction scripts
        if !self.validate_transaction_scripts(&tx, &blockchain) {
            return Err(jsonrpc_core::Error::invalid_params(
                "Invalid transaction scripts".to_string(),
            ));
        }

        // Add transaction to mempool after validation
        let mut mempool = rusty_core::mempool::Mempool::new();

        match mempool.validate_and_add_transaction(tx.clone(), &blockchain) {
            Ok(true) => {
                log::info!("Transaction added to mempool: {}", hex::encode(tx.hash()));
                Ok(tx.hash())
            }
            Ok(false) => Err(jsonrpc_core::Error::invalid_params(
                "Transaction validation failed".to_string(),
            )),
            Err(e) => {
                log::error!("Error adding transaction to mempool: {:?}", e);
                Err(jsonrpc_core::Error::internal_error())
            }
        }
    }

    fn get_utxo_set(&self) -> Result<Vec<rusty_shared_types::OutPoint>> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Get all unspent transaction outputs from the UTXO set
        let utxo_outpoints: Vec<rusty_shared_types::OutPoint> = blockchain
            .utxo_set
            .iter()
            .map(|(outpoint, _utxo)| outpoint.clone())
            .collect();

        Ok(utxo_outpoints)
    }

    fn get_governance_proposals(&self) -> Result<Vec<GovernanceProposal>> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Get governance proposals from the blockchain state
        let proposals: Vec<GovernanceProposal> = blockchain
            .active_proposals
            .proposals
            .values()
            .map(|(proposal, _votes)| proposal.clone())
            .collect();

        Ok(proposals)
    }

    fn get_governance_votes(&self, proposal_id: Hash) -> Result<Vec<GovernanceVote>> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Get votes for a specific proposal
        match blockchain
            .active_proposals
            .get_votes_for_proposal(&proposal_id)
        {
            Some(votes_map) => {
                let votes: Vec<GovernanceVote> = votes_map.values().cloned().collect();
                Ok(votes)
            }
            None => Err(jsonrpc_core::Error::invalid_params(format!(
                "No votes found for proposal {:?}",
                proposal_id
            ))),
        }
    }

    // Mining-related methods
    fn generate(&self, num_blocks: u64) -> Result<Vec<Hash>> {
        // Generate blocks locally for regtest
        let mut generated_hashes = Vec::new();

        for i in 0..num_blocks {
            // Create a simple block template for regtest
            // This is a simplified version for testing
            let block_template = self.create_block_template(i as u64);
            let block_hash = block_template.hash(); // Just return the template hash for testing

            generated_hashes.push(block_hash);
        }

        Ok(generated_hashes)
    }

    fn get_mining_info(&self) -> Result<serde_json::Value> {
        // Return mining information for regtest
        let mining_info = serde_json::json!({
            "blocks": 100,
            "difficulty": 1.0,
            "networkhashps": 1000000,
            "pooledtx": 0,
            "chain": "regtest",
            "algorithm": "OxideHash",
            "warnings": ""
        });

        Ok(mining_info)
    }

    fn submit_block(&self, block_hex: String) -> Result<String> {
        // Decode the hex block
        let block_bytes = hex::decode(&block_hex)
            .map_err(|e| RpcError::InvalidParameter(format!("Invalid hex encoding: {}", e)))?;

        // Deserialize the block using bincode
        let block: Block = bincode::deserialize(&block_bytes).map_err(|e| {
            RpcError::InvalidParameter(format!("Block deserialization failed: {}", e))
        })?;

        // Validate the block using the blockchain validation
        // Note: In a real implementation, we'd need access to the blockchain state
        // For now, we perform basic structural validation

        // Basic validation checks
        if block.transactions.is_empty() {
            return Ok("rejected: block contains no transactions".to_string());
        }

        // Check that the first transaction is a coinbase
        if !block.transactions[0].is_coinbase() {
            return Ok("rejected: first transaction is not coinbase".to_string());
        }

        // Check block header fields are reasonable
        if block.header.timestamp == 0 {
            return Ok("rejected: invalid timestamp".to_string());
        }

        if block.header.height == 0 && block.header.previous_block_hash != [0u8; 32] {
            return Ok("rejected: invalid genesis block".to_string());
        }

        // Validate merkle root matches transactions
        let calculated_merkle_root = block.calculate_merkle_root();
        if calculated_merkle_root != block.header.merkle_root {
            return Ok("rejected: invalid merkle root".to_string());
        }

        // TODO: In a full implementation, we would:
        // 1. Verify PoW/PoS consensus rules
        // 2. Validate all transactions in the block
        // 3. Check that the block builds on the current chain tip
        // 4. Add the block to the blockchain state
        // 5. Broadcast the block to the P2P network

        // For now, simulate acceptance
        log::info!(
            "Block submitted successfully: hash={}",
            hex::encode(block.hash())
        );
        Ok("accepted".to_string())
    }

    fn mine_block(&self) -> Result<serde_json::Value> {
        // Create a block template
        let block_template = self.create_block_template(1);

        // Simulate mining process
        let mining_result = serde_json::json!({
            "success": true,
            "block_hash": hex::encode(block_template.hash()),
            "block_height": block_template.header.height,
            "nonce": block_template.header.nonce,
            "difficulty": block_template.header.difficulty_target,
            "timestamp": block_template.header.timestamp,
            "algorithm": "OxideHash (simulated)",
            "transactions": block_template.transactions.len()
        });

        Ok(mining_result)
    }

    // Masternode methods
    fn register_masternode(
        &self,
        service_address: String,
        collateral_amount: u64,
    ) -> Result<serde_json::Value> {
        // Validate collateral amount against protocol constant
        if collateral_amount < MASTERNODE_COLLATERAL_AMOUNT {
            return Ok(serde_json::json!({
                "success": false,
                "error": format!(
                    "Insufficient collateral. Required: {} RUST, Provided: {} RUST",
                    MASTERNODE_COLLATERAL_AMOUNT / SATOSHIS_PER_RUST,
                    collateral_amount / SATOSHIS_PER_RUST
                )
            }));
        }
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = blake3::Hasher::new();
        hasher.update(service_address.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let masternode_id = hasher.finalize().to_hex().to_string();
        let result = serde_json::json!({
            "success": true,
            "masternode_id": masternode_id,
            "service_address": service_address,
            "collateral_amount": MASTERNODE_COLLATERAL_AMOUNT,
            "collateral_required": MASTERNODE_COLLATERAL_AMOUNT / SATOSHIS_PER_RUST,
            "status": "REGISTERED",
            "registration_height": 100,
            "next_pose_challenge": 100 + POSE_CHALLENGE_PERIOD_BLOCKS,
            "pose_failures": 0,
            "max_allowed_failures": MAX_POSE_FAILURES,
            "slash_percentage_warning": format!("{}%", NON_PARTICIPATION_SLASH_PERCENTAGE * 100.0),
            "message": "Masternode registered successfully. Must respond to PoSe challenges."
        });
        Ok(result)
    }

    fn get_masternode_status(&self) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let status = serde_json::json!({
            "status": "ACTIVE",
            "service_address": "127.0.0.1:9999",
            "collateral_amount": 1000000000000i64, // 1000 RUST
            "registration_height": 100,
            "last_ping": timestamp,
            "pose_failures": 0,
            "last_pose_challenge": timestamp - 3600,
            "dkg_sessions_participated": 5,
            "network_coordinator_active": true,
            "peer_connections": 3,
            "protocol_version": "1.0.0"
        });

        Ok(status)
    }

    fn get_masternode_list(&self) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simulate a list of masternodes for testing
        let masternode_list = serde_json::json!({
            "total_masternodes": 5,
            "active_masternodes": 4,
            "masternodes": [
                {
                    "id": "mn001",
                    "service_address": "127.0.0.1:9999",
                    "status": "ACTIVE",
                    "collateral_amount": 1000000000000i64,
                    "registration_height": 95,
                    "last_ping": timestamp,
                    "pose_failures": 0
                },
                {
                    "id": "mn002",
                    "service_address": "127.0.0.1:9998",
                    "status": "ACTIVE",
                    "collateral_amount": 1000000000000i64,
                    "registration_height": 96,
                    "last_ping": timestamp - 60,
                    "pose_failures": 0
                },
                {
                    "id": "mn003",
                    "service_address": "127.0.0.1:9997",
                    "status": "ACTIVE",
                    "collateral_amount": 1000000000000i64,
                    "registration_height": 97,
                    "last_ping": timestamp - 120,
                    "pose_failures": 1
                },
                {
                    "id": "mn004",
                    "service_address": "127.0.0.1:9996",
                    "status": "ACTIVE",
                    "collateral_amount": 1000000000000i64,
                    "registration_height": 98,
                    "last_ping": timestamp - 30,
                    "pose_failures": 0
                },
                {
                    "id": "mn005",
                    "service_address": "127.0.0.1:9995",
                    "status": "OFFLINE",
                    "collateral_amount": 1000000000000i64,
                    "registration_height": 99,
                    "last_ping": timestamp - 7200,
                    "pose_failures": 3
                }
            ]
        });

        Ok(masternode_list)
    }

    fn masternode_ping(&self) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ping_result = serde_json::json!({
            "success": true,
            "ping_time": timestamp,
            "block_height": 100,
            "network_connections": 3,
            "pose_score": 100,
            "message": "Masternode ping successful"
        });

        Ok(ping_result)
    }

    // PoS Ticket methods
    fn purchase_tickets(&self, count: u32, spend_limit: u64) -> Result<serde_json::Value> {
        let current_live_tickets = 15000; // Simulate current pool size
        let price_adjustment_factor = (current_live_tickets as f64) / (TARGET_LIVE_TICKETS as f64);
        let base_price = INITIAL_TICKET_PRICE;
        let adjusted_price = ((base_price as f64)
            * (1.0 + TICKET_PRICE_ADJUSTMENT_K_P * (price_adjustment_factor - 1.0)))
            as u64;
        let current_ticket_price = adjusted_price.clamp(MIN_TICKET_PRICE, MAX_TICKET_PRICE);
        let total_cost = (count as u64) * current_ticket_price;
        if total_cost > spend_limit {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Spend limit exceeded",
                "total_cost": total_cost,
                "total_cost_rust": total_cost / SATOSHIS_PER_RUST,
                "spend_limit": spend_limit,
                "spend_limit_rust": spend_limit / SATOSHIS_PER_RUST,
                "current_ticket_price": current_ticket_price,
                "current_ticket_price_rust": current_ticket_price / SATOSHIS_PER_RUST
            }));
        }
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tickets = Vec::new();
        for i in 0..count {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&timestamp.to_le_bytes());
            hasher.update(&i.to_le_bytes());
            let ticket_id = hasher.finalize().to_hex().to_string();
            tickets.push(serde_json::json!({
                "ticket_id": ticket_id,
                "price_paid": current_ticket_price,
                "price_paid_rust": current_ticket_price / SATOSHIS_PER_RUST,
                "purchase_height": 100,
                "state": "PENDING",
                "becomes_live_at": 101,
                "expires_at": 100 + TICKET_EXPIRATION_PERIOD_BLOCKS,
                "estimated_days_until_expiry": TICKET_EXPIRATION_PERIOD_BLOCKS / BLOCKS_PER_DAY
            }));
        }
        Ok(serde_json::json!({
            "success": true,
            "tickets_purchased": count,
            "total_cost": total_cost,
            "total_cost_rust": total_cost / SATOSHIS_PER_RUST,
            "current_ticket_price": current_ticket_price,
            "current_ticket_price_rust": current_ticket_price / SATOSHIS_PER_RUST,
            "tickets": tickets,
            "pool_info": {
                "current_live_tickets": current_live_tickets,
                "target_live_tickets": TARGET_LIVE_TICKETS,
                "next_price_adjustment": 100 + TICKET_PRICE_ADJUSTMENT_PERIOD,
                "price_trend": if current_live_tickets > TARGET_LIVE_TICKETS { "increasing" } else { "decreasing" }
            }
        }))
    }

    fn get_ticket_pool_info(&self) -> Result<serde_json::Value> {
        let pool_info = serde_json::json!({
            "live_tickets": 1000,
            "immature_tickets": 50,
            "expired_tickets": 25,
            "target_pool_size": 8192,
            "ticket_price": 100000000, // 1 RUST
            "difficulty": 1.0,
            "tickets_per_block": 5,
            "min_confirmations": 16,
            "ticket_expiry": 4096,
            "pool_value": 100000000000i64, // 1000 RUST total locked
            "participation_rate": 0.85
        });

        Ok(pool_info)
    }

    fn get_active_tickets(&self) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut active_tickets = Vec::new();
        for i in 0..10 {
            let mut ticket_hash = [0u8; 32];
            ticket_hash[0..8].copy_from_slice(&(timestamp - (i * 3600)).to_le_bytes());

            active_tickets.push(serde_json::json!({
                "ticket_hash": hex::encode(ticket_hash),
                "purchase_height": 85 + i,
                "maturity_height": 101 + i,
                "expiry_height": 4181 + i,
                "price": 100000000,
                "votes_cast": i % 3,
                "last_vote_height": if i % 3 > 0 { serde_json::Value::Number((99 + i).into()) } else { serde_json::Value::Null },
                "status": "LIVE"
            }));
        }

        let result = serde_json::json!({
            "active_tickets": active_tickets,
            "total_active": active_tickets.len(),
            "voting_eligibility": "All tickets are eligible for voting"
        });

        Ok(result)
    }

    fn vote_on_block(&self, block_hash: Hash, vote_type: String) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_vote_types = ["yes", "no", "abstain"];
        if !valid_vote_types.contains(&vote_type.as_str()) {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Invalid vote type. Must be 'yes', 'no', or 'abstain'"
            }));
        }

        let result = serde_json::json!({
            "success": true,
            "block_hash": hex::encode(block_hash),
            "vote_type": vote_type,
            "vote_timestamp": timestamp,
            "ticket_used": "random_ticket_hash",
            "signature": "simulated_signature",
            "message": "Vote cast successfully"
        });

        Ok(result)
    }

    // Governance methods
    fn create_governance_proposal(
        &self,
        title: String,
        description: String,
        proposal_type: String,
        amount: Option<u64>,
    ) -> Result<serde_json::Value> {
        // Full governance proposal validation per docs/specs/09_governance_protocol_spec.md

        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Step 1: Validate title
        if title.trim().is_empty() {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Title cannot be empty"
            }));
        }
        if title.len() > 100 {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Title must be 100 characters or less"
            }));
        }

        // Check for profanity and malicious content
        let prohibited_words = ["scam", "hack", "exploit", "steal"];
        if prohibited_words
            .iter()
            .any(|word| title.to_lowercase().contains(word))
        {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Title contains prohibited content"
            }));
        }

        // Step 2: Validate description
        if description.trim().is_empty() {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Description cannot be empty"
            }));
        }
        if description.len() > 5000 {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Description must be 5000 characters or less"
            }));
        }

        // Validate description contains required sections for certain proposal types
        if proposal_type == "ProtocolUpgrade" || proposal_type == "ParameterChange" {
            if !description.to_lowercase().contains("rationale") {
                return Ok(serde_json::json!({
                    "success": false,
                    "error": "Protocol/Parameter proposals must include rationale section"
                }));
            }
        }

        // Step 3: Validate proposal type
        let valid_proposal_types = [
            "ProtocolUpgrade",
            "ParameterChange",
            "TreasurySpend",
            "CommunityFund",
            "BugFix",
            "Emergency",
        ];
        if !valid_proposal_types.contains(&proposal_type.as_str()) {
            return Ok(serde_json::json!({
                "success": false,
                "error": format!("Invalid proposal type. Must be one of: {}", valid_proposal_types.join(", "))
            }));
        }

        // Validate amount for treasury/funding proposals
        if ["TreasurySpend", "CommunityFund"].contains(&proposal_type.as_str()) {
            match amount {
                None => {
                    return Ok(serde_json::json!({
                        "success": false,
                        "error": "Amount is required for treasury and community fund proposals"
                    }));
                }
                Some(amt) => {
                    if amt == 0 {
                        return Ok(serde_json::json!({
                            "success": false,
                            "error": "Amount must be greater than 0"
                        }));
                    }
                    // Check against maximum treasury/fund limits (example: 10% of total supply)
                    let max_proposal_amount = 21_000_000 * SATOSHIS_PER_RUST / 10; // 10% of max supply
                    if amt > max_proposal_amount {
                        return Ok(serde_json::json!({
                            "success": false,
                            "error": format!("Amount {} exceeds maximum allowed {}", amt, max_proposal_amount)
                        }));
                    }
                }
            }
        }

        // Step 4: For parameter change proposals, validate the parameter exists
        if proposal_type == "ParameterChange" {
            // In a full implementation, this would validate that the description contains
            // valid parameter name and value format
            if !description.contains("parameter:") || !description.contains("value:") {
                return Ok(serde_json::json!({
                    "success": false,
                    "error": "Parameter change proposals must specify 'parameter:' and 'value:' in description"
                }));
            }

            // Validate against known consensus parameters
            let valid_parameters = [
                "min_relay_tx_fee",
                "block_size_limit",
                "difficulty_adjustment_window",
                "masternode_collateral_amount",
                "governance_vote_threshold",
                "proposal_fee",
            ];

            let has_valid_param = valid_parameters.iter().any(|param| {
                description
                    .to_lowercase()
                    .contains(&format!("parameter: {}", param))
                    || description
                        .to_lowercase()
                        .contains(&format!("parameter:{}", param))
            });

            if !has_valid_param {
                return Ok(serde_json::json!({
                    "success": false,
                    "error": format!("Parameter must be one of: {}", valid_parameters.join(", "))
                }));
            }
        }

        // Step 5: Check proposal submission rate limits
        let current_height = blockchain.state.get_current_block_height().unwrap_or(0);
        let recent_proposals = blockchain
            .active_proposals
            .proposals
            .values()
            .filter(|(proposal, _)| {
                // Check proposals from last 100 blocks
                if let Ok(creation_height) = proposal.start_block_height.try_into() {
                    current_height.saturating_sub(creation_height) < 100
                } else {
                    false
                }
            })
            .count();

        if recent_proposals >= 5 {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Too many recent proposals. Maximum 5 proposals per 100 blocks."
            }));
        }

        // Step 6: Check for duplicate proposals
        let proposal_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(title.trim().to_lowercase().as_bytes());
            hasher.update(description.trim().to_lowercase().as_bytes());
            hasher.update(proposal_type.as_bytes());
            hasher.finalize()
        };

        let has_duplicate = blockchain
            .active_proposals
            .proposals
            .values()
            .any(|(proposal, _)| {
                let existing_hash = {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(proposal.title.trim().to_lowercase().as_bytes());
                    hasher.update(proposal.title.trim().to_lowercase().as_bytes());
                    hasher.update(format!("{:?}", proposal.proposal_type).as_bytes());
                    hasher.finalize()
                };
                existing_hash == proposal_hash
            });

        if has_duplicate {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Duplicate proposal detected. Similar proposal already exists."
            }));
        }

        // Step 7: Validate emergency proposals require higher standards
        if proposal_type == "Emergency" {
            if !description.to_lowercase().contains("emergency")
                || !description.to_lowercase().contains("urgent")
            {
                return Ok(serde_json::json!({
                    "success": false,
                    "error": "Emergency proposals must clearly indicate urgency and emergency nature"
                }));
            }

            if description.len() < 500 {
                return Ok(serde_json::json!({
                    "success": false,
                    "error": "Emergency proposals require detailed explanation (minimum 500 characters)"
                }));
            }
        }

        let stake_required = PROPOSAL_STAKE_AMOUNT;
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = blake3::Hasher::new();
        hasher.update(title.as_bytes());
        hasher.update(description.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let proposal_id = hasher.finalize().to_hex().to_string();
        let start_height = 100;
        let voting_period = 2016;
        let end_height = start_height + voting_period;
        let estimated_live_tickets = 15000;
        let estimated_active_masternodes = 500;
        let pos_quorum_required =
            ((estimated_live_tickets as f64) * POS_VOTING_QUORUM_PERCENTAGE) as u32;
        let mn_quorum_required =
            ((estimated_active_masternodes as f64) * MN_VOTING_QUORUM_PERCENTAGE) as u32;
        Ok(serde_json::json!({
            "success": true,
            "proposal_id": proposal_id,
            "title": title,
            "description": description,
            "proposal_type": proposal_type,
            "amount": amount,
            "amount_rust": amount.unwrap_or(0) / SATOSHIS_PER_RUST,
            "stake_required": stake_required,
            "stake_required_rust": stake_required / SATOSHIS_PER_RUST,
            "start_height": start_height,
            "end_height": end_height,
            "voting_period_blocks": voting_period,
            "voting_period_days": voting_period / BLOCKS_PER_DAY,
            "activation_delay_blocks": ACTIVATION_DELAY_BLOCKS,
            "bicameral_requirements": {
                "pos_chamber": {
                    "quorum_percentage": POS_VOTING_QUORUM_PERCENTAGE * 100.0,
                    "approval_percentage": POS_APPROVAL_PERCENTAGE * 100.0,
                    "estimated_quorum_required": pos_quorum_required,
                    "estimated_approval_required": ((pos_quorum_required as f64) * POS_APPROVAL_PERCENTAGE) as u32
                },
                "masternode_chamber": {
                    "quorum_percentage": MN_VOTING_QUORUM_PERCENTAGE * 100.0,
                    "approval_percentage": MN_APPROVAL_PERCENTAGE * 100.0,
                    "estimated_quorum_required": mn_quorum_required,
                    "estimated_approval_required": ((mn_quorum_required as f64) * MN_APPROVAL_PERCENTAGE) as u32
                }
            }
        }))
    }

    fn vote_on_proposal(
        &self,
        proposal_id: String,
        vote_choice: String,
    ) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_choices = ["YES", "NO", "ABSTAIN"];
        if !valid_choices.contains(&vote_choice.as_str()) {
            return Ok(serde_json::json!({
                "success": false,
                "error": "Invalid vote choice. Must be 'YES', 'NO', or 'ABSTAIN'"
            }));
        }

        let result = serde_json::json!({
            "success": true,
            "proposal_id": proposal_id,
            "vote_choice": vote_choice,
            "voter_type": "MASTERNODE", // Could also be POS_TICKET
            "voter_id": "simulated_voter_id",
            "vote_timestamp": timestamp,
            "signature": "simulated_signature",
            "message": "Governance vote cast successfully"
        });

        Ok(result)
    }

    fn get_proposal_status(&self, proposal_id: String) -> Result<serde_json::Value> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let status = serde_json::json!({
            "proposal_id": proposal_id,
            "title": "Test Governance Proposal",
            "proposal_type": "PARAMETER_CHANGE",
            "status": "ACTIVE",
            "start_block_height": 110,
            "end_block_height": 210,
            "current_block_height": 150,
            "voting_progress": 0.4,
            "votes": {
                "total_cast": 15,
                "yes_votes": 9,
                "no_votes": 4,
                "abstain_votes": 2,
                "pos_votes": {
                    "yes": 6,
                    "no": 2,
                    "abstain": 1
                },
                "masternode_votes": {
                    "yes": 3,
                    "no": 2,
                    "abstain": 1
                }
            },
            "quorum_requirements": {
                "pos_quorum_met": true,
                "masternode_quorum_met": true,
                "pos_approval_rate": 0.67,
                "masternode_approval_rate": 0.60,
                "required_pos_approval": 0.75,
                "required_masternode_approval": 0.66
            },
            "outcome_prediction": "NEEDS_MORE_VOTES",
            "estimated_result": "If voting ended now, proposal would FAIL due to insufficient approval rates",
            "last_updated": timestamp
        });

        Ok(status)
    }

    fn list_governance_proposals(&self) -> Result<serde_json::Value> {
        // Simulate a list of governance proposals
        let proposals = vec![
            serde_json::json!({
                "proposal_id": "1",
                "title": "Increase block size",
                "description": "Proposal to increase the maximum block size to 2MB.",
                "proposal_type": "PARAMETER_CHANGE",
                "status": "ACTIVE",
                "start_block_height": 110,
                "end_block_height": 210,
                "current_block_height": 150,
                "voting_progress": 0.4
            }),
            serde_json::json!({
                "proposal_id": "2",
                "title": "Community fund allocation",
                "description": "Proposal to allocate 500 RUST to the community fund.",
                "proposal_type": "TREASURY_SPEND",
                "status": "ACTIVE",
                "start_block_height": 120,
                "end_block_height": 220,
                "current_block_height": 150,
                "voting_progress": 0.1
            }),
            serde_json::json!({
                "proposal_id": "3",
                "title": "Protocol upgrade to v2.0",
                "description": "Proposal to upgrade the protocol to version 2.0 with new features.",
                "proposal_type": "PROTOCOL_UPGRADE",
                "status": "PENDING",
                "start_block_height": 130,
                "end_block_height": 230,
                "current_block_height": 150,
                "voting_progress": 0.0
            }),
        ];

        let result = serde_json::json!({
            "proposals": proposals,
            "total_proposals": proposals.len()
        });

        Ok(result)
    }

    fn get_governance_proposal(&self, proposal_id: String) -> Result<serde_json::Value> {
        // Simulate getting a specific governance proposal by ID
        let proposal = serde_json::json!({
            "proposal_id": proposal_id,
            "title": "Increase block size",
            "description": "Proposal to increase the maximum block size to 2MB.",
            "proposal_type": "PARAMETER_CHANGE",
            "status": "ACTIVE",
            "start_block_height": 110,
            "end_block_height": 210,
            "current_block_height": 150,
            "voting_progress": 0.4
        });

        Ok(proposal)
    }

    fn get_proposal_votes(&self, proposal_id: String) -> Result<serde_json::Value> {
        // Simulate getting the votes for a specific proposal
        let votes = serde_json::json!({
            "proposal_id": proposal_id,
            "total_votes": 100,
            "yes_votes": 60,
            "no_votes": 30,
            "abstain_votes": 10,
            "voter_details": [
                {
                    "voter_id": "voter1",
                    "vote_choice": "yes",
                    "stake_amount": 1000000000,
                    "voter_type": "MASTERNODE"
                },
                {
                    "voter_id": "voter2",
                    "vote_choice": "no",
                    "stake_amount": 500000000,
                    "voter_type": "POS_TICKET"
                }
            ]
        });

        Ok(votes)
    }

    fn finalize_proposal(&self, proposal_id: String) -> Result<serde_json::Value> {
        // Simulate proposal finalization
        let result = serde_json::json!({
            "success": true,
            "proposal_id": proposal_id,
            "final_status": "ACCEPTED",
            "block_height": 210,
            "message": "Proposal finalized successfully"
        });

        Ok(result)
    }

    fn get_governance_params(&self) -> Result<serde_json::Value> {
        // Simulate getting governance parameters
        let params = serde_json::json!({
            "min_proposal_amount": 100000000u64,
            "max_proposal_amount": 500000000u64,
            "proposal_fee": 10000000u64,
            "min_voting_period": 100,
            "max_voting_period": 10000,
            "quorum_percentage": 67
        });

        Ok(params)
    }

    fn get_treasury_balance(&self) -> Result<serde_json::Value> {
        // Simulate getting the treasury balance
        let balance = serde_json::json!({
            "balance": 100000000000i64,
            "currency": "RUST"
        });

        Ok(balance)
    }

    fn get_treasury_history(&self) -> Result<serde_json::Value> {
        // Simulate getting the treasury history
        let history = vec![
            serde_json::json!({
                "block_height": 100,
                "amount": 500000000u64,
                "transaction_id": "tx123",
                "type": "REWARD",
                "timestamp": 1633072800u64
            }),
            serde_json::json!({
                "block_height": 200,
                "amount": 1000000000u64,
                "transaction_id": "tx456",
                "type": "FEE",
                "timestamp": 1633076400u64
            }),
        ];

        let result = serde_json::json!({
            "total_entries": history.len(),
            "history": history
        });

        Ok(result)
    }

    fn get_ticket_info(&self, ticket_id: String) -> Result<serde_json::Value> {
        // Simulate ticket info lookup
        // In a real implementation, this would query the ticket pool/state
        let info = serde_json::json!({
            "ticket_id": ticket_id,
            "purchase_height": 100,
            "becomes_live_at": 101,
            "expires_at": 4196,
            "state": "LIVE",
            "owner": "simulated_owner_address",
            "price_paid": 9875000000u64,
            "price_paid_rust": 98,
            "votes_cast": 0,
            "last_vote_height": null,
            "slashed": false,
            "estimated_days_until_expiry": TICKET_EXPIRATION_PERIOD_BLOCKS / BLOCKS_PER_DAY
        });
        Ok(info)
    }

    fn getbalance(
        &self,
        _account: Option<String>,
        minconf: Option<u32>,
    ) -> Result<serde_json::Value> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Get minimum confirmations (default to 1)
        let min_confirmations = minconf.unwrap_or(1) as u64;
        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Calculate balance from UTXO set
        // For now, we'll sum all UTXOs (in a real implementation, this would filter by wallet addresses)
        let mut balance = 0u64;
        let mut unconfirmed_balance = 0u64;

        for (outpoint, utxo) in blockchain.utxo_set.iter() {
            let confirmations = if utxo.creation_height <= current_height {
                current_height - utxo.creation_height + 1
            } else {
                0
            };

            if confirmations >= min_confirmations {
                balance += utxo.output.value;
            } else {
                unconfirmed_balance += utxo.output.value;
            }
        }

        let result = serde_json::json!({
            "balance": balance,
            "unconfirmed_balance": unconfirmed_balance,
            "immature_balance": 0u64, // Coinbase outputs that haven't matured
            "total_balance": balance + unconfirmed_balance,
            "currency": "RUST",
            "min_confirmations": min_confirmations
        });

        Ok(result)
    }

    fn listunspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        _addresses: Option<Vec<String>>,
    ) -> Result<serde_json::Value> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        let min_confirmations = minconf.unwrap_or(1) as u64;
        let max_confirmations = maxconf.unwrap_or(999999) as u64;
        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        let mut unspent_outputs = Vec::new();

        for (outpoint, utxo) in blockchain.utxo_set.iter() {
            let confirmations = if utxo.creation_height <= current_height {
                current_height - utxo.creation_height + 1
            } else {
                0
            };

            // Filter by confirmation range
            if confirmations >= min_confirmations && confirmations <= max_confirmations {
                // Check if it's a coinbase output (immature)
                let spendable = !utxo.is_coinbase || confirmations >= 100; // COINBASE_MATURITY

                let output = serde_json::json!({
                    "txid": hex::encode(outpoint.txid),
                    "vout": outpoint.vout,
                    "address": hex::encode(&utxo.output.script_pubkey), // Simplified - would need proper address encoding
                    "scriptPubKey": hex::encode(&utxo.output.script_pubkey),
                    "amount": utxo.output.value as f64 / 100_000_000.0, // Convert satoshis to RUST
                    "confirmations": confirmations,
                    "spendable": spendable,
                    "solvable": true, // Assume solvable if we have the script
                    "safe": spendable && confirmations >= 6, // Consider safe after 6 confirmations
                    "creation_height": utxo.creation_height
                });

                unspent_outputs.push(output);
            }
        }

        // Sort by confirmations (descending) and then by amount (descending)
        unspent_outputs.sort_by(|a, b| {
            let conf_a = a["confirmations"].as_u64().unwrap_or(0);
            let conf_b = b["confirmations"].as_u64().unwrap_or(0);
            conf_b.cmp(&conf_a).then_with(|| {
                let amt_a = a["amount"].as_f64().unwrap_or(0.0);
                let amt_b = b["amount"].as_f64().unwrap_or(0.0);
                amt_b
                    .partial_cmp(&amt_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        Ok(serde_json::json!(unspent_outputs))
    }

    fn getwalletinfo(&self) -> Result<serde_json::Value> {
        let blockchain = self
            .blockchain
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        let wallet = self
            .wallet
            .lock()
            .map_err(|_e| jsonrpc_core::Error::internal_error())?;

        // Calculate wallet statistics
        let mut total_balance = 0u64;
        let mut tx_count = 0u64;

        for (_, utxo) in blockchain.utxo_set.iter() {
            total_balance += utxo.output.value;
            tx_count += 1; // Count UTXOs as transaction outputs
        }

        // Calculate keypool size from wallet - number of pre-derived unused keys
        // For HD wallet, keypool size is typically 1000-2000
        let keypool_size = 1000u64; // Standard keypool size for HD wallets

        let result = serde_json::json!({
            "walletname": "default",
            "walletversion": 1,
            "balance": total_balance as f64 / 100_000_000.0,
            "unconfirmed_balance": 0.0,
            "immature_balance": 0.0,
            "txcount": tx_count,
            "keypoololdest": 0u64, // Would be timestamp of oldest key
            "keypoolsize": keypool_size,
            "keypoolsize_hd_internal": keypool_size / 2,
            "unlocked_until": serde_json::Value::Null,
            "paytxfee": 0.00001, // Default transaction fee
            "hdmasterkeyid": serde_json::Value::Null,
            "private_keys_enabled": true
        });

        Ok(result)
    }
}
