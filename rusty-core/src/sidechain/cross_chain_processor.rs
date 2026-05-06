//! Cross-chain transaction processing
//!
//! This module handles the validation, routing, and execution of cross-chain
//! transactions between mainchain and sidechains.

use crate::sidechain::cross_chain_communication::{CrossChainCommunication, CrossChainMessage};
use crate::sidechain::federation_manager::FederationManager;
use crate::sidechain::types::*;
use rusty_shared_types::{Hash, OutPoint};
use std::collections::HashMap;
use std::sync::Arc;

/// Cross-chain transaction processor
pub struct CrossChainProcessor {
    /// Communication manager
    communication: Arc<std::sync::Mutex<CrossChainCommunication>>,
    /// Transaction pools by chain
    tx_pools: HashMap<Hash, Vec<CrossChainTransaction>>,
    /// Processed transaction cache
    processed_txs: HashMap<Hash, CrossChainTxStatus>,
    /// Mainchain interface
    mainchain_interface: Option<Box<dyn MainchainInterface>>,
    /// Federation manager for signature verification
    federation_manager: Arc<std::sync::Mutex<FederationManager>>,
}

/// Status of cross-chain transaction
#[derive(Debug, Clone, PartialEq)]
pub enum CrossChainTxStatus {
    /// Transaction received but not validated
    Received,
    /// Transaction validated and pending execution
    Validated,
    /// Transaction executed successfully
    Executed,
    /// Transaction failed validation
    Failed,
    /// Transaction rejected
    Rejected,
}

/// Mainchain interface trait
pub trait MainchainInterface: Send + Sync {
    /// Submit transaction to mainchain
    fn submit_transaction(&self, tx: &rusty_shared_types::Transaction) -> Result<Hash, String>;
    /// Get mainchain block height
    fn get_block_height(&self) -> u64;
    /// Get mainchain block hash
    fn get_block_hash(&self, height: u64) -> Option<Hash>;
    /// Validate mainchain transaction
    fn validate_transaction(&self, tx_hash: &Hash) -> bool;
}

impl CrossChainProcessor {
    /// Create a new cross-chain processor
    pub fn new(
        communication: Arc<std::sync::Mutex<CrossChainCommunication>>,
        federation_manager: Arc<std::sync::Mutex<FederationManager>>,
    ) -> Self {
        Self {
            communication,
            tx_pools: HashMap::new(),
            processed_txs: HashMap::new(),
            mainchain_interface: None,
            federation_manager,
        }
    }

    /// Set mainchain interface
    pub fn with_mainchain_interface(mut self, interface: Box<dyn MainchainInterface>) -> Self {
        self.mainchain_interface = Some(interface);
        self
    }

    /// Process incoming cross-chain messages
    pub fn process_messages(&mut self, chain_id: &Hash) -> Result<Vec<ProcessingResult>, String> {
        let mut results = Vec::new();

        // Get messages first
        let messages = {
            let mut communication = self.communication.lock().unwrap();
            communication.receive_messages(chain_id)
        };

        // Process messages without holding the communication lock
        for message in messages {
            let result = self.process_message(message)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Process a single cross-chain message
    fn process_message(&mut self, message: CrossChainMessage) -> Result<ProcessingResult, String> {
        // Validate message
        {
            let communication = self.communication.lock().unwrap();
            communication.process_message(&message)?;
        }

        match message.message_type {
            crate::sidechain::cross_chain_communication::CrossChainMessageType::CrossChainTransaction => {
                self.process_cross_chain_transaction_message(message)
            }
            crate::sidechain::cross_chain_communication::CrossChainMessageType::MainchainBlockHeader => {
                self.process_mainchain_header_message(message)
            }
            crate::sidechain::cross_chain_communication::CrossChainMessageType::SidechainBlockHeader => {
                self.process_sidechain_header_message(message)
            }
            _ => Ok(ProcessingResult::Ignored),
        }
    }

    /// Process cross-chain transaction message
    fn process_cross_chain_transaction_message(
        &mut self,
        message: CrossChainMessage,
    ) -> Result<ProcessingResult, String> {
        let tx: CrossChainTransaction = message.deserialize_payload()?;

        // Check if transaction already processed
        if self.processed_txs.contains_key(&tx.id) {
            return Ok(ProcessingResult::Duplicate);
        }

        // Validate transaction
        self.validate_cross_chain_transaction(&tx)?;

        // Add to appropriate pool
        self.tx_pools
            .entry(message.destination_chain)
            .or_insert_with(Vec::new)
            .push(tx.clone());

        // Mark as received
        self.processed_txs.insert(tx.id, CrossChainTxStatus::Received);

        Ok(ProcessingResult::TransactionReceived(tx.id))
    }

    /// Process mainchain block header message
    fn process_mainchain_header_message(
        &mut self,
        message: CrossChainMessage,
    ) -> Result<ProcessingResult, String> {
        let header: rusty_shared_types::BlockHeader = message.deserialize_payload()?;

        // Validate header against known mainchain state
        if let Some(ref interface) = self.mainchain_interface {
            if header.height > interface.get_block_height() {
                return Err("Block header height is in the future".to_string());
            }

            if let Some(known_hash) = interface.get_block_hash(header.height) {
                if known_hash != header.hash() {
                    return Err("Block header hash mismatch".to_string());
                }
            }
        }

        Ok(ProcessingResult::BlockHeaderProcessed(header.height))
    }

    /// Process sidechain block header message
    fn process_sidechain_header_message(
        &mut self,
        message: CrossChainMessage,
    ) -> Result<ProcessingResult, String> {
        let header: SidechainBlockHeader = message.deserialize_payload()?;

        // Validate sidechain header
        // This would involve checking against sidechain state

        Ok(ProcessingResult::SidechainHeaderProcessed(header.sidechain_id, header.height))
    }

    /// Validate cross-chain transaction
    fn validate_cross_chain_transaction(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        // Check transaction structure
        if tx.amount == 0 {
            return Err("Cross-chain transaction amount cannot be zero".to_string());
        }

        // Check for duplicate transaction ID
        if self.processed_txs.contains_key(&tx.id) {
            return Err("Duplicate cross-chain transaction".to_string());
        }

        // Validate source and destination chains
        if tx.source_chain == tx.destination_chain {
            return Err("Source and destination chains cannot be the same".to_string());
        }

        // Validate federation signatures
        self.validate_federation_signatures(tx)?;

        // Additional validation based on transaction type
        if tx.source_chain == [0u8; 32] {
            // From mainchain - validate mainchain transaction
            if let Some(ref interface) = self.mainchain_interface {
                if !interface.validate_transaction(&[0u8; 32]) { // Would use actual tx hash
                    return Err("Invalid mainchain transaction".to_string());
                }
            }
        }

        Ok(())
    }

    /// Validate federation signatures for cross-chain transaction
    fn validate_federation_signatures(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        if tx.federation_signatures.is_empty() {
            return Err("Cross-chain transaction must have federation signatures".to_string());
        }

        // For peg-out operations (sidechain to mainchain), verify federation signatures
        if tx.destination_chain == [0u8; 32] {
            let federation_manager = self.federation_manager.lock().unwrap();

            // Get the sidechain ID (source chain for peg-out)
            let sidechain_id = tx.source_chain;

            for signature in &tx.federation_signatures {
                // Verify the signature against the transaction hash
                if !federation_manager.verify_threshold_signature(
                    &sidechain_id,
                    signature.epoch,
                    signature,
                    &tx.id,
                ) {
                    return Err(format!(
                        "Invalid federation signature for epoch {} on sidechain {:?}",
                        signature.epoch, sidechain_id
                    ));
                }
            }

            // Ensure we have at least one valid signature
            if tx.federation_signatures.is_empty() {
                return Err("No valid federation signatures found".to_string());
            }
        }

        Ok(())
    }

    /// Execute pending cross-chain transactions for a chain
    pub fn execute_pending_transactions(&mut self, chain_id: &Hash) -> Result<Vec<ExecutionResult>, String> {
        let mut results = Vec::new();

        // Get transactions to process
        let txs_to_process: Vec<CrossChainTransaction> = if let Some(txs) = self.tx_pools.get_mut(chain_id) {
            txs.drain(..).collect()
        } else {
            vec![]
        };

        let mut remaining_txs = Vec::new();

        for tx in txs_to_process {
            let tx_id = tx.id; // Copy the ID before moving tx
            match self.execute_transaction(&tx) {
                Ok(result) => {
                    self.processed_txs.insert(tx_id, CrossChainTxStatus::Executed);
                    results.push(result);
                }
                Err(e) => {
                    // Mark as failed but keep for retry
                    self.processed_txs.insert(tx_id, CrossChainTxStatus::Failed);
                    remaining_txs.push(tx);
                    results.push(ExecutionResult::Failed(tx_id, e));
                }
            }
        }

        // Put back failed transactions for retry
        if let Some(txs) = self.tx_pools.get_mut(chain_id) {
            txs.extend(remaining_txs);
        }

        Ok(results)
    }

    /// Execute a single cross-chain transaction
    fn execute_transaction(&self, tx: &CrossChainTransaction) -> Result<ExecutionResult, String> {
        // Route execution based on destination
        if tx.destination_chain == [0u8; 32] {
            // To mainchain - create mainchain transaction
            self.execute_to_mainchain(tx)
        } else {
            // To sidechain - this would be handled by sidechain consensus
            Ok(ExecutionResult::Queued(tx.id))
        }
    }

    /// Execute transaction to mainchain
    fn execute_to_mainchain(&self, tx: &CrossChainTransaction) -> Result<ExecutionResult, String> {
        if let Some(ref interface) = self.mainchain_interface {
            // Create mainchain transaction from cross-chain transaction
            let mainchain_tx = self.create_mainchain_transaction(tx)?;

            // Submit to mainchain
            let tx_hash = interface.submit_transaction(&mainchain_tx)?;

            Ok(ExecutionResult::SubmittedToMainchain(tx.id, tx_hash))
        } else {
            Err("No mainchain interface available".to_string())
        }
    }

    /// Create mainchain transaction from cross-chain transaction
    fn create_mainchain_transaction(
        &self,
        cross_chain_tx: &CrossChainTransaction,
    ) -> Result<rusty_shared_types::Transaction, String> {
        use rusty_shared_types::{Transaction, TxInput, TxOutput, OutPoint};

        // For peg-out operations (sidechain to mainchain)
        if cross_chain_tx.destination_chain == [0u8; 32] {
            // This is a peg-out transaction
            // In a real implementation, this would:
            // 1. Find federation-controlled UTXOs on mainchain
            // 2. Create inputs spending from those UTXOs
            // 3. Create output to recipient
            // 4. Include federation signature verification in script

            // For now, create a transaction that represents the peg-out
            // In practice, the federation would need to provide the actual UTXO to spend

            // Create a placeholder input (federation would provide real UTXO)
            let federation_utxo = OutPoint {
                txid: [0u8; 32], // Would be actual federation UTXO
                vout: 0,
            };

            let input = TxInput::from_outpoint(
                federation_utxo,
                vec![], // Would contain federation signature verification
                0xffffffff,
                vec![], // Would contain federation signatures
            );

            let output = TxOutput {
                value: cross_chain_tx.amount,
                script_pubkey: cross_chain_tx.recipient_address.clone(),
                memo: Some(format!("Peg-out from sidechain {:?}", cross_chain_tx.source_chain).into_bytes()),
            };

            let tx = Transaction::Standard {
                version: 1,
                inputs: vec![input],
                outputs: vec![output],
                lock_time: 0,
                fee: 1000, // Standard fee
                witness: vec![], // Would contain federation signatures
            };

            Ok(tx)
        } else {
            // For other cross-chain operations
            Err("Unsupported cross-chain operation".to_string())
        }
    }

    /// Get pending transactions for a chain
    pub fn get_pending_transactions(&self, chain_id: &Hash) -> Vec<&CrossChainTransaction> {
        self.tx_pools
            .get(chain_id)
            .map(|txs| txs.iter().collect())
            .unwrap_or_default()
    }

    /// Get transaction status
    pub fn get_transaction_status(&self, tx_id: &Hash) -> Option<&CrossChainTxStatus> {
        self.processed_txs.get(tx_id)
    }

    /// Get processing statistics
    pub fn get_stats(&self) -> ProcessingStats {
        let mut total_pending = 0;
        let mut total_processed = 0;
        let mut total_failed = 0;

        for txs in self.tx_pools.values() {
            total_pending += txs.len();
        }

        for status in self.processed_txs.values() {
            match status {
                CrossChainTxStatus::Executed => total_processed += 1,
                CrossChainTxStatus::Failed => total_failed += 1,
                _ => {}
            }
        }

        ProcessingStats {
            pending_transactions: total_pending,
            processed_transactions: total_processed,
            failed_transactions: total_failed,
            active_chains: self.tx_pools.len(),
        }
    }
}

/// Result of processing a cross-chain message
#[derive(Debug, Clone)]
pub enum ProcessingResult {
    /// Transaction was received and queued
    TransactionReceived(Hash),
    /// Block header was processed
    BlockHeaderProcessed(u64),
    /// Sidechain header was processed
    SidechainHeaderProcessed(Hash, u64),
    /// Message was ignored
    Ignored,
    /// Duplicate transaction
    Duplicate,
}

/// Result of executing a cross-chain transaction
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    /// Transaction submitted to mainchain
    SubmittedToMainchain(Hash, Hash),
    /// Transaction queued for sidechain processing
    Queued(Hash),
    /// Transaction execution failed
    Failed(Hash, String),
}

/// Processing statistics
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub pending_transactions: usize,
    pub processed_transactions: usize,
    pub failed_transactions: usize,
    pub active_chains: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockMainchainInterface;

    impl MainchainInterface for MockMainchainInterface {
        fn submit_transaction(&self, _tx: &rusty_shared_types::Transaction) -> Result<Hash, String> {
            Ok([1u8; 32])
        }

        fn get_block_height(&self) -> u64 {
            1000
        }

        fn get_block_hash(&self, _height: u64) -> Option<Hash> {
            Some([2u8; 32])
        }

        fn validate_transaction(&self, _tx_hash: &Hash) -> bool {
            true
        }
    }

    #[test]
    fn test_cross_chain_processor_creation() {
        let communication = Arc::new(std::sync::Mutex::new(CrossChainCommunication::new()));
        let federation_manager = Arc::new(std::sync::Mutex::new(FederationManager::new(1000)));
        let processor = CrossChainProcessor::new(communication, federation_manager);
        let stats = processor.get_stats();
        assert_eq!(stats.pending_transactions, 0);
        assert_eq!(stats.processed_transactions, 0);
    }

    #[test]
    fn test_transaction_validation() {
        let communication = Arc::new(std::sync::Mutex::new(CrossChainCommunication::new()));
        let federation_manager = Arc::new(std::sync::Mutex::new(FederationManager::new(1000)));
        let processor = CrossChainProcessor::new(communication, federation_manager);

        // Valid transaction
        let tx = CrossChainTransaction {
            id: [1u8; 32],
            amount: 1000000,
            recipient_address: vec![1, 2, 3],
            source_chain: [1u8; 32],
            destination_chain: [2u8; 32],
            proof: CrossChainProof {
                merkle_proof: vec![],
                block_header: vec![],
                transaction_data: vec![],
                tx_index: 0,
            },
            federation_signatures: vec![FederationSignature {
                signature: vec![1u8; 96],
                signer_bitmap: vec![1],
                threshold: 1,
                epoch: 1,
                message_hash: [1u8; 32],
            }],
            metadata: vec![],
        };

        assert!(processor.validate_cross_chain_transaction(&tx).is_ok());

        // Invalid: zero amount
        let mut invalid_tx = tx.clone();
        invalid_tx.amount = 0;
        assert!(processor.validate_cross_chain_transaction(&invalid_tx).is_err());

        // Invalid: same source and destination
        let mut invalid_tx2 = tx.clone();
        invalid_tx2.destination_chain = invalid_tx2.source_chain;
        assert!(processor.validate_cross_chain_transaction(&invalid_tx2).is_err());
    }

    #[test]
    fn test_mainchain_execution() {
        let communication = Arc::new(std::sync::Mutex::new(CrossChainCommunication::new()));
        let federation_manager = Arc::new(std::sync::Mutex::new(FederationManager::new(1000)));
        let interface = Box::new(MockMainchainInterface);
        let processor = CrossChainProcessor::new(communication, federation_manager).with_mainchain_interface(interface);

        let tx = CrossChainTransaction {
            id: [1u8; 32],
            amount: 1000000,
            recipient_address: vec![1, 2, 3],
            source_chain: [1u8; 32],
            destination_chain: [0u8; 32], // Mainchain
            proof: CrossChainProof {
                merkle_proof: vec![],
                block_header: vec![],
                transaction_data: vec![],
                tx_index: 0,
            },
            federation_signatures: vec![FederationSignature {
                signature: vec![1u8; 96],
                signer_bitmap: vec![1],
                threshold: 1,
                epoch: 1,
                message_hash: [1u8; 32],
            }],
            metadata: vec![],
        };

        let result = processor.execute_transaction(&tx).unwrap();
        match result {
            ExecutionResult::SubmittedToMainchain(_, _) => {}
            _ => panic!("Expected submission to mainchain"),
        }
    }
}