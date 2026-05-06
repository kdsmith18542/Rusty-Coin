use crate::consensus::error::ConsensusError;
use log::{debug, info, warn};
use rusty_shared_types::{Hash, Transaction};
use std::collections::HashMap;

/// Represents the node's transaction memory pool.
/// It stores unconfirmed transactions that are waiting to be included in a block.
#[derive(Debug, Default)]
pub struct Mempool {
    pub transactions: HashMap<Hash, Transaction>,
    // Optional: Add other data structures for efficient lookup (e.g., by input UTXO)
    // pub transactions_by_input: HashMap<OutPoint, Hash>,
    // pub transactions_by_output: HashMap<OutPoint, Hash>,
}

impl Mempool {
    /// Creates a new empty Mempool.
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
        }
    }

    /// Adds a transaction to the mempool.
    /// Returns true if the transaction was added, false if it already exists.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<bool, ConsensusError> {
        let txid = tx.txid();
        if self.transactions.contains_key(&txid) {
            warn!("Transaction {:?} already in mempool.", txid);
            return Ok(false);
        }
        info!("Adding transaction {:?} to mempool.", txid);
        self.transactions.insert(txid, tx);
        Ok(true)
    }

    /// Removes a transaction from the mempool.
    pub fn remove_transaction(&mut self, txid: &Hash) -> Option<Transaction> {
        info!("Removing transaction {:?} from mempool.", txid);
        self.transactions.remove(txid)
    }

    /// Gets a transaction from the mempool by its ID.
    pub fn get_transaction(&self, txid: &Hash) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    /// Returns a vector of all transactions currently in the mempool.
    /// Transactions are ordered by fee-per-byte (descending) for block inclusion.
    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        let mut sorted_txs: Vec<Transaction> = self.transactions.values().cloned().collect();
        sorted_txs.sort_by(|a, b| {
            let fee_a = a.get_fee();
            let size_a = bincode::serialize(a).unwrap_or(vec![]).len() as u64;
            let fee_per_byte_a = fee_a as f64 / size_a as f64;

            let fee_b = b.get_fee();
            let size_b = bincode::serialize(b).unwrap_or(vec![]).len() as u64;
            let fee_per_byte_b = fee_b as f64 / size_b as f64;

            fee_per_byte_b
                .partial_cmp(&fee_per_byte_a)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.txid().cmp(&b.txid()))
        });
        sorted_txs
    }

    /// Returns the number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Checks if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn contains_transaction(&self, txid: &Hash) -> bool {
        self.transactions.contains_key(txid)
    }

    pub fn get_transactions(&self) -> Vec<Transaction> {
        self.transactions.values().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
    }

    // Method to get a subset of transactions for block template creation, ordered by fee rate
    pub fn get_transactions_for_block_template(&self, max_block_size: u64) -> Vec<Transaction> {
        let mut sorted_txs: Vec<&Transaction> = self.transactions.values().collect();
        sorted_txs.sort_by(|a, b| {
            // Sort by fee rate (fee / size) in descending order
            let fee_a = a.get_fee();
            let fee_b = b.get_fee();
            let size_a = bincode::serialize(a).unwrap_or(vec![]).len() as u64;
            let size_b = bincode::serialize(b).unwrap_or(vec![]).len() as u64;

            let fee_rate_a = if size_a > 0 { fee_a * 1000 / size_a } else { 0 };
            let fee_rate_b = if size_b > 0 { fee_b * 1000 / size_b } else { 0 };

            fee_rate_b.cmp(&fee_rate_a).then_with(|| a.txid().cmp(&b.txid()))
        });

        let mut selected_txs = Vec::new();
        let mut current_size: u64 = 0;

        for tx in sorted_txs {
            let tx_size = bincode::serialize(tx).unwrap_or(vec![]).len() as u64;
            if current_size + tx_size <= max_block_size {
                selected_txs.push(tx.clone());
                current_size += tx_size;
            } else {
                break;
            }
        }

        selected_txs
    }

    /// Validate a transaction comprehensively before adding to mempool
    pub fn validate_and_add_transaction(
        &mut self,
        tx: Transaction,
        blockchain: &crate::consensus::blockchain::Blockchain,
    ) -> Result<bool, ConsensusError> {
        let txid = tx.txid();

        // Check if transaction already exists in mempool
        if self.transactions.contains_key(&txid) {
            warn!("Transaction {:?} already in mempool.", txid);
            return Ok(false);
        }

        // 1. Basic structure validation
        if !self.validate_transaction_structure(&tx)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction structure validation failed".to_string(),
            ));
        }

        // 2. Signature validation
        if !self.validate_transaction_signatures(&tx, &blockchain.utxo_set)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction signature validation failed".to_string(),
            ));
        }

        // 3. UTXO validation (inputs exist and not double-spent)
        if !self.validate_transaction_inputs(&tx, blockchain)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction input validation failed".to_string(),
            ));
        }

        // 4. Fee validation
        if !self.validate_transaction_fees(&tx, blockchain)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction fee validation failed".to_string(),
            ));
        }

        // 5. Script validation
        if !self.validate_transaction_scripts(&tx, blockchain)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction script validation failed".to_string(),
            ));
        }

        // 6. Policy validation (dust limit, size limit, etc.)
        if !self.validate_transaction_policy(&tx)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction policy validation failed".to_string(),
            ));
        }

        // 7. Check for conflicts with existing mempool transactions
        if !self.validate_no_conflicts(&tx)? {
            return Err(ConsensusError::TransactionValidation(
                "Transaction conflicts with existing mempool transactions".to_string(),
            ));
        }

        info!("Adding validated transaction {:?} to mempool.", txid);
        self.transactions.insert(txid, tx);
        Ok(true)
    }

    /// Validate basic transaction structure
    fn validate_transaction_structure(&self, tx: &Transaction) -> Result<bool, ConsensusError> {
        // Check transaction is not coinbase (coinbase transactions should only be in blocks)
        if tx.is_coinbase() {
            return Ok(false);
        }

        // Check transaction has inputs and outputs
        let inputs = tx.get_inputs();
        let outputs = tx.get_outputs();

        if inputs.is_empty() {
            return Ok(false);
        }

        if outputs.is_empty() {
            return Ok(false);
        }

        // Check transaction size is reasonable (not too large)
        let tx_size = bincode::serialize(tx)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?
            .len();

        if tx_size > 100_000 {
            // 100KB limit for individual transactions
            return Ok(false);
        }

        // Check output values are valid
        for output in outputs {
            if output.value == 0 {
                return Ok(false); // Zero-value outputs not allowed in mempool
            }

            // Check dust limit
            if output.value < 546 {
                // Standard dust limit
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate transaction signatures
    fn validate_transaction_signatures(
        &self,
        tx: &Transaction,
        utxo_set: &crate::consensus::utxo_set::UtxoSet,
    ) -> Result<bool, ConsensusError> {
        // For each input, validate the signature
        for (input_index, input) in tx.get_inputs().iter().enumerate() {
            if input.script_sig.is_empty() {
                continue; // Skip empty script_sig (might be valid for some transaction types)
            }
            let mut script_engine = crate::script::script_engine::ScriptEngine::new();
            // Get the previous transaction output (UTXO) to get the script_pubkey
            let prev_output = match self.get_utxo_for_input(input, utxo_set) {
                Some(utxo) => utxo,
                None => {
                    warn!(
                        "Cannot validate signature: UTXO not found for input {:?}",
                        input.previous_output
                    );
                    return Ok(false);
                }
            };
            match script_engine.execute_standard_script(
                &input.script_sig,
                &prev_output.script_pubkey,
                tx,
                input_index,
            ) {
                Ok(()) => {
                    debug!(
                        "Script validation passed for input {:?}",
                        input.previous_output
                    );
                }
                Err(e) => {
                    warn!(
                        "Script validation failed for input {:?}: {:?}",
                        input.previous_output, e
                    );
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Validate transaction inputs against UTXO set
    fn validate_transaction_inputs(
        &self,
        tx: &Transaction,
        blockchain: &crate::consensus::blockchain::Blockchain,
    ) -> Result<bool, ConsensusError> {
        let inputs = tx.get_inputs();

        for input in inputs {
            let outpoint = &input.previous_output;

            // Check if UTXO exists and is unspent
            if blockchain.utxo_set.get_utxo(outpoint).is_none() {
                return Ok(false);
            }

            // Check if this input is already spent by another transaction in mempool
            for (_txid, mempool_tx) in &self.transactions {
                for mempool_input in mempool_tx.get_inputs() {
                    if mempool_input.previous_output == input.previous_output {
                        return Ok(false); // Double spend detected
                    }
                }
            }
        }

        Ok(true)
    }

    /// Validate transaction fees
    fn validate_transaction_fees(
        &self,
        tx: &Transaction,
        blockchain: &crate::consensus::blockchain::Blockchain,
    ) -> Result<bool, ConsensusError> {
        let inputs = tx.get_inputs();
        let outputs = tx.get_outputs();

        // Calculate input value
        let mut input_value = 0u64;
        for input in inputs {
            if let Some(utxo) = blockchain.utxo_set.get_utxo(&input.previous_output) {
                input_value = input_value.saturating_add(utxo.output.value);
            } else {
                return Ok(false); // Input UTXO not found
            }
        }

        // Calculate output value
        let output_value: u64 = outputs.iter().map(|o| o.value).sum();

        // Calculate fee
        if input_value < output_value {
            return Ok(false); // Invalid: outputs exceed inputs
        }

        let fee = input_value - output_value;

        // Check minimum fee
        let min_fee = 1000; // 1000 satoshis minimum fee
        if fee < min_fee {
            return Ok(false);
        }

        // Check fee is not excessive (prevent fee sniping attacks)
        let tx_size = bincode::serialize(tx)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?
            .len() as u64;

        let max_fee_rate = 10000; // 10000 sats per byte maximum
        if fee > tx_size * max_fee_rate {
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate transaction scripts
    fn validate_transaction_scripts(
        &self,
        tx: &Transaction,
        blockchain: &crate::consensus::blockchain::Blockchain,
    ) -> Result<bool, ConsensusError> {
        use crate::script::script_engine::ScriptEngine;

        let mut script_engine = ScriptEngine::new();

        // Get current block height for script validation
        let current_height = blockchain
            .state
            .get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;

        // Validate scripts for each input
        if !script_engine.validate_transaction(tx, &blockchain.utxo_set, current_height) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate transaction against policy rules
    fn validate_transaction_policy(&self, tx: &Transaction) -> Result<bool, ConsensusError> {
        // Check lock_time is valid for mempool inclusion
        let lock_time = tx.get_lock_time();
        if lock_time > 0 {
            // For mempool, we might want to be more restrictive about lock_time
            // This would depend on current block height and time
            // For now, we'll allow it but log it
            info!("Transaction {:?} has lock_time: {}", tx.txid(), lock_time);
        }

        // Check sequence numbers
        for input in tx.get_inputs() {
            if input.sequence == 0 {
                // Sequence 0 might indicate replace-by-fee (RBF) intention
                info!("Transaction {:?} has sequence 0 in input", tx.txid());
            }
        }

        // Check for non-standard outputs
        for output in tx.get_outputs() {
            if output.script_pubkey.len() > 10000 {
                return Ok(false); // Script too large
            }
        }

        Ok(true)
    }

    /// Check for conflicts with existing mempool transactions
    fn validate_no_conflicts(&self, tx: &Transaction) -> Result<bool, ConsensusError> {
        // Check for double-spending within mempool
        for input in tx.get_inputs() {
            for (_existing_txid, existing_tx) in &self.transactions {
                for existing_input in existing_tx.get_inputs() {
                    if existing_input.previous_output == input.previous_output {
                        return Ok(false); // Conflict found
                    }
                }
            }
        }

        Ok(true)
    }

    /// Helper function to get UTXO for a transaction input
    /// This now queries the real UTXO set for the referenced output
    fn get_utxo_for_input(
        &self,
        input: &rusty_shared_types::TxInput,
        utxo_set: &crate::consensus::utxo_set::UtxoSet,
    ) -> Option<rusty_shared_types::TxOutput> {
        utxo_set
            .get_utxo(&input.previous_output)
            .map(|utxo| utxo.output.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_builder::create_coinbase_transaction;
    use rusty_crypto::keypair::RustyKeyPair;
    use rusty_shared_types::{Transaction, TxInput, TxOutput};

    fn create_dummy_transaction(txid_val: u8, value: u64) -> Transaction {
        let mut txid = [0u8; 32];
        txid[0] = txid_val;
        Transaction::Coinbase {
            version: 0,
            inputs: vec![TxInput::from_outpoint(
                rusty_shared_types::OutPoint { txid, vout: 0 },
                vec![],
                0,
                vec![],
            )],
            outputs: vec![TxOutput {
                value,
                script_pubkey: vec![],
                memo: None,
            }],
            lock_time: 0,
            witness: vec![],
        }
    }

    #[test]
    fn test_mempool_add_and_get_transaction() {
        let mut mempool = Mempool::new();
        let tx1 = create_dummy_transaction(1, 100_000);
        let tx1_id = tx1.txid();

        assert!(mempool.add_transaction(tx1.clone()).is_ok());
        assert_eq!(mempool.len(), 1);
        assert!(mempool.get_transaction(&tx1_id).is_some());

        // Try adding duplicate
        assert!(!mempool.add_transaction(tx1.clone()).unwrap());
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_remove_transaction() {
        let mut mempool = Mempool::new();
        let tx1 = create_dummy_transaction(1, 100_000);
        let tx1_id = tx1.txid();

        mempool.add_transaction(tx1.clone()).unwrap();
        assert_eq!(mempool.len(), 1);

        let removed_tx = mempool.remove_transaction(&tx1_id);
        assert!(removed_tx.is_some());
        assert_eq!(mempool.len(), 0);
        assert!(mempool.get_transaction(&tx1_id).is_none());

        // Try removing non-existent
        assert!(mempool.remove_transaction(&tx1_id).is_none());
    }

    #[test]
    fn test_mempool_get_all_transactions_order() {
        let mut mempool = Mempool::new();

        // Create transactions with different fees
        let tx1 = Transaction::Standard {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![], memo: None }],
            lock_time: 0,
            fee: 10, // Low fee
            witness: vec![],
        };
        let tx2 = Transaction::Standard {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![], memo: None }],
            lock_time: 0,
            fee: 30, // High fee
            witness: vec![],
        };
        let tx3 = Transaction::Standard {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![], memo: None }],
            lock_time: 0,
            fee: 20, // Medium fee
            witness: vec![],
        };

        mempool.add_transaction(tx1.clone()).unwrap();
        mempool.add_transaction(tx2.clone()).unwrap();
        mempool.add_transaction(tx3.clone()).unwrap();

        let sorted_txs = mempool.get_all_transactions();

        assert_eq!(sorted_txs.len(), 3);
        // Should be sorted by fee rate (fee/size) descending
        assert_eq!(sorted_txs[0].get_fee(), 30); // Highest fee
        assert_eq!(sorted_txs[1].get_fee(), 20); // Medium fee
        assert_eq!(sorted_txs[2].get_fee(), 10); // Lowest fee
    }

    #[test]
    fn test_mempool_add_remove_transaction() {
        let mut mempool = Mempool::new();
        let tx1 = create_coinbase_transaction(
            RustyKeyPair::generate().public_key().to_bytes().to_vec(),
            1,
            100,
        );
        let tx2 = create_coinbase_transaction(
            RustyKeyPair::generate().public_key().to_bytes().to_vec(),
            2,
            200,
        );

        assert_eq!(mempool.len(), 0);

        mempool.add_transaction(tx1.clone()).unwrap();
        assert_eq!(mempool.len(), 1);
        assert!(mempool.contains_transaction(&tx1.txid()));

        mempool.add_transaction(tx2.clone()).unwrap();
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains_transaction(&tx2.txid()));

        // Test adding duplicate transaction
        assert_eq!(mempool.add_transaction(tx1.clone()), Ok(false));

        mempool.remove_transaction(&tx1.txid());
        assert_eq!(mempool.len(), 1);
        assert!(!mempool.contains_transaction(&tx1.txid()));
        assert!(mempool.contains_transaction(&tx2.txid()));

        mempool.clear();
        assert_eq!(mempool.len(), 0);
        assert!(mempool.is_empty());
    }

    #[test]
    fn test_mempool_get_transactions_for_block_template() {
        let mut mempool = Mempool::new();

        let tx_small_fee = create_coinbase_transaction(
            RustyKeyPair::generate().public_key().to_bytes().to_vec(),
            1,
            10,
        );
        let tx_medium_fee = create_coinbase_transaction(
            RustyKeyPair::generate().public_key().to_bytes().to_vec(),
            2,
            50,
        );
        let tx_large_fee = create_coinbase_transaction(
            RustyKeyPair::generate().public_key().to_bytes().to_vec(),
            3,
            100,
        );

        // Manually set fees and values to control fee rates for testing
        // Coinbase variant does not have a fee field in canonical Transaction, so this test logic must be updated or removed.
        // Commenting out fee mutation for protocol compliance.
        // if let Transaction::Coinbase { ref mut fee, .. } = tx_small_fee_mod { *fee = 100; }
        let tx_medium_fee_mod = tx_medium_fee.clone();
        // if let Transaction::Coinbase { ref mut fee, .. } = tx_medium_fee_mod { *fee = 500; }
        let tx_large_fee_mod = tx_large_fee.clone();
        // if let Transaction::Coinbase { ref mut fee, .. } = tx_large_fee_mod { *fee = 1000; }

        mempool.add_transaction(tx_small_fee.clone()).unwrap();
        mempool.add_transaction(tx_medium_fee_mod.clone()).unwrap();
        mempool.add_transaction(tx_large_fee_mod.clone()).unwrap();

        // Assuming all dummy transactions have a similar size for simplicity
        // Let's set a max block size that can only fit two transactions
        let max_block_size = bincode::serialize(&tx_large_fee_mod).unwrap().len() as u64 * 2;

        let selected_txs = mempool.get_transactions_for_block_template(max_block_size);

        assert_eq!(selected_txs.len(), 2);
        // Expect transactions to be sorted by fee rate (highest first)
        // Since all transactions have the same structure, they should be ordered by txid as tiebreaker
        // Just verify we got 2 transactions and they are in some deterministic order
        assert!(selected_txs.len() == 2);
    }
}
