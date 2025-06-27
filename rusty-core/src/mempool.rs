use std::collections::{HashMap, HashSet};
use rusty_shared_types::{Transaction, Hash};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument};
use crate::consensus::error::ConsensusError;
use crate::transaction_builder::create_coinbase_transaction;
use rusty_crypto::keypair::RustyKeyPair;

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

            fee_per_byte_b.partial_cmp(&fee_per_byte_a).unwrap_or(std::cmp::Ordering::Equal)
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

            fee_rate_b.cmp(&fee_rate_a)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::{Transaction, TxInput, TxOutput, Hash};
    use crate::transaction_builder::create_coinbase_transaction;
    use crate::RustyKeyPair;

    fn create_dummy_transaction(txid_val: u8, value: u64) -> Transaction {
        let mut txid = [0u8; 32];
        txid[0] = txid_val;
        Transaction::Coinbase {
            version: 0,
            inputs: vec![TxInput { previous_output: rusty_shared_types::OutPoint { txid, vout: 0 }, script_sig: vec![], sequence: 0, witness: vec![] }],
            outputs: vec![TxOutput { value, script_pubkey: vec![], memo: None }],
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
        let tx1 = create_dummy_transaction(1, 100_000);
        let tx2 = create_dummy_transaction(2, 200_000);
        let tx3 = create_dummy_transaction(3, 150_000);

        mempool.add_transaction(tx1.clone()).unwrap();
        mempool.add_transaction(tx2.clone()).unwrap();
        mempool.add_transaction(tx3.clone()).unwrap();

        let sorted_txs = mempool.get_all_transactions();

        assert_eq!(sorted_txs.len(), 3);
        assert_eq!(sorted_txs[0].txid(), tx2.txid()); // Highest fee/byte
        assert_eq!(sorted_txs[1].txid(), tx3.txid()); // Middle
        assert_eq!(sorted_txs[2].txid(), tx1.txid()); // Lowest
    }

    #[test]
    fn test_mempool_add_remove_transaction() {
        let mut mempool = Mempool::new();
        let tx1 = create_coinbase_transaction(RustyKeyPair::generate().public_key().to_vec(), 1, 100);
        let tx2 = create_coinbase_transaction(RustyKeyPair::generate().public_key().to_vec(), 2, 200);

        assert_eq!(mempool.len(), 0);

        mempool.add_transaction(tx1.clone()).unwrap();
        assert_eq!(mempool.len(), 1);
        assert!(mempool.contains_transaction(&tx1.txid()));

        mempool.add_transaction(tx2.clone()).unwrap();
        assert_eq!(mempool.len(), 2);
        assert!(mempool.contains_transaction(&tx2.txid()));

        // Test adding duplicate transaction
        assert!(mempool.add_transaction(tx1.clone()).is_err());

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

        let tx_small_fee = create_coinbase_transaction(RustyKeyPair::generate().public_key().to_vec(), 1, 10);
        let tx_medium_fee = create_coinbase_transaction(RustyKeyPair::generate().public_key().to_vec(), 2, 50);
        let tx_large_fee = create_coinbase_transaction(RustyKeyPair::generate().public_key().to_vec(), 3, 100);

        // Manually set fees and values to control fee rates for testing
        let mut tx_small_fee_mod = tx_small_fee.clone();
        if let Transaction::Coinbase { ref mut fee, .. } = tx_small_fee_mod { *fee = 100; }
        let mut tx_medium_fee_mod = tx_medium_fee.clone();
        if let Transaction::Coinbase { ref mut fee, .. } = tx_medium_fee_mod { *fee = 500; }
        let mut tx_large_fee_mod = tx_large_fee.clone();
        if let Transaction::Coinbase { ref mut fee, .. } = tx_large_fee_mod { *fee = 1000; }

        mempool.add_transaction(tx_small_fee_mod.clone()).unwrap();
        mempool.add_transaction(tx_medium_fee_mod.clone()).unwrap();
        mempool.add_transaction(tx_large_fee_mod.clone()).unwrap();

        // Assuming all dummy transactions have a similar size for simplicity
        // Let's set a max block size that can only fit two transactions
        let max_block_size = bincode::serialize(&tx_large_fee_mod).unwrap().len() as u64 * 2;

        let selected_txs = mempool.get_transactions_for_block_template(max_block_size);

        assert_eq!(selected_txs.len(), 2);
        // Expect transactions to be sorted by fee rate (highest first)
        assert_eq!(selected_txs[0].txid(), tx_large_fee_mod.txid());
        assert_eq!(selected_txs[1].txid(), tx_medium_fee_mod.txid());
    }
} 