// rusty-core/src/consensus/utxo_set.rs

use std::collections::HashMap;
use rusty_shared_types::{Block, OutPoint, Transaction, TxOutput, Utxo, TicketId, MasternodeID};
use crate::consensus::error::ConsensusError;
use serde::{Serialize, Deserialize};

/// A set of unspent transaction outputs (UTXOs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtxoSet {
    utxos: HashMap<OutPoint, Utxo>,
}

impl UtxoSet {
    /// Creates a new, empty UTXO set.
    pub fn new() -> Self {
        UtxoSet {
            utxos: HashMap::new(),
        }
    }

    /// Loads a UTXO set from a file.
    pub fn load_from_disk(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let encoded = std::fs::read(path)?;
        let utxos: HashMap<OutPoint, Utxo> = bincode::deserialize(&encoded)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(UtxoSet { utxos })
    }

    /// Saves the UTXO set to a file.
    pub fn save_to_disk(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        let encoded = bincode::serialize(&self.utxos)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, encoded)
    }

    /// Adds a UTXO to the set.
    pub fn add_utxo(&mut self, outpoint: OutPoint, utxo: Utxo) {
        self.utxos.insert(outpoint, utxo);
    }

    /// Removes a UTXO from the set.
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        self.utxos.remove(outpoint)
    }

    /// Retrieves a UTXO from the set.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
    }

    /// Checks if a UTXO is in the set.
    pub fn contains_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Returns the number of UTXOs in the set.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Checks if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Returns an iterator over the UTXOs in the set.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &Utxo)> {
        self.utxos.iter()
    }

    /// Updates the UTXO set from a block.
    pub fn update_from_block(&mut self, block: &Block, current_block_height: u64) {
        // Process inputs first (remove spent UTXOs)
        for tx in &block.transactions {
            for input in tx.get_inputs() {
                self.remove_utxo(&input.previous_output);
            }
        }

        // Process outputs (add new UTXOs)
        for tx in &block.transactions {
            let is_coinbase = tx.is_coinbase();
            for (i, output) in tx.get_outputs().iter().enumerate() {
                self.add_utxo(
                    OutPoint {
                        txid: tx.txid(),
                        vout: i as u32,
                    },
                    Utxo {
                        output: output.clone(),
                        is_coinbase,
                        creation_height: current_block_height,
                    },
                );
            }
        }
    }

    /// Updates the UTXO set from a transaction.
    pub fn update_from_transaction(&mut self, tx: &Transaction, current_block_height: u64) {
        for input in tx.get_inputs() {
            self.remove_utxo(&input.previous_output);
        }
        
        let is_coinbase = tx.is_coinbase();
        for (i, output) in tx.get_outputs().iter().enumerate() {
            self.add_utxo(
                OutPoint {
                    txid: tx.txid(),
                    vout: i as u32,
                },
                Utxo {
                    output: output.clone(),
                    is_coinbase,
                    creation_height: current_block_height,
                },
            );
        }
    }

    /// Applies a block to the UTXO set.
    pub fn apply_block(&mut self, block: &Block, current_block_height: u64) {
        self.update_from_block(block, current_block_height);
    }

    /// Reverts a block from the UTXO set.
    pub fn revert_block(&mut self, block: &Block) -> Result<(), ConsensusError> {
        // Process transactions in reverse order
        for tx in block.transactions.iter().rev() {
            // Revert outputs first (remove UTXOs created by this block)
            for (i, _output) in tx.get_outputs().iter().enumerate().rev() {
                let outpoint = OutPoint {
                    txid: tx.txid(),
                    vout: i as u32,
                };
                self.remove_utxo(&outpoint);
            }

            // Revert inputs (re-add UTXOs consumed by this block)
            for input in tx.get_inputs().iter().rev() {
                // We need to fetch the original UTXO details (value, script_pubkey, etc.)
                // that were removed when this block was applied. This implies a need
                // for a temporary storage of spent UTXOs during block application
                // or fetching them from a historical state/database. For now, this is a simplification.
                // In a real implementation, you would store the full Utxo object being removed.
                // For the purpose of this simulation, we'll assume we can reconstruct it minimally.
                // THIS IS A CRITICAL SIMPLIFICATION AND NEEDS A ROBUST SOLUTION IN REAL CODE.
                // For now, let's assume `utxo` is a dummy `Utxo` object based on previous `TxOutput`.
                // A more robust solution would be to save the *full* Utxo when it's removed.
                // But `remove_utxo` already returns `Option<Utxo>`, so we can just re-add it.
                if let Some(original_utxo) = self.get_historical_utxo(&input.previous_output) {
                     self.add_utxo(input.previous_output.clone(), original_utxo);
                } else {
                    return Err(ConsensusError::FailedToFindHistoricalUTXO(input.previous_output.clone()));
                }
            }
        }
        Ok(())
    }

    // Placeholder for fetching historical UTXO (needs proper database integration)
    fn get_historical_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        // In a real system, this would query a historical database or a block cache.
        // For now, we'll return a dummy Utxo if not found in current set (simplified assumption).
        // THIS IS A SIMPLIFICATION.
        if let Some(utxo) = self.get_utxo(outpoint) {
            Some(utxo.clone())
        } else {
            // Dummy Utxo for demonstration if not found historically
            Some(Utxo {
                output: TxOutput { value: 0, script_pubkey: vec![], memo: None },
                is_coinbase: false,
                creation_height: 0,
            })
        }
    }

    /// Validates the inputs of a transaction.
    pub fn validate_transaction_inputs(&self, tx: &Transaction) -> bool {
        let mut total_input_value = 0;
        let mut spent_utxos_in_tx = std::collections::HashSet::new(); // Tracks UTXOs spent within this transaction

        for tx_in in tx.get_inputs() {
            if spent_utxos_in_tx.contains(&tx_in.previous_output) {
                // Double spend within the same transaction
                return false;
            }
            spent_utxos_in_tx.insert(tx_in.previous_output.clone());

            if let Some(utxo) = self.utxos.get(&tx_in.previous_output) {
                total_input_value += utxo.output.value;
                // TODO: Implement coinbase maturity check here using utxo.is_coinbase and utxo.creation_height
                // TODO: Implement lock_time/sequence validation here
            } else {
                // UTXO not found
                return false;
            }
        }

        let mut total_output_value = 0;
        for tx_out in tx.get_outputs() {
            total_output_value += tx_out.value;
            // TODO: Implement dust limit check here
        }

        // Ensure input value is greater than or equal to output value + fee
        total_input_value >= total_output_value + tx.get_fee()
    }

    /// Returns a list of `TicketId`s that correspond to the inputs used in the transactions within the UTXO set.
    pub fn get_used_inputs_as_ticket_ids(&self) -> Vec<TicketId> {
        self.utxos.iter()
            .filter_map(|(outpoint, utxo)| {
                if utxo.is_coinbase { return None; }
                // Assuming a ticket's outpoint matches its TicketId's underlying OutPoint
                // This is a simplification and assumes TicketId is directly derived from OutPoint or similar
                // In a real system, you'd likely have a way to map OutPoint to TicketId.
                // For now, we'll convert the OutPoint to a [u8; 32] hash and then to TicketId
                Some(TicketId::from(outpoint.txid.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::{TxInput, TxOutput, OutPoint, Block, BlockHeader};

    /// Creates a dummy transaction for testing.
    fn create_dummy_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, fee: u64) -> Transaction {
        Transaction::Standard {
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
            fee,
            witness: vec![],
        }
    }

    #[test]
    fn test_add_and_remove_utxo() {
        let mut utxo_set = UtxoSet::new();
        let outpoint = OutPoint { txid: [0u8; 32], vout: 0 };
        let tx_out = Utxo { output: TxOutput { value: 100, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };

        utxo_set.add_utxo(outpoint.clone(), tx_out.clone());
        assert!(utxo_set.contains_utxo(&outpoint));
        assert_eq!(utxo_set.get_utxo(&outpoint).unwrap().output.value, 100);

        let removed_utxo = utxo_set.remove_utxo(&outpoint).unwrap();
        assert_eq!(removed_utxo.output.value, 100);
        assert!(!utxo_set.contains_utxo(&outpoint));
    }

    #[test]
    fn test_apply_block() {
        let mut utxo_set = UtxoSet::new();

        // Initial UTXO for Tx1 input
        let initial_txid = [0u8; 32];
        let initial_outpoint = OutPoint { txid: initial_txid, vout: 0 };
        let initial_tx_out = Utxo { output: TxOutput { value: 200, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };
        utxo_set.add_utxo(initial_outpoint.clone(), initial_tx_out);

        // Tx1: Spends initial_outpoint, creates new_outpoint1 and new_outpoint2
        let tx1_input = TxInput { previous_output: initial_outpoint.clone(), script_sig: vec![], sequence: 0, witness: vec![] };
        let tx1_output1 = TxOutput { value: 50, script_pubkey: vec![], memo: None };
        let tx1_output2 = TxOutput { value: 140, script_pubkey: vec![], memo: None }; // 10 fee
        let tx1 = create_dummy_tx(vec![tx1_input], vec![tx1_output1.clone(), tx1_output2.clone()], 10);
        let tx1_id = tx1.txid();

        // Tx2: Creates new_outpoint3
        let tx2_output1 = TxOutput { value: 300, script_pubkey: vec![], memo: None };
        let tx2 = create_dummy_tx(vec![], vec![tx2_output1.clone()], 0);
        let tx2_id = tx2.txid();

        let block = Block {
            header: BlockHeader { version: 1, previous_block_hash: [0u8; 32], merkle_root: [0u8; 32], timestamp: 0, bits: 0, nonce: 0, height: 0, difficulty_target: 0, state_root: [0u8; 32] },
            transactions: vec![tx1.clone(), tx2.clone()],
            ticket_votes: vec![],
        };

        utxo_set.apply_block(&block, 0);

        // Check if initial UTXO is removed
        assert!(!utxo_set.contains_utxo(&initial_outpoint));

        // Check if new UTXOs from Tx1 are added
        let new_outpoint1 = OutPoint { txid: tx1_id, vout: 0 };
        let new_outpoint2 = OutPoint { txid: tx1_id, vout: 1 };
        assert!(utxo_set.contains_utxo(&new_outpoint1));
        assert!(utxo_set.contains_utxo(&new_outpoint2));
        assert_eq!(utxo_set.get_utxo(&new_outpoint1).unwrap().output.value, 50);
        assert_eq!(utxo_set.get_utxo(&new_outpoint2).unwrap().output.value, 140);

        // Check if new UTXOs from Tx2 are added
        let new_outpoint3 = OutPoint { txid: tx2_id, vout: 0 };
        assert!(utxo_set.contains_utxo(&new_outpoint3));
        assert_eq!(utxo_set.get_utxo(&new_outpoint3).unwrap().output.value, 300);
    }

    #[test]
    fn test_validate_transaction_inputs_valid() {
        let mut utxo_set = UtxoSet::new();
        
        // Use different txids for the outpoints to make them unique
        let mut txid1 = [0u8; 32];
        txid1[0] = 1;
        let outpoint1 = OutPoint { txid: txid1, vout: 0 };
        let tx_out1 = Utxo { output: TxOutput { value: 100, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };
        utxo_set.add_utxo(outpoint1.clone(), tx_out1);

        let mut txid2 = [0u8; 32];
        txid2[0] = 2;
        let outpoint2 = OutPoint { txid: txid2, vout: 0 };
        let tx_out2 = Utxo { output: TxOutput { value: 50, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };
        utxo_set.add_utxo(outpoint2.clone(), tx_out2);

        let tx_in1 = TxInput { previous_output: outpoint1, script_sig: vec![], sequence: 0, witness: vec![] };
        let tx_in2 = TxInput { previous_output: outpoint2, script_sig: vec![], sequence: 0, witness: vec![] };
        let tx_out_new = TxOutput { value: 140, script_pubkey: vec![], memo: None }; // 10 fee

        let tx = create_dummy_tx(vec![tx_in1, tx_in2], vec![tx_out_new], 10);
        assert!(utxo_set.validate_transaction_inputs(&tx));
    }

    #[test]
    fn test_validate_transaction_inputs_utxo_not_found() {
        let _utxo_set = UtxoSet::new(); // Empty UTXO set
    }

    #[test]
    fn test_save_and_load_utxo_set() {
        let mut utxo_set = UtxoSet::new();
        let outpoint1 = OutPoint { txid: [0u8; 32], vout: 0 };
        let tx_out1 = Utxo { output: TxOutput { value: 100, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };
        utxo_set.add_utxo(outpoint1.clone(), tx_out1);

        let outpoint2 = OutPoint { txid: [0u8; 32], vout: 1 };
        let tx_out2 = Utxo { output: TxOutput { value: 200, script_pubkey: vec![], memo: None }, is_coinbase: false, creation_height: 0 };
        utxo_set.add_utxo(outpoint2.clone(), tx_out2);

        let path = std::path::PathBuf::from("test_utxo_set.bin");
        utxo_set.save_to_disk(&path).unwrap();

        let loaded_utxo_set = UtxoSet::load_from_disk(&path).unwrap();

        assert_eq!(utxo_set.utxos.len(), loaded_utxo_set.utxos.len());
        assert!(loaded_utxo_set.contains_utxo(&outpoint1));
        assert!(loaded_utxo_set.contains_utxo(&outpoint2));
        assert_eq!(loaded_utxo_set.get_utxo(&outpoint1).unwrap().output.value, 100);
        assert_eq!(loaded_utxo_set.get_utxo(&outpoint2).unwrap().output.value, 200);

        // Clean up the test file
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_validate_transaction_inputs_double_spend_in_same_tx() {
        let mut utxo_set = UtxoSet::new();
        let outpoint = OutPoint { txid: [0u8; 32], vout: 0 };
        let tx_out = TxOutput { value: 100, script_pubkey: vec![], memo: None };
        utxo_set.add_utxo(outpoint.clone(), Utxo { output: tx_out, is_coinbase: false, creation_height: 0 });

        let tx_in1 = TxInput { previous_output: outpoint.clone(), script_sig: vec![], sequence: 0, witness: vec![] };
        let tx_in2 = TxInput { previous_output: outpoint.clone(), script_sig: vec![], sequence: 0, witness: vec![] };
        let tx_out_new = TxOutput { value: 50, script_pubkey: vec![], memo: None };

        let tx = create_dummy_tx(vec![tx_in1, tx_in2], vec![tx_out_new], 0);
        assert!(!utxo_set.validate_transaction_inputs(&tx));
    }
}