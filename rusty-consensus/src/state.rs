use rusty_types::block::Block;
use rusty_types::transaction::{OutPoint, TxOutput};

use rocksdb::{Options, WriteBatch, DB};
use std::collections::HashMap;
use std::path::Path;
use bincode::{encode_to_vec, decode_from_slice, config};
use rusty_types::block::Block;
use rusty_types::transaction::{OutPoint, Transaction, TxOutput};
use super::pos::{LiveTicketsPool, Ticket, TicketId};

pub struct BlockchainState {
    db: DB,
}

impl BlockchainState {
    pub fn get_block_subsidy(&self, height: u64, halving_interval: u64, initial_block_reward: u64) -> u64 {
        let halvings = height / halving_interval;
        if halvings >= 64 {
            return 0;
        }
        initial_block_reward >> halvings
    }
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(BlockchainState { db })
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<(TxOutput, u32, bool)>, String> {
        let key = format!("UTXO {:?}:{}", outpoint.txid, outpoint.vout);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                let (output, creation_height, is_coinbase) = decode_from_slice(&value, config::standard())
                     .map_err(|e| format!("Failed to deserialize UTXO: {}", e))?.0;
                Ok(Some((output, creation_height, is_coinbase)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get UTXO from DB: {}", e)),
        }
    }

    pub fn update_utxo_set(
        &self,
        utxos: &HashMap<OutPoint, (TxOutput, u32, bool)>,
    ) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        for (outpoint, data) in utxos {
            let key = format!("UTXO {:?}:{}", outpoint.txid, outpoint.vout);
            let encoded: Vec<u8> =
            bincode::serde::encode_to_vec(utxo, bincode::config::standard()).map_err(|e| StateError::Serialization(e.to_string()))?;
            batch.put(key, encoded);
        }
        self.db
            .write(batch)
            .map_err(|e| format!("Failed to write UTXO batch to DB: {}", e))?;
        Ok(())
    }

    pub fn apply_block(&self, block: &Block, current_height: u32, live_tickets_pool: &mut LiveTicketsPool) -> Result<(), String> {
        let mut batch = WriteBatch::default();

        for tx in &block.transactions {
            match tx {
                Transaction::TicketPurchase(tx) => {
                    let ticket_id = TicketId {
                        txid: tx.txid(),
                        vout_index: 0, // Assuming ticket purchase creates a single ticket output
                    };
                    let ticket = Ticket {
                        id: ticket_id.clone(),
                        purchase_block_height: current_height as u64,
                        locked_amount: tx.locked_amount,
                        public_key: tx.output.extract_public_key_hash().ok_or("Failed to extract public key hash from ticket purchase output")?,
                    };
                    live_tickets_pool.add_ticket(ticket);
                },
                Transaction::TicketRedemption(tx) => {
                    let ticket_id = TicketId {
                        txid: tx.ticket_id,
                        vout_index: 0, // Assuming ticket redemption refers to a single ticket output
                    };
                    live_tickets_pool.remove_ticket(&ticket_id);
                },
                _ => {},
            }
            // Process inputs: remove spent UTXOs
            for input in &tx.inputs {
                let key = format!("utxo_{}_{}", input.prev_out.txid, input.prev_out.vout_index);
                batch.delete(key);
            }

            // Process outputs: add new UTXOs
            for (i, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: tx.txid(),
                    vout: i as u32,
                };
                let is_coinbase = block
                    .transactions
                    .first()
                    .map_or(false, |first_tx| first_tx.txid() == tx.txid());
                let data = (output.clone(), current_height, is_coinbase);
                let encoded: Vec<u8> = encode_to_vec(&data, config::standard())
                     .map_err(|e| format!("Failed to serialize UTXO: {}", e))?;
                let key = format!("UTXO {:?}:{}", outpoint.txid, outpoint.vout);
                batch.put(key, encoded);
            }
        }
        self.db
            .write(batch)
            .map_err(|e| format!("Failed to apply block to DB: {}", e))?;
        Ok(())
    }

    pub fn put_block(&self, block: &Block) -> Result<(), String> {
        let key = format!("block_{}", block.header.calculate_hash());
        let encoded: Vec<u8> =
            bincode::serde::encode_to_vec(block, bincode::config::standard()).map_err(|e| StateError::Serialization(e.to_string()))?;
        self.db
            .put(key, encoded)
            .map_err(|e| format!("Failed to put block to DB: {}", e))?;
        Ok(())
    }

    pub fn get_block(&self, height: u32) -> Result<Option<Block>, String> {
        let hash_key = format!("block_hash_{}", height);
        let block_hash = match self.db.get(&hash_key) {
            Ok(Some(value)) => {
                let hash: [u8; 32] = bincode::decode_from_slice(&value, bincode::config::standard()).map_err(|e| format!("Failed to deserialize block hash: {}", e))?.0;
                hash
            }
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("Failed to get block hash from DB: {:?}", e)),
        };

        let block_key = format!("block_{}", block_hash);
        match self.db.get(&block_key) {
            Ok(Some(value)) => {
                let block: Block = bincode::decode_from_slice(&value, bincode::config::standard()).map_err(|e| format!("Failed to deserialize block: {}", e))?.0;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get block from DB: {}", e)),
        }
    }

    pub fn get_current_block_height(&self) -> Result<u64, String> {
        match self.db.get("current_block_height") {
            Ok(Some(value)) => {
                let height: u64 = bincode::decode_from_slice(&value, bincode::config::standard()).map_err(|e| format!("Failed to deserialize current block height: {}", e))?.0;
                Ok(height)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(format!("Failed to get current block height from DB: {}", e)),
        }
    }

    pub fn set_current_block_height(&self, height: u64) -> Result<(), String> {
        let encoded: Vec<u8> = bincode::encode_to_vec(&height, bincode::config::standard()).map_err(|e| format!("Failed to serialize current block height: {}", e))?;
        self.db
            .put("current_block_height", encoded)
            .map_err(|e| format!("Failed to set current block height in DB: {}", e))?;
        Ok(())
    }

    pub fn get_current_block_hash(&self) -> Result<Option<[u8; 32]>, String> {
        match self.db.get("current_block_hash") {
            Ok(Some(value)) => {
                let hash: [u8; 32] = decode_from_slice(&value, config::standard())
                     .map_err(|e| format!("Failed to deserialize current block hash: {}", e))?.0;
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get current block hash from DB: {}", e)),
        }
    }

    pub fn put_block_hash(&self, height: u32, hash: &[u8; 32]) -> Result<(), String> {
        let key = format!("block_hash_{}", height);
        let encoded: Vec<u8> = bincode::encode_to_vec(hash, bincode::config::standard()).map_err(|e| format!("Failed to serialize block hash: {}", e))?;
        self.db
            .put(key, encoded)
            .map_err(|e| format!("Failed to put block hash to DB: {}", e))?;
        Ok(())
    }

    pub fn get_block_hash(&self, height: u32) -> Result<Option<[u8; 32]>, String> {
        let key = format!("block_hash_{}", height);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                let hash: [u8; 32] = decode_from_slice(&value, config::standard())
                     .map_err(|e| format!("Failed to deserialize block hash: {}", e))?.0;
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get block hash from DB: {}", e)),
        }
    }
}
