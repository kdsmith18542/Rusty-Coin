use crate::error::ConsensusError;
use crate::pos::LiveTicketsPool;
use bincode::{deserialize, serialize};
use rocksdb::{Options, WriteBatch, DB};
use rusty_shared_types::{Block, Hash, OutPoint, Ticket, TicketId, Transaction, TxOutput};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct GovernanceState {
    pub active_proposals: HashMap<Hash, rusty_shared_types::governance::GovernanceProposal>,
    pub proposal_votes: HashMap<Hash, GovernanceVoteTally>,
    pub parameter_change_history: Option<HashMap<u64, Vec<String>>>,
}

#[derive(Debug, Clone, Default)]
pub struct GovernanceVoteTally {
    pub pos_yes_votes: i64,
    pub pos_no_votes: i64,
    pub mn_yes_votes: i64,
    pub mn_no_votes: i64,
}

pub struct BlockchainState {
    db: DB,
    pub governance_state: GovernanceState,
    tickets: HashMap<TicketId, Ticket>,
}

impl BlockchainState {
    pub fn get_block_subsidy(
        &self,
        height: u64,
        halving_interval: u64,
        initial_block_reward: u64,
    ) -> u64 {
        let halvings = height / halving_interval;
        if halvings >= 64 {
            return 0;
        }
        initial_block_reward >> halvings
    }
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self {
            db,
            tickets: HashMap::new(),
            governance_state: GovernanceState::default(),
        })
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<(TxOutput, u32, bool)>, String> {
        let key = format!("UTXO {:?}:{}", outpoint.txid, outpoint.vout);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                let (output, creation_height, is_coinbase): (TxOutput, u32, bool) =
                    deserialize(&value)
                        .map_err(|e| format!("Failed to deserialize UTXO: {}", e))?;
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
                serialize(data).map_err(|e| format!("Serialization error: {}", e))?;
            batch.put(key, encoded);
        }
        self.db
            .write(batch)
            .map_err(|e| format!("Failed to write UTXO batch to DB: {}", e))?;
        Ok(())
    }

    pub fn apply_block(
        &self,
        block: &Block,
        current_height: u32,
        live_tickets_pool: &mut LiveTicketsPool,
    ) -> Result<(), String> {
        let mut batch = WriteBatch::default();

        for tx in &block.transactions {
            match tx {
                Transaction::TicketPurchase {
                    ticket_id,
                    inputs: _,
                    outputs,
                    ..
                } => {
                    let ticket_id = TicketId(*ticket_id);
                    // Assume first output is the ticket output
                    let output = outputs.get(0).ok_or("No output in ticket purchase")?;
                    let pubkey = output
                        .extract_public_key_hash()
                        .ok_or("Failed to extract public key hash from ticket purchase output")?;
                    let value = output.value;
                    let ticket = Ticket {
                        id: ticket_id,
                        pubkey: pubkey.to_vec(),
                        height: current_height as u64,
                        value,
                        // Per spec 03 Section 3.2.2: Tickets start as PENDING
                        // They transition to LIVE when block reaches POS_FINALITY_DEPTH
                        status: rusty_shared_types::TicketStatus::Pending,
                    };
                    live_tickets_pool.add_ticket(ticket);
                }
                Transaction::TicketRedemption { ticket_id, .. } => {
                    let ticket_id = TicketId(*ticket_id);
                    live_tickets_pool.remove_ticket(&ticket_id);
                }
                _ => {}
            }
            // Process inputs: remove spent UTXOs
            for input in tx.get_inputs() {
                let key = format!(
                    "utxo_{:?}_{}",
                    input.previous_output.txid, input.previous_output.vout
                );
                batch.delete(key);
            }

            // Process outputs: add new UTXOs
            for (i, output) in tx.get_outputs().iter().enumerate() {
                let outpoint = OutPoint {
                    txid: tx.txid(),
                    vout: i as u32,
                };
                let is_coinbase = block
                    .transactions
                    .first()
                    .map_or(false, |first_tx| first_tx.txid() == tx.txid());
                let data = (output.clone(), current_height, is_coinbase);
                let encoded: Vec<u8> =
                    serialize(&data).map_err(|e| format!("Serialization error: {}", e))?;
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
        let key = format!("block_{:?}", block.header.hash());
        let encoded: Vec<u8> =
            serialize(block).map_err(|e| format!("Serialization error: {}", e))?;
        self.db
            .put(key, encoded)
            .map_err(|e| format!("Failed to put block to DB: {}", e))?;
        Ok(())
    }

    pub fn get_block(&self, height: u32) -> Result<Option<Block>, String> {
        let hash_key = format!("block_hash_{}", height);
        let block_hash = match self.db.get(&hash_key) {
            Ok(Some(value)) => {
                let hash: [u8; 32] = deserialize::<[u8; 32]>(&value)
                    .map_err(|e| format!("Failed to deserialize block hash: {}", e))?;
                hash
            }
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("Failed to get block hash from DB: {:?}", e)),
        };

        let block_key = format!("block_{:?}", block_hash);
        match self.db.get(&block_key) {
            Ok(Some(value)) => {
                let block: Block = deserialize::<Block>(&value)
                    .map_err(|e| format!("Failed to deserialize block: {}", e))?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get block from DB: {}", e)),
        }
    }

    pub fn get_current_block_height(&self) -> Result<u64, String> {
        match self.db.get("current_block_height") {
            Ok(Some(value)) => {
                let height: u64 = deserialize::<u64>(&value)
                    .map_err(|e| format!("Failed to deserialize current block height: {}", e))?;
                Ok(height)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(format!("Failed to get current block height from DB: {}", e)),
        }
    }

    pub fn set_current_block_height(&self, height: u64) -> Result<(), String> {
        let encoded: Vec<u8> = serialize(&height)
            .map_err(|e| format!("Failed to serialize current block height: {}", e))?;
        self.db
            .put("current_block_height", encoded)
            .map_err(|e| format!("Failed to set current block height in DB: {}", e))?;
        Ok(())
    }

    pub fn get_current_block_hash(&self) -> Result<Option<[u8; 32]>, String> {
        match self.db.get("current_block_hash") {
            Ok(Some(value)) => {
                let hash: [u8; 32] = deserialize::<[u8; 32]>(&value)
                    .map_err(|e| format!("Failed to deserialize current block hash: {}", e))?;
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get current block hash from DB: {}", e)),
        }
    }

    pub fn put_block_hash(&self, height: u32, hash: &[u8; 32]) -> Result<(), String> {
        let key = format!("block_hash_{}", height);
        let encoded: Vec<u8> =
            serialize(hash).map_err(|e| format!("Failed to serialize block hash: {}", e))?;
        self.db
            .put(key, encoded)
            .map_err(|e| format!("Failed to put block hash to DB: {}", e))?;
        Ok(())
    }

    pub fn get_block_hash(&self, height: u32) -> Result<Option<[u8; 32]>, String> {
        let key = format!("block_hash_{}", height);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                let hash: [u8; 32] = deserialize::<[u8; 32]>(&value)
                    .map_err(|e| format!("Failed to deserialize block hash: {}", e))?;
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get block hash from DB: {}", e)),
        }
    }

    /// Get a ticket from the live tickets pool
    pub fn get_ticket(&self, ticket_id: &TicketId) -> Option<&Ticket> {
        self.tickets.get(ticket_id)
    }

    /// Add a ticket to the live tickets pool
    pub fn add_ticket(&mut self, ticket: Ticket) {
        self.tickets.insert(ticket.id.clone(), ticket);
    }

    /// Remove a ticket from the live tickets pool
    pub fn remove_ticket(&mut self, ticket_id: &TicketId) -> Option<Ticket> {
        self.tickets.remove(ticket_id)
    }

    /// Get all tickets in the live tickets pool
    pub fn get_all_tickets(&self) -> &HashMap<TicketId, Ticket> {
        &self.tickets
    }

    /// Get the count of live tickets
    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }

    /// Set a protocol flag in the blockchain state
    pub fn set_protocol_flag(&mut self, key: String, value: Vec<u8>) -> Result<(), ConsensusError> {
        self.db
            .put(key.as_bytes(), value)
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get a protocol flag from the blockchain state
    pub fn get_protocol_flag(&self, key: &str) -> Result<Option<Vec<u8>>, ConsensusError> {
        match self
            .db
            .get(key.as_bytes())
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?
        {
            Some(value) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    /// Set the protocol version
    pub fn set_protocol_version(&mut self, version: u32) -> Result<(), ConsensusError> {
        self.db
            .put(b"protocol_version", &version.to_le_bytes())
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get the protocol version
    pub fn get_protocol_version(&self) -> Result<Option<u32>, ConsensusError> {
        match self
            .db
            .get(b"protocol_version")
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => match bincode::deserialize::<u32>(&bytes) {
                Ok(version) => Ok(Some(version)),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Set hard fork height
    pub fn set_hard_fork_height(&mut self, height: u64) -> Result<(), ConsensusError> {
        self.db
            .put(b"hard_fork_height", &height.to_le_bytes())
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get hard fork height
    pub fn get_hard_fork_height(&self) -> Result<Option<u64>, ConsensusError> {
        match self
            .db
            .get(b"hard_fork_height")
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => match bincode::deserialize::<u64>(&bytes) {
                Ok(height) => Ok(Some(height)),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Check if an output is spent
    pub fn is_output_spent(&self, outpoint: &OutPoint) -> Result<bool, ConsensusError> {
        // In a real implementation, this would check the UTXO set and spent status
        // For now, return false as a placeholder
        Ok(false)
    }

    /// Get critical UTXOs (used for validation)
    pub fn get_critical_utxos(&self) -> Result<Vec<OutPoint>, ConsensusError> {
        // In a real implementation, this would return UTXOs that are critical for validation
        // For now, return empty vector as a placeholder
        Ok(Vec::new())
    }
}
