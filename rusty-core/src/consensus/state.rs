use rusty_shared_types::{Block, OutPoint, TxOutput, Transaction, Utxo, Ticket, TicketId, BlockHeader, Hash};
use rusty_shared_types::masternode::{MasternodeList, MasternodeID};
use rusty_shared_types::governance::{GovernanceProposal, VoteChoice};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use crate::consensus::blockchain::Blockchain;
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::utxo_set::UtxoSet;
use crate::consensus::governance_state::ActiveProposals;
use crate::consensus::error::ConsensusError;
use crate::state::{MerklePatriciaTrie, TicketData};

/// Tracks the current consensus state of the node
pub struct ConsensusState {
    pub blockchain: Arc<Blockchain>,
    pub state: BlockchainState,
    pub current_height: u64,
    pub current_tip: [u8; 32],
}

impl ConsensusState {
    pub fn new(blockchain: Arc<Blockchain>, state: BlockchainState) -> Result<Self, ConsensusError> {
        Ok(Self {
            blockchain,
            state,
            current_height: 0,
            current_tip: [0; 32],
        })
    }
    
    pub fn update_tip(&mut self, block_hash: [u8; 32], height: u64) {
        self.current_tip = block_hash;
        self.current_height = height;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockchainState {
    pub current_height: u64,
    pub tip: Hash,
    pub live_tickets: LiveTicketsPool,
    pub utxo_set: UtxoSet,
    pub active_proposals: ActiveProposals,
    #[serde(skip)] // We don't want to serialize the DB directly.
    db: HashMap<Vec<u8>, Vec<u8>>, // In-memory representation for simplicity. Replace with persistent DB.
}

impl BlockchainState {
    pub fn new() -> Self {
        BlockchainState {
            current_height: 0,
            tip: [0; 32],
            live_tickets: LiveTicketsPool::new(),
            utxo_set: UtxoSet::new(),
            active_proposals: ActiveProposals::new(),
            db: HashMap::new(), // Initialize the in-memory DB
        }
    }

    pub fn load_from_disk(path: &std::path::Path) -> Result<Self, ConsensusError> {
        let encoded = std::fs::read(path).map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        let db: HashMap<Vec<u8>, Vec<u8>> = bincode::deserialize(&encoded)
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;

        let current_height = match db.get(b"current_height".as_ref()) {
            Some(encoded) => bincode::deserialize(encoded.as_ref())
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?,
            None => 0,
        };

        let tip = match db.get(b"tip".as_ref()) {
            Some(encoded) => bincode::deserialize(encoded.as_ref())
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?,
            None => [0; 32],
        };

        let live_tickets = match db.get(b"live_tickets".as_ref()) {
            Some(encoded) => bincode::deserialize(encoded.as_ref())
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?,
            None => LiveTicketsPool::new(),
        };

        let utxo_set = match db.get(b"utxo_set".as_ref()) {
            Some(encoded) => bincode::deserialize(encoded.as_ref())
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?,
            None => UtxoSet::new(),
        };

        let active_proposals = match db.get(b"active_proposals".as_ref()) {
            Some(encoded) => bincode::deserialize(encoded.as_ref())
                .map_err(|e| ConsensusError::SerializationError(e.to_string()))?,
            None => ActiveProposals::new(),
        };

        Ok(BlockchainState {
            current_height,
            tip,
            live_tickets,
            utxo_set,
            active_proposals,
            db,
        })
    }

    pub fn save_to_disk(&mut self, path: &std::path::Path) -> Result<(), ConsensusError> {
        self.db.insert(b"current_height".to_vec(), bincode::serialize(&self.current_height)?);
        self.db.insert(b"tip".to_vec(), bincode::serialize(&self.tip)?);
        self.db.insert(b"live_tickets".to_vec(), bincode::serialize(&self.live_tickets)?);
        self.db.insert(b"utxo_set".to_vec(), bincode::serialize(&self.utxo_set)?);
        self.db.insert(b"active_proposals".to_vec(), bincode::serialize(&self.active_proposals)?);

        let encoded: Vec<u8> = bincode::serialize(&self.db)
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        std::fs::write(path, encoded).map_err(|e| ConsensusError::DatabaseError(e.to_string()))
    }

    /// Updates the tip of the blockchain.
    pub fn update_tip(&mut self, new_tip_hash: Hash, new_height: u64) -> Result<(), ConsensusError> {
        self.tip = new_tip_hash;
        self.current_height = new_height;
        Ok(())
    }

    /// Removes a block by its hash from the blockchain state.
    pub fn remove_block_by_hash(&mut self, block_hash: &Hash) -> Result<(), ConsensusError> {
        // In a real implementation, this would involve more complex database operations
        // to remove block data, transactions, etc. For this in-memory simulation,
        // we'll simply acknowledge the request.
        println!("Simulating removal of block with hash: {:?}", block_hash);
        Ok(())
    }

    /// Removes a block by its height from the blockchain state.
    pub fn remove_block_by_height(&mut self, height: u64) -> Result<(), ConsensusError> {
        // Similar to remove_block_by_hash, this is a placeholder.
        println!("Simulating removal of block at height: {}", height);
        Ok(())
    }

    /// Validates a transaction against the current UTXO set.
    pub fn validate_transaction(&self, _tx: &rusty_shared_types::Transaction, _current_block_height: u64) -> Result<(), ConsensusError> {
        // ... existing code ...
        Ok(())
    }

    pub fn get_block_subsidy(&self, height: u64, halving_interval: u64, initial_block_reward: u64) -> u64 {
        let halvings = height / halving_interval;
        if halvings >= 64 {
            return 0;
        }
        initial_block_reward >> halvings
    }

    pub fn calculate_state_root(
        utxo_set: &UtxoSet,
        live_tickets: &LiveTicketsPool,
        masternode_list: &Option<Arc<Mutex<Vec<MasternodeID>>>>,
        active_proposals: &ActiveProposals,
    ) -> Result<[u8; 32], ConsensusError> {
        // Convert UTXO set to HashMap for trie construction
        let utxo_map: HashMap<OutPoint, Utxo> = utxo_set.iter()
            .map(|(outpoint, utxo)| (outpoint.clone(), utxo.clone()))
            .collect();

        // Convert live tickets to HashMap with TicketData
        let ticket_map: HashMap<TicketId, TicketData> = live_tickets.tickets.iter()
            .map(|(ticket_id, ticket)| {
                let ticket_data = TicketData {
                    owner: ticket.pubkey.to_vec(),
                    value: ticket.value,
                    expiration_height: ticket.height,
                    creation_height: ticket.height,
                };
                (*ticket_id, ticket_data)
            })
            .collect();

        // Convert masternode list to HashMap
        let mn_map: HashMap<Vec<u8>, Vec<u8>> = if let Some(mn_list) = masternode_list {
            let locked_mn_list = mn_list.lock()
                .map_err(|e| ConsensusError::StateError(format!("Failed to lock masternode list: {}", e)))?;
            locked_mn_list.iter()
                .enumerate()
                .map(|(i, mn_id)| {
                    let key = format!("mn_{}", i).into_bytes();
                    let value = bincode::serialize(mn_id)
                        .unwrap_or_default();
                    (key, value)
                })
                .collect()
        } else {
            HashMap::new()
        };

        // Convert active proposals to HashMap
        let proposal_map: HashMap<Vec<u8>, Vec<u8>> = active_proposals.proposals.iter()
            .map(|(proposal_id, proposal)| {
                let key = format!("prop_{}", hex::encode(proposal_id)).into_bytes();
                let mut proposal_data = bincode::serialize(proposal)
                    .unwrap_or_default();

                // Include votes in the proposal data
                if let Some(votes) = active_proposals.get_votes_for_proposal(proposal_id) {
                    let votes_data = bincode::serialize(votes)
                        .unwrap_or_default();
                    proposal_data.extend_from_slice(&votes_data);
                }

                (key, proposal_data)
            })
            .collect();

        // Create Merkle Patricia Trie from state data
        let trie = MerklePatriciaTrie::from_state_data(
            &utxo_map,
            &ticket_map,
            &mn_map,
            &proposal_map,
        )?;

        Ok(trie.root_hash())
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<(TxOutput, u64, bool)>, ConsensusError> {
        let key = outpoint.encode_to_vec()?;
        let result = self.db.get(&key).cloned();
        match result {
            Some(value) => {
                let decoded: Utxo = bincode::deserialize(&value)
                    .map_err(|e| ConsensusError::UtxoSetError(format!("Failed to decode UTXO: {}", e)))?;
                Ok(Some((decoded.output, decoded.creation_height, decoded.is_coinbase)))
            }
            None => Ok(None),
        }
    }

    pub fn update_utxo_set(
        &mut self,
        outpoint: &OutPoint,
        output: Option<&TxOutput>,
        height: u64,
        is_coinbase: bool,
    ) -> Result<Option<(TxOutput, u64, bool)>, ConsensusError> {
        let key = outpoint.encode_to_vec()?;
        match output {
            Some(output) => {
                let value = bincode::serialize(&(output, height, is_coinbase))?;
                self.db.insert(key.clone(), value);
                Ok(Some((output.clone(), height, is_coinbase)))
            }
            None => {
                self.db.remove(&key);
                Ok(None)
            }
        }
    }

    pub fn apply_block(&mut self, block: &Block) -> Result<(), ConsensusError> {
        // Update current height and tip
        self.current_height = block.header.height;
        self.tip = block.hash();

        // Update UTXO set and live tickets pool based on transactions in the block
        for tx in &block.transactions {
            match tx {
                Transaction::TicketPurchase { ticket_id, locked_amount, ticket_address, .. } => {
                    let _outpoint = OutPoint { txid: *ticket_id, vout: 0 }; // Assuming vout 0 for ticket purchase output
                    let commitment: Hash = blake3::hash(ticket_address.as_slice()).into();
                    let public_key: [u8; 32] = ticket_address.as_slice().try_into()
                        .map_err(|_| ConsensusError::InvalidTicket("Invalid public key length in ticket address.".to_string()))?;
                    let new_ticket = Ticket {
                        id: TicketId::from_bytes(commitment),
                        pubkey: public_key.to_vec(),
                        height: block.header.height,
                        value: *locked_amount,
                        status: rusty_shared_types::TicketStatus::Live,
                    };
                    self.live_tickets.add_ticket(new_ticket);
                }
                Transaction::TicketRedemption { ticket_id, .. } => {
        self.live_tickets.remove_ticket(&TicketId::from(*ticket_id));
                }
                _ => { /* Handle other transaction types as needed */ }
            }
        }

        // Apply transactions to UTXO set
        self.utxo_set.apply_block(&block, block.header.height);

        // Persist updated state
        self.db.insert(b"current_height".to_vec(), bincode::serialize(&self.current_height)?);
        self.db.insert(b"tip".to_vec(), bincode::serialize(&self.tip)?);
        self.db.insert(b"live_tickets".to_vec(), bincode::serialize(&self.live_tickets)?);
        self.db.insert(b"utxo_set".to_vec(), bincode::serialize(&self.utxo_set)?);
        self.db.insert(b"active_proposals".to_vec(), bincode::serialize(&self.active_proposals)?);

        Ok(())
    }

    pub fn put_block(&mut self, block: &Block) -> Result<(), ConsensusError> {
        let block_hash = block.hash();
        let block_data = bincode::serialize(block)?;
        
        // Store block by hash
        let hash_key = block_hash.to_vec();
        self.db.insert(hash_key, block_data);
        
        // Store block hash by height
        self.put_block_hash(block.header.height.try_into().unwrap(), block_hash)
    }

    pub fn put_block_hash(&mut self, height: u32, hash: [u8; 32]) -> Result<(), ConsensusError> {
        let key = format!("block_hash_{}", height).into_bytes();
        let value_encoded = bincode::serialize(&hash)?;
        self.db.insert(key, value_encoded);
        Ok(())
    }

    pub fn get_block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, ConsensusError> {
        let key = format!("block_hash_{}", height).into_bytes();
        if let Some(value) = self.db.get(&key) {
            let hash: [u8; 32] = bincode::deserialize(value)?;
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    pub fn get_block(&self, height: u32) -> Result<Option<Block>, ConsensusError> {
        if let Some(hash) = self.get_block_hash(height as u64)? {
            if let Some(data) = self.db.get(&hash.to_vec()) {
                let block: Block = bincode::deserialize(data)?;
                Ok(Some(block))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_current_block_height(&self) -> Result<u64, ConsensusError> {
        if let Some(height_bytes) = self.db.get(&b"current_height".to_vec()) {
            let height: u64 = bincode::deserialize(height_bytes)?;
            Ok(height)
        } else {
            Ok(0)
        }
    }

    pub fn set_current_block_height(&mut self, height: u64) -> Result<(), ConsensusError> {
        self.db.insert(b"current_height".to_vec(), height.to_le_bytes().to_vec());
        Ok(())
    }
}

#[cfg(feature = "rocksdb")]
impl From<rocksdb::Error> for ConsensusError {
    fn from(e: rocksdb::Error) -> Self {
        ConsensusError::UtxoSetError(e.to_string())
    }
}
