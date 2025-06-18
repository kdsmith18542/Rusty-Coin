//! Sled-based blockchain state storage implementation

use bincode::{config, Encode, Decode};
use std::time::{SystemTime, UNIX_EPOCH};
use rusty_coin_core::{
    types::{BlockHeader, Hash, Masternode, Transaction, OutPoint, TxOutput, MasternodeStatus, GovernanceProposalPayload, GovernanceVotePayload, ActiveTicket, Block, UTXO, Vin, ProposalType, Ticket, prelude::*},
    consensus::pos::VotingTicket,
    error::Error,
};
use sled::Db;

/// Type alias for Result with crate::error::Error
type Result<T = (), E = Error> = std::result::Result<T, E>;

const CF_HEADERS: &str = "headers";
const CF_BLOCKS: &str = "blocks";
const CF_TRANSACTIONS: &str = "transactions";
const CF_ACTIVE_TICKETS: &str = "active_tickets";
const CF_METADATA: &str = "metadata";
const CF_UTXOS: &str = "utxos";
const CF_MASTERNODES: &str = "masternodes";
const CF_POS_VOTES: &str = "pos_votes";
const CF_GOVERNANCE_PROPOSALS: &str = "governance_proposals";
const CF_GOVERNANCE_VOTES: &str = "governance_votes";
const CF_BLOCK_SIZE_HISTORY: &str = "block_size_history";

/// Sled-based implementation of the BlockchainState trait.
/// 
/// This implementation provides persistent storage for all blockchain data
/// using the Sled embedded database.
///
/// # Fields
/// * `db` - The underlying Sled database
/// * `headers` - Tree for storing block headers
/// * `blocks` - Tree for storing full blocks
/// * `transactions` - Tree for storing transactions
/// * `utxos` - Tree for storing unspent transaction outputs
/// * `masternodes` - Tree for storing masternode information
/// * `active_tickets` - Tree for storing active voting tickets
/// * `pos_votes` - Tree for storing PoS votes
/// * `metadata` - Tree for storing metadata like chain height
/// * `governance_proposals` - Tree for storing governance proposals
/// * `governance_votes` - Tree for storing governance votes
/// * `block_size_history` - Tree for storing block size history
pub struct SledBlockchainState {
    db: Db,
    headers: sled::Tree,
    blocks: sled::Tree,
    transactions: sled::Tree,
    utxos: sled::Tree,
    masternodes: sled::Tree,
    active_tickets: sled::Tree,
    pos_votes: sled::Tree,
    metadata: sled::Tree,
    governance_proposals: sled::Tree,
    governance_votes: sled::Tree,
    block_size_history: sled::Tree,
}

impl SledBlockchainState {
    /// Creates a new SledBlockchainState with the given database path.
    /// 
    /// # Arguments
    /// * `path` - Filesystem path where the database will be stored
    /// 
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        
        Ok(Self {
            headers: db.open_tree(CF_HEADERS)?,
            blocks: db.open_tree(CF_BLOCKS)?,
            transactions: db.open_tree(CF_TRANSACTIONS)?,
            utxos: db.open_tree(CF_UTXOS)?,
            masternodes: db.open_tree(CF_MASTERNODES)?,
            active_tickets: db.open_tree(CF_ACTIVE_TICKETS)?,
            pos_votes: db.open_tree(CF_POS_VOTES)?,
            metadata: db.open_tree(CF_METADATA)?,
            governance_proposals: db.open_tree(CF_GOVERNANCE_PROPOSALS)?,
            governance_votes: db.open_tree(CF_GOVERNANCE_VOTES)?,
            block_size_history: db.open_tree(CF_BLOCK_SIZE_HISTORY)?,
            db,
        })
    }

    /// Creates a key for UTXO storage
    /// 
    /// Combines transaction ID and output index into a single byte vector
    /// 
    /// # Arguments
    /// * `txid` - The transaction ID
    /// * `output_index` - The output index
    /// 
    /// # Returns
    /// A byte vector containing the transaction ID followed by the output index in big-endian format
    fn create_utxo_key(txid: &Hash, output_index: u32) -> Vec<u8> {
        let mut key = txid.as_ref().to_vec();
        key.extend_from_slice(&output_index.to_be_bytes());
        key
    }

    /// Inserts a serializable value into a sled tree
    /// 
    /// # Type Parameters
    /// * `T` - Type of the value to insert (must implement serde::Serialize)
    /// 
    /// # Arguments
    /// * `tree` - Reference to the sled Tree
    /// * `key` - Key to insert
    /// * `value` - Value to insert
    /// 
    /// # Errors
    /// Returns an error if serialization or insertion fails
    fn insert_into_tree<T: serde::Serialize + Encode>(
        &self,
        tree: &sled::Tree,
        key: &[u8],
        value: &T,
    ) -> Result<()> {
        let serialized = bincode::encode_to_vec(value, bincode::config::standard()).expect("Failed to encode value");
        tree.insert(key, serialized)?;
        Ok(())
    }

    /// Retrieves a value from a sled tree
    /// 
    /// # Type Parameters
    /// * `T` - Type of the value to retrieve (must implement serde::de::DeserializeOwned)
    /// 
    /// # Arguments
    /// * `tree` - Reference to the sled Tree
    /// * `key` - Key to look up
    /// 
    /// # Returns
    /// `Ok(Some(value))` if found, `Ok(None)` if not found, or an error
    fn get_from_tree<T: serde::de::DeserializeOwned + Decode>(
        &self,
        tree: &sled::Tree,
        key: &[u8],
    ) -> Result<Option<T>> {
        if let Some(value) = tree.get(key)? {
            let deserialized = bincode::decode_from_slice(&value, bincode::config::standard())
                .map_err(Into::into)?
                .0;
            Ok(Some(deserialized))
        } else {
            Ok(None)
        }
    }

    /// Removes a value from a tree by key
    /// 
    /// # Arguments
    /// * `tree` - The tree to remove from
    /// * `key` - The key to remove
    /// 
    /// # Errors
    /// Returns an error if the removal operation fails
    /// 
    /// # Returns
    /// `Ok(())` if the operation was successful
    fn remove_from_tree(&self, tree: &sled::Tree, key: &[u8]) -> Result<()> {
        tree.remove(key)?;
        Ok(())
    }

    /// Gets the current blockchain height from the database
    /// 
    /// # Returns
    /// The current blockchain height, or 0 if no height is stored yet
    /// 
    /// # Errors
    /// Returns an error if there's a problem accessing the database
    fn get_height_from_db(&self) -> Result<u64> {
        if let Some(height_bytes) = self.metadata.get(b"height")? {
            bincode::decode_from_slice(&height_bytes, bincode::config::standard())
                .map_err(Into::into)?
                .0
        } else {
            Ok(0)
        }
    }

    pub fn get_last_n_headers(&self, n: u32) -> Result<Vec<BlockHeader>> {
        let mut headers = Vec::with_capacity(n as usize);
        let mut current_block_hash = self.get_block_hash_at_height(self.height())?;

        for _i in 0..n {
            if let Some(header) = self.get_header(&current_block_hash) {
                headers.push(header.clone());
                current_block_hash = header.prev_block_hash;
            } else {
                // If we can't find a header, we've reached the beginning of the chain or an inconsistency
                break;
            }
        }
        // Headers are collected from newest to oldest, reverse to get oldest to newest
        headers.reverse();
        Ok(headers)
    }

    // Helper to get the block hash at a specific height
    fn get_block_hash_at_height(&self, height: u64) -> Result<Hash> {
        if height == 0 {
            return Ok(Hash::zero());
        }

        // Retrieve the hash of the block at the specified height from block_size_history
        // This is a workaround since a direct height-to-hash map is not maintained.
        // We assume block_size_history keys are block heights in big-endian bytes.
        // This is not ideal as block_size_history stores size, not block hash.
        // A proper solution requires a dedicated height-to-hash mapping.

        // For now, if we need a specific block hash by height, and it's not the current tip,
        // we'll fetch the block at that height (if `get_block` can do so via some other means like scanning)
        // or rely on `get_last_n_headers` for recent blocks.

        // To get the tip hash if height matches current, we use the `tip_hash` in metadata.
        if let Some(height_bytes) = self.metadata.get(b"height")? {
            let current_chain_height: u64 = bincode::decode_from_slice(&height_bytes, bincode::config::standard())
                .map_err(Into::into)?
                .0;
            
            if height == current_chain_height {
                if let Some(tip_hash_bytes) = self.metadata.get(b"tip_hash")? {
                    Ok(Hash::from_bytes(&tip_hash_bytes)?)
                } else {
                    Ok(Hash::zero()) // Fallback for genesis or empty chain
                }
            } else {
                // This scenario means we are asking for a historical block hash by height.
                // This needs a proper index (height -> block_hash).
                // For now, return error or try to walk back if close enough (not implemented here).
                Err(Error::Other(format!("Unsupported: get_block_hash_at_height for historical height {}", height)))
            }
        } else {
            Ok(Hash::zero()) // If no height is stored, assume genesis (height 0)
        }
    }

    /// Helper to get a Masternode by its registration transaction hash.
    pub fn get_masternode(&self, pro_reg_tx_hash: &Hash) -> Option<Masternode> {
        self.get_from_tree(&self.masternodes, pro_reg_tx_hash.as_ref()).ok().flatten()
    }

    /// Helper to get a spent UTXO for revert operations. 
    /// This is a simplified placeholder; a real implementation would need a historical UTXO store.
    pub fn get_spent_utxo(&self, txid: &Hash, output_index: u32) -> Option<UTXO> {
        // In a real system, you might have a separate historical UTXO database or a snapshotting mechanism.
        // For this example, we'll just return a dummy UTXO if not found, or try to get it from transactions.
        // This part needs a proper implementation based on how spent UTXOs are truly archived.
        if let Some(tx) = self.get_transaction(txid) {
            if let Some(output) = tx.outputs.get(output_index as usize) {
                return Some(UTXO {
                    tx_hash: tx.hash(),
                    output_index,
                    value: output.value,
                    script_pubkey: output.pubkey_hash,
                });
            }
        }
        None
    }
}

impl BlockchainState for SledBlockchainState {
    fn get_header(&self, hash: &Hash) -> Option<BlockHeader> {
        self.get_from_tree(&self.headers, hash.as_ref()).ok().flatten()
    }

    fn get_block(&self, hash: &Hash) -> Option<Block> {
        self.get_from_tree(&self.blocks, hash.as_ref()).ok().flatten()
    }

    fn get_transaction(&self, txid: &Hash) -> Option<Transaction> {
        self.get_from_tree(&self.transactions, txid.as_ref()).ok().flatten()
    }

    fn get_utxo(&self, txid: &Hash, output_index: u32) -> Option<UTXO> {
        let key = Self::create_utxo_key(txid, output_index);
        self.get_from_tree(&self.utxos, &key).ok().flatten()
    }

    fn add_utxo(&self, utxo: UTXO) -> Result<()> {
        let key = Self::create_utxo_key(&utxo.tx_hash, utxo.output_index);
        self.insert_into_tree(&self.utxos, &key, &utxo)
    }

    fn remove_utxo(&self, txid: &Hash, output_index: u32) -> Result<()> {
        let key = Self::create_utxo_key(txid, output_index);
        self.remove_from_tree(&self.utxos, &key)
    }

    fn height(&self) -> u64 {
        self.get_height_from_db().unwrap_or(0)
    }

    fn contains_tx(&self, txid: &Hash) -> bool {
        self.transactions.contains_key(txid.as_ref()).unwrap_or(false)
    }

    fn put_header(&self, header: &BlockHeader) -> Result<()> {
        self.insert_into_tree(&self.headers, header.hash().as_ref(), header)
    }

    fn put_block(&self, block: &Block) -> Result<()> {
        self.insert_into_tree(&self.blocks, block.hash().as_ref(), block)?;
        // Update the tip hash in metadata
        self.metadata.insert(b"tip_hash", block.hash().as_ref().to_vec())?;
        Ok(())
    }

    fn put_transaction(&self, tx: &Transaction) -> Result<()> {
        self.insert_into_tree(&self.transactions, tx.hash().as_ref(), tx)
    }

    fn active_tickets(&self) -> Vec<VotingTicket> {
        self.active_tickets.iter().filter_map(|res| {
            res.ok().and_then(|(_k, v)| {
                bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(ticket, _)| ticket)
            })
        }).collect()
    }

    fn masternodes(&self) -> Vec<Masternode> {
        self.masternodes.iter().filter_map(|res| {
            res.ok().and_then(|(_k, v)| {
                bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(masternode, _)| masternode)
            })
        }).collect()
    }

    fn add_active_ticket(&self, ticket: VotingTicket) -> Result<()> {
        self.insert_into_tree(&self.active_tickets, ticket.hash.as_ref(), &ticket)
    }

    fn remove_active_ticket(&self, ticket_hash: &Hash) -> Result<()> {
        self.remove_from_tree(&self.active_tickets, ticket_hash.as_ref())
    }

    fn add_masternode(&self, masternode: Masternode) -> Result<()> {
        self.insert_into_tree(&self.masternodes, masternode.pro_reg_tx_hash.as_ref(), &masternode)
    }

    fn update_masternode(&self, masternode: Masternode) -> Result<()> {
        self.insert_into_tree(&self.masternodes, masternode.pro_reg_tx_hash.as_ref(), &masternode)
    }

    fn remove_masternode(&self, pro_reg_tx_hash: &Hash) -> Result<()> {
        self.remove_from_tree(&self.masternodes, pro_reg_tx_hash.as_ref())
    }

    fn add_pos_vote(&self, vote: PoSVote) -> Result<()> {
        // Store PoS votes keyed by block hash
        self.insert_into_tree(&self.pos_votes, vote.block_hash.as_ref(), &vote)
    }

    fn get_pos_votes(&self, block_hash: &Hash) -> Vec<PoSVote> {
        // This implementation needs to iterate and filter if multiple votes per block hash can exist
        // For simplicity, returning a vector of votes associated with that block hash.
        self.pos_votes.iter().filter_map(|res| {
            res.ok().and_then(|(k, v)| {
                let key_hash = Hash::from_slice(&k).ok()?;
                if &key_hash == block_hash {
                    bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(vote, _)| vote)
                } else {
                    None
                }
            })
        }).collect()
    }

    fn update_masternode_last_seen(&self, pro_reg_tx_hash: &Hash) -> Result<()> {
        if let Some(mut masternode) = self.get_masternode(pro_reg_tx_hash) {
            masternode.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            // Reset failed PoSe challenges on successful update
            masternode.failed_pose_challenges = 0;
            self.update_masternode(masternode)?; 
        }
        Ok(())
    }

    fn increment_masternode_pose_failures(&self, pro_reg_tx_hash: &Hash) -> Result<()> {
        if let Some(mut masternode) = self.get_masternode(pro_reg_tx_hash) {
            masternode.failed_pose_challenges += 1;
            self.update_masternode(masternode)?;
        }
        Ok(())
    }

    fn deactivate_masternode(&self, pro_reg_tx_hash: &Hash) -> Result<()> {
        if let Some(mut masternode) = self.get_masternode(pro_reg_tx_hash) {
            masternode.status = MasternodeStatus::PoSeFailed;
            self.update_masternode(masternode)?;
        }
        Ok(())
    }

    fn put_governance_proposal(&self, proposal_tx_hash: &Hash, proposal_payload: &GovernanceProposalPayload) -> Result<()> {
        self.insert_into_tree(&self.governance_proposals, proposal_tx_hash.as_ref(), proposal_payload)
    }

    fn get_governance_proposal(&self, proposal_tx_hash: &Hash) -> Option<GovernanceProposalPayload> {
        self.get_from_tree(&self.governance_proposals, proposal_tx_hash.as_ref()).ok().flatten()
    }

    fn get_all_governance_proposals(&self) -> Vec<GovernanceProposalPayload> {
        self.governance_proposals.iter().filter_map(|res| {
            res.ok().and_then(|(_k, v)| {
                bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(proposal, _)| proposal)
            })
        }).collect()
    }

    fn put_governance_vote(&self, vote_tx_hash: &Hash, vote_payload: &GovernanceVotePayload) -> Result<()> {
        self.insert_into_tree(&self.governance_votes, vote_tx_hash.as_ref(), vote_payload)
    }

    fn get_governance_votes_for_proposal(&self, proposal_id: &Hash) -> Vec<GovernanceVotePayload> {
        self.governance_votes.iter().filter_map(|res| {
            res.ok().and_then(|(_k, v)| {
                bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(vote, _)| vote)
            }).filter(|vote| &vote.proposal_id == proposal_id)
        }).collect()
    }

    fn remove_governance_proposal(&self, proposal_tx_hash: &Hash) -> Result<()> {
        self.remove_from_tree(&self.governance_proposals, proposal_tx_hash.as_ref())
    }

    fn remove_governance_vote(&self, vote_tx_hash: &Hash, _proposal_id: &Hash) -> Result<()> {
        self.remove_from_tree(&self.governance_votes, vote_tx_hash.as_ref())
    }

    fn put_block_size(&self, height: u64, size: u64) -> Result<()> {
        self.insert_into_tree(&self.block_size_history, &height.to_be_bytes(), &size)
    }

    fn get_block_sizes_in_range(&self, start_height: u64, end_height: u64) -> Vec<u64> {
        self.block_size_history.range(start_height.to_be_bytes()..=end_height.to_be_bytes())
            .filter_map(|res| {
                res.ok().and_then(|(_k, v)| {
                    bincode::decode_from_slice(&v, bincode::config::standard()).ok().map(|(size, _)| size)
                })
            }).collect()
    }

    fn update_height(&self, height: u64) -> Result<()> {
        self.insert_into_tree(&self.metadata, b"height", &height)
    }
}