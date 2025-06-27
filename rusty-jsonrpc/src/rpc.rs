use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use bincode;
use hex;
use rusty_core::types::transaction::Transaction;
use rusty_core::types::block::{Block, BlockHeader};
use rusty_core::types::Hash;
use rusty_core::types::governance::{GovernanceProposal, GovernanceVote};
use crate::error::RpcError;

pub struct RpcImpl {
    blockchain: rusty_core::Blockchain,
}

impl RpcImpl {
    pub fn new(blockchain: rusty_core::Blockchain) -> Self {
        RpcImpl {
            blockchain,
        }
    }
}

impl Rpc for RpcImpl {
    #[rpc(name = "start_sync")]
    fn start_sync(&self) -> Result<String> {
        // Placeholder for actual sync logic
        Ok("Network synchronization started.".to_string())
    }

#[rpc]
pub trait Rpc {
    #[rpc(name = "get_block_count")]
    fn get_block_count(&self) -> Result<u64> {
        Ok(self.blockchain.get_current_block_height())
    }

    #[rpc(name = "get_block_hash")]
    fn get_block_hash(&self, height: u64) -> Result<Hash> {
        self.blockchain.get_block_hash(height).map_err(RpcError::from)?
    }

    #[rpc(name = "get_block")]
    fn get_block(&self, hash: Hash) -> Result<Block> {
        self.blockchain.get_block(&hash).map_err(RpcError::from)?
    }

    #[rpc(name = "get_transaction")]
    fn get_transaction(&self, txid: Hash) -> Result<Transaction> {
        // This requires iterating through blocks or having a transaction index
        // For now, return a placeholder error
        Err(jsonrpc_core::Error::method_not_found())
    }

    #[rpc(name = "send_raw_transaction")]
    fn send_raw_transaction(&self, raw_tx: String) -> Result<Hash> {
        // Deserialize the transaction
        let tx: Transaction = bincode::deserialize(&hex::decode(raw_tx).map_err(RpcError::from)?)
            .map_err(RpcError::from)?;

        // Validate the transaction
        self.blockchain.validate_transaction(&tx).map_err(RpcError::from)?;

        // Add to mempool (placeholder for now)
        // self.mempool.add_transaction(tx.clone());

        Ok(tx.calculate_hash())
    }

    #[rpc(name = "get_utxo_set")]
    fn get_utxo_set(&self) -> Result<Vec<rusty_core::types::transaction::OutPoint>> {
        self.blockchain.get_utxo_set().map_err(RpcError::from)?
    }

    #[rpc(name = "get_governance_proposals")]
    fn get_governance_proposals(&self) -> Result<Vec<GovernanceProposal>> {
        Ok(self.blockchain.active_proposals.proposals.values().cloned().collect())
    }

    #[rpc(name = "get_governance_votes")]
    fn get_governance_votes(&self, proposal_id: Hash) -> Result<Vec<GovernanceVote>> {
        match self.blockchain.active_proposals.get_votes_for_proposal(&proposal_id) {
            Some(votes_map) => Ok(votes_map.values().cloned().collect()),
            None => Ok(vec![]), // Return empty vec if proposal not found or no votes
        }
    }
}