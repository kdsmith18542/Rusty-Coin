//! RPC method definitions for Rusty-Coin.

use jsonrpsee::proc_macros::rpc;
use serde_json::Value;

#[rpc(server, namespace = "rusty_coin")]
pub trait RustyRpc {
    // Read-only methods
    #[method(name = "get_block_count")]
    async fn get_block_count(&self) -> Result<u64, jsonrpsee::core::Error>;

    #[method(name = "get_block_hash")]
    async fn get_block_hash(&self, height: u64) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "get_block")]
    async fn get_block(&self, hash: String) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_transaction")]
    async fn get_transaction(&self, txid: String) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_blockchain_info")]
    async fn get_blockchain_info(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_mempool_info")]
    async fn get_mempool_info(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_peer_info")]
    async fn get_peer_info(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_network_info")]
    async fn get_network_info(&self) -> Result<Value, jsonrpsee::core::Error>;

    // Standard operations
    #[method(name = "send_raw_transaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "create_raw_transaction")]
    async fn create_raw_transaction(
        &self,
        inputs: Value,
        outputs: Value,
    ) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "sign_raw_transaction")]
    async fn sign_raw_transaction(&self, tx_hex: String) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "estimate_fee")]
    async fn estimate_fee(&self, blocks: u32) -> Result<f64, jsonrpsee::core::Error>;

    #[method(name = "list_unspent")]
    async fn list_unspent(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "get_balance")]
    async fn get_balance(&self) -> Result<f64, jsonrpsee::core::Error>;

    // Administrative operations
    #[method(name = "start_mining")]
    async fn start_mining(&self, address: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "stop_mining")]
    async fn stop_mining(&self) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "set_mining_address")]
    async fn set_mining_address(&self, address: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "add_peer")]
    async fn add_peer(&self, address: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "remove_peer")]
    async fn remove_peer(&self, address: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "ban_peer")]
    async fn ban_peer(
        &self,
        address: String,
        duration: u64,
    ) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "unban_peer")]
    async fn unban_peer(&self, address: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "invalidate_block")]
    async fn invalidate_block(&self, hash: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "reconsider_block")]
    async fn reconsider_block(&self, hash: String) -> Result<bool, jsonrpsee::core::Error>;

    // Super administrative operations
    #[method(name = "shutdown")]
    async fn shutdown(&self) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "debug_level")]
    async fn debug_level(&self, level: String) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "generate_blocks")]
    async fn generate_blocks(&self, count: u32) -> Result<Vec<String>, jsonrpsee::core::Error>;

    #[method(name = "reset_blockchain")]
    async fn reset_blockchain(&self) -> Result<bool, jsonrpsee::core::Error>;

    // Governance operations
    #[method(name = "submit_proposal")]
    async fn submit_proposal(&self, proposal: Value) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "vote_proposal")]
    async fn vote_proposal(
        &self,
        proposal_id: String,
        vote: bool,
    ) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "get_governance_info")]
    async fn get_governance_info(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "list_proposals")]
    async fn list_proposals(&self) -> Result<Value, jsonrpsee::core::Error>;

    // Masternode operations
    #[method(name = "start_masternode")]
    async fn start_masternode(&self) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "stop_masternode")]
    async fn stop_masternode(&self) -> Result<bool, jsonrpsee::core::Error>;

    #[method(name = "get_masternode_status")]
    async fn get_masternode_status(&self) -> Result<Value, jsonrpsee::core::Error>;

    #[method(name = "list_masternodes")]
    async fn list_masternodes(&self) -> Result<Value, jsonrpsee::core::Error>;
}
