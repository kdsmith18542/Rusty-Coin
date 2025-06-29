//! RPC method definitions for Rusty-Coin.

use serde::{Deserialize, Serialize};
use jsonrpsee::proc_macros::rpc;

#[rpc(server, namespace = "rusty_coin")]
pub trait RustyRpc {
    #[method(name = "get_block_count")]
    async fn get_block_count(&self) -> Result<u64, jsonrpsee::core::Error>;

    #[method(name = "get_block_hash")]
    async fn get_block_hash(&self, height: u64) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "get_block")]
    async fn get_block(&self, hash: String) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "send_raw_transaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, jsonrpsee::core::Error>;

    #[method(name = "get_transaction")]
    async fn get_transaction(&self, txid: String) -> Result<String, jsonrpsee::core::Error>;
} 