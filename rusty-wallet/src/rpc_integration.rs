// rusty-wallet/src/rpc_integration.rs

use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use bincode::{self, config};

pub async fn send_transaction_rpc(rpc_url: &str, raw_tx: String) -> Result<String, Box<dyn std::error::Error>> {
    let client = WsClientBuilder::default().build(rpc_url).await?;
    let params = rpc_params![raw_tx];
    let response: String = client.request("send_transaction", params).await?;
    Ok(response)
}

// Placeholder for RPC integration functionalities

use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use jsonrpsee::core::Error as RpcError;
use serde_json::value::RawValue;

// Re-export necessary types from rusty-shared-types and rusty-core for RPC communication
pub use rusty_shared_types::transaction::Transaction;
pub use rusty_core::blockchain::Block;

pub struct RpcClient {
    http_client: Option<HttpClient>,
    ws_client: Option<WsClient>,
}

impl RpcClient {
    pub fn new() -> Self {
        RpcClient {
            http_client: None,
            ws_client: None,
        }
    }

    pub async fn connect_http(&mut self, url: &str) -> Result<(), String> {
        let client = HttpClientBuilder::default().build(url)
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        self.http_client = Some(client);
        Ok(())
    }

    pub async fn connect_ws(&mut self, url: &str) -> Result<(), String> {
        let client = WsClientBuilder::default().build(url).await
            .map_err(|e| format!("Failed to build WebSocket client: {}", e))?;
        self.ws_client = Some(client);
        Ok(())
    }

    pub async fn get_block_count(&self) -> Result<u64, String> {
        let client = self.http_client.as_ref().ok_or("HTTP client not connected")?;
        let response: u64 = client.request("get_block_count", jsonrpsee::rpc_params![]).await
            .map_err(|e| format!("RPC call 'get_block_count' failed: {}", e))?;
        Ok(response)
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<String, String> {
        let client = self.http_client.as_ref().ok_or("HTTP client not connected")?;
        let response: String = client.request("get_block_hash", jsonrpsee::rpc_params![height]).await
            .map_err(|e| format!("RPC call 'get_block_hash' failed: {}", e))?;
        Ok(response)
    }

    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String, String> {
        let tx_bytes = bincode::serialize(tx)
            .map_err(|e| format!("Serialization failed: {}", e))?;
        let tx_hex = hex::encode(tx_bytes);
        
        match &self.http_client {
            Some(client) => {
                let response: String = client.request("send_transaction", rpc_params![tx_hex])
                    .map_err(|e| format!("RPC call failed: {}", e))?;
                Ok(response)
            }
            None => Err("Not connected to RPC server".to_string()),
        }
    }

    // Example of a state query for UTXOs for a given address
    pub async fn get_utxos_by_address(&self, address: &str) -> Result<Vec<rusty_core::utxo_set::Utxo>, String> {
        let client = self.http_client.as_ref().ok_or("HTTP client not connected")?;
        let response: Vec<rusty_core::utxo_set::Utxo> = client.request("get_utxos_by_address", jsonrpsee::rpc_params![address]).await
            .map_err(|e| format!("RPC call 'get_utxos_by_address' failed: {}", e))?;
        Ok(response)
    }

    // You can add more RPC methods as needed
}