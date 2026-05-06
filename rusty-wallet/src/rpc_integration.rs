// rusty-wallet/src/rpc_integration.rs

use bincode::{self};
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use rusty_shared_types::{Block, Transaction};

/// Error type for RPC operations
#[derive(Debug)]
pub enum RpcError {
    /// Connection error
    ConnectionError(String),
    /// Response parsing error
    ParseError(String),
    /// General RPC error
    RpcError(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            RpcError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            RpcError::RpcError(msg) => write!(f, "RPC error: {}", msg),
        }
    }
}

impl std::error::Error for RpcError {}

pub async fn send_transaction_rpc(
    rpc_url: &str,
    raw_tx: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = WsClientBuilder::default().build(rpc_url).await?;
    let params = rpc_params![raw_tx];
    let response: String = client.request("send_transaction", params).await?;
    Ok(response)
}

/// RPC client for wallet-blockchain communication
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
        let client = HttpClientBuilder::default()
            .build(url)
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        self.http_client = Some(client);
        Ok(())
    }

    pub async fn connect_ws(&mut self, url: &str) -> Result<(), String> {
        let client = WsClientBuilder::default()
            .build(url)
            .await
            .map_err(|e| format!("Failed to build WebSocket client: {}", e))?;
        self.ws_client = Some(client);
        Ok(())
    }

    /// Get the current blockchain height
    pub async fn get_block_count(&self) -> Result<u64, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: u64 = client
            .request("get_block_count", jsonrpsee::rpc_params![])
            .await
            .map_err(|e| format!("RPC call 'get_block_count' failed: {}", e))?;
        Ok(response)
    }

    /// Get block hash by height
    pub async fn get_block_hash(&self, height: u64) -> Result<String, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: String = client
            .request("get_block_hash", jsonrpsee::rpc_params![height])
            .await
            .map_err(|e| format!("RPC call 'get_block_hash' failed: {}", e))?;
        Ok(response)
    }

    /// Get detailed block information by hash
    pub async fn get_block_by_hash(&self, hash: &str) -> Result<Block, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: Block = client
            .request("get_block_by_hash", jsonrpsee::rpc_params![hash])
            .await
            .map_err(|e| format!("RPC call 'get_block_by_hash' failed: {}", e))?;
        Ok(response)
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String, String> {
        let tx_bytes =
            bincode::serialize(tx).map_err(|e| format!("Serialization failed: {}", e))?;
        let tx_hex = hex::encode(tx_bytes);

        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: String = client
            .request("send_transaction", jsonrpsee::rpc_params![tx_hex])
            .await
            .map_err(|e| format!("RPC call 'send_transaction' failed: {}", e))?;
        Ok(response)
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, txid: &str) -> Result<Transaction, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: Transaction = client
            .request("get_transaction", jsonrpsee::rpc_params![txid])
            .await
            .map_err(|e| format!("RPC call 'get_transaction' failed: {}", e))?;
        Ok(response)
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<u64, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: u64 = client
            .request("get_balance", jsonrpsee::rpc_params![address])
            .await
            .map_err(|e| format!("RPC call 'get_balance' failed: {}", e))?;
        Ok(response)
    }

    /// Get unspent transaction outputs for an address
    pub async fn get_utxos_by_address(&self, address: &str) -> Result<Vec<UtxoInfo>, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: Vec<UtxoInfo> = client
            .request("get_utxos_by_address", jsonrpsee::rpc_params![address])
            .await
            .map_err(|e| format!("RPC call 'get_utxos_by_address' failed: {}", e))?;
        Ok(response)
    }

    /// Get mempool information
    pub async fn get_mempool_info(&self) -> Result<MempoolInfo, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: MempoolInfo = client
            .request("get_mempool_info", jsonrpsee::rpc_params![])
            .await
            .map_err(|e| format!("RPC call 'get_mempool_info' failed: {}", e))?;
        Ok(response)
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<NetworkInfo, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: NetworkInfo = client
            .request("get_network_info", jsonrpsee::rpc_params![])
            .await
            .map_err(|e| format!("RPC call 'get_network_info' failed: {}", e))?;
        Ok(response)
    }

    /// Estimate fee for transaction
    pub async fn estimate_fee(&self, target_blocks: u32) -> Result<u64, String> {
        let client = self
            .http_client
            .as_ref()
            .ok_or("HTTP client not connected")?;
        let response: u64 = client
            .request("estimate_fee", jsonrpsee::rpc_params![target_blocks])
            .await
            .map_err(|e| format!("RPC call 'estimate_fee' failed: {}", e))?;
        Ok(response)
    }

    /// Subscribe to new blocks (WebSocket only)
    pub async fn subscribe_new_blocks(&self) -> Result<(), String> {
        let client = self
            .ws_client
            .as_ref()
            .ok_or("WebSocket client not connected")?;
        let _subscription: jsonrpsee::core::client::Subscription<serde_json::Value> = client
            .subscribe("subscribe_blocks", jsonrpsee::rpc_params![], "new_block")
            .await
            .map_err(|e| format!("Subscription failed: {}", e))?;
        Ok(())
    }

    /// Check if the RPC connection is healthy
    pub async fn health_check(&self) -> Result<bool, String> {
        match self.get_block_count().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// UTXO information for wallet management
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmations: u32,
    pub script_pubkey: Vec<u8>,
}

/// Mempool information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
    pub usage: usize,
    pub max_mempool: usize,
    pub mempool_min_fee: u64,
}

/// Network information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInfo {
    pub version: String,
    pub protocol_version: u32,
    pub connections: u32,
    pub network_time_offset: i64,
    pub relay_fee: u64,
}
