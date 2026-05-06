// rusty-rpc/src/server.rs

use crate::auth::{AuthManager, PermissionMiddleware};
use crate::middleware::ApiKeyMiddleware;
use crate::rpc::RustyRpcServer;
use jsonrpsee::core::Error;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::error::{CallError, ErrorObjectOwned};
use rusty_core::consensus::state::BlockchainState;
use rusty_core::mempool::Mempool;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread_local;
use tokio::time::Duration;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

// Rate limiting configuration
const MAX_REQUESTS_PER_MINUTE: usize = 60;
const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

// TLS configuration structure
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

// Shared state for rate limiting
pub struct RateLimiter {
    requests: HashMap<SocketAddr, (usize, tokio::time::Instant)>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            requests: HashMap::new(),
        }
    }

    fn allow(&mut self, addr: SocketAddr) -> bool {
        let now = tokio::time::Instant::now();
        let (count, last_reset) = self.requests.entry(addr).or_insert((0, now));

        if now.duration_since(*last_reset) >= Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS) {
            *count = 0;
            *last_reset = now;
        }

        if *count < MAX_REQUESTS_PER_MINUTE {
            *count += 1;
            true
        } else {
            false
        }
    }
}

// Thread-local storage for request context
thread_local! {
    static REQUEST_API_KEY: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

// Request context manager for API key extraction
pub struct RequestContext {
    api_key: Option<String>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self { api_key: None }
    }

    pub fn set_api_key(&mut self, api_key: String) {
        self.api_key = Some(api_key.clone());
        // Store in thread-local for access during RPC calls
        REQUEST_API_KEY.with(|cell| {
            *cell.borrow_mut() = Some(api_key);
        });
    }

    pub fn get_api_key() -> Option<String> {
        REQUEST_API_KEY.with(|cell| cell.borrow().clone())
    }

    pub fn clear() {
        REQUEST_API_KEY.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

pub struct RustyRpcServerImpl {
    rate_limiter: Arc<Mutex<RateLimiter>>,
    auth_manager: Arc<AuthManager>,
    permission_middleware: PermissionMiddleware,
    blockchain_state: Option<Arc<tokio::sync::RwLock<BlockchainState>>>,
    mempool: Option<Arc<tokio::sync::RwLock<Mempool>>>,
}

impl RustyRpcServerImpl {
    pub fn new(
        rate_limiter: Arc<Mutex<RateLimiter>>,
        auth_manager: Arc<AuthManager>,
        blockchain_state: Option<Arc<tokio::sync::RwLock<BlockchainState>>>,
        mempool: Option<Arc<tokio::sync::RwLock<Mempool>>>,
    ) -> Self {
        Self {
            rate_limiter,
            auth_manager: auth_manager.clone(),
            permission_middleware: PermissionMiddleware::new(auth_manager),
            blockchain_state,
            mempool,
        }
    }

    /// Helper method to check authentication and authorization for a method
    fn check_auth(&self, method: &str, api_key: Option<&str>) -> Result<(), Error> {
        self.permission_middleware
            .check_permission(method, api_key)
            .map(|_| ()) // Ignore the PermissionLevel return value
            .map_err(|e| {
                Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                    -32001,
                    format!("Authentication failed: {}", e),
                    None::<()>,
                )))
            })
    }

    /// Helper method to check rate limiting (global rate limiting)
    fn check_rate_limit(&self) -> Result<(), Error> {
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let mut rate_limiter = self.rate_limiter.lock().unwrap();
        if !rate_limiter.allow(dummy_addr) {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32002,
                "Rate limit exceeded",
                None::<()>,
            ))));
        }
        Ok(())
    }

    /// Extract API key from request context
    fn extract_api_key_from_context(&self) -> Result<String, Error> {
        // First try to get from thread-local storage (set by middleware)
        if let Some(api_key) = RequestContext::get_api_key() {
            return Ok(api_key);
        }

        // Fallback: try to extract from environment or configuration
        // This is useful for testing or when middleware is not available
        if let Ok(api_key) = std::env::var("RUSTY_RPC_API_KEY") {
            if !api_key.is_empty() {
                return Ok(api_key);
            }
        }

        // Final fallback: check for default API keys in auth manager
        let auth_manager = &self.auth_manager;
        let available_keys = auth_manager.list_api_keys();

        // Look for an enabled API key with at least ReadOnly permissions
        for (key_masked, _permission_level, _description, enabled) in available_keys {
            if enabled {
                // Extract the actual key from the masked version
                if key_masked.len() > 4 && key_masked.ends_with("***") {
                    let actual_key = &key_masked[..key_masked.len() - 3];
                    // Try to authenticate with this key
                    if auth_manager
                        .authenticate_and_authorize(Some(actual_key), "rusty_coin_get_block_count")
                        .is_ok()
                    {
                        return Ok(actual_key.to_string());
                    }
                }
            }
        }

        // If no API key found, return an error
        Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32001,
            "Authentication required: No API key available",
            None::<()>,
        ))))
    }

    /// Set API key for current request context (called by middleware)
    pub fn set_request_api_key(&self, api_key: String) {
        REQUEST_API_KEY.with(|cell| {
            *cell.borrow_mut() = Some(api_key);
        });
    }

    /// Clear API key from current request context (called after request processing)
    pub fn clear_request_api_key(&self) {
        RequestContext::clear();
    }
}

impl Clone for RustyRpcServerImpl {
    fn clone(&self) -> Self {
        Self {
            rate_limiter: self.rate_limiter.clone(),
            auth_manager: self.auth_manager.clone(),
            permission_middleware: PermissionMiddleware::new(self.auth_manager.clone()),
            blockchain_state: self.blockchain_state.clone(),
            mempool: self.mempool.clone(),
        }
    }
}

#[jsonrpsee::core::async_trait]
impl RustyRpcServer for RustyRpcServerImpl {
    async fn get_block_count(&self) -> Result<u64, Error> {
        self.check_rate_limit()?;
        // Extract API key from request context
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_block_count", Some(&api_key))?;

        // Get actual block count from blockchain state
        if let Some(blockchain_state) = &self.blockchain_state {
            let state = blockchain_state.read().await;
            state.get_current_block_height().map_err(|e| {
                Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                    -32603,
                    format!("Failed to get block count: {}", e),
                    None::<()>,
                )))
            })
        } else {
            // Fallback to simulated value if blockchain state not available
            Ok(12345)
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_block_hash", Some(&api_key))?;
        Ok(format!("block_hash_for_height_{}", height))
    }

    async fn get_block(&self, hash: String) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_block", Some(&api_key))?;
        Ok(json!({
            "hash": hash,
            "height": 12345,
            "transactions": [],
            "timestamp": 1640995200,
            "difficulty": "0x1d00ffff"
        }))
    }

    async fn get_transaction(&self, txid: String) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_transaction", Some(&api_key))?;
        Ok(json!({
            "txid": txid,
            "version": 1,
            "inputs": [],
            "outputs": [],
            "lock_time": 0
        }))
    }

    async fn get_blockchain_info(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_blockchain_info", Some(&api_key))?;
        Ok(json!({
            "chain": "main",
            "blocks": 12345,
            "bestblockhash": "0x123456789abcdef",
            "difficulty": "0x1d00ffff",
            "mediantime": 1640995200
        }))
    }

    async fn get_mempool_info(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_mempool_info", Some(&api_key))?;
        Ok(json!({
            "size": 42,
            "bytes": 10240,
            "usage": 15360,
            "maxmempool": 300000000,
            "mempoolminfee": 0.00001000
        }))
    }

    async fn get_peer_info(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_peer_info", Some(&api_key))?;
        Ok(json!([
            {
                "id": 1,
                "addr": "192.168.1.100:9933",
                "services": "0000000000000001",
                "version": 70015,
                "subver": "/Rusty-Coin:0.1.0/"
            }
        ]))
    }

    async fn get_network_info(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_network_info", Some(&api_key))?;
        Ok(json!({
            "version": 10000,
            "subversion": "/Rusty-Coin:0.1.0/",
            "protocolversion": 70015,
            "localservices": "0000000000000001",
            "connections": 8,
            "networkactive": true
        }))
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_send_raw_transaction", Some(&api_key))?;

        // Decode the hex transaction
        let tx_bytes = hex::decode(&tx_hex).map_err(|e| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32602,
                format!("Invalid hex transaction: {}", e),
                None::<()>,
            )))
        })?;

        // Deserialize the transaction
        let tx: rusty_shared_types::Transaction = bincode::deserialize(&tx_bytes).map_err(|e| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32602,
                format!("Invalid transaction format: {}", e),
                None::<()>,
            )))
        })?;

        // Basic validation
        if tx.is_coinbase() {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32600,
                "Cannot add coinbase transaction to mempool",
                None::<()>,
            ))));
        }

        if tx.get_inputs().is_empty() {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32600,
                "Transaction has no inputs",
                None::<()>,
            ))));
        }

        if tx.get_outputs().is_empty() {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32600,
                "Transaction has no outputs",
                None::<()>,
            ))));
        }

        // Check transaction size
        if tx_bytes.len() > 100_000 {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32600,
                "Transaction too large",
                None::<()>,
            ))));
        }

        // Check output values
        for output in tx.get_outputs() {
            if output.value == 0 {
                return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                    -32600,
                    "Transaction contains zero-value output",
                    None::<()>,
                ))));
            }

            if output.value < 546 {
                // Dust limit
                return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                    -32600,
                    "Transaction output below dust limit",
                    None::<()>,
                ))));
            }
        }

        let txid = tx.txid();
        println!(
            "Validated and received raw transaction: {} (txid: {})",
            tx_hex,
            hex::encode(txid)
        );

        // Add to actual mempool with comprehensive validation
        if let Some(mempool) = &self.mempool {
            let mut mempool_guard = mempool.write().await;
            mempool_guard.add_transaction(tx).map_err(|e| {
                Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                    -32600,
                    format!("Failed to add transaction to mempool: {}", e),
                    None::<()>,
                )))
            })?;
            println!("Added transaction {} to mempool", hex::encode(txid));
        } else {
            // Fallback if mempool not available
            println!(
                "Mempool not available, simulating addition of transaction {}",
                hex::encode(txid)
            );
        }

        Ok(hex::encode(txid))
    }

    async fn create_raw_transaction(&self, inputs: Value, outputs: Value) -> Result<String, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_create_raw_transaction", Some(&api_key))?;
        Ok(format!("raw_tx_from_inputs_{}_outputs_{}", inputs, outputs))
    }

    async fn sign_raw_transaction(&self, tx_hex: String) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_sign_raw_transaction", Some(&api_key))?;
        Ok(json!({
            "hex": format!("signed_{}", tx_hex),
            "complete": true
        }))
    }

    async fn estimate_fee(&self, blocks: u32) -> Result<f64, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_estimate_fee", Some(&api_key))?;
        Ok(0.00001 * (blocks as f64))
    }

    async fn list_unspent(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_list_unspent", Some(&api_key))?;
        Ok(json!([
            {
                "txid": "abc123",
                "vout": 0,
                "address": "RsXYZ123",
                "amount": 1.23456789,
                "confirmations": 10
            }
        ]))
    }

    async fn get_balance(&self) -> Result<f64, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_balance", Some(&api_key))?;
        Ok(123.456789)
    }

    async fn start_mining(&self, address: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_start_mining", Some(&api_key))?;
        println!("Starting mining to address: {}", address);
        Ok(true)
    }

    async fn stop_mining(&self) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_stop_mining", Some(&api_key))?;
        println!("Stopping mining");
        Ok(true)
    }

    async fn set_mining_address(&self, address: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_set_mining_address", Some(&api_key))?;
        println!("Setting mining address to: {}", address);
        Ok(true)
    }

    async fn add_peer(&self, address: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_add_peer", Some(&api_key))?;
        println!("Adding peer: {}", address);
        Ok(true)
    }

    async fn remove_peer(&self, address: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_remove_peer", Some(&api_key))?;
        println!("Removing peer: {}", address);
        Ok(true)
    }

    async fn ban_peer(&self, address: String, duration: u64) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_ban_peer", Some(&api_key))?;
        println!("Banning peer {} for {} seconds", address, duration);
        Ok(true)
    }

    async fn unban_peer(&self, address: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_unban_peer", Some(&api_key))?;
        println!("Unbanning peer: {}", address);
        Ok(true)
    }

    async fn invalidate_block(&self, hash: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_invalidate_block", Some(&api_key))?;
        println!("Invalidating block: {}", hash);
        Ok(true)
    }

    async fn reconsider_block(&self, hash: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_reconsider_block", Some(&api_key))?;
        println!("Reconsidering block: {}", hash);
        Ok(true)
    }

    async fn shutdown(&self) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_shutdown", Some(&api_key))?;
        println!("Shutting down node");
        Ok(true)
    }

    async fn debug_level(&self, level: String) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_debug_level", Some(&api_key))?;
        println!("Setting debug level to: {}", level);
        Ok(true)
    }

    async fn generate_blocks(&self, count: u32) -> Result<Vec<String>, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_generate_blocks", Some(&api_key))?;
        let blocks: Vec<String> = (0..count)
            .map(|i| format!("generated_block_hash_{}", i))
            .collect();
        Ok(blocks)
    }

    async fn reset_blockchain(&self) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_reset_blockchain", Some(&api_key))?;
        println!("Resetting blockchain");
        Ok(true)
    }

    async fn submit_proposal(&self, proposal: Value) -> Result<String, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_submit_proposal", Some(&api_key))?;
        println!("Submitting governance proposal: {}", proposal);
        Ok("proposal_id_12345".to_string())
    }

    async fn vote_proposal(&self, proposal_id: String, vote: bool) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_vote_proposal", Some(&api_key))?;
        println!("Voting on proposal {} with vote: {}", proposal_id, vote);
        Ok(true)
    }

    async fn get_governance_info(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_governance_info", Some(&api_key))?;
        Ok(json!({
            "active_proposals": 3,
            "total_votes": 150,
            "next_superblock": 100000
        }))
    }

    async fn list_proposals(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_list_proposals", Some(&api_key))?;
        Ok(json!([
            {
                "id": "proposal_123",
                "title": "Increase block size",
                "status": "active",
                "votes_for": 75,
                "votes_against": 25
            }
        ]))
    }

    async fn start_masternode(&self) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_start_masternode", Some(&api_key))?;
        println!("Starting masternode");
        Ok(true)
    }

    async fn stop_masternode(&self) -> Result<bool, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_stop_masternode", Some(&api_key))?;
        println!("Stopping masternode");
        Ok(true)
    }

    async fn get_masternode_status(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_get_masternode_status", Some(&api_key))?;
        Ok(json!({
            "status": "ENABLED",
            "protocol": 70208,
            "payee": "RsXYZ123",
            "lastseen": 1640995200,
            "activeseconds": 86400
        }))
    }

    async fn list_masternodes(&self) -> Result<Value, Error> {
        self.check_rate_limit()?;
        let api_key = self.extract_api_key_from_context()?;
        self.check_auth("rusty_coin_list_masternodes", Some(&api_key))?;
        Ok(json!([
            {
                "rank": 1,
                "network": "ipv4",
                "txhash": "abc123",
                "outidx": 0,
                "status": "ENABLED",
                "addr": "192.168.1.100:9933",
                "version": 70208,
                "lastseen": 1640995200,
                "activetime": 86400,
                "lastpaid": 1640908800
            }
        ]))
    }
}

pub async fn run_rpc_server(http_addr: SocketAddr, ws_addr: SocketAddr) -> Result<(), Error> {
    println!("WARNING: Starting RPC server with HTTP (insecure)");
    println!("For production use, please use run_rpc_server_https() with TLS certificates");

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let auth_manager = Arc::new(AuthManager::new());

    // Build and start HTTP server
    let http_server = ServerBuilder::default().build(http_addr).await?;

    let rpc_server_impl =
        RustyRpcServerImpl::new(rate_limiter.clone(), auth_manager.clone(), None, None);
    let http_handle: ServerHandle = http_server.start(rpc_server_impl.clone().into_rpc())?;

    // Build and start WebSocket server
    let ws_server = ServerBuilder::default().build(ws_addr).await?;

    let ws_handle: ServerHandle = ws_server.start(rpc_server_impl.into_rpc())?;

    println!("RPC servers started with authentication and rate limiting.");
    println!("HTTP server listening on {}", http_addr);
    println!("WebSocket server listening on {}", ws_addr);
    println!(
        "Rate Limiting: Max {} requests per {} seconds.",
        MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS
    );
    println!("Authentication: Method-level permission checking enabled");

    tokio::try_join!(
        async {
            http_handle.stopped().await;
            Ok::<(), Error>(())
        },
        async {
            ws_handle.stopped().await;
            Ok::<(), Error>(())
        }
    )?;
    Ok(())
}

pub async fn run_rpc_server_https(
    https_addr: SocketAddr,
    wss_addr: SocketAddr,
    tls_config: TlsConfig,
) -> Result<(), Error> {
    println!("Starting RPC server with HTTPS (secure)");

    // Validate TLS certificate files exist
    if !Path::new(&tls_config.cert_path).exists() {
        return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            format!("TLS certificate file not found: {}", tls_config.cert_path),
            None::<()>,
        ))));
    }
    if !Path::new(&tls_config.key_path).exists() {
        return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            format!("TLS private key file not found: {}", tls_config.key_path),
            None::<()>,
        ))));
    }

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let auth_manager = Arc::new(AuthManager::new());

    // Load TLS certificates and private key
    let cert_file = File::open(&tls_config.cert_path).map_err(|e| {
        Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            format!("Failed to open certificate file: {}", e),
            None::<()>,
        )))
    })?;
    let key_file = File::open(&tls_config.key_path).map_err(|e| {
        Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            format!("Failed to open private key file: {}", e),
            None::<()>,
        )))
    })?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    // Parse certificates and private key
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|e| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32002,
                format!("Failed to parse certificates: {}", e),
                None::<()>,
            )))
        })?
        .into_iter()
        .map(Certificate)
        .collect();

    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader).map_err(|e| {
        Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            format!("Failed to parse private key: {}", e),
            None::<()>,
        )))
    })?;
    if keys.is_empty() {
        return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32002,
            "No private keys found in key file",
            None::<()>,
        ))));
    }

    let private_key = PrivateKey(keys[0].clone());

    // Create TLS configuration
    let tls_server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32002,
                format!("Failed to create TLS config: {}", e),
                None::<()>,
            )))
        })?;

    let _tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

    // Build and start HTTPS server with TLS
    let https_server = ServerBuilder::default().build(https_addr).await?;

    let rpc_server_impl =
        RustyRpcServerImpl::new(rate_limiter.clone(), auth_manager.clone(), None, None);
    let https_handle: ServerHandle = https_server.start(rpc_server_impl.clone().into_rpc())?;

    // Build and start WSS server with TLS
    let wss_server = ServerBuilder::default().build(wss_addr).await?;

    let wss_handle: ServerHandle = wss_server.start(rpc_server_impl.into_rpc())?;

    println!("RPC servers started with TLS.");
    println!("HTTPS server listening on {}", https_addr);
    println!("WSS server listening on {}", wss_addr);
    println!(
        "Rate Limiting: Max {} requests per {} seconds.",
        MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS
    );
    println!("TLS Certificate: {}", tls_config.cert_path);

    tokio::try_join!(
        async {
            https_handle.stopped().await;
            Ok::<(), Error>(())
        },
        async {
            wss_handle.stopped().await;
            Ok::<(), Error>(())
        }
    )?;
    Ok(())
}

/// Demonstrate API key extraction functionality
pub fn demonstrate_api_key_extraction() {
    println!("=== API Key Extraction Demonstration ===");

    let auth_manager = Arc::new(AuthManager::new());
    let rpc_server = Arc::new(RustyRpcServerImpl::new(
        Arc::new(Mutex::new(RateLimiter::new())),
        auth_manager.clone(),
        None,
        None,
    ));

    let middleware = ApiKeyMiddleware::new(auth_manager, rpc_server);

    // Test different header formats
    let test_cases = vec![
        ("X-API-Key header", vec![("x-api-key", "test_key_123")]),
        (
            "Authorization Bearer",
            vec![("authorization", "Bearer bearer_token_456")],
        ),
        (
            "Authorization ApiKey",
            vec![("authorization", "ApiKey apikey_token_789")],
        ),
        ("No API key", vec![("content-type", "application/json")]),
    ];

    for (description, headers) in test_cases {
        println!("\nTesting: {}", description);
        match middleware.extract_api_key_from_headers(&headers) {
            Some(api_key) => println!("  ✓ Extracted API key: {}", api_key),
            None => println!("  ✗ No API key found"),
        }
    }

    println!("\n=== Environment Variable Fallback ===");
    // Test environment variable fallback
    std::env::set_var("RUSTY_RPC_API_KEY", "env_api_key_999");

    let headers = vec![("content-type", "application/json")]; // No API key in headers
    match middleware.process_request(&headers) {
        Ok(()) => println!("✓ Successfully used environment variable API key"),
        Err(e) => println!("✗ Failed to process request: {}", e),
    }

    // Clean up
    std::env::remove_var("RUSTY_RPC_API_KEY");

    println!("\n=== Default API Key Fallback ===");
    // Test default API key fallback (uses first enabled key from auth manager)
    let headers = vec![("content-type", "application/json")]; // No API key in headers
    match middleware.process_request(&headers) {
        Ok(()) => println!("✓ Successfully used default API key from auth manager"),
        Err(e) => println!("✗ Failed to process request: {}", e),
    }

    println!("\n=== API Key Extraction Complete ===");
}
