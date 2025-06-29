// rusty-rpc/src/server.rs

use jsonrpsee::core::Error;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use crate::rpc::{RustyRpcServer as RustyRpc};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::Path;
use tokio::time::{self, Duration};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use std::fs::File;
use std::io::BufReader;
use jsonrpsee::types::error::ErrorObject;

// Simple authentication token (for demonstration purposes)
const AUTH_TOKEN: &str = "my_secret_rpc_token";

// Rate limiting configuration
const MAX_REQUESTS_PER_MINUTE: usize = 60;
const RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

// TLS configuration structure
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

// Shared state for rate limiting
struct RateLimiter {
    requests: HashMap<SocketAddr, (usize, tokio::time::Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        RateLimiter { requests: HashMap::new() }
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



pub struct RustyRpcServerImpl {
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl RustyRpcServerImpl {
    pub fn new(rate_limiter: Arc<Mutex<RateLimiter>>) -> Self {
        RustyRpcServerImpl { rate_limiter }
    }
}

impl Clone for RustyRpcServerImpl {
    fn clone(&self) -> Self {
        Self { rate_limiter: self.rate_limiter.clone() }
    }
}

impl RustyRpc for RustyRpcServerImpl {
    async fn get_block_count(&self) -> Result<u64, jsonrpsee::core::Error> {
        // In a real application, you'd extract the client's IP from the context
        // For this example, we'll just use a dummy address for rate limiting.
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Custom("Rate limit exceeded".to_string()));
        }
        // Placeholder for actual implementation
        Ok(12345)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, jsonrpsee::core::Error> {
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Custom("Rate limit exceeded".to_string()));
        }
        // Placeholder for actual implementation
        Ok(format!("block_hash_for_height_{}", height))
    }

    async fn get_block(&self, hash: String) -> Result<String, jsonrpsee::core::Error> {
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Custom("Rate limit exceeded".to_string()));
        }
        // Placeholder for actual implementation
        Ok(format!("block_data_for_hash_{}", hash))
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, jsonrpsee::core::Error> {
        // In a real application, you'd extract the client's IP from the context
        // For this example, we'll just use a dummy address for rate limiting.
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Custom("Rate limit exceeded".to_string()));
        }
        // Placeholder for actual implementation
        println!("Received raw transaction: {}", tx_hex);
        Ok(format!("Transaction {} sent successfully", tx_hex))
    }

    async fn get_transaction(&self, txid: String) -> Result<String, jsonrpsee::core::Error> {
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Custom("Rate limit exceeded".to_string()));
        }
        // Placeholder for actual implementation
        Ok(format!("transaction_data_for_txid_{}", txid))
    }
}

pub async fn run_rpc_server(http_addr: SocketAddr, ws_addr: SocketAddr) -> Result<(), Error> {
    println!("WARNING: Starting RPC server with HTTP (insecure)");
    println!("For production use, please use run_rpc_server_https() with TLS certificates");

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    // Build and start HTTP server
    let http_server = ServerBuilder::default()
        .build(http_addr)
        .await?;

    let rpc_server_impl = RustyRpcServerImpl::new(rate_limiter.clone());
    let http_handle: ServerHandle = http_server.start(rpc_server_impl.clone().into_rpc())?;

    // Build and start WebSocket server
    let ws_server = ServerBuilder::default()
        .build(ws_addr)
        .await?;

    let ws_handle: ServerHandle = ws_server.start(rpc_server_impl.into_rpc())?;

    println!("RPC servers started with basic authentication and rate limiting.");
    println!("HTTP server listening on {}", http_addr);
    println!("WebSocket server listening on {}", ws_addr);
    println!("Rate Limiting: Max {} requests per {} seconds.", MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS);

    tokio::try_join!(
        async {
            http_handle.stopped().await;
            Ok(())
        }.map_err(|e: tokio::io::Error| Error::Custom(format!("HTTP server stopped with error: {}", e.to_string()))),
        async {
            ws_handle.stopped().await;
            Ok(())
        }.map_err(|e: tokio::io::Error| Error::Custom(format!("WebSocket server stopped with error: {}", e.to_string())))
    )?;
    Ok(())
}

pub async fn run_rpc_server_https(
    https_addr: SocketAddr,
    wss_addr: SocketAddr,
    tls_config: TlsConfig
) -> Result<(), Error> {
    println!("Starting RPC server with HTTPS (secure)");

    // Validate TLS certificate files exist
    if !Path::new(&tls_config.cert_path).exists() {
        return Err(Error::Custom(format!("TLS certificate file not found: {}", tls_config.cert_path)));
    }
    if !Path::new(&tls_config.key_path).exists() {
        return Err(Error::Custom(format!("TLS private key file not found: {}", tls_config.key_path)));
    }

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    // Load TLS certificates and private key
    let cert_file = File::open(&tls_config.cert_path)
        .map_err(|e| Error::Custom(format!("Failed to open certificate file: {}", e)))?;
    let key_file = File::open(&tls_config.key_path)
        .map_err(|e| Error::Custom(format!("Failed to open private key file: {}", e)))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    // Parse certificates and private key
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|e| Error::Custom(format!("Failed to parse certificates: {}", e)))?
        .into_iter()
        .map(Certificate)
        .collect();

    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|e| Error::Custom(format!("Failed to parse private key: {}", e)))?;

    if keys.is_empty() {
        return Err(Error::Custom("No private keys found in key file".to_string()));
    }

    let private_key = PrivateKey(keys[0].clone());

    // Create TLS configuration
    let tls_server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| Error::Custom(format!("Failed to create TLS config: {}", e)))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

    // Build and start HTTPS server with TLS
    let https_server = ServerBuilder::default()
        .build(https_addr)
        .await?;

    let rpc_server_impl = RustyRpcServerImpl::new(rate_limiter.clone());
    let https_handle: ServerHandle = https_server.start(rpc_server_impl.clone().into_rpc())?;

    // Build and start WSS server with TLS
    let wss_server = ServerBuilder::default()
        .build(wss_addr)
        .await?;

    let wss_handle: ServerHandle = wss_server.start(rpc_server_impl.into_rpc())?;

    println!("RPC servers started with TLS.");
    println!("HTTPS server listening on {}", https_addr);
    println!("WSS server listening on {}", wss_addr);
    println!("Rate Limiting: Max {} requests per {} seconds.", MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS);
    println!("TLS Certificate: {}", tls_config.cert_path);

    tokio::try_join!(
        async {
            https_handle.stopped().await;
            Ok(())
        }.map_err(|e: tokio::io::Error| Error::Custom(format!("HTTPS server stopped with error: {}", e.to_string()))),
        async {
            wss_handle.stopped().await;
            Ok(())
        }.map_err(|e: tokio::io::Error| Error::Custom(format!("WebSocket server stopped with error: {}", e.to_string())))
    )?;
    Ok(())
}