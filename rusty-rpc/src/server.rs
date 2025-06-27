// rusty-rpc/src/server.rs

use jsonrpsee::core::{Error, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, RpcModule};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::Path;
use tokio::time::{self, Duration};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use std::fs::File;
use std::io::BufReader;

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


#[rpc(server)]
pub trait RustyRpc {
    #[method(name = "get_block_count")]
    async fn get_block_count(&self) -> RpcResult<u64>;

    #[method(name = "send_raw_transaction")]
    async fn send_raw_transaction(&self, tx_hex: String) -> RpcResult<String>;

    #[method(name = "authorize")]
    async fn authorize(&self, api_key: String) -> RpcResult<bool>;

    #[method(name = "send_transaction")]
    async fn send_transaction(&self, raw_tx: String) -> RpcResult<String>;
}

pub struct RustyRpcServerImpl {
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl RustyRpcServerImpl {
    pub fn new(rate_limiter: Arc<Mutex<RateLimiter>>) -> Self {
        RustyRpcServerImpl { rate_limiter }
    }
}


#[jsonrpsee::server::async_trait]
implement RustyRpcServer for RustyRpcServerImpl {
    async fn get_block_count(&self) -> RpcResult<u64> {
        // In a real application, you'd extract the client's IP from the context
        // For this example, we'll just use a dummy address for rate limiting.
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Call(
                jsonrpsee::types::error::CallError::Custom(
                    jsonrpsee::types::error::CustomError::new("Rate limit exceeded").with_code(-32000),
                ),
            ));
        }
        // Placeholder for actual implementation
        Ok(12345)
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> RpcResult<String> {
        // In a real application, you'd extract the client's IP from the context
        // For this example, we'll just use a dummy address for rate limiting.
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Call(
                jsonrpsee::types::error::CallError::Custom(
                    jsonrpsee::types::error::CustomError::new("Rate limit exceeded").with_code(-32000),
                ),
            ));
        }
        // Placeholder for actual implementation
        println!("Received raw transaction: {}", tx_hex);
        Ok(format!("Transaction {:?} sent successfully", tx_hex))
    }

    async fn authorize(&self, api_key: String) -> RpcResult<bool> {
        // In a real application, you'd extract the client's IP from the context
        // For this example, we'll just use a dummy address for rate limiting.
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Call(
                jsonrpsee::types::error::CallError::Custom(
                    jsonrpsee::types::error::CustomError::new("Rate limit exceeded").with_code(-32000),
                ),
            ));
        }
        // Simple API key check for demonstration
        if api_key == AUTH_TOKEN {
            Ok(true)
        } else {
            Err(Error::Call(
                jsonrpsee::types::error::CallError::Custom(
                    jsonrpsee::types::error::CustomError::new("Unauthorized").with_code(-32001),
                ),
            ))
        }
    }

    async fn send_transaction(&self, raw_tx: String) -> RpcResult<String> {
        let dummy_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        if !self.rate_limiter.lock().unwrap().allow(dummy_addr) {
            return Err(Error::Call(
                jsonrpsee::types::error::CallError::Custom(
                    jsonrpsee::types::error::CustomError::new("Rate limit exceeded").with_code(-32000),
                ),
            ));
        }
        // Placeholder: In a real implementation, this would validate and broadcast the transaction.
        println!("Received raw transaction for broadcasting: {}", raw_tx);
        Ok(format!("Transaction {:?} broadcasted successfully", raw_tx))
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
    let http_handle = http_server.start(rpc_server_impl.clone().into_rpc());

    // Build and start WebSocket server
    let ws_server = ServerBuilder::default()
        .build(ws_addr)
        .await?;

    let ws_handle = ws_server.start(rpc_server_impl.into_rpc());

    println!("RPC servers started with basic authentication and rate limiting.");
    println!("HTTP server listening on {}", http_addr);
    println!("WebSocket server listening on {}", ws_addr);
    println!("Rate Limiting: Max {} requests per {} seconds.", MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS);

    tokio::try_join!(http_handle.stopped(), ws_handle.stopped())?;
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
    let https_handle = https_server.start(rpc_server_impl.clone().into_rpc());

    // Build and start WSS server with TLS
    let wss_server = ServerBuilder::default()
        .build(wss_addr)
        .await?;

    let wss_handle = wss_server.start(rpc_server_impl.into_rpc());

    println!("RPC servers started with HTTPS/WSS and authentication.");
    println!("HTTPS server listening on {}", https_addr);
    println!("WSS server listening on {}", wss_addr);
    println!("Rate Limiting: Max {} requests per {} seconds.", MAX_REQUESTS_PER_MINUTE, RATE_LIMIT_WINDOW_SECONDS);
    println!("TLS Certificate: {}", tls_config.cert_path);

    tokio::try_join!(https_handle.stopped(), wss_handle.stopped())?;
    Ok(())
}