// rusty-rpc/src/lib.rs
//! `rusty-rpc` provides the JSON-RPC server implementation for the Rusty Coin node.

pub mod auth;
pub mod error;
pub mod middleware;
pub mod rpc;
pub mod server;

use crate::auth::AuthManager;
use crate::server::RateLimiter;
use crate::server::{RustyRpcServerImpl, TlsConfig};
use anyhow::Result;
use rusty_core::consensus::state::BlockchainState;
use rusty_core::mempool::Mempool;
use std::net::SocketAddr;
use std::sync::Arc;

/// Comprehensive RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub http_addr: SocketAddr,
    pub ws_addr: SocketAddr,
    pub enable_tls: bool,
    pub tls_config: Option<TlsConfig>,
    pub max_connections: usize,
    pub request_timeout_ms: u64,
    pub rate_limit_per_minute: usize,
    pub enable_auth: bool,
    pub cors_origins: Vec<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:9944".parse().unwrap(),
            ws_addr: "127.0.0.1:9945".parse().unwrap(),
            enable_tls: false,
            tls_config: None,
            max_connections: 100,
            request_timeout_ms: 30000,
            rate_limit_per_minute: 60,
            enable_auth: true,
            cors_origins: vec!["*".to_string()],
        }
    }
}

/// RPC server state and dependencies
pub struct RpcServerState {
    pub blockchain_state: Option<Arc<tokio::sync::RwLock<BlockchainState>>>,
    pub mempool: Option<Arc<tokio::sync::RwLock<Mempool>>>,
    pub auth_manager: Arc<AuthManager>,
    pub rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
}

impl RpcServerState {
    pub fn new(
        blockchain_state: Option<Arc<tokio::sync::RwLock<BlockchainState>>>,
        mempool: Option<Arc<tokio::sync::RwLock<Mempool>>>,
    ) -> Self {
        Self {
            blockchain_state,
            mempool,
            auth_manager: Arc::new(AuthManager::new()),
            rate_limiter: Arc::new(std::sync::Mutex::new(RateLimiter::new())),
        }
    }
}

/// Initialize RPC server with full configuration and state management
pub async fn init_rpc_with_state(config: RpcConfig, server_state: RpcServerState) -> Result<()> {
    log::info!("Initializing RPC server with configuration: {:?}", config);

    // Validate configuration
    if config.enable_tls && config.tls_config.is_none() {
        return Err(anyhow::anyhow!(
            "TLS enabled but no TLS configuration provided"
        ));
    }

    // Initialize authentication if enabled
    if config.enable_auth {
        log::info!("Authentication enabled - API keys required for RPC access");
        // Create default admin API key if none exists
        let auth_manager = &server_state.auth_manager;
        if auth_manager.list_api_keys().is_empty() {
            let admin_key = auth_manager.create_api_key(
                crate::auth::PermissionLevel::Admin,
                "Default admin key".to_string(),
            );
            log::warn!(
                "Created default admin API key: {} (Change this in production!)",
                admin_key
            );
        }
    }

    // Create RPC server implementation with blockchain state and mempool
    let _rpc_server_impl = RustyRpcServerImpl::new(
        server_state.rate_limiter,
        server_state.auth_manager,
        server_state.blockchain_state,
        server_state.mempool,
    );

    // Start appropriate server based on TLS configuration
    if config.enable_tls {
        let tls_config = config.tls_config.unwrap();
        log::info!(
            "Starting HTTPS/WSS RPC server on {}:{}",
            config.http_addr,
            config.ws_addr
        );
        server::run_rpc_server_https(config.http_addr, config.ws_addr, tls_config).await?
    } else {
        log::warn!(
            "Starting HTTP/WS RPC server (insecure) on {}:{}",
            config.http_addr,
            config.ws_addr
        );
        server::run_rpc_server(config.http_addr, config.ws_addr).await?
    }

    Ok(())
}

/// Simple RPC initialization with default configuration
pub async fn init_rpc() -> Result<()> {
    let config = RpcConfig::default();
    let server_state = RpcServerState::new(None, None);
    init_rpc_with_state(config, server_state).await
}

/// Initialize RPC with blockchain state integration
pub async fn init_rpc_with_blockchain(
    blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>,
    mempool: Arc<tokio::sync::RwLock<Mempool>>,
) -> Result<()> {
    let config = RpcConfig::default();
    let server_state = RpcServerState::new(Some(blockchain_state), Some(mempool));
    init_rpc_with_state(config, server_state).await
}

/// Initialize RPC with HTTPS support and custom configuration
pub async fn init_rpc_https(
    https_addr: SocketAddr,
    wss_addr: SocketAddr,
    cert_path: String,
    key_path: String,
) -> Result<()> {
    let tls_config = TlsConfig {
        cert_path,
        key_path,
    };
    let config = RpcConfig {
        http_addr: https_addr,
        ws_addr: wss_addr,
        enable_tls: true,
        tls_config: Some(tls_config),
        ..Default::default()
    };
    let server_state = RpcServerState::new(None, None);
    init_rpc_with_state(config, server_state).await
}

/// Initialize RPC with custom addresses (HTTP only)
pub async fn init_rpc_custom_addr(http_addr: SocketAddr, ws_addr: SocketAddr) -> Result<()> {
    let config = RpcConfig {
        http_addr,
        ws_addr,
        ..Default::default()
    };
    let server_state = RpcServerState::new(None, None);
    init_rpc_with_state(config, server_state).await
}

/// Initialize RPC server with full blockchain integration and TLS
pub async fn init_rpc_full(
    config: RpcConfig,
    blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>,
    mempool: Arc<tokio::sync::RwLock<Mempool>>,
) -> Result<()> {
    let server_state = RpcServerState::new(Some(blockchain_state), Some(mempool));
    init_rpc_with_state(config, server_state).await
}
