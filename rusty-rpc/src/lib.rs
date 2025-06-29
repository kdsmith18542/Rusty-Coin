// rusty-rpc/src/lib.rs
//! `rusty-rpc` provides the JSON-RPC server implementation for the Rusty Coin node.

pub mod server;
pub mod rpc;
pub mod error;

use server::{run_rpc_server, run_rpc_server_https};
use std::net::SocketAddr;

// Placeholder for RPC initialization or core logic
pub async fn init_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let http_addr = "127.0.0.1:9944".parse()?;
    let ws_addr = "127.0.0.1:9945".parse()?;
    server::run_rpc_server(http_addr, ws_addr).await?;
    Ok(())
}

// Initialize RPC with HTTPS support
pub async fn init_rpc_https(
    https_addr: SocketAddr,
    wss_addr: SocketAddr,
    cert_path: String,
    key_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls_config = TlsConfig { cert_path, key_path };
    server::run_rpc_server_https(https_addr, wss_addr, tls_config).await?;
    Ok(())
}

// Re-export for convenience
pub use server::TlsConfig;