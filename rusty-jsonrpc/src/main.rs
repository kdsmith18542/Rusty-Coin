use rusty_jsonrpc::{RpcImpl, RpcServer};
use log::info;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::fs;
use rusty_core::Blockchain;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting Rusty Coin JSON-RPC server...");

    // Initialize rusty-core with a data directory
    let data_dir = PathBuf::from("./data");
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create data directory: {}", e))?;
    }
    let blockchain = rusty_core::init(&data_dir).map_err(|e| format!("Failed to initialize rusty-core: {}", e))?;

    let rpc_impl = RpcImpl::new(blockchain);
    let server = RpcServer::new(rpc_impl);
    server.start("127.0.0.1:8080").await?;

    Ok(())
}