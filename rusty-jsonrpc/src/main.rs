use log::info;
use rusty_core::consensus::blockchain::Blockchain;
use rusty_jsonrpc::auth::ApiKeyManager;
use rusty_jsonrpc::rpc::RpcImpl;
use rusty_jsonrpc::server::RpcServer;
use rusty_p2p::{P2PNetwork, RustyCoinNetworkConfig};
use rusty_wallet::Wallet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting Rusty Coin JSON-RPC server...");

    // Initialize P2P network
    let p2p_config = RustyCoinNetworkConfig {
        enable_mdns: true,
        enable_kademlia: true,
        bootstrap_nodes: vec![],
        protocol_version: "1.0".to_string(),
        max_peers: 50,
        max_inbound_connections: 25,
        max_outbound_connections: 25,
        max_message_size: 2 * 1024 * 1024, // 2MB
        max_pending_requests_per_peer: 32,
        block_sync_timeout: Duration::from_secs(30),
        tx_propagation_timeout: Duration::from_secs(10),
        tx_propagation_queue_size: 1024,
        enable_tx_relay: true,
        enable_block_relay: true,
        listen_port: 30334, // Different port from p2p binary
        max_messages_per_peer_per_second: 100,
        max_bytes_per_peer_per_second: 1024 * 1024, // 1MB per second
        rate_limit_window_duration: Duration::from_secs(1),
    };
    let p2p_network = Arc::new(Mutex::new(
        P2PNetwork::new(p2p_config).await.map_err(|e| format!("Failed to create P2P network: {}", e))?,
    ));

    // Initialize blockchain
    let blockchain = Arc::new(Mutex::new(
        Blockchain::new(p2p_network.clone()).map_err(|e| format!("Failed to create blockchain: {}", e))?,
    ));

    // Initialize wallet
    let wallet = Arc::new(Mutex::new(
        Wallet::new().map_err(|e| format!("Failed to create wallet: {}", e))?,
    ));
    info!("Initialized HD wallet for JSON-RPC operations");

    // Initialize API key manager
    let api_key_manager = Arc::new(ApiKeyManager::new());
    info!("Initialized API key manager with default development keys");
    info!("Available API keys:");
    info!("  - readonly_key_123 (Read-only access)");
    info!("  - standard_key_456 (Standard access)");
    info!("  - admin_key_789 (Admin access)");
    info!("  - superadmin_key_000 (Super admin access)");

    // Start P2P network
    let p2p_network_clone = p2p_network.clone();
    tokio::spawn(async move {
        let network = p2p_network_clone.lock().unwrap();
        network.run().expect("Failed to start P2P network");
    });

    let rpc_impl = RpcImpl::new(blockchain, wallet, api_key_manager);
    let server = RpcServer::new(rpc_impl);

    info!("Starting JSON-RPC server on 127.0.0.1:8080");
    info!("Use API key via 'Authorization: Bearer <key>' or 'X-API-Key: <key>' header");
    server.start("127.0.0.1:8080").await?;

    Ok(())
}
