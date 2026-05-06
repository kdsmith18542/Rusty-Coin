use axum::{routing::get, Router};
use clap::Parser;
use confy::{load, store, ConfyError};
use rusty_core::init as init_blockchain; // Alias to avoid name collision
use rusty_jsonrpc::auth::ApiKeyManager;
use rusty_jsonrpc::rpc::RpcImpl;
use rusty_jsonrpc::server::RpcServer;
use rusty_p2p::behaviour::RustyCoinNetworkConfig as P2PNetworkConfig;
use rusty_p2p::network::P2PNetwork;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod sync_integration;

/// Rusty Coin Node
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on for incoming connections
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// List of bootstrap nodes to connect to
    #[arg(short, long, value_delimiter = ',')]
    bootstrap_nodes: Option<Vec<String>>,

    /// Node ID
    #[arg(long, default_value = "default_node")]
    node_id: String,

    /// Set logging level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Path to the log file (optional). If not provided, logs will only go to stdout.
    #[arg(long)]
    log_file: Option<String>,

    /// Network to connect to (mainnet, testnet, regtest)
    #[arg(long, default_value = "mainnet")]
    network: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeConfig {
    node_id: String,
    listen_port: u16,
    bootstrap_nodes: Vec<String>,
    max_inbound_peers: Option<usize>,
    max_outbound_peers: Option<usize>,
    network: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: "default_node".to_string(),
            listen_port: 8080,
            bootstrap_nodes: vec!["127.0.0.1:8081".to_string(), "127.0.0.1:8082".to_string()],
            max_inbound_peers: Some(125),
            max_outbound_peers: Some(8),
            network: "mainnet".to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ConfyError> {
    let args = Args::parse();

    let subscriber_builder = FmtSubscriber::builder()
        .with_max_level(args.log_level.parse::<Level>().unwrap_or(Level::INFO));

    if let Some(log_file_path) = args.log_file {
        let file = File::create(&log_file_path).expect("Failed to create log file");
        let (non_blocking_writer, _guard) = tracing_appender::non_blocking(file);
        let subscriber = subscriber_builder.with_writer(non_blocking_writer).finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
        std::mem::forget(_guard); // Keep the guard alive for the duration of the program
    } else {
        let subscriber = subscriber_builder.finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }

    let app_name = "rusty-coin";
    let config_name = "node-config";

    let path = confy::get_configuration_file_path(app_name, config_name)?;
    info!("Configuration file path: {:?}", path);

    let mut cfg: NodeConfig = match load(app_name, config_name) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {:?}. Using default.", e);
            NodeConfig::default()
        }
    };

    // Override config with CLI arguments if provided
    cfg.node_id = args.node_id;
    cfg.listen_port = args.port;
    cfg.network = args.network;
    if let Some(bootstrap_nodes) = args.bootstrap_nodes {
        cfg.bootstrap_nodes = bootstrap_nodes;
    }

    // Adjust default port based on network if not explicitly set
    if args.port == 8080 {
        // Default port
        cfg.listen_port = match cfg.network.as_str() {
            "testnet" => 18333,
            "regtest" => 18444,
            _ => 8333, // mainnet
        };
    }

    info!(
        "Starting {} network on port {}",
        cfg.network, cfg.listen_port
    );

    info!("Loaded configuration: {:#?}", cfg);

    info!("Starting node components...");

    let (shutdown_sender, _shutdown_receiver) = broadcast::channel(1);

    // Initialize P2P Network first
    let max_inbound = cfg.max_inbound_peers.unwrap_or(125);
    let max_outbound = cfg.max_outbound_peers.unwrap_or(8);
    let p2p_config = P2PNetworkConfig {
        enable_mdns: true,
        enable_kademlia: true,
        bootstrap_nodes: cfg
            .bootstrap_nodes
            .iter()
            .map(|s| {
                s.parse()
                    .unwrap_or_else(|_| format!("/ip4/127.0.0.1/tcp/8333").parse().unwrap())
            })
            .collect(),
        protocol_version: "1.0".to_string(),
        max_peers: max_inbound + max_outbound,
        max_inbound_connections: max_inbound,
        max_outbound_connections: max_outbound,
        max_message_size: 2 * 1024 * 1024, // 2MB
        max_pending_requests_per_peer: 32,
        block_sync_timeout: std::time::Duration::from_secs(30),
        tx_propagation_timeout: std::time::Duration::from_secs(10),
        tx_propagation_queue_size: 1024,
        enable_tx_relay: true,
        enable_block_relay: true,
        listen_port: cfg.listen_port,
        max_messages_per_peer_per_second: 100,
        max_bytes_per_peer_per_second: 1024 * 1024, // 1MB per second
        rate_limit_window_duration: std::time::Duration::from_secs(1),
    };
    let p2p_network = P2PNetwork::new(p2p_config)
        .await
        .expect("Failed to create P2P network");

    // Wrap P2P network in Arc<Mutex<>> for blockchain initialization
    let p2p_network_mutex = Arc::new(std::sync::Mutex::new(p2p_network));

    // Initialize Blockchain with P2P network
    let data_dir = confy::get_configuration_file_path(app_name, "blockchain-data")?;
    let blockchain_result = init_blockchain(&data_dir.parent().unwrap(), p2p_network_mutex.clone());
    let blockchain = match blockchain_result {
        Ok(bc) => Arc::new(std::sync::Mutex::new(bc)),
        Err(e) => {
            error!("Failed to initialize blockchain: {}", e);
            std::process::exit(1);
        }
    };

    // Start sync manager
    sync_integration::start_sync_manager(blockchain.clone(), p2p_network_mutex.clone()).await;

    // Create ApiKeyManager for RPC
    let api_key_manager = Arc::new(ApiKeyManager::new());

    // Create a basic wallet instance for RPC
    let wallet = Arc::new(std::sync::Mutex::new(rusty_wallet::Wallet::new().expect("Failed to create wallet")));

    // Start RPC Server
    let rpc_impl = RpcImpl::new(blockchain.clone(), wallet, api_key_manager);
    let rpc_server = RpcServer::new(rpc_impl);
    let rpc_addr = format!("127.0.0.1:{}", cfg.listen_port);
    let mut rpc_shutdown_receiver = shutdown_sender.subscribe();
    tokio::spawn(async move {
        rpc_server
            .start(&rpc_addr)
            .await
            .expect("Failed to start RPC server");
        rpc_shutdown_receiver.recv().await.ok(); // Wait for shutdown signal
        info!("RPC server shut down.");
    });

    // P2P persistent key and peer list paths (unused for now)
    let _key_path = data_dir.parent().unwrap().join("p2p_key.bin");
    let _peer_list_path = data_dir.parent().unwrap().join("peers.json");

    // Start P2P network
    let _p2p_shutdown_receiver = shutdown_sender.subscribe();
    let p2p_network_clone = p2p_network_mutex.clone();
    tokio::spawn(async move {
        let p2p_network = p2p_network_clone.lock().unwrap();
        p2p_network
            .run()
            .expect("Failed to start P2P network");
        // p2p_network.save_peer_list(&peer_list_path); // Not available in current impl
    });

    // Health-check endpoint
    let app = Router::new().route("/health", get(health_check));
    let addr = format!("0.0.0.0:{}", cfg.listen_port + 1);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind health check server");
    info!("Health check server listening on {}", addr);
    let mut health_check_shutdown_receiver = shutdown_sender.subscribe();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                health_check_shutdown_receiver.recv().await.ok();
            })
            .await
            .expect("Failed to run health check server");
    });

    // Simulate a long-running task
    let mut long_running_task_shutdown_receiver = shutdown_sender.subscribe();
    tokio::spawn(async move {
        info!("Node component 1 started.");
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(3600)) => {
                info!("Node component 1 finished normally.");
            }
            _ = long_running_task_shutdown_receiver.recv() => {
                info!("Node component 1 received shutdown signal.");
            }
        }
    });

    info!(
        "Node is running on port {}. Press Ctrl+C to shut down gracefully.",
        cfg.listen_port
    );

    signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl-c event");
    info!("Ctrl+C received, sending shutdown signal.");
    shutdown_sender
        .send(())
        .expect("Failed to send shutdown signal");

    // Store the updated configuration
    match store(app_name, config_name, &cfg) {
        Ok(_) => info!("Configuration updated and stored."),
        Err(e) => error!("Failed to store configuration: {:?}", e),
    };

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
