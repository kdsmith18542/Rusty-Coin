use env_logger::{Builder, Target};
use log::LevelFilter;
use rusty_p2p::{P2PNetwork, RustyCoinNetworkConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Builder::new()
        .filter_level(LevelFilter::Info)
        .target(Target::Stdout)
        .init();

    // Construct a minimal RustyCoinNetworkConfig
    let config = RustyCoinNetworkConfig {
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
        listen_port: 30333,
        max_messages_per_peer_per_second: 100,
        max_bytes_per_peer_per_second: 1024 * 1024, // 1MB per second
        rate_limit_window_duration: Duration::from_secs(1),
    };

    let network = P2PNetwork::new(config).await?;
    network.run()?;

    Ok(())
}
