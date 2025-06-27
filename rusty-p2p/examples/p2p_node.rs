//! Example of a simple Rusty-Coin P2P node

use rusty_p2p::{P2PNetwork, RustyCoinNetworkConfig};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    env_logger::init();
    
    // Create a default configuration
    let config = RustyCoinNetworkConfig::default();
    
    // Create and start the P2P network
    let mut network = P2PNetwork::new(config).await?;
    
    // Get the local peer ID and listen addresses
    let peer_id = network.local_peer_id();
    let listen_addrs = network.swarm.listeners()?;
    
    println!("Starting P2P node with ID: {}", peer_id);
    for addr in listen_addrs {
        println!("Listening on {}/p2p/{}", addr, peer_id);
    }
    
    // Run the network event loop
    if let Err(e) = network.run().await {
        log::error!("Network error: {}", e);
        return Err(e);
    }
    
    Ok(())
}
