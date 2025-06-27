# Rusty-Coin P2P Network

A high-performance, modular P2P networking library for the Rusty-Coin cryptocurrency, built on top of libp2p.

## Features

- **Peer Discovery**: Combines Kademlia DHT and mDNS for efficient peer discovery
- **Block Synchronization**: Request/Response protocol for block and header synchronization
- **Transaction Propagation**: Efficient gossip-based transaction propagation
- **Peer Scoring**: Sybil-resistant peer scoring and reputation system
- **DoS Protection**: Rate limiting and peer banning mechanisms
- **Modular Design**: Easy to extend with new protocols and behaviors

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rusty-p2p = { path = "./rusty-p2p" }
```

### Starting a P2P Node

```rust
use rusty_p2p::{P2PNetwork, RustyCoinNetworkConfig};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    env_logger::init();
    
    // Create a default configuration
    let config = RustyCoinNetworkConfig::default();
    
    // Create and start the P2P network
    let network = P2PNetwork::new(config).await?;
    
    // Run the network event loop
    network.run().await?;
    
    Ok(())
}
```

### Custom Configuration

```rust
use rusty_p2p::RustyCoinNetworkConfig;
use std::time::Duration;

let config = RustyCoinNetworkConfig {
    enable_mdns: true,
    enable_kademlia: true,
    max_peers: 50,
    max_message_size: 10 * 1024 * 1024, // 10MB
    block_sync_timeout: Duration::from_secs(30),
    tx_propagation_timeout: Duration::from_secs(10),
    ..Default::default()
};
```

## Protocols

### Block Synchronization

Request blocks or headers from peers:

```rust
// Request blocks starting from height 1000
let request_id = network.request_blocks(peer_id, 1000, 10).await?;

// Request block headers starting from a specific hash
let start_hash = [0u8; 32]; // Replace with actual hash
let request_id = network.request_headers(peer_id, start_hash, 10).await?;
```

### Transaction Propagation

Broadcast transactions to the network:

```rust
let tx_data = vec![/* serialized transaction */];
network.broadcast_transaction(tx_data).await?;
```

## Peer Management

Manage peer connections and reputation:

```rust
// Get list of connected peers
let peers = network.connected_peers();

// Get a peer's reputation score
let score = network.peer_score(&peer_id);

// Ban a misbehaving peer
network.ban_peer(peer_id, Duration::from_secs(3600), "Bad behavior".to_string());

// Unban a peer
network.unban_peer(&peer_id);
```

## Running the Example

```bash
# Start a node
cargo run --example p2p_node

# Start additional nodes to form a network
RUST_LOG=info cargo run --example p2p_node
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
