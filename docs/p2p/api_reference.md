# Rusty Coin P2P API Reference

This document provides a comprehensive API reference for the Rusty Coin P2P networking layer.

## Core API Components

### P2PNetwork

The main P2P network interface for managing connections and protocols.

```rust
pub struct P2PNetwork {
    pub swarm: libp2p::Swarm<RustyCoinBehaviour>,
    pub peer_id: PeerId,
    pub event_receiver: tokio::sync::mpsc::Receiver<RustyCoinEvent>,
    // ... private fields
}
```

#### Constructor Methods

##### `new() -> Result<Self, Box<dyn std::error::Error>>`
Creates a new P2P network instance with default configuration.

**Returns**: `Result<P2PNetwork, Error>`

**Example**:
```rust
let network = P2PNetwork::new().await?;
```

##### `new_with_bootstrap(bootstrap_nodes: Vec<String>) -> Result<Self, Box<dyn std::error::Error>>`
Creates a new P2P network instance with specified bootstrap nodes.

**Parameters**:
- `bootstrap_nodes`: List of bootstrap node addresses

**Returns**: `Result<P2PNetwork, Error>`

**Example**:
```rust
let bootstrap_nodes = vec![
    "/ip4/127.0.0.1/tcp/8000".to_string(),
    "/ip4/192.168.1.100/tcp/8000".to_string(),
];
let network = P2PNetwork::new_with_bootstrap(bootstrap_nodes).await?;
```

##### `new_with_bootstrap_and_key(bootstrap_nodes: Vec<String>, key_path: &str) -> Result<Self, Box<dyn std::error::Error>>`
Creates a new P2P network instance with bootstrap nodes and persistent key.

**Parameters**:
- `bootstrap_nodes`: List of bootstrap node addresses
- `key_path`: Path to store/load the node's private key

**Returns**: `Result<P2PNetwork, Error>`

**Example**:
```rust
let network = P2PNetwork::new_with_bootstrap_and_key(
    bootstrap_nodes,
    "./node_key.pem"
).await?;
```

#### Core Methods

##### `next_event() -> Option<RustyCoinEvent>`
Receives the next network event.

**Returns**: `Option<RustyCoinEvent>`

**Example**:
```rust
while let Some(event) = network.next_event().await {
    match event {
        RustyCoinEvent::PeerConnected(peer_id) => {
            println!("Peer connected: {:?}", peer_id);
        }
        RustyCoinEvent::MessageReceived(peer_id, message) => {
            println!("Message from {:?}: {:?}", peer_id, message);
        }
        // ... handle other events
    }
}
```

##### `send_message(peer_id: PeerId, message: P2PMessage) -> Result<(), NetworkError>`
Sends a message to a specific peer.

**Parameters**:
- `peer_id`: Target peer identifier
- `message`: Message to send

**Returns**: `Result<(), NetworkError>`

**Example**:
```rust
let message = P2PMessage::BlockRequest(BlockRequest {
    start_height: 100,
    end_height: 200,
});
network.send_message(peer_id, message).await?;
```

##### `broadcast_message(message: P2PMessage) -> Result<(), NetworkError>`
Broadcasts a message to all connected peers.

**Parameters**:
- `message`: Message to broadcast

**Returns**: `Result<(), NetworkError>`

**Example**:
```rust
let inv_message = P2PMessage::Inv(Inv {
    txid: transaction_hash,
});
network.broadcast_message(inv_message).await?;
```

##### `get_connected_peers() -> Vec<PeerId>`
Returns a list of currently connected peers.

**Returns**: `Vec<PeerId>`

**Example**:
```rust
let peers = network.get_connected_peers();
println!("Connected to {} peers", peers.len());
```

##### `get_peer_info(peer_id: PeerId) -> Option<PeerInfo>`
Gets information about a specific peer.

**Parameters**:
- `peer_id`: Peer identifier

**Returns**: `Option<PeerInfo>`

**Example**:
```rust
if let Some(info) = network.get_peer_info(peer_id) {
    println!("Peer info: {:?}", info);
}
```

## Message Types

### P2PMessage Enum

The main message type for P2P communication.

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum P2PMessage {
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    GetHeaders(GetHeaders),
    Headers(Headers),
    Inv(Inv),
    TxData(TxData),
    CompactBlock(CompactBlock),
    GetBlockTxs(GetBlockTxs),
    BlockTxs(BlockTxs),
    MasternodeListRequest(MasternodeListRequest),
    MasternodeListResponse(MasternodeListResponse),
    MasternodeUpdate(MasternodeUpdate),
    MasternodeListSync(MasternodeListSync),
    PoSeResponse(PoSeResponse),
    Chunk(Chunk),
}
```

### Block Synchronization Messages

#### BlockRequest
Request a range of blocks from a peer.

```rust
pub struct BlockRequest {
    pub start_height: u32,
    pub end_height: u32,
}
```

**Usage**:
```rust
let request = BlockRequest {
    start_height: 1000,
    end_height: 1500,
};
```

#### BlockResponse
Response containing requested blocks.

```rust
pub struct BlockResponse {
    pub blocks: Vec<Block>,
}
```

#### GetHeaders
Request block headers using locator hashes.

```rust
pub struct GetHeaders {
    pub locator_hashes: Vec<[u8; 32]>,
    pub stop_hash: [u8; 32],
}
```

**Usage**:
```rust
let get_headers = GetHeaders {
    locator_hashes: vec![latest_block_hash, previous_block_hash],
    stop_hash: [0u8; 32], // Request all headers
};
```

#### Headers
Response containing block headers.

```rust
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}
```

### Transaction Propagation Messages

#### Inv
Announce a transaction ID to peers.

```rust
pub struct Inv {
    pub txid: [u8; 32],
}
```

**Usage**:
```rust
let inv = Inv {
    txid: transaction.hash(),
};
```

#### TxData
Send full transaction data.

```rust
pub struct TxData {
    pub transaction: Transaction,
}
```

### Compact Block Messages

#### CompactBlock
Bandwidth-efficient block representation.

```rust
pub struct CompactBlock {
    pub header: BlockHeader,
    pub short_txids: Vec<[u8; 6]>,
    pub prefilled_txn: Vec<(u32, Transaction)>,
}
```

#### GetBlockTxs
Request missing transactions from a compact block.

```rust
pub struct GetBlockTxs {
    pub block_hash: [u8; 32],
    pub indexes: Vec<u32>,
}
```

#### BlockTxs
Provide missing transactions.

```rust
pub struct BlockTxs {
    pub block_hash: [u8; 32],
    pub transactions: Vec<Transaction>,
}
```

### Masternode Messages

#### MasternodeListRequest
Request masternode list information.

```rust
pub struct MasternodeListRequest {
    pub version: u32,
    pub last_known_hash: Option<[u8; 32]>,
    pub request_full_list: bool,
}
```

#### MasternodeListResponse
Provide masternode list information.

```rust
pub struct MasternodeListResponse {
    pub version: u32,
    pub list_hash: [u8; 32],
    pub block_height: u64,
    pub masternodes: Vec<MasternodeEntry>,
    pub is_full_list: bool,
}
```

#### MasternodeUpdate
Announce masternode status changes.

```rust
pub struct MasternodeUpdate {
    pub masternode_id: MasternodeID,
    pub update_type: MasternodeUpdateType,
    pub entry: Option<MasternodeEntry>,
    pub block_height: u64,
    pub signature: Vec<u8>,
}
```

## Event Types

### RustyCoinEvent

Network events that can be received from the P2P layer.

```rust
#[derive(Debug, Clone)]
pub enum RustyCoinEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    MessageReceived(PeerId, P2PMessage),
    BlockReceived(Block),
    TransactionReceived(Transaction),
    MasternodeListUpdated(Vec<MasternodeEntry>),
    NetworkError(NetworkError),
}
```

## Configuration

### P2PNetworkConfig

Configuration options for the P2P network.

```rust
pub struct P2PNetworkConfig {
    pub max_peers: usize,
    pub max_chunk_size: usize,
    pub max_message_size: usize,
    pub connection_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub max_blocks_per_response: usize,
    pub rate_limit_messages_per_sec: u32,
    pub rate_limit_bytes_per_sec: u64,
}
```

**Default Values**:
```rust
impl Default for P2PNetworkConfig {
    fn default() -> Self {
        Self {
            max_peers: 8,
            max_chunk_size: 1_000_000,      // 1MB
            max_message_size: 10_000_000,   // 10MB
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(60),
            max_blocks_per_response: 500,
            rate_limit_messages_per_sec: 100,
            rate_limit_bytes_per_sec: 1_000_000, // 1MB/s
        }
    }
}
```

## Error Types

### NetworkError

Comprehensive error types for P2P operations.

```rust
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Peer not found: {0:?}")]
    PeerNotFound(PeerId),
    
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Rate limit exceeded for peer: {0:?}")]
    RateLimitExceeded(PeerId),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    
    #[error("Transport error: {0}")]
    TransportError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}
```

## Usage Examples

### Basic Network Setup

```rust
use rusty_p2p::{P2PNetwork, P2PMessage, RustyCoinEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create network with bootstrap nodes
    let bootstrap_nodes = vec![
        "/ip4/127.0.0.1/tcp/8000".to_string(),
    ];
    
    let mut network = P2PNetwork::new_with_bootstrap(bootstrap_nodes).await?;
    
    // Start listening for events
    tokio::spawn(async move {
        while let Some(event) = network.next_event().await {
            handle_network_event(event).await;
        }
    });
    
    Ok(())
}

async fn handle_network_event(event: RustyCoinEvent) {
    match event {
        RustyCoinEvent::PeerConnected(peer_id) => {
            println!("New peer connected: {:?}", peer_id);
        }
        RustyCoinEvent::MessageReceived(peer_id, message) => {
            println!("Message from {:?}: {:?}", peer_id, message);
        }
        RustyCoinEvent::BlockReceived(block) => {
            println!("New block received: height {}", block.header.height);
        }
        _ => {}
    }
}
```

### Block Synchronization

```rust
async fn sync_blocks(
    network: &mut P2PNetwork,
    peer_id: PeerId,
    start_height: u32,
    end_height: u32,
) -> Result<(), NetworkError> {
    // Request block headers first
    let get_headers = P2PMessage::GetHeaders(GetHeaders {
        locator_hashes: vec![],
        stop_hash: [0u8; 32],
    });
    
    network.send_message(peer_id, get_headers).await?;
    
    // Then request blocks
    let block_request = P2PMessage::BlockRequest(BlockRequest {
        start_height,
        end_height,
    });
    
    network.send_message(peer_id, block_request).await?;
    
    Ok(())
}
```

### Transaction Broadcasting

```rust
async fn broadcast_transaction(
    network: &mut P2PNetwork,
    transaction: Transaction,
) -> Result<(), NetworkError> {
    // First announce the transaction
    let inv = P2PMessage::Inv(Inv {
        txid: transaction.hash(),
    });
    
    network.broadcast_message(inv).await?;
    
    // Then send full transaction data when requested
    let tx_data = P2PMessage::TxData(TxData {
        transaction,
    });
    
    // This would typically be sent in response to GetData requests
    // network.send_message(requesting_peer, tx_data).await?;
    
    Ok(())
}
```

This API reference provides comprehensive documentation for integrating with the Rusty Coin P2P networking layer, enabling developers to build applications that interact with the blockchain network efficiently and securely.
