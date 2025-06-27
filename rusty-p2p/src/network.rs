// Standard library
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

// External crates
use async_std::io;
use async_std::task;
use async_trait::async_trait;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::future::BoxFuture;
use log::{debug, error, info, trace, warn};
use rand;
use rusty_consensus::error::ConsensusError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, timeout};
use libp2p::{
    core::{
        connection::ConnectionId as Libp2pConnectionId,
        muxing::StreamMuxerBox,
        transport::Boxed,
        upgrade,
    },
    gossipsub::{
        Config as GossipsubConfig, Gossipsub, GossipsubEvent, IdentTopic as GossipsubTopic, Message,
        MessageAuthenticity, MessageId, Topic, ValidationMode,
    },
    identity,
    kad::{
        store::MemoryStore, Config as KademliaConfig, GetClosestPeersResult, Kademlia, KademliaEvent,
        Mode, Record,
    },
    mdns::{tokio::Behaviour as TokioMdns, Config as MdnsConfig, Mdns, MdnsEvent},
    noise::{self, NoiseConfig, X25519Spec, Authenticated, Keypair, Keypair as NoiseKeypair},
    request_response::{
        Config as RequestResponseConfig, Protocol as RpcProtocol, ProtocolName, ProtocolSupport,
        RequestId, RequestResponse, RequestResponseCodec, RequestResponseEvent,
        RequestResponseMessage, ResponseChannel, ResponseChannel as RpcResponseChannel,
    },
    swarm::{
        ConnectionHandler, ConnectionHandlerUpgrErr, NetworkBehaviour, NetworkBehaviourAction,
        NetworkBehaviourEventProcess, NotifyHandler, PollParameters, StreamProtocol, SubstreamProtocol,
        SwarmEvent, ToSwarm,
    },
    tcp::Config as TcpConfig,
    yamux::YamuxConfig,
    Multiaddr, PeerId, Swarm, SwarmBuilder, Transport,
};

// Crate modules
use crate::{
    protocols::{
        block_sync::{BlockData, BlockHeaderData, BlockSyncCodec, BlockSyncRequest, BlockSyncResponse},
        peer_discovery::{DiscoveryConfig, DiscoveryEvent, PeerDiscovery},
        tx_prop::{TxPropHandler, TxPropMessage, TX_PROPAGATION_TOPIC},
    },
    types::{BlockRequest, BlockResponse, GetHeaders, Headers, Inv, P2PMessage, TxData},
};

// Constants
const MAX_CHUNK_SIZE: usize = 1_000_000; // 1MB per spec
const MAX_PEER_CONNECTIONS: usize = 8; // Max 8 peer connections

/// Custom error type for P2P network operations
#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Network error: {0}")]
    NetworkError(#[from] Box<dyn std::error::Error + Send + Sync>),
    
    #[error("Peer error: {0}")]
    PeerError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    
    #[error("Consensus error: {0}")]
    ConsensusError(#[from] ConsensusError),
}

/// Type alias for P2P operation results
pub type P2PResult<T> = std::result::Result<T, P2PError>;

/// Configuration for the RustyCoin network
#[derive(Clone, Debug)]
pub struct RustyCoinNetworkConfig {
    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,
    
    /// Enable Kademlia DHT for peer and content routing
    pub enable_kademlia: bool,
    
    /// List of bootstrap nodes to connect to
    pub bootstrap_nodes: Vec<Multiaddr>,
    
    /// Protocol version string for network protocol compatibility
    pub protocol_version: String,
    
    /// Maximum number of peers to maintain connections with
    pub max_peers: usize,
    
    /// Maximum number of inbound connections to accept
    pub max_inbound_connections: usize,
    
    /// Maximum number of outbound connections to maintain
    pub max_outbound_connections: usize,
    
    /// Maximum message size in bytes
    pub max_message_size: usize,
    
    /// Maximum number of pending block requests per peer
    pub max_pending_requests_per_peer: usize,
    
    /// Timeout for block sync requests
    pub block_sync_timeout: Duration,
    
    /// Timeout for transaction propagation
    pub tx_propagation_timeout: Duration,
    
    /// Maximum number of transactions to queue for propagation
    pub tx_propagation_queue_size: usize,
    
    /// Enable/disable transaction relay
    pub enable_tx_relay: bool,
    
    /// Enable/disable block relay
    pub enable_block_relay: bool,
    
    /// Maximum number of blocks to request in a single batch
    pub max_blocks_per_request: u32,
    
    /// Maximum number of block headers to request in a single batch
    pub max_headers_per_request: u32,
    
    /// Maximum number of transaction announcements to process per peer per second
    pub max_tx_announcements_per_second: u32,
    
    /// Maximum number of block announcements to process per peer per second
    pub max_block_announcements_per_second: u32,
}

impl Default for RustyCoinNetworkConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_kademlia: true,
            bootstrap_nodes: Vec::new(),
            protocol_version: "rusty/1.0.0".to_string(),
            max_peers: 50,
            max_inbound_connections: 100,
            max_outbound_connections: 10,
            max_message_size: 10 * 1024 * 1024, // 10MB
            max_pending_requests_per_peer: 10,
            block_sync_timeout: Duration::from_secs(30),
            tx_propagation_timeout: Duration::from_secs(10),
            tx_propagation_queue_size: 1000,
            enable_tx_relay: true,
            enable_block_relay: true,
            max_blocks_per_request: 128,
            max_headers_per_request: 2000,
            max_tx_announcements_per_second: 1000,
            max_block_announcements_per_second: 10,
        }
    }
}

/// Custom network behaviour that combines all the network behaviours we use.
pub struct RustyCoinBehaviour {
    /// Floodsub protocol for simple pub/sub messaging (legacy, may be deprecated)
    pub floodsub: Floodsub,
    
    /// mDNS for local peer discovery
    pub mdns: Mdns,
    
    /// Kademlia DHT for peer and content routing
    pub kademlia: Kademlia<MemoryStore>,
    
    /// Gossipsub for efficient pub/sub messaging
    pub gossipsub: Gossipsub,
    
    /// Request/Response protocol for direct communication
    
    /// Banned peers and their unban time
    banned_peers: HashMap<PeerId, Instant>,
    
    /// Peer scores for Sybil resistance and quality of service
    peer_scores: HashMap<PeerId, f64>,
    
    /// Rate limiter for inbound messages
    rate_limiter: PeerRateLimiter,
    
    /// Reassembly buffer for fragmented messages
    reassembler: MessageReassembler,
    
    /// Metrics for message fragmentation
    frag_metrics: FragmentationMetrics,
    
    /// Active block sync requests
    active_block_requests: HashMap<RequestId, (PeerId, Instant)>,
    
    /// Pending transactions waiting to be propagated
    pending_transactions: VecDeque<Vec<u8>>,
    
    /// Track when we last sent a message to each peer
    last_message_time: HashMap<PeerId, Instant>,
    
    /// Track message rates per peer for DoS protection
    message_rates: HashMap<PeerId, (u32, Instant)>,
    
    /// Connected peers and their metadata
    connected_peers: HashMap<PeerId, PeerMetadata>,
}

/// Metadata about a connected peer
#[derive(Debug, Clone)]
pub struct PeerMetadata {
    /// When the peer connected
    pub connected_since: Instant,
    /// Peer's protocol version
    pub protocol_version: String,
    /// Peer's user agent
    pub user_agent: String,
    /// Whether the peer supports bloom filters
    pub supports_bloom: bool,
    /// Whether the peer supports segwit
    pub supports_segwit: bool,
}

impl RustyCoinBehaviour {
    /// Validates a P2P message and checks if it should be processed
    pub fn validate_p2p_message(&mut self, peer_id: &PeerId, message: &P2PMessage) -> Result<(), ConsensusError> {
        // Check if peer is banned
        if let Some(ban_until) = self.banned_peers.get(peer_id) {
            if *ban_until > Instant::now() {
                return Err(ConsensusError::PeerBanned);
            } else {
                self.banned_peers.remove(peer_id);
            }
        }
        
        // Check message rate limiting
        let now = Instant::now();
        let (count, last_reset) = self.message_rates.entry(*peer_id).or_insert((0, now));
        
        // Reset counter if it's been more than 1 second
        if now.duration_since(*last_reset) > Duration::from_secs(1) {
            *count = 0;
            *last_reset = now;
        }
        
        // Increment message count and check rate limit (e.g., 1000 messages/sec)
        *count += 1;
        if *count > 1000 {
            return Err(ConsensusError::RateLimitExceeded);
        }
        
        // Validate message type specific rules
        match message {
            P2PMessage::BlockRequest(req) => {
                // Validate block request range
                if req.end_height <= req.start_height {
                    return Err(ConsensusError::InvalidBlockRange);
                }
                if req.end_height - req.start_height > 2000 {
                    return Err(ConsensusError::BlockRangeTooLarge);
                }
                info!("Valid BlockRequest from {}: {} to {}", peer_id, req.start_height, req.end_height);
            },
            P2PMessage::BlockResponse(res) => {
                // Validate block count is reasonable
                if res.blocks.is_empty() {
                    return Err(ConsensusError::EmptyBlockResponse);
                }
                if res.blocks.len() > 2000 {
                    return Err(ConsensusError::TooManyBlocks);
                }
                info!("Valid BlockResponse from {}: {} blocks", peer_id, res.blocks.len());
            },
            P2PMessage::GetHeaders(req) => {
                // Validate locator hashes
                if req.locator_hashes.is_empty() {
                    return Err(ConsensusError::NoLocatorHashes);
                }
                if req.locator_hashes.len() > 101 {
                    return Err(ConsensusError::TooManyLocatorHashes);
                }
                info!("Valid GetHeaders from {}: {} locators", peer_id, req.locator_hashes.len());
            },
            P2PMessage::Headers(res) => {
                // Validate headers count is reasonable
                if res.headers.is_empty() {
                    return Err(ConsensusError::EmptyHeaders);
                }
                if res.headers.len() > 2000 {
                    return Err(ConsensusError::TooManyHeaders);
                }
                info!("Valid Headers from {}: {} headers", peer_id, res.headers.len());
            },
            P2PMessage::Inv(inv) => {
                // Validate transaction ID format (32 bytes for SHA-256)
                if inv.txid.len() != 32 {
                    return Err(ConsensusError::InvalidTxId);
                }
                trace!("Valid Inv from {}: {:?}", peer_id, inv.txid);
            },
            P2PMessage::TxData(tx_data) => {
                // Basic transaction validation
                if tx_data.transaction.inputs.is_empty() && !tx_data.transaction.is_coinbase() {
                    return Err(ConsensusError::EmptyTransaction);
                }
                
                // Check transaction size
                let tx_size = bincode::serialized_size(&tx_data.transaction)
                    .map_err(|_| ConsensusError::SerializationError)? as usize;
                    
                if tx_size > 1_000_000 { // 1MB max transaction size
                    return Err(ConsensusError::TransactionTooLarge);
                }
                trace!("Valid TxData from {}", peer_id);
            },
            P2PMessage::Chunk(_) => {
                // Chunk validation is handled separately
                trace!("Received chunk from {}", peer_id);
            },
            // Add validation for other message types as needed
            _ => {}
        }
        
        Ok(())
    }
}

pub struct ChunkHeader {
    /// Unique message ID
    message_id: u64,
    
    /// Total number of chunks in the message
    total_chunks: u16,
    
    /// Index of this chunk in the message
    chunk_index: u16,
    
    /// Total size of the message in bytes
    total_size: u32,
}

/// Sends a request to a peer and returns the response.
pub async fn send_request(
    &mut self, 
    peer_id: PeerId, 
    message: P2PMessage
) -> P2PResult<()> {
    // Check if peer is banned
    if let Some(ban_until) = self.banned_peers.get(&peer_id) {
        if *ban_until > Instant::now() {
            return Err(P2PError::PeerError(format!("Peer {} is banned", peer_id)));
        } else {
            self.banned_peers.remove(&peer_id);
        }
    }
    
    // Check if we're already connected to this peer
    if !self.connected_peers.contains_key(&peer_id) {
        return Err(P2PError::PeerError(format!("Not connected to peer {}", peer_id)));
    }
    
    // Use chunking for large messages
    if let Some(serialized_size) = bincode::serialized_size(&message).ok() {
        if serialized_size > MAX_CHUNK_SIZE as u64 {
            return self.send_chunked(peer_id, message).await;
        }
    }
    
    // Send the request directly for small messages
    self.request_response.send_request(&peer_id, message)
        .map(|_| ())
        .map_err(|e| P2PError::NetworkError(Box::new(e)))
}

/// Sends a chunked message to a peer.
async fn send_chunked(&mut self, peer_id: PeerId, message: P2PMessage) -> P2PResult<()> {
    // Serialize the message
    let serialized = bincode::serialize(&message)
        .map_err(P2PError::SerializationError)?;
    
    // Split message into chunks
    let message_id = rand::random();
    let chunks: Vec<_> = serialized.chunks(MAX_CHUNK_SIZE).collect();
    let total_chunks = chunks.len();
    
    // Send each chunk with a header
    for (index, chunk) in chunks.into_iter().enumerate() {
        let header = ChunkHeader {
            message_id,
            total_chunks: total_chunks as u16,
            chunk_index: index as u16,
            total_size: serialized.len() as u32,
        };
        
        // Serialize header and combine with chunk data
        let mut chunk_data = bincode::serialize(&header)
            .map_err(P2PError::SerializationError)?;
        chunk_data.extend_from_slice(chunk);
        
        // Create and send chunk message
        let chunk_message = P2PMessage::Chunk(chunk_data);
        self.request_response.send_request(&peer_id, chunk_message)
            .map(|_| ())
            .map_err(|e| P2PError::NetworkError(Box::new(e)))?;
    }
    
    Ok(())
}

/// Handles an inbound request from a peer.
pub async fn handle_inbound_request(
    &mut self,
    request: P2PMessage,
    channel: ResponseChannel<P2PMessage>,
) -> P2PResult<()> {
    let mut network = P2PNetwork::new()?;
    let test_msg = P2PMessage::Ping;
    
    // Test small message (no chunking)
    let small_msg = P2PMessage::Ping;
    assert!(network.send_chunked(PeerId::random(), small_msg).is_ok());
    
    // Test large message (chunking)
    let large_data = vec![0u8; 2_000_000]; // 2MB
    let large_msg = P2PMessage::TxData(TxData {
        transaction: Transaction::new(large_data)
    });
    assert!(network.send_chunked(PeerId::random(), large_msg).is_ok());
    
    Ok(())
}

/// Handles an inbound response from a peer.
pub async fn handle_inbound_response(&mut self, response: P2PMessage) -> P2PResult<()> {
    // Initialize logging for tests
    let _ = env_logger::try_init();
    
    // Create two network instances
    let mut network1 = P2PNetwork::new().await?;
    let mut network2 = P2PNetwork::new().await?;

    // Get listen addresses
    let addr1 = "/ip4/127.0.0.1/tcp/0".parse()?;
    let addr2 = "/ip4/127.0.0.1/tcp/0".parse()?;

    // Listen on random ports
    let _ = network1.swarm.listen_on(addr1)?;
    let _ = network2.swarm.listen_on(addr2)?;

    // Get the actual listening addresses
    let listen_addrs1: Vec<_> = network1.swarm.listeners().cloned().collect();
    let listen_addrs2: Vec<_> = network2.swarm.listeners().cloned().collect();

    assert!(!listen_addrs1.is_empty(), "Network 1 should have listening addresses");
    assert!(!listen_addrs2.is_empty(), "Network 2 should have listening addresses");

    // Try to connect network2 to network1
    network2.swarm.dial_addr(listen_addrs1[0].clone())?;

    // Run both networks in the background
    let (shutdown_send, mut shutdown_recv) = tokio::sync::broadcast::channel(1);
    
    let handle1 = tokio::spawn({
        let mut network = network1;
        let mut recv = shutdown_recv.resubscribe();
        async move {
            tokio::select! {
                _ = network.start_with_shutdown(recv) => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
    });

    let handle2 = tokio::spawn({
        let mut network = network2;
        let mut recv = shutdown_recv.resubscribe();
        async move {
            tokio::select! {
                _ = network.start_with_shutdown(recv) => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
    });

    // Wait for connection to be established
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Test sending a message
    let peer1_id = *network1.local_peer_id();
    let peer2_id = *network2.local_peer_id();
    
    // Send a message from network1 to network2
    let message = P2PMessage::Ping { nonce: 1234 };
    network1.send_request(peer2_id, message.clone()).await?;

    // Clean up
    let _ = shutdown_send.send(());
    let _ = future::join(handle1, handle2).await;

    Ok(())
        
        // Test large message (chunking)
        let large_data = vec![0u8; 2_000_000]; // 2MB
        let large_msg = P2PMessage::TxData(TxData {
            transaction: Transaction::new(large_data)
        });
        assert!(network.send_chunked(PeerId::random(), large_msg).is_ok());
        
        Ok(())
    }

    #[test]
    fn test_duplicate_chunks() {
        let mut reassembler = MessageReassembler::new(Duration::from_secs(30), Arc::new(AtomicU64::new(0)), 50_000_000);
        let header = ChunkHeader {
            message_id: 1,
            total_chunks: 2,
            chunk_index: 0,
            total_size: 10,
        };
        
        reassembler.add_chunk(header.clone(), vec![1, 2, 3, 4, 5]);
        reassembler.add_chunk(header, vec![1, 2, 3, 4, 5]);
        
        assert_eq!(reassembler.buffers[&1].chunks.iter().filter(|c| c.is_some()).count(), 1);
    }

    #[test]
    fn test_corrupted_header() {
        let mut network = P2PNetwork::new().unwrap();
        assert!(network.handle_chunk(vec![0; 10]).is_err());
    }

    #[test]
    fn test_malicious_oversized_chunk() {
        let mut reassembler = MessageReassembler::new(Duration::from_secs(30), Arc::new(AtomicU64::new(0)), 50_000_000);
        let header = ChunkHeader {
            message_id: 1,
            total_chunks: 1,
            chunk_index: 0,
            total_size: 10,
        };
        
        assert!(reassembler.add_chunk(header, vec![0; 20]).is_none());
    }

    #[test]
    fn test_invalid_chunk_index() {
        let mut reassembler = MessageReassembler::new(Duration::from_secs(30), Arc::new(AtomicU64::new(0)), 50_000_000);
        let header = ChunkHeader {
            message_id: 1,
            total_chunks: 2,
            chunk_index: 3, // Invalid index
            total_size: 10,
        };
        
        assert!(reassembler.add_chunk(header, vec![1, 2, 3]).is_none());
    }
}

pub struct PersistentPeerList {
    pub peers: Vec<String>, // Multiaddr as string
}
