// Standard library
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// External crates
use async_trait::async_trait;
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    identity,
    kad::{Kademlia, KademliaEvent, KademliaStoreInserts, KademliaStoreInsertsRecord, KademliaStoreInsertsValue},
    mdns::tokio::Behaviour as Mdns,
    noise::{self, NoiseConfig, X25519Spec, Keypair as NoiseKeypair},
    request_response::{RequestId, ResponseChannel},
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent},
    tcp::Config as TcpConfig,
    tcp::tokio::TcpTransport,
    yamux, Multiaddr, PeerId, Transport,
};
use log::{debug, error, info, warn};
use thiserror::Error;
use tokio::sync::mpsc;

// Crate modules
use crate::{
    protocols::{
        block_sync::{BlockSyncRequest, BlockSyncResponse, BlockData, BlockHeaderData},
        tx_prop::TxPropHandler,
    },
    RustyCoinBehaviour, RustyCoinEvent, RustyCoinNetworkConfig,
};

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
}

/// Type alias for P2P operation results
pub type P2PResult<T> = std::result::Result<T, P2PError>;

/// Main P2P network manager
#[derive(Debug)]
pub struct P2PNetwork {
    /// The libp2p Swarm that manages the network
    pub swarm: Swarm<RustyCoinBehaviour>,
    
    /// Channel for receiving events from the network
    pub event_receiver: tokio::sync::mpsc::UnboundedReceiver<RustyCoinEvent>,
    
    /// Local peer ID
    pub local_peer_id: PeerId,
    
    /// Known peers and their last seen time
    known_peers: HashMap<PeerId, Instant>,
    
    /// Banned peers and their unban time
    banned_peers: HashMap<PeerId, Instant>,
    
    /// Peer scores for Sybil resistance and quality of service
    peer_scores: HashMap<PeerId, f64>,
    
    /// Active block sync requests
    active_block_requests: HashMap<RequestId, (PeerId, Instant)>,
    
    /// Pending transactions waiting to be propagated
    pending_transactions: VecDeque<Vec<u8>>,
    
    /// Track when we last sent a message to each peer
    last_message_time: HashMap<PeerId, Instant>,
    
    /// Track message rates per peer for DoS protection
    message_rates: HashMap<PeerId, (u32, Instant)>, // (count, last_reset)
    
    /// Configuration for the network
    config: RustyCoinNetworkConfig,
}

impl P2PNetwork {
    /// Creates a new P2P network instance with the given configuration
    pub async fn new(config: RustyCoinNetworkConfig) -> P2PResult<Self> {
        // Generate a new Ed25519 keypair for this node
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        // Create channels for network events
        let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        // Create the network behaviour with the provided config
        let behaviour = RustyCoinBehaviour::new(local_key, config.clone(), event_sender)?;
        
        // Set up the transport with noise for encryption and yamux for multiplexing
        let noise_keys = NoiseKeypair::<noise::X25519Spec>::new()
            .into_authentic(&local_key)
            .expect("Signing libp2p-noise static DH keypair failed.");
            
        let tcp = TcpConfig::new()
            .nodelay(true);
            
        let transport = TcpTransport::new(tcp)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&noise_keys).expect("Signing libp2p-noise static DH keypair failed."))
            .multiplex(YamuxConfig::default())
            .timeout(Duration::from_secs(20))
            .boxed();
        
        // Create the swarm
        let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();
        
        // Listen on all interfaces and a random port
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        
        // Start the Kademlia bootstrap process if enabled
        if config.enable_kademlia {
            swarm.behaviour_mut().kademlia.bootstrap()?;
        }
        
        // Initialize the peer discovery system
        if config.enable_mdns {
            swarm.behaviour_mut().start_mdns()?;
        }
        
        // Initialize the transaction propagation system
        swarm.behaviour_mut().tx_prop.initialize()?;
        
        Ok(Self {
            swarm,
            event_receiver,
            local_peer_id,
            known_peers: HashMap::new(),
            banned_peers: HashMap::new(),
            peer_scores: HashMap::new(),
            active_block_requests: HashMap::new(),
            pending_transactions: VecDeque::with_capacity(config.tx_propagation_queue_size),
            last_message_time: HashMap::new(),
            message_rates: HashMap::new(),
            config,
        })
    }
    
    /// Run the network event loop
    pub async fn run(mut self) -> P2PResult<()> {
        info!("Starting P2P network with peer ID: {}", self.local_peer_id);
        
        loop {
            tokio::select! {
                // Handle swarm events
                event = self.swarm.select_next_some() => {
                    if let Err(e) = self.handle_swarm_event(event).await {
                        error!("Error handling swarm event: {}", e);
                    }
                },
                
                // Handle application events
                event = self.event_receiver.recv() => {
                    match event {
                        Some(event) => {
                            if let Err(e) = self.handle_application_event(event).await {
                                error!("Error handling application event: {}", e);
                            }
                        },
                        None => {
                            // Channel closed, shutdown
                            info!("Event channel closed, shutting down");
                            break;
                        }
                    }
                },
                
                // Handle periodic tasks
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if let Err(e) = self.periodic_tasks().await {
                        error!("Error in periodic tasks: {}", e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle periodic tasks like peer cleanup and statistics
    pub async fn periodic_tasks(&mut self) -> P2PResult<()> {
        self.cleanup_stale_peers();
        self.cleanup_expired_bans();
        self.cleanup_expired_requests();
        self.cleanup_message_rates();
        self.log_network_stats();
        Ok(())
    }
    
    /// Clean up stale peers that haven't been seen in a while
    fn cleanup_stale_peers(&mut self) {
        let now = Instant::now();
        let stale_peers: Vec<_> = self.known_peers
            .iter()
            .filter(|(_, &last_seen)| now.duration_since(last_seen) > Duration::from_secs(3600)) // 1 hour
            .map(|(peer_id, _)| *peer_id)
            .collect();
            
        for peer_id in stale_peers {
            debug!("Removing stale peer: {}", peer_id);
            self.known_peers.remove(&peer_id);
        }
    }
    
    /// Clean up expired bans
    fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        let expired_bans: Vec<_> = self.banned_peers
            .iter()
            .filter(|(_, &unban_time)| now >= unban_time)
            .map(|(peer_id, _)| *peer_id)
            .collect();
            
        for peer_id in expired_bans {
            debug!("Ban expired for peer: {}", peer_id);
            self.banned_peers.remove(&peer_id);
        }
    }
    
    /// Clean up expired block sync requests
    fn cleanup_expired_requests(&mut self) {
        let now = Instant::now();
        let expired_requests: Vec<RequestId> = self.active_block_requests
            .iter()
            .filter(|(_, (_, timestamp))| now.duration_since(*timestamp) > self.config.block_sync_timeout)
            .map(|(request_id, _)| *request_id)
            .collect();
            
        for request_id in expired_requests {
            debug!("Block sync request {} timed out", request_id);
            self.active_block_requests.remove(&request_id);
        }
    }
    
    /// Clean up old message rate counters
    fn cleanup_message_rates(&mut self) {
        let now = Instant::now();
        let old_peers: Vec<_> = self.message_rates
            .iter()
            .filter(|(_, (_, last_reset))| now.duration_since(*last_reset) > Duration::from_secs(60)) // 60 seconds
            .map(|(peer_id, _)| *peer_id)
            .collect();
            
        for peer_id in old_peers {
            self.message_rates.remove(&peer_id);
        }
    }
    
    /// Process pending transactions from the queue
    pub async fn process_pending_transactions(&mut self) -> P2PResult<()> {
        while let Some(tx_data) = self.pending_transactions.pop_front() {
            // Get connected peers
            let peers: Vec<_> = self.swarm.connected_peers().cloned().collect();
            
            if peers.is_empty() {
                // No peers to broadcast to, requeue the transaction
                self.pending_transactions.push_front(tx_data);
                break;
            }
            
            // Broadcast to all connected peers
            for peer_id in peers {
                if let Err(e) = self.swarm.behaviour_mut().send_transaction(peer_id, tx_data.clone()) {
                    warn!("Failed to send transaction to {}: {}", peer_id, e);
                    // Consider penalizing the peer
                    self.penalize_peer(peer_id, 10.0, format!("Failed to send transaction: {}", e));
                }
            }
        }
        
        Ok(())
    }
    
    /// Request blocks from a peer
    pub fn request_blocks(
        &mut self,
        peer_id: PeerId,
        start_height: u64,
        count: u32,
    ) -> P2PResult<RequestId> {
        let request = BlockSyncRequest::Blocks { start_height, count };
        let request_id = self.swarm.behaviour_mut().send_block_sync_request(peer_id, request);
        
        // Track the request
        self.active_block_requests.insert(request_id, (peer_id, Instant::now()));
        
        Ok(request_id)
    }
    
    /// Request block headers from a peer
    pub fn request_headers(
        &mut self,
        peer_id: PeerId,
        start_hash: [u8; 32],
        count: u32,
    ) -> P2PResult<RequestId> {
        let request = BlockSyncRequest::Headers { start_hash, count };
        let request_id = self.swarm.behaviour_mut().send_block_sync_request(peer_id, request);
        
        // Track the request
        self.active_block_requests.insert(request_id, (peer_id, Instant::now()));
        
        Ok(request_id)
    }
    
    /// Handle incoming block sync requests
    pub async fn handle_block_sync_request(
        &mut self,
        peer_id: PeerId,
        request: BlockSyncRequest,
        channel: ResponseChannel<BlockSyncResponse>,
    ) -> P2PResult<()> {
        // Update peer's last message time
        self.last_message_time.insert(peer_id, Instant::now());
        
        // Process the request based on its type
        match request {
            BlockSyncRequest::Blocks { start_height, count } => {
                debug!("Received block sync request from {}: {} blocks starting from height {}", 
                    peer_id, count, start_height);
                
                // TODO: Fetch blocks from the blockchain
                let blocks = Vec::new();
                
                // Send the response
                let response = BlockSyncResponse::Blocks(blocks);
                if let Err(e) = self.swarm.behaviour_mut().send_block_sync_response(channel, response) {
                    warn!("Failed to send block sync response to {}: {}", peer_id, e);
                }
            }
            BlockSyncRequest::Headers { start_hash, count } => {
                debug!("Received header sync request from {}: {} headers starting from hash {}", 
                    peer_id, count, hex::encode(start_hash));
                
                // TODO: Fetch block headers from the blockchain
                let headers = Vec::new();
                
                // Send the response
                let response = BlockSyncResponse::Headers(headers);
                if let Err(e) = self.swarm.behaviour_mut().send_block_sync_response(channel, response) {
                    warn!("Failed to send header sync response to {}: {}", peer_id, e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle behaviour events
    pub async fn handle_behaviour_event(
        &mut self,
        event: RustyCoinEvent,
    ) -> P2PResult<()> {
        match event {
            RustyCoinEvent::PeerConnected(peer_id) => {
                info!("Peer connected: {}", peer_id);
                self.known_peers.insert(peer_id, Instant::now());
            }
            RustyCoinEvent::PeerDisconnected(peer_id) => {
                info!("Peer disconnected: {}", peer_id);
                self.known_peers.remove(&peer_id);
            }
            RustyCoinEvent::PeerDiscovered(peer_id) => {
                info!("Discovered peer: {}", peer_id);
                self.known_peers.insert(peer_id, Instant::now());
            }
            RustyCoinEvent::TransactionReceived { peer, transaction } => {
                if let Err(e) = self.handle_transaction(peer, transaction).await {
                    warn!("Error handling transaction: {}", e);
                }
            }
            RustyCoinEvent::BlocksReceived { peer, blocks } => {
                if let Err(e) = self.handle_blocks_received(peer, blocks).await {
                    warn!("Error handling blocks: {}", e);
                }
            }
            RustyCoinEvent::BlockHeadersReceived { peer, headers } => {
                if let Err(e) = self.handle_headers_received(peer, headers).await {
                    warn!("Error handling block headers: {}", e);
                }
            }
            RustyCoinEvent::BlockSyncRequested { peer, request, channel } => {
                if let Err(e) = self.handle_block_sync_request(peer, request, channel).await {
                    warn!("Error handling block sync request: {}", e);
                }
            }
            RustyCoinEvent::PeerBanned { peer, duration, reason } => {
                self.ban_peer(peer, duration, reason);
            }
            RustyCoinEvent::PeerScoreUpdated { peer, score, delta: _ } => {
                debug!("Peer {} score updated: {:.2}", peer, score);
                self.peer_scores.insert(peer, score);
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Connect to a peer at the given address
    pub async fn connect_to_peer(&mut self, addr: Multiaddr) -> P2PResult<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&mut self, peer_id: PeerId) -> P2PResult<()> {
        self.swarm.disconnect_peer(peer_id);
        Ok(())
    }
}
