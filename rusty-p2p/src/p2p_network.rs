// Standard library
use thiserror::Error;
use crate::RustyCoinBehaviour;
use crate::RustyCoinEvent;
use crate::RustyCoinNetworkConfig;
use crate::protocols::block_sync::BlockSyncProtocol;
use crate::protocols::tx_prop::TxPropProtocol;
use libp2p::PeerId;
use libp2p::identity::Keypair;
use libp2p::Swarm;
use libp2p::Transport;

/// Custom error type for P2P network operations
#[derive(Error, Debug)]
/// Errors that can occur in the P2P network.
pub enum P2PError {
    /// Network error.
    #[error("Network error: {0}")]
    NetworkError(#[from] Box<dyn std::error::Error + Send + Sync>),
    /// Peer error.
    #[error("Peer error: {0}")]
    PeerError(String),
    /// Protocol error.
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    /// Validation error.
    #[error("Validation error: {0}")]
    ValidationError(String),
    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    /// Transport error.
    #[error("Transport error: {0}")]
    TransportError(#[from] libp2p::TransportError<std::io::Error>),
    /// Quorum error.
    #[error("Quorum error: {0}")]
    QuorumError(String),
    /// Other error.
    #[error("Other error: {0}")]
    Other(String),
    /// Gossipsub error.
    #[error("Gossipsub error: {0}")]
    GossipsubError(#[from] libp2p::gossipsub::PublishError),
    /// Transaction propagation error.
    #[error("TxProp error: {0}")]
    TxPropError(#[from] crate::protocols::tx_prop::TxPropError),
    /// Peer discovery error.
    #[error("Discovery error: {0}")]
    DiscoveryError(#[from] crate::protocols::peer_discovery::DiscoveryError),
}

/// Type alias for P2P operation results
pub type P2PResult<T> = std::result::Result<T, P2PError>;

/// Main P2P network manager. Provides an API for interacting with the Rusty Coin P2P network.
///
/// This struct is the main entry point for starting, controlling, and sending commands to the
/// P2P event loop. All network state is managed internally by the event loop.
pub struct P2PNetwork {
    /// Channel for sending commands to the event loop
    command_sender: tokio::sync::mpsc::UnboundedSender<P2PCommand>,
    /// Local node's keypair (unused, kept for compatibility)
    _local_key: libp2p::identity::Keypair,
    /// Local node's peer ID (unused, kept for compatibility)
    _local_peer_id: libp2p::PeerId,
    /// Network configuration (unused, kept for compatibility)
    _config: RustyCoinNetworkConfig,
}

// Define a command enum for all actions the event loop can perform
/// Command enum for actions the P2P event loop can perform
pub enum P2PCommand {
    /// Send a block request to a peer.
    SendBlockRequest {
        /// Peer to send the request to.
        peer_id: PeerId,
        /// Hash to start from.
        start_hash: [u8; 32],
        /// Number of blocks to request.
        count: u64,
    },
    /// Send a transaction to the network.
    SendTx {
        /// Raw transaction data.
        tx_data: Vec<u8>,
    },
    // ... add more as needed for protocol compliance ...
}

impl P2PNetwork {
    /// Creates a new P2P network instance with the given configuration
    pub async fn new(config: RustyCoinNetworkConfig) -> P2PResult<Self> {
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        // Create channels for network events
        let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();

        // Build sub-behaviours
        let gossipsub_config = libp2p::gossipsub::Config::default();
        let gossipsub = libp2p::gossipsub::Behaviour::new(libp2p::gossipsub::MessageAuthenticity::Signed(local_key.clone()), gossipsub_config)
            .map_err(|e| P2PError::Other(e.to_string()))?;
        let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new("/rusty/1.0".into(), local_key.public()));
        let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());
        let block_sync = libp2p::request_response::Behaviour::new(
            vec![(BlockSyncProtocol, libp2p::request_response::ProtocolSupport::Full)],
            libp2p::request_response::Config::default(),
        );
        let tx_prop = libp2p::request_response::Behaviour::new(
            vec![(TxPropProtocol, libp2p::request_response::ProtocolSupport::Full)],
            libp2p::request_response::Config::default(),
        );
        let store = libp2p::kad::store::MemoryStore::new(local_peer_id.clone());
        let kademlia = libp2p::kad::Behaviour::new(local_peer_id.clone(), store);
        let mdns = libp2p::mdns::tokio::Behaviour::new(Default::default(), local_peer_id.clone())?;
        // let peer_discovery = PeerDiscovery::new(local_peer_id.clone(), DiscoveryConfig::default()).unwrap();

        // Create the network behaviour with struct literal (derive macro, no .new())
        let behaviour = RustyCoinBehaviour {
            gossipsub,
            identify,
            ping,
            block_sync,
            tx_prop,
            kademlia,
            mdns,
            // peer_discovery, // Removed
        };

        // Set up the transport with noise for encryption and yamux for multiplexing
        let noise_config = libp2p::noise::Config::new(&local_key).expect("NoiseConfig failed");
        let tcp_transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default());
        // SwarmBuilder: use with_existing_identity, with_tokio, with_other_transport (closure), with_behaviour, build
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_other_transport(|_| {
                tcp_transport
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(noise_config.clone())
                    .multiplex(libp2p::yamux::Config::default())
                    .timeout(std::time::Duration::from_secs(20))
                    .boxed()
            })
            .map_err(|e| P2PError::Other(format!("SwarmBuilder transport error: {:?}", e)))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| P2PError::Other(format!("SwarmBuilder behaviour error: {:?}", e)))?
            .build();
        // Listen on all interfaces and a random port
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", config.listen_port).parse()
            .map_err(|e| P2PError::Other(format!("Multiaddr parse error: {:?}", e)))?)
            .map_err(|e| P2PError::Other(format!("Swarm listen_on error: {:?}", e)))?;
        // Start the Kademlia bootstrap process if enabled
        if config.enable_kademlia {
            swarm.behaviour_mut().kademlia.bootstrap()
                .map_err(|e| P2PError::Other(format!("Kademlia bootstrap error: {:?}", e)))?;
        }
        // Initialize the peer discovery system
        // mDNS starts automatically after construction; no need to call start_emitting_packets

        // Create a command channel for controlling the event loop
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        // Spawn the swarm event loop, passing the command receiver
        tokio::spawn(async move {
            Self::swarm_event_loop(swarm, event_sender, event_receiver, command_receiver).await;
        });
        Ok(Self {
            command_sender,
            _local_key: local_key,
            _local_peer_id: local_peer_id,
            _config: config,
        })
    }
    
    /// Run the network event loop (no-op; logic is in the event loop)
    pub async fn run(&self) -> P2PResult<()> {
        Ok(())
    }
    
    /// Handle periodic tasks like peer cleanup and statistics (stub)
    pub async fn periodic_tasks(&mut self) -> P2PResult<()> {
        Ok(())
    }
    
    /// Send a block request to a peer
    pub fn send_block_request(&self, peer_id: PeerId, start_hash: [u8; 32], count: u64) {
        let _ = self.command_sender.send(P2PCommand::SendBlockRequest { peer_id, start_hash, count });
    }
    
    /// Send a transaction to the network
    pub fn send_tx(&self, tx_data: Vec<u8>) {
        let _ = self.command_sender.send(P2PCommand::SendTx { tx_data });
    }

    /// Private: swarm event loop for handling network events and commands
    async fn swarm_event_loop(
        mut swarm: Swarm<RustyCoinBehaviour>,
        _event_sender: tokio::sync::mpsc::UnboundedSender<RustyCoinEvent>,
        mut event_receiver: tokio::sync::mpsc::UnboundedReceiver<RustyCoinEvent>,
        mut command_receiver: tokio::sync::mpsc::UnboundedReceiver<P2PCommand>,
    ) {
        loop {
            tokio::select! {
                event = futures::StreamExt::next(&mut swarm) => {
                    if let Some(_event) = event {
                        // Handle swarm events here (stubbed for now)
                    } else {
                        break;
                    }
                },
                _ = event_receiver.recv() => {
                    // Handle application events (stubbed)
                },
                _ = command_receiver.recv() => {
                    // Handle commands (stubbed)
                },
            }
        }
    }
} // End of impl P2PNetwork
