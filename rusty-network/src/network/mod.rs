//! Network layer for Rusty Coin

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// Remove old tokio and tokio-tungstenite imports
// use tokio::net::{TcpListener, TcpStream};
// use tokio::sync::{broadcast, mpsc, RwLock};
// use tokio_tungstenite::accept_async;
// use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::error::{NetworkError, NetworkResult};
// Removed old peer module imports
// use crate::peer::{Peer, PeerInfo, PeerState};
use crate::protocol::{Message, Network as NetworkType};
use rusty_core::consensus::state::BlockchainState;

// Add libp2p imports
use libp2p::{futures::StreamExt, identity, swarm::{NetworkBehaviour, SwarmEvent}, PeerId, Multiaddr};
use libp2p::core::transport::Transport;
use libp2p::gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent, MessageAuthenticity, ValidationMode};
use libp2p::kad::{Kademlia, KademliaEvent};
use libp2p::mdns::{Mdns, MdnsEvent};


/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Network type (mainnet, testnet, etc.)
    pub network: NetworkType,
    /// Local address to bind to
    pub bind_addr: Multiaddr,
    /// List of seed nodes to connect to
    pub seed_nodes: Vec<Multiaddr>,
    /// User agent string
    pub user_agent: String,
    /// Protocol version
    pub protocol_version: i32,
    /// Services supported by this node
    pub services: u64,
    /// Relay transactions
    pub relay: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: NetworkType::Mainnet,
            bind_addr: "/ip4/0.0.0.0/tcp/8333".parse().unwrap(),
            seed_nodes: vec![], // Seed nodes will be Multiaddrs
            user_agent: "/rusty-coin:0.1.0/".to_string(),
            protocol_version: 70015,
            services: 0,
            relay: true,
        }
    }
}

impl NetworkConfig {
    pub fn testnet() -> Self {
        Self {
            network: NetworkType::Testnet,
            bind_addr: "/ip4/0.0.0.0/tcp/18333".parse().unwrap(),
            seed_nodes: vec![], // Testnet seed nodes as Multiaddrs
            user_agent: "/rusty-coin-testnet:0.1.0/".to_string(),
            protocol_version: 70015,
            services: 0,
            relay: true,
        }
    }

    /// Regtest configuration - local network with mainnet parameters
    pub fn regtest() -> Self {
        Self {
            network: NetworkType::Regtest,
            bind_addr: "/ip4/0.0.0.0/tcp/18444".parse().unwrap(),
            seed_nodes: vec![], // No seed nodes for local regtest
            user_agent: "/rusty-coin-regtest:0.1.0/".to_string(),
            protocol_version: 70015,
            services: 0,
            relay: true,
        }
    }
}

// We will define a custom `NetworkBehaviour` for Rusty Coin.
// This struct combines the functionalities of Gossipsub, Kademlia, and mDNS.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent")]
pub struct RustyCoinBehaviour {
    pub gossipsub: Gossipsub,
    pub kademlia: Kademlia,
    pub mdns: Mdns,
    // We'll add custom protocols later, e.g., for block sync
}

impl RustyCoinBehaviour {
    pub async fn new(local_peer_id: PeerId, keypair: &identity::Keypair) -> NetworkResult<Self> {
        // Create a Gossipsub topic
        let gossipsub_config = GossipsubConfig::default();
        let gossipsub = Gossipsub::new(MessageAuthenticity::Signed(keypair.clone()), gossipsub_config)
            .map_err(|e| NetworkError::Other(format!("Failed to create Gossipsub: {}", e)))?;

        // Create a Kademlia instance for peer discovery
        let mut kademlia = Kademlia::new(local_peer_id, Default::default(), Default::default());
        // Add bootstrap nodes if any, this will be done later

        // Create an mDNS instance for local peer discovery
        let mdns = Mdns::new(Default::default())
            .await
            .map_err(|e| NetworkError::Other(format!("Failed to create mDNS: {}", e)))?;

        Ok(Self {
            gossipsub,
            kademlia,
            mdns,
        })
    }
}

// Define custom events that our `NetworkBehaviour` will emit
#[derive(Debug)]
pub enum NetworkEvent {
    /// Event from Gossipsub
    Gossipsub(GossipsubEvent),
    /// Event from Kademlia
    Kademlia(KademliaEvent),
    /// Event from mDNS
    Mdns(MdnsEvent),
    // Custom events for block sync, tx propagation, etc.
    // PeerConnected(PeerInfo),
    // PeerDisconnected(SocketAddr),
    // MessageReceived { peer: SocketAddr, message: Message },
    // Error(NetworkError),
}

impl From<GossipsubEvent> for NetworkEvent {
    fn from(event: GossipsubEvent) -> Self {
        NetworkEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for NetworkEvent {
    fn from(event: KademliaEvent) -> Self {
        NetworkEvent::Kademlia(event)
    }
}

impl From<MdnsEvent> for NetworkEvent {
    fn from(event: MdnsEvent) -> Self {
        NetworkEvent::Mdns(event)
    }
}

/// Network manager
pub struct NetworkManager {
    /// libp2p Swarm instance
    swarm: libp2p::Swarm<RustyCoinBehaviour>,
    /// Network configuration
    config: NetworkConfig,
    /// Network event sender
    event_tx: tokio::sync::mpsc::UnboundedSender<NetworkEvent>,
    /// Network event receiver
    event_rx: tokio::sync::mpsc::UnboundedReceiver<NetworkEvent>,
    /// Shutdown signal
    shutdown_tx: tokio::sync::broadcast::Sender<()>, 
    /// Blockchain state
    blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub async fn new(config: NetworkConfig, blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>) -> NetworkResult<Self> {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        // Create a cryptographic keypair for the local peer
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        log::info!("Local Peer ID: {}", local_peer_id);

        // Create a transport
        let transport = libp2p::development_transport(local_key.clone())
            .await
            .map_err(|e| NetworkError::Other(format!("Failed to create transport: {}", e)))?;

        // Create the network behaviour
        let behaviour = RustyCoinBehaviour::new(local_peer_id, &local_key).await?;

        // Create the Swarm
        let swarm = libp2p::SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| { tokio::spawn(fut); }))
            .build();
        
        Ok(Self {
            swarm,
            config,
            event_tx,
            event_rx,
            shutdown_tx,
            blockchain_state,
        })
    }
    
    /// Start the network manager
    pub async fn start(&mut self) -> NetworkResult<()> {
        // Start listening on the configured address
        self.swarm.listen_on(self.config.bind_addr.clone())
            .map_err(|e| NetworkError::Other(format!("Failed to listen on address: {}", e)))?;

        log::info!("Listening on {:?}", self.swarm.listeners());

        // Connect to seed nodes
        for addr in &self.config.seed_nodes {
            log::info!("Connecting to seed node: {}", addr);
            self.swarm.dial(addr.clone())
                .map_err(|e| NetworkError::Other(format!("Failed to dial seed node {}: {}", addr, e)))?;
        }

        // Main event loop for the Swarm
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            log::info!("Local node listening on {}", address);
                        }
                        SwarmEvent::Behaviour(behaviour_event) => {
                            // Forward behaviour events to our event channel
                            let _ = self.event_tx.send(behaviour_event);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            log::info!("Connection established with peer: {} ({:?})", peer_id, endpoint);
                            // Optionally send a PeerConnected event for external listeners
                            // let _ = self.event_tx.send(NetworkEvent::PeerConnected(PeerInfo { peer_id, address: endpoint.get_remote_address().clone().into(), is_outbound: endpoint.is_dialer() }));
                        }
                        SwarmEvent::ConnectionClosed { peer_id, endpoint, .. } => {
                            log::info!("Connection closed with peer: {} ({:?})", peer_id, endpoint);
                            // Optionally send a PeerDisconnected event
                            // let _ = self.event_tx.send(NetworkEvent::PeerDisconnected(endpoint.get_remote_address().clone().into()));
                        }
                        e => {
                            // log::debug!("Unhandled Swarm Event: {:?}", e);
                        }
                    }
                }
                _ = self.shutdown_tx.subscribe().recv() => {
                    log::info!("Shutting down network manager");
                    break;
                }
            }
        }

        Ok(())
    }
    
    pub async fn broadcast(&self, message: Message) -> NetworkResult<()> {
        // TODO: Implement actual broadcast using gossipsub
        log::warn!("Broadcast not yet fully implemented for libp2p. Message: {:?}", message);
        // Example of publishing a message to a topic
        // self.swarm.behaviour_mut().gossipsub.publish(topic, message_data);
        Ok(())
    }

    pub async fn get_peers(&self) -> Vec<String> {
        // TODO: Implement peer listing from Kademlia or Swarm connections
        log::warn!("get_peers not yet implemented for libp2p.");
        vec![]
    }

    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    pub async fn shutdown(self) -> NetworkResult<()> {
        log::info!("NetworkManager shutdown initiated.");
        let _ = self.shutdown_tx.send(()); // Signal all tasks to shut down
        // The `swarm.select_next_some()` loop will naturally terminate upon shutdown_tx signal
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Network as NetworkType;
    use rusty_core::consensus::state::BlockchainState;

    #[tokio::test]
    async fn test_network_manager_initialization() {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        
        let config = NetworkConfig::testnet();
        let blockchain_state = Arc::new(tokio::sync::RwLock::new(BlockchainState::new()));

        let network_manager = NetworkManager::new(config, blockchain_state).await;
        assert!(network_manager.is_ok());
    }
}
