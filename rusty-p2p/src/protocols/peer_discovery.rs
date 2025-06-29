//! Peer Discovery Implementation
//! 
//! Implements peer discovery mechanisms for the Rusty Coin network.

use libp2p::PeerId;
use libp2p::kad::{Behaviour as Kademlia, Event as KademliaEvent, store::MemoryStore};
use libp2p::mdns::tokio::{Behaviour as Mdns};
use libp2p::mdns::Event as MdnsEvent;
use libp2p::Multiaddr;
use libp2p::swarm::NetworkBehaviour;
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur during peer discovery.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Kademlia error.
    #[error("Kademlia error: {0}")]
    Kademlia(String),
    /// mDNS error.
    #[error("mDNS error: {0}")]
    Mdns(String),
    /// Invalid peer address.
    #[error("Invalid peer address: {0}")]
    InvalidAddress(String),
    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Configuration for peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Whether to enable Kademlia DHT for peer discovery
    pub enable_kademlia: bool,
    /// Whether to enable mDNS for local peer discovery
    pub enable_mdns: bool,
    /// Bootstrap nodes to connect to initially
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// Protocol version for Kademlia
    pub protocol_version: String,
    /// Query timeout for Kademlia lookups
    pub query_timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_kademlia: true,
            enable_mdns: true,
            bootstrap_nodes: Vec::new(),
            protocol_version: "/rusty/1.0.0".to_string(),
            query_timeout: Duration::from_secs(30),
        }
    }
}

/// Event type for PeerDiscovery (required by NetworkBehaviour macro).
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PeerDiscoveryEvent {
    /// Kademlia DHT event.
    Kademlia(KademliaEvent),
    /// mDNS event.
    Mdns(MdnsEvent),
}

impl PeerDiscoveryEvent {
    /// Helper to match and extract Kademlia events
    pub fn as_kademlia(&self) -> Option<&KademliaEvent> {
        if let PeerDiscoveryEvent::Kademlia(ev) = self {
            Some(ev)
        } else {
            None
        }
    }
    /// Helper to match and extract mDNS events
    pub fn as_mdns(&self) -> Option<&MdnsEvent> {
        if let PeerDiscoveryEvent::Mdns(ev) = self {
            Some(ev)
        } else {
            None
        }
    }
}

/// Peer discovery handler.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PeerDiscoveryEvent")]
pub struct PeerDiscovery {
    /// Kademlia DHT for peer discovery.
    pub kademlia: Kademlia<MemoryStore>,
    /// mDNS for local peer discovery.
    pub mdns: Mdns,
}

impl PeerDiscovery {
    /// Create a new peer discovery handler
    pub async fn new(
        local_peer_id: PeerId,
        config: DiscoveryConfig,
    ) -> Result<Self, DiscoveryError> {
        let mut kademlia = Kademlia::new(local_peer_id, MemoryStore::new(local_peer_id));
        // Add bootstrap nodes
        for (peer_id, addr) in &config.bootstrap_nodes {
            kademlia.add_address(peer_id, addr.clone());
        }
        let mdns = Mdns::new(Default::default(), local_peer_id)
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(Self {
            kademlia,
            mdns,
        })
    }
    /// Bootstrap the Kademlia DHT
    pub fn bootstrap(&mut self) -> Result<(), DiscoveryError> {
        let _query_id = self.kademlia.bootstrap().map_err(|e| DiscoveryError::Kademlia(e.to_string()))?;
        Ok(())
    }
    /// Start discovering peers
    pub fn discover_peers(&mut self) -> Result<(), DiscoveryError> {
        let _query_id = self.kademlia.get_closest_peers(PeerId::random());
        Ok(())
    }
    /// Get a list of known peers
    pub fn known_peers(&mut self) -> Vec<PeerId> {
        self.kademlia
            .kbuckets()
            .map(|b| b.iter().map(|e| e.node.key.preimage().clone()).collect::<Vec<_>>())
            .flatten()
            .collect()
    }
}

// Correct From impls for macro compatibility
impl From<libp2p::kad::Event> for PeerDiscoveryEvent {
    fn from(ev: libp2p::kad::Event) -> Self {
        PeerDiscoveryEvent::Kademlia(ev)
    }
}
impl From<libp2p::mdns::Event> for PeerDiscoveryEvent {
    fn from(ev: libp2p::mdns::Event) -> Self {
        PeerDiscoveryEvent::Mdns(ev)
    }
}
