//! Peer Discovery Implementation
//! 
//! Implements peer discovery mechanisms for the Rusty Coin network,
//! including Kademlia DHT for decentralized peer discovery and mDNS for local network discovery.

use libp2p::{
    kad::{self, Kademlia, KademliaEvent, QueryId, QueryResult, Record, RecordKey},
    mdns::{self, tokio::Behaviour as Mdns, Event as MdnsEvent, TokioMdns},
    Multiaddr, PeerId,
};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur during peer discovery
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Kademlia error: {0}")]
    Kademlia(#[from] kad::Error),
    
    #[error("mDNS error: {0}")]
    Mdns(#[from] mdns::Error),
    
    #[error("Invalid peer address: {0}")]
    InvalidAddress(String),
    
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

/// Peer discovery handler
pub struct PeerDiscovery {
    /// Kademlia DHT for peer discovery
    pub kademlia: Option<Kademlia>,
    
    /// mDNS for local peer discovery
    pub mdns: Option<Mdns>,
    
    /// Active Kademlia queries
    active_queries: HashMap<QueryId, DiscoveryQuery>,
    
    /// Configuration
    config: DiscoveryConfig,
}

/// Type of peer discovery query
#[derive(Debug)]
enum DiscoveryQuery {
    /// Finding peers in the DHT
    FindPeers,
    
    /// Looking up a specific peer
    GetPeer(PeerId),
    
    /// Looking up a provider
    GetProvider(RecordKey),
}

impl PeerDiscovery {
    /// Create a new peer discovery handler
    pub fn new(
        local_peer_id: PeerId,
        config: DiscoveryConfig,
    ) -> Result<Self, DiscoveryError> {
        let kademlia = if config.enable_kademlia {
            let mut kademlia = Kademlia::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
            
            // Set the protocol version
            kademlia.set_protocol_name(config.protocol_version.as_bytes());
            
            // Add bootstrap nodes
            for (peer_id, addr) in &config.bootstrap_nodes {
                kademlia.add_address(peer_id, addr.clone());
            }
            
            Some(kademlia)
        } else {
            None
        };
        
        let mdns = if config.enable_mdns {
            Some(TokioMdns::new()?)
        } else {
            None
        };
        
        Ok(Self {
            kademlia,
            mdns,
            active_queries: HashMap::new(),
            config,
        })
    }
    
    /// Bootstrap the Kademlia DHT
    pub fn bootstrap(&mut self) -> Result<(), DiscoveryError> {
        if let Some(kademlia) = &mut self.kademlia {
            // Start bootstrapping the DHT
            let query_id = kademlia.bootstrap()?;
            self.active_queries.insert(query_id, DiscoveryQuery::FindPeers);
        }
        Ok(())
    }
    
    /// Start discovering peers
    pub fn discover_peers(&mut self) -> Result<(), DiscoveryError> {
        if let Some(kademlia) = &mut self.kademlia {
            // Start a query to find peers
            let query_id = kademlia.get_closest_peers(PeerId::random());
            self.active_queries.insert(query_id, DiscoveryQuery::FindPeers);
        }
        
        Ok(())
    }
    
    /// Get a list of known peers
    pub fn known_peers(&self) -> Vec<PeerId> {
        self.kademlia
            .as_ref()
            .map(|k| k.kbuckets().flat_map(|b| b.iter().map(|e| *e.node.key.preimage())).collect())
            .unwrap_or_default()
    }
    
    /// Handle Kademlia events
    pub fn on_kademlia_event(&mut self, event: KademliaEvent) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();
        
        match event {
            KademliaEvent::OutboundQueryProgressed {
                id,
                result: QueryResult::Bootstrap(result),
                ..
            } => {
                // Handle bootstrap result
                if let Err(e) = result {
                    events.push(DiscoveryEvent::BootstrapFailed(e));
                } else {
                    events.push(DiscoveryEvent::Bootstrapped);
                }
                self.active_queries.remove(&id);
            }
            
            KademliaEvent::OutboundQueryProgressed {
                id,
                result: QueryResult::GetClosestPeers(result),
                ..
            } => {
                if let Ok(peers) = result {
                    for peer_id in peers.peers {
                        events.push(DiscoveryEvent::PeerDiscovered(peer_id));
                    }
                }
                self.active_queries.remove(&id);
            }
            
            KademliaEvent::RoutingUpdated { peer, .. } => {
                events.push(DiscoveryEvent::PeerDiscovered(peer));
            }
            
            _ => {}
        }
        
        events
    }
    
    /// Handle mDNS events
    pub fn on_mdns_event(&mut self, event: MdnsEvent) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();
        
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer_id, addr) in list {
                    events.push(DiscoveryEvent::PeerDiscovered(peer_id));
                    events.push(DiscoveryEvent::PeerAddressDiscovered(peer_id, addr));
                }
            }
            
            MdnsEvent::Expired(list) => {
                for (peer_id, _) in list {
                    events.push(DiscoveryEvent::PeerExpired(peer_id));
                }
            }
        }
        
        events
    }
    
    /// Handle a swarm event
    pub fn on_swarm_event(&mut self, event: &libp2p::swarm::SwarmEvent<impl std::fmt::Debug>) -> Vec<DiscoveryEvent> {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

/// Events emitted by the peer discovery system
#[derive(Debug)]
pub enum DiscoveryEvent {
    /// A new peer was discovered
    PeerDiscovered(PeerId),
    
    /// A peer's address was discovered
    PeerAddressDiscovered(PeerId, Multiaddr),
    
    /// A peer is no longer available (mDNS)
    PeerExpired(PeerId),
    
    /// The DHT was successfully bootstrapped
    Bootstrapped,
    
    /// DHT bootstrap failed
    BootstrapFailed(kad::Error),
    
    /// A Kademlia query completed
    QueryCompleted(QueryId, Result<QueryResult, kad::Error>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p::multiaddr::Protocol;
    
    fn create_test_peer() -> (PeerId, Multiaddr) {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let addr = "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap();
        (peer_id, addr)
    }
    
    #[test]
    fn test_peer_discovery_creation() {
        let (peer_id, _) = create_test_peer();
        let config = DiscoveryConfig::default();
        
        let discovery = PeerDiscovery::new(peer_id, config);
        assert!(discovery.is_ok());
    }
    
    #[test]
    fn test_bootstrap() {
        let (peer_id, _) = create_test_peer();
        let config = DiscoveryConfig::default();
        
        let mut discovery = PeerDiscovery::new(peer_id, config).unwrap();
        assert!(discovery.bootstrap().is_ok());
    }
    
    #[test]
    fn test_discover_peers() {
        let (peer_id, _) = create_test_peer();
        let config = DiscoveryConfig::default();
        
        let mut discovery = PeerDiscovery::new(peer_id, config).unwrap();
        assert!(discovery.discover_peers().is_ok());
    }
    
    #[test]
    fn test_known_peers() {
        let (peer_id, _) = create_test_peer();
        let config = DiscoveryConfig::default();
        
        let discovery = PeerDiscovery::new(peer_id, config).unwrap();
        let peers = discovery.known_peers();
        assert!(peers.is_empty());
    }
    
    #[test]
    fn test_on_kademlia_event() {
        let (peer_id, _) = create_test_peer();
        let config = DiscoveryConfig::default();
        
        let mut discovery = PeerDiscovery::new(peer_id, config).unwrap();
        
        // Test bootstrap completed
        let event = KademliaEvent::OutboundQueryProgressed {
            id: QueryId(0),
            result: Ok(QueryResult::Bootstrap(Ok(()))),
            stats: Default::default(),
        };
        
        let events = discovery.on_kademlia_event(event);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DiscoveryEvent::Bootstrapped));
    }
}
