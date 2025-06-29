//! Rusty Coin P2P Behaviour and Event Types (restored from backup)

// Use correct subcrate imports for all libp2p types (latest API)
use libp2p::gossipsub::{Behaviour as Gossipsub, Event as GossipsubEvent};
use libp2p::identify::{Behaviour as Identify, Event as IdentifyEvent};
use libp2p::kad::{Behaviour as Kademlia, Event as KademliaEvent, store::MemoryStore};
use libp2p::mdns::{tokio::Behaviour as MdnsTokioBehaviour, Event as MdnsEvent};
use libp2p::ping::{Behaviour as Ping, Event as PingEvent};
use libp2p::request_response::{Behaviour as RequestResponse, Event as RequestResponseEvent};
use libp2p::Multiaddr;
use libp2p::PeerId;
use crate::protocols::{
    block_sync::{BlockSyncCodec, BlockSyncRequest, BlockSyncResponse},
    tx_prop::{TxPropCodec, TxPropRequest, TxPropResponse},
};

/// Network configuration for Rusty Coin P2P.
#[derive(Debug, Clone)]
pub struct RustyCoinNetworkConfig {
    /// Enable mDNS peer discovery
    pub enable_mdns: bool,
    /// Enable Kademlia DHT peer discovery
    pub enable_kademlia: bool,
    /// List of bootstrap nodes for Kademlia
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Protocol version string
    pub protocol_version: String,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Maximum inbound connections
    pub max_inbound_connections: usize,
    /// Maximum outbound connections
    pub max_outbound_connections: usize,
    /// Maximum allowed message size (bytes)
    pub max_message_size: usize,
    /// Maximum pending requests per peer
    pub max_pending_requests_per_peer: usize,
    /// Timeout for block sync requests
    pub block_sync_timeout: std::time::Duration,
    /// Timeout for transaction propagation
    pub tx_propagation_timeout: std::time::Duration,
    /// Queue size for transaction propagation
    pub tx_propagation_queue_size: usize,
    /// Enable transaction relay
    pub enable_tx_relay: bool,
    /// Enable block relay
    pub enable_block_relay: bool,
    /// TCP port to listen on
    pub listen_port: u16,
}

/// Combined network behaviour for Rusty Coin P2P.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[doc = "Combined network behaviour for Rusty Coin P2P."]
pub struct CombinedBehaviour {
    /// Gossipsub behaviour for pubsub messaging
    pub gossipsub: Gossipsub,
    /// Identify protocol behaviour
    pub identify: Identify,
    /// Ping protocol behaviour
    pub ping: Ping,
    /// Block sync request/response protocol
    pub block_sync: RequestResponse<BlockSyncCodec>,
    /// Transaction propagation request/response protocol
    pub tx_prop: RequestResponse<TxPropCodec>,
    /// Kademlia DHT behaviour
    pub kademlia: Kademlia<MemoryStore>,
    /// mDNS peer discovery behaviour
    pub mdns: MdnsTokioBehaviour,
}

/// Network event type for Rusty Coin P2P.
#[derive(Debug)]
pub enum RustyCoinEvent {
    /// Gossipsub event
    Gossipsub(GossipsubEvent),
    /// Identify event
    Identify(IdentifyEvent),
    /// Kademlia DHT event
    Kademlia(KademliaEvent),
    /// mDNS event
    Mdns(MdnsEvent),
    /// Ping event
    Ping(PingEvent),
    /// Block sync request/response event
    BlockSync(RequestResponseEvent<BlockSyncRequest, BlockSyncResponse>),
    /// Transaction propagation request/response event
    TxProp(RequestResponseEvent<TxPropRequest, TxPropResponse>),
    /// Node started listening on an address
    StartedListening(Multiaddr),
    /// Peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Dial to peer failed
    DialFailure(PeerId, String),
    /// Received a P2P message
    Message(PeerId, crate::types::P2PMessage),
}

// Implement From<Event> for RustyCoinEvent for all sub-behaviour events
impl From<GossipsubEvent> for RustyCoinEvent {
    fn from(event: GossipsubEvent) -> Self {
        RustyCoinEvent::Gossipsub(event)
    }
}

impl From<IdentifyEvent> for RustyCoinEvent {
    fn from(event: IdentifyEvent) -> Self {
        RustyCoinEvent::Identify(event)
    }
}

impl From<KademliaEvent> for RustyCoinEvent {
    fn from(event: KademliaEvent) -> Self {
        RustyCoinEvent::Kademlia(event)
    }
}

impl From<MdnsEvent> for RustyCoinEvent {
    fn from(event: MdnsEvent) -> Self {
        RustyCoinEvent::Mdns(event)
    }
}

impl From<PingEvent> for RustyCoinEvent {
    fn from(event: PingEvent) -> Self {
        RustyCoinEvent::Ping(event)
    }
}

impl From<RequestResponseEvent<BlockSyncRequest, BlockSyncResponse>> for RustyCoinEvent {
    fn from(event: RequestResponseEvent<BlockSyncRequest, BlockSyncResponse>) -> Self {
        RustyCoinEvent::BlockSync(event)
    }
}

impl From<RequestResponseEvent<TxPropRequest, TxPropResponse>> for RustyCoinEvent {
    fn from(event: RequestResponseEvent<TxPropRequest, TxPropResponse>) -> Self {
        RustyCoinEvent::TxProp(event)
    }
}
