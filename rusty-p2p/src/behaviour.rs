//! Rusty Coin P2P Behaviour and Event Types (restored from backup)

// Use correct subcrate imports for all libp2p types (latest API)
use crate::protocols::{
    block_sync::{BlockSyncCodec, BlockSyncRequest, BlockSyncResponse},
    proof_sync::{ProofSyncCodec, ProofSyncRequest, ProofSyncResponse},
    tx_prop::{TxPropCodec, TxPropRequest, TxPropResponse},
};
use libp2p::gossipsub::{Behaviour as Gossipsub, Event as GossipsubEvent};
use libp2p::identify::{Behaviour as Identify, Event as IdentifyEvent};
use libp2p::kad::{store::MemoryStore, Behaviour as Kademlia, Event as KademliaEvent};
use libp2p::mdns::{tokio::Behaviour as MdnsTokioBehaviour, Event as MdnsEvent};
use libp2p::ping::{Behaviour as Ping, Event as PingEvent};
use libp2p::request_response::{Behaviour as RequestResponse, Event as RequestResponseEvent};
use libp2p::Multiaddr;
use libp2p::PeerId;

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
    /// Rate limit: maximum messages per peer per second
    pub max_messages_per_peer_per_second: u32,
    /// Rate limit: maximum bytes per peer per second
    pub max_bytes_per_peer_per_second: u64,
    /// Rate limit: window duration for tracking message counts
    pub rate_limit_window_duration: std::time::Duration,
}

/// Combined network behaviour for Rusty Coin P2P.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[allow(missing_docs)]
pub struct CombinedBehaviour {
    #[allow(missing_docs)]
    /// Gossipsub behaviour for pubsub messaging
    pub gossipsub: Gossipsub,
    #[allow(missing_docs)]
    /// Identify protocol behaviour
    pub identify: Identify,
    #[allow(missing_docs)]
    /// Ping protocol behaviour
    pub ping: Ping,
    #[allow(missing_docs)]
    /// Block sync request/response protocol
    pub block_sync: RequestResponse<BlockSyncCodec>,
    #[allow(missing_docs)]
    /// Transaction propagation request/response protocol
    pub tx_prop: RequestResponse<TxPropCodec>,
    #[allow(missing_docs)]
    /// State proof synchronization request/response protocol
    pub proof_sync: RequestResponse<ProofSyncCodec>,
    #[allow(missing_docs)]
    /// Kademlia DHT behaviour
    pub kademlia: Kademlia<MemoryStore>,
    #[allow(missing_docs)]
    /// mDNS peer discovery behaviour
    pub mdns: MdnsTokioBehaviour,
}

/// Network event type for Rusty Coin P2P.
#[derive(Debug)]
#[allow(missing_docs)]
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
    /// State proof synchronization request/response event
    ProofSync(RequestResponseEvent<ProofSyncRequest, ProofSyncResponse>),
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

impl From<RequestResponseEvent<ProofSyncRequest, ProofSyncResponse>> for RustyCoinEvent {
    fn from(event: RequestResponseEvent<ProofSyncRequest, ProofSyncResponse>) -> Self {
        RustyCoinEvent::ProofSync(event)
    }
}
