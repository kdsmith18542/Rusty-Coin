//! Rusty Coin P2P Network Implementation
//! 
//! This crate provides the peer-to-peer networking functionality for the Rusty Coin
//! blockchain, including block and transaction propagation, peer discovery, and more.

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]

pub mod network;
pub mod protocols;
pub mod types;
pub mod p2p_network;

// Re-export commonly used types
pub use libp2p::{Multiaddr, PeerId};
pub use network::{RustyCoinBehaviour, RustyCoinEvent, RustyCoinNetworkConfig};
pub use p2p_network::P2PNetwork;
pub use protocols::{
    block_sync::{BlockSyncRequest, BlockSyncResponse, BlockData, BlockHeaderData},
    peer_discovery::PeerDiscoveryConfig,
    tx_prop::TxPropHandler,
};
pub use protocols::peer_discovery::DiscoveryEvent;
pub use protocols::peer_discovery::PeerDiscovery;