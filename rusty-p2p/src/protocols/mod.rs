//! P2P protocol implementations for Rusty Coin
//! 
//! This module contains the implementation of various P2P protocols used in the network,
//! including block synchronization, transaction propagation, and peer discovery.

pub mod block_sync;
pub mod tx_prop;
pub mod peer_discovery;

use libp2p::request_response::ProtocolSupport;
use libp2p::StreamProtocol;

/// Protocol versions and names
pub const BLOCK_SYNC_PROTOCOL: &str = "/rusty/block-sync/1.0";

/// Protocol string for transaction propagation protocol.
pub const TX_PROPAGATION_PROTOCOL: &str = "/rusty/tx-prop/1.0";

/// Returns the list of supported protocols with their supported modes
pub fn supported_protocols() -> Vec<(StreamProtocol, ProtocolSupport)> {
    vec![
        (StreamProtocol::new(BLOCK_SYNC_PROTOCOL), ProtocolSupport::Full),
        (StreamProtocol::new(TX_PROPAGATION_PROTOCOL), ProtocolSupport::Full),
    ]
}
