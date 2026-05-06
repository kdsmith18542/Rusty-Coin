use async_trait::async_trait;

use crate::types::{BlockRequest, BlockResponse, GetHeaders, Headers, P2PMessage, PeerInfo};

pub mod sync;
pub mod sync_manager;

/// Peer identifier type
pub type PeerId = String;

/// Trait for P2P network implementations
pub trait P2PNetwork: Send + Sync {
    /// Send a message to a specific peer
    fn send_message(&self, peer_id: PeerId, message: P2PMessage) -> Result<(), String>;

    /// Broadcast a message to all connected peers
    fn broadcast_message(&self, message: P2PMessage) -> Result<(), String>;

    /// Receive a message from the network
    fn receive_message(&mut self) -> Option<(PeerId, P2PMessage)>;

    /// Get information about a specific peer
    fn get_peer_info(&self, peer_id: PeerId) -> Option<PeerInfo>;

    /// Get list of connected peers
    fn get_connected_peers(&self) -> Vec<PeerId>;

    /// Request blocks from a peer
    fn request_blocks(
        &self,
        peer_id: PeerId,
        request: BlockRequest,
    ) -> Option<BlockResponse>;

    /// Request headers from a peer
    fn request_headers(&self, peer_id: PeerId, request: GetHeaders) -> Option<Headers>;
}
