use async_trait::async_trait;

use crate::types::{P2PMessage, BlockRequest, BlockResponse, GetHeaders, Headers, PeerInfo};

pub mod sync;
pub mod sync_manager;

/// Peer identifier type
pub type PeerId = String;

/// Trait for P2P network implementations
#[async_trait]
pub trait P2PNetwork: Send + Sync {
    /// Send a message to a specific peer
    async fn send_message(&mut self, peer_id: PeerId, message: P2PMessage) -> Result<(), String>;

    /// Broadcast a message to all connected peers
    async fn broadcast_message(&mut self, message: P2PMessage) -> Result<(), String>;

    /// Receive a message from the network
    async fn receive_message(&mut self) -> Option<(PeerId, P2PMessage)>;

    /// Get information about a specific peer
    async fn get_peer_info(&self, peer_id: PeerId) -> Option<PeerInfo>;

    /// Get list of connected peers
    fn get_connected_peers(&self) -> Vec<PeerId>;

    /// Request blocks from a peer
    async fn request_blocks(&mut self, peer_id: PeerId, request: BlockRequest) -> Option<BlockResponse>;

    /// Request headers from a peer
    async fn request_headers(&mut self, peer_id: PeerId, request: GetHeaders) -> Option<Headers>;
}
