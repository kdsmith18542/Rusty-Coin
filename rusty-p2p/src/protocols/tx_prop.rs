//! Transaction Propagation Protocol Implementation
//! 
//! Implements the `/rusty/tx-prop/1.0` protocol for efficient transaction
//! propagation across the Rusty Coin network using a gossipsub model.

use libp2p::gossipsub::{Behaviour, ConfigBuilder, ValidationMode, MessageAuthenticity, Message, IdentTopic, MessageId};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use log::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::io;
use std::pin::Pin;
use std::future::Future;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::request_response::Codec;

/// Topic for transaction propagation
pub const TX_PROPAGATION_TOPIC: &str = "/rusty/txs/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Transaction propagation protocol message types.
pub enum TxPropMessage {
    /// Inventory message containing transaction hashes.
    Inv(Vec<[u8; 32]>),
    /// Request for specific transactions by hash.
    GetData(Vec<[u8; 32]>),
    /// Full transaction data.
    Tx(Vec<u8>),
}

/// Errors that can occur during transaction propagation.
#[derive(Debug, Error)]
pub enum TxPropError {
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    /// Gossipsub error.
    #[error("Gossipsub error: {0}")]
    Gossipsub(#[from] libp2p::gossipsub::PublishError),
    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),
    /// Invalid message error.
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    /// Subscription error.
    #[error("Subscription error: {0}")]
    Subscription(#[from] libp2p::gossipsub::SubscriptionError),
}

impl From<&'static str> for TxPropError {
    fn from(s: &'static str) -> Self {
        TxPropError::Protocol(s.to_string())
    }
}

/// Handler for transaction propagation
pub struct TxPropHandler {
    /// Gossipsub behavior for pub/sub
    gossipsub: Behaviour,
    /// Set of transaction hashes we've recently seen
    known_txs: lru::LruCache<[u8; 32], ()>,
}

impl TxPropHandler {
    /// Create a new transaction propagation handler
    pub fn new(local_keypair: Keypair) -> Result<Self, TxPropError> {
        let message_id_fn = |message: &Message| {
            // Create a message id using the transaction hash if available
            // Otherwise fall back to the default message id
            if let Ok(tx_msg) = bincode::deserialize::<TxPropMessage>(&message.data) {
                if let TxPropMessage::Tx(tx_data) = tx_msg {
                    if tx_data.len() >= 32 {
                        let mut tx_hash = [0u8; 32];
                        tx_hash.copy_from_slice(&tx_data[..32]);
                        return MessageId::from(tx_hash.to_vec());
                    }
                }
            }
            // Default to the message hash
            MessageId::from(message.data.as_slice())
        };

        let gossipsub_config = ConfigBuilder::default()
            .max_transmit_size(1_000_000) // 1MB max message size
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|e| TxPropError::Protocol(format!("Failed to create gossipsub config: {}", e)))?;

        let mut gossipsub = Behaviour::new(
            MessageAuthenticity::Signed(local_keypair),
            gossipsub_config,
        )?;

        // Subscribe to the transaction topic
        let topic = IdentTopic::new(TX_PROPAGATION_TOPIC);
        gossipsub.subscribe(&topic)?;

        Ok(Self {
            gossipsub,
            known_txs: lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()),
        })
    }

    /// Handle an incoming message from a peer
    pub fn handle_message(&mut self, source: PeerId, message: &[u8]) -> Result<(), TxPropError> {
        let tx_msg: TxPropMessage = bincode::deserialize(message)?;
        
        match tx_msg {
            TxPropMessage::Inv(hashes) => {
                self.handle_inv(source, &hashes)?;
            }
            TxPropMessage::GetData(hashes) => {
                self.handle_get_data(source, &hashes)?;
            }
            TxPropMessage::Tx(tx_data) => {
                self.handle_tx(source, &tx_data)?;
            }
        }
        
        Ok(())
    }
    
    /// Broadcast a new transaction to the network
    pub fn broadcast_tx(&mut self, tx_data: Vec<u8>) -> Result<(), TxPropError> {
        let tx_hash = blake3::hash(&tx_data);
        
        // Add to our known transactions
        self.known_txs.put(tx_hash.into(), ());
        
        // Create and publish the transaction message
        let message = TxPropMessage::Tx(tx_data);
        let serialized = bincode::serialize(&message)?;
        
        let topic = IdentTopic::new(TX_PROPAGATION_TOPIC);
        self.gossipsub.publish(topic, serialized)?;
        
        Ok(())
    }
    
    fn handle_inv(&mut self, source: PeerId, hashes: &[[u8; 32]]) -> Result<(), TxPropError> {
        // Filter out transactions we already know about
        let unknown_hashes: Vec<[u8; 32]> = hashes
            .iter()
            .filter(|h| !self.known_txs.contains(*h))
            .cloned()
            .collect();
            
        if !unknown_hashes.is_empty() {
            // Request the unknown transactions
            let get_data = TxPropMessage::GetData(unknown_hashes.clone());
            let _serialized = bincode::serialize(&get_data)?;
            // In a real implementation, we would send this to the peer
            // For now, we'll just log it
            log::debug!("Requesting {} txs from {}", unknown_hashes.len(), source);
        }
        
        Ok(())
    }
    
    fn handle_get_data(&mut self, source: PeerId, hashes: &[[u8; 32]]) -> Result<(), TxPropError> {
        // In a real implementation, we would look up the requested transactions
        // in our mempool and send them to the peer
        // For now, we'll just log the request
        log::debug!("Received request for {} transactions from peer {}", hashes.len(), source);
        Ok(())
    }
    
    fn handle_tx(&mut self, source: PeerId, tx_data: &[u8]) -> Result<(), TxPropError> {
        let tx_hash = blake3::hash(tx_data);
        
        // Skip if we've already seen this transaction
        if self.known_txs.contains(tx_hash.as_bytes()) {
            return Ok(());
        }
        
        // Add to our known transactions
        self.known_txs.put(tx_hash.into(), ());
        
        // Process the transaction (validation, add to mempool, etc.)
        // TODO: Implement transaction validation and mempool logic
        log::debug!("Received new transaction {} from peer {}", hex::encode(tx_hash.as_bytes()), source);
        
        // Forward to peers who didn't send it to us
        // In a real implementation, we would use the gossipsub mesh to forward the message
        
        Ok(())
    }
    
    /// Get a reference to the underlying gossipsub behavior
    pub fn gossipsub(&self) -> &Behaviour {
        &self.gossipsub
    }
    
    /// Get a mutable reference to the underlying gossipsub behavior
    pub fn gossipsub_mut(&mut self) -> &mut Behaviour {
        &mut self.gossipsub
    }
}

/// Transaction propagation request for request-response protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPropRequest {
    /// Raw transaction data.
    pub tx: Vec<u8>,
}

/// Transaction propagation response for request-response protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPropResponse {
    /// Whether the transaction was accepted.
    pub accepted: bool,
}

/// Transaction propagation protocol marker type.
#[derive(Debug, Clone)]
pub struct TxPropProtocol;

impl AsRef<str> for TxPropProtocol {
    fn as_ref(&self) -> &str {
        "/rusty/tx-prop/1.0"
    }
}

/// Codec for transaction propagation request-response protocol.
#[derive(Default, Clone)]
pub struct TxPropCodec;

/// Type alias for transaction propagation request
pub type TxPropRequestType = TxPropRequest;
/// Type alias for transaction propagation response
pub type TxPropResponseType = TxPropResponse;

impl Codec for TxPropCodec {
    type Protocol = TxPropProtocol;
    type Request = TxPropRequestType;
    type Response = TxPropResponseType;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Request>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(TxPropRequestType {
            tx: vec![],
        }) })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(TxPropResponseType {
            accepted: true,
        }) })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
        _req: Self::Request,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(()) })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
        _res: Self::Response,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    
    fn create_test_peer() -> (PeerId, Keypair) {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        (peer_id, keypair)
    }
    
    #[test]
    fn test_tx_prop_handler_creation() {
        let (peer_id, _) = create_test_peer();
        let handler = TxPropHandler::new(peer_id);
        assert!(handler.is_ok());
    }
    
    #[test]
    fn test_broadcast_tx() {
        let (peer_id, _) = create_test_peer();
        let mut handler = TxPropHandler::new(peer_id).unwrap();
        
        let tx_data = vec![1, 2, 3, 4, 5];
        let tx_hash = blake3::hash(&tx_data);
        
        // Broadcast the transaction
        assert!(handler.broadcast_tx(tx_data.clone()).is_ok());
        
        // Should be in known transactions
        assert!(handler.known_txs.contains(tx_hash.as_bytes()));
    }
    
    #[test]
    fn test_handle_inv() {
        let (peer_id, _) = create_test_peer();
        let mut handler = TxPropHandler::new(peer_id).unwrap();
        
        // Create some test transaction hashes
        let tx_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        // Handle the INV message
        let result = handler.handle_inv(PeerId::random(), &tx_hashes);
        assert!(result.is_ok());
        
        // The handler should now know about these transactions
        for hash in &tx_hashes {
            assert!(handler.known_txs.contains(hash));
        }
    }
    
    #[test]
    fn test_handle_duplicate_tx() {
        let (peer_id, _) = create_test_peer();
        let mut handler = TxPropHandler::new(peer_id).unwrap();
        
        let tx_data = vec![1, 2, 3, 4, 5];
        let tx_hash = blake3::hash(&tx_data);
        
        // Add to known transactions
        handler.known_txs.put(tx_hash.into(), ());
        
        // Try to handle the same transaction again
        let result = handler.handle_tx(PeerId::random(), &tx_data);
        assert!(result.is_ok());
        
        // Should still only have one transaction in the cache
        assert_eq!(handler.known_txs.len(), 1);
    }
}
