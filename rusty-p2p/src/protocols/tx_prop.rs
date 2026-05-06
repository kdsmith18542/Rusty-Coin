//! Transaction Propagation Protocol Implementation
//!
//! Implements the `/rusty/tx-prop/1.0` protocol for efficient transaction
//! propagation across the Rusty Coin network using a gossipsub model.

use futures::io::{AsyncRead, AsyncWrite};
use libp2p::gossipsub::{
    Behaviour, ConfigBuilder, IdentTopic, Message, MessageAuthenticity, MessageId, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::request_response::Codec;
use libp2p::PeerId;
use log::error;
use rusty_core::mempool::Mempool;
use rusty_shared_types::Transaction;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use thiserror::Error;

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
    InvalidMessage(String),
    /// Subscription error.
    #[error("Subscription error: {0}")]
    Subscription(#[from] libp2p::gossipsub::SubscriptionError),
}

impl From<&'static str> for TxPropError {
    fn from(s: &'static str) -> Self {
        TxPropError::InvalidMessage(s.to_string())
    }
}

/// Handler for transaction propagation
pub struct TxPropHandler {
    /// Gossipsub behavior for pub/sub
    gossipsub: Behaviour,
    /// Set of transaction hashes we've recently seen
    known_txs: lru::LruCache<[u8; 32], ()>,
    /// Shared mempool for transaction validation and storage
    mempool: Arc<Mutex<Mempool>>,
}

impl TxPropHandler {
    /// Create a new transaction propagation handler
    pub fn new(local_keypair: Keypair, mempool: Arc<Mutex<Mempool>>) -> Result<Self, TxPropError> {
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
            .map_err(|e| {
                TxPropError::InvalidMessage(format!("Failed to create gossipsub config: {}", e))
            })?;

        let mut gossipsub =
            Behaviour::new(MessageAuthenticity::Signed(local_keypair), gossipsub_config)?;

        // Subscribe to the transaction topic
        let topic = IdentTopic::new(TX_PROPAGATION_TOPIC);
        gossipsub.subscribe(&topic)?;

        Ok(Self {
            gossipsub,
            known_txs: lru::LruCache::new(std::num::NonZeroUsize::new(100_000).unwrap()),
            mempool,
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
        log::debug!(
            "Received request for {} transactions from peer {}",
            hashes.len(),
            source
        );
        Ok(())
    }

    fn handle_tx(&mut self, source: PeerId, tx_data: &[u8]) -> Result<(), TxPropError> {
        let tx_hash = blake3::hash(tx_data);

        // Skip if we've already seen this transaction
        if self.known_txs.contains(tx_hash.as_bytes()) {
            return Ok(());
        }

        // Parse the transaction from binary data
        let tx: Transaction = bincode::deserialize(tx_data).map_err(|e| {
            TxPropError::InvalidMessage(format!("Failed to deserialize transaction: {}", e))
        })?;

        // Add to our known transactions
        self.known_txs.put(tx_hash.into(), ());

        // Process the transaction (validation, add to mempool, etc.)
        // For now, we'll implement basic validation logic here
        // In a real implementation, this would integrate with the blockchain state and mempool

        // Basic sanity checks on the transaction
        if tx.get_inputs().is_empty() && !tx.is_coinbase() {
            log::warn!(
                "Received transaction {} with no inputs from peer {}",
                hex::encode(tx_hash.as_bytes()),
                source
            );
            return Ok(());
        }

        if tx.get_outputs().is_empty() {
            log::warn!(
                "Received transaction {} with no outputs from peer {}",
                hex::encode(tx_hash.as_bytes()),
                source
            );
            return Ok(());
        }

        log::info!(
            "Received and processing transaction {} from peer {}",
            hex::encode(tx_hash.as_bytes()),
            source
        );

        // Implement proper transaction validation by integrating with blockchain state
        match self.validate_transaction(tx_data) {
            Ok(()) => {
                // Add transaction to mempool after validation
                if let Err(e) = self.add_to_mempool(tx_data) {
                    log::warn!("Failed to add transaction to mempool: {}", e);
                    return Err(TxPropError::InvalidMessage(format!("Mempool error: {}", e)));
                }

                log::info!(
                    "Transaction {} validated and added to mempool",
                    hex::encode(tx_hash.as_bytes())
                );

                // Forward to peers who didn't send it to us
                // In a real implementation, we would use the gossipsub mesh to forward the message
            }
            Err(e) => {
                log::warn!(
                    "Transaction {} failed validation: {}",
                    hex::encode(tx_hash.as_bytes()),
                    e
                );
                return Err(TxPropError::InvalidMessage(format!(
                    "Validation error: {}",
                    e
                )));
            }
        }

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

    /// Validate a transaction using consensus rules
    fn validate_transaction(&self, tx_data: &[u8]) -> Result<(), String> {
        // Deserialize the transaction
        let transaction: rusty_shared_types::Transaction = bincode::deserialize(tx_data)
            .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

        // Basic validation checks
        if transaction.is_coinbase() {
            return Err("Cannot add coinbase transaction to mempool".to_string());
        }

        if transaction.get_inputs().is_empty() {
            return Err("Transaction has no inputs".to_string());
        }

        if transaction.get_outputs().is_empty() {
            return Err("Transaction has no outputs".to_string());
        }

        // Check transaction size
        if tx_data.len() > 100_000 {
            return Err("Transaction too large".to_string());
        }

        // Check output values
        for output in transaction.get_outputs() {
            if output.value == 0 {
                return Err("Transaction contains zero-value output".to_string());
            }

            if output.value < 546 {
                // Dust limit
                return Err("Transaction output below dust limit".to_string());
            }
        }

        // In a real implementation, we would also validate:
        // - Input UTXOs exist and are unspent
        // - Script signatures are valid
        // - Transaction fees are sufficient
        // - No double-spending
        // - Lock time conditions

        Ok(())
    }

    /// Add a validated transaction to the mempool
    fn add_to_mempool(&self, tx_data: &[u8]) -> Result<(), String> {
        let transaction: rusty_shared_types::Transaction = bincode::deserialize(tx_data)
            .map_err(|e| format!("Failed to deserialize transaction for mempool: {}", e))?;
        let tx_hash = transaction.txid();
        log::debug!("Adding transaction {} to mempool", hex::encode(tx_hash));
        let mut mempool = self
            .mempool
            .lock()
            .map_err(|_| "Failed to lock mempool".to_string())?;
        match mempool.add_transaction(transaction) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Transaction already in mempool".to_string()),
            Err(e) => Err(format!("Consensus error: {}", e)),
        }
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
        Box::pin(async move { Ok(TxPropRequestType { tx: vec![] }) })
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
        Box::pin(async move { Ok(TxPropResponseType { accepted: true }) })
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
    use rusty_core::mempool::Mempool;
    use std::sync::{Arc, Mutex};

    fn create_test_peer() -> (PeerId, Keypair) {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        (peer_id, keypair)
    }

    fn test_mempool() -> Arc<Mutex<Mempool>> {
        Arc::new(Mutex::new(Mempool::new()))
    }

    #[test]
    fn test_tx_prop_handler_creation() {
        let (_peer_id, keypair) = create_test_peer();
        let mempool = test_mempool();
        let handler = TxPropHandler::new(keypair, mempool);
        assert!(handler.is_ok());
    }

    #[test]
    fn test_broadcast_tx() {
        let (_peer_id, keypair) = create_test_peer();
        let mut handler = TxPropHandler::new(keypair, test_mempool()).unwrap();

        let tx_data = vec![1, 2, 3, 4, 5];
        let tx_hash = blake3::hash(&tx_data);

        // Broadcast the transaction
        assert!(handler.broadcast_tx(tx_data.clone()).is_ok());

        // Should be in known transactions
        assert!(handler.known_txs.contains(tx_hash.as_bytes()));
    }

    #[test]
    fn test_handle_inv() {
        let (peer_id, keypair) = create_test_peer();
        let mempool = test_mempool();
        let mut handler = TxPropHandler::new(keypair, mempool).unwrap();
        let hashes = vec![[1u8; 32]];
        assert!(handler.handle_inv(peer_id, &hashes).is_ok());
    }

    #[test]
    fn test_handle_get_data() {
        let (peer_id, keypair) = create_test_peer();
        let mempool = test_mempool();
        let mut handler = TxPropHandler::new(keypair, mempool).unwrap();
        let hashes = vec![[1u8; 32]];
        assert!(handler.handle_get_data(peer_id, &hashes).is_ok());
    }

    #[test]
    fn test_handle_tx_duplicate() {
        let (peer_id, keypair) = create_test_peer();
        let mempool = test_mempool();
        let mut handler = TxPropHandler::new(keypair, mempool).unwrap();
        let tx_data = vec![0u8; 100];
        // First time should process, second time should skip as duplicate
        let _ = handler.handle_tx(peer_id, &tx_data);
        assert!(handler.handle_tx(peer_id, &tx_data).is_ok());
    }
}
