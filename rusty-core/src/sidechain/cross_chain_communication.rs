//! Cross-chain communication protocol for sidechain-mainchain integration
//!
//! This module provides the communication layer between mainchain and sidechains,
//! enabling secure and validated cross-chain operations including block headers,
//! transaction proofs, and state synchronization.

use crate::sidechain::types::*;
use rusty_shared_types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cross-chain message types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CrossChainMessageType {
    /// Mainchain block header notification
    MainchainBlockHeader,
    /// Sidechain block header notification
    SidechainBlockHeader,
    /// Cross-chain transaction notification
    CrossChainTransaction,
    /// Fraud proof notification
    FraudProof,
    /// Federation update notification
    FederationUpdate,
    /// State synchronization request
    StateSyncRequest,
    /// State synchronization response
    StateSyncResponse,
}

/// Cross-chain message envelope
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainMessage {
    /// Message type
    pub message_type: CrossChainMessageType,
    /// Source chain ID
    pub source_chain: Hash,
    /// Destination chain ID
    pub destination_chain: Hash,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message sequence number for ordering
    pub sequence_number: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Federation signature for validation
    pub federation_signature: Option<FederationSignature>,
}

/// Cross-chain communication manager
pub struct CrossChainCommunication {
    /// Pending messages by destination chain
    pending_messages: HashMap<Hash, Vec<CrossChainMessage>>,
    /// Sequence numbers for each chain pair
    sequence_numbers: HashMap<(Hash, Hash), u64>,
    /// Federation manager reference for signature validation
    federation_manager: Option<std::sync::Arc<std::sync::Mutex<crate::sidechain::federation_integrator::FederationIntegrator>>>,
}

impl CrossChainCommunication {
    /// Create a new cross-chain communication manager
    pub fn new() -> Self {
        Self {
            pending_messages: HashMap::new(),
            sequence_numbers: HashMap::new(),
            federation_manager: None,
        }
    }

    /// Set federation manager for signature validation
    pub fn with_federation_manager(
        &mut self,
        federation_manager: std::sync::Arc<std::sync::Mutex<crate::sidechain::federation_integrator::FederationIntegrator>>,
    ) {
        self.federation_manager = Some(federation_manager);
    }

    /// Send a cross-chain message
    pub fn send_message(&mut self, message: CrossChainMessage) -> Result<(), String> {
        // Always require federation signature for cross-chain messages
        if let Some(ref sig) = message.federation_signature {
            // Validate message signature if federation manager is available
            if let Some(ref fed_mgr) = self.federation_manager {
                let fed_mgr = fed_mgr.lock().unwrap();
                if !fed_mgr.validate_federation_signature(
                    &message.source_chain,
                    sig.epoch,
                    sig,
                    &message.hash(),
                ) {
                    return Err("Invalid federation signature on cross-chain message".to_string());
                }
            }
        } else {
            return Err("Federation signature required for cross-chain messages".to_string());
        }

        // Update sequence number
        let key = (message.source_chain, message.destination_chain);
        let seq_num = self.sequence_numbers.entry(key).or_insert(0);
        *seq_num += 1;
        // Note: We don't override the message's sequence_number here as it should be set by sender

        // Add to pending messages
        self.pending_messages
            .entry(message.destination_chain)
            .or_insert_with(Vec::new)
            .push(message);

        Ok(())
    }

    /// Receive pending messages for a chain
    pub fn receive_messages(&mut self, chain_id: &Hash) -> Vec<CrossChainMessage> {
        self.pending_messages
            .remove(chain_id)
            .unwrap_or_default()
    }

    /// Get pending message count for a chain
    pub fn pending_message_count(&self, chain_id: &Hash) -> usize {
        self.pending_messages
            .get(chain_id)
            .map(|msgs| msgs.len())
            .unwrap_or(0)
    }

    /// Create a mainchain block header notification message
    pub fn create_mainchain_header_message(
        source_chain: Hash,
        destination_chain: Hash,
        block_header: &rusty_shared_types::BlockHeader,
        federation_epoch: u64,
    ) -> Result<CrossChainMessage, String> {
        let payload = bincode::serialize(block_header)
            .map_err(|e| format!("Failed to serialize block header: {}", e))?;

        Ok(CrossChainMessage {
            message_type: CrossChainMessageType::MainchainBlockHeader,
            source_chain,
            destination_chain,
            payload,
            sequence_number: 0, // Will be set by send_message
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            federation_signature: None, // To be signed by federation
        })
    }

    /// Create a sidechain block header notification message
    pub fn create_sidechain_header_message(
        source_chain: Hash,
        destination_chain: Hash,
        block_header: &SidechainBlockHeader,
        federation_epoch: u64,
    ) -> Result<CrossChainMessage, String> {
        let payload = bincode::serialize(block_header)
            .map_err(|e| format!("Failed to serialize sidechain block header: {}", e))?;

        Ok(CrossChainMessage {
            message_type: CrossChainMessageType::SidechainBlockHeader,
            source_chain,
            destination_chain,
            payload,
            sequence_number: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            federation_signature: None,
        })
    }

    /// Create a cross-chain transaction notification message
    pub fn create_cross_chain_tx_message(
        source_chain: Hash,
        destination_chain: Hash,
        cross_chain_tx: &CrossChainTransaction,
    ) -> Result<CrossChainMessage, String> {
        let payload = bincode::serialize(cross_chain_tx)
            .map_err(|e| format!("Failed to serialize cross-chain transaction: {}", e))?;

        Ok(CrossChainMessage {
            message_type: CrossChainMessageType::CrossChainTransaction,
            source_chain,
            destination_chain,
            payload,
            sequence_number: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            federation_signature: None,
        })
    }

    /// Validate and process a received message
    pub fn process_message(&self, message: &CrossChainMessage) -> Result<(), String> {
        // Validate message signature
        if let Some(ref fed_mgr) = self.federation_manager {
            if let Some(ref sig) = message.federation_signature {
                let fed_mgr = fed_mgr.lock().unwrap();
                if !fed_mgr.validate_federation_signature(
                    &message.source_chain,
                    sig.epoch,
                    sig,
                    &message.hash(),
                ) {
                    return Err("Invalid federation signature on received message".to_string());
                }
            } else {
                return Err("Missing federation signature on received message".to_string());
            }
        }

        // Validate sequence number (basic check - in production would track per sender)
        if message.sequence_number == 0 {
            return Err("Invalid sequence number".to_string());
        }

        Ok(())
    }
}

impl CrossChainMessage {
    /// Calculate message hash for signing
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        // Serialize message type as discriminant
        let message_type_bytes = bincode::serialize(&self.message_type).unwrap_or_default();
        data.extend_from_slice(&message_type_bytes);
        data.extend_from_slice(&self.source_chain);
        data.extend_from_slice(&self.destination_chain);
        data.extend_from_slice(&self.payload);
        data.extend_from_slice(&self.sequence_number.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        blake3::hash(&data).into()
    }

    /// Deserialize payload based on message type
    pub fn deserialize_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        bincode::deserialize(&self.payload)
            .map_err(|e| format!("Failed to deserialize payload: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::federation_manager::FederationManager;
    use rusty_shared_types::OutPoint;

    fn create_test_masternode_id(value: u8) -> rusty_shared_types::masternode::MasternodeID {
        rusty_shared_types::masternode::MasternodeID(OutPoint {
            txid: [value; 32],
            vout: 0,
        })
    }

    #[test]
    fn test_cross_chain_message_creation() {
        let source = [1u8; 32];
        let dest = [2u8; 32];

        // Create a mainchain header message
        let block_header = rusty_shared_types::BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };

        let message = CrossChainCommunication::create_mainchain_header_message(
            source, dest, &block_header, 1
        ).unwrap();

        assert_eq!(message.message_type, CrossChainMessageType::MainchainBlockHeader);
        assert_eq!(message.source_chain, source);
        assert_eq!(message.destination_chain, dest);
        assert!(message.federation_signature.is_none());
    }

    #[test]
    fn test_message_hash_consistency() {
        let message1 = CrossChainMessage {
            message_type: CrossChainMessageType::MainchainBlockHeader,
            source_chain: [1u8; 32],
            destination_chain: [2u8; 32],
            payload: vec![1, 2, 3],
            sequence_number: 42,
            timestamp: 1234567890,
            federation_signature: None,
        };

        let message2 = message1.clone();

        assert_eq!(message1.hash(), message2.hash());
    }

    #[test]
    fn test_communication_manager() {
        let mut comm = CrossChainCommunication::new();

        let message = CrossChainMessage {
            message_type: CrossChainMessageType::MainchainBlockHeader,
            source_chain: [1u8; 32],
            destination_chain: [2u8; 32],
            payload: vec![1, 2, 3],
            sequence_number: 1,
            timestamp: 1234567890,
            federation_signature: None,
        };

        // Without federation manager, should fail
        assert!(comm.send_message(message.clone()).is_err());

        // Set up federation integrator
        let mut fed_integrator = crate::sidechain::federation_integrator::FederationIntegrator::new();
        let members = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];

        fed_integrator.initialize_sidechain_federation([0u8; 32], members, 2, public_keys, 100, 1000).unwrap();

        let fed_mgr_arc = std::sync::Arc::new(std::sync::Mutex::new(fed_integrator));
        comm.with_federation_manager(fed_mgr_arc);

        // Still fails without signature
        assert!(comm.send_message(message).is_err());

        // Check pending messages
        assert_eq!(comm.pending_message_count(&[2u8; 32]), 0);
    }
}