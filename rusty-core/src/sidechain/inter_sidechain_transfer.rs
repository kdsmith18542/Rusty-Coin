//! Inter-Sidechain Transfer Mechanism
//!
//! This module implements the mechanism for transferring assets between different sidechains,
//! coordinated through the mainchain. Per spec 10 (Sidechain Protocol) Section 4.3.

use hex;
use log::{info, warn};
use rusty_shared_types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::sidechain::{
    CrossChainProof, CrossChainTransaction, FederationSignature,
    SidechainTransaction,
};

/// Status of an inter-sidechain transfer
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InterSidechainStatus {
    /// Transfer initiated on source sidechain
    Initiated,
    /// Waiting for source sidechain confirmation
    WaitingSourceConfirmation { current: u32, required: u32 },
    /// Waiting for mainchain coordination
    WaitingMainchainCoordination,
    /// Waiting for destination sidechain confirmation
    WaitingDestinationConfirmation { current: u32, required: u32 },
    /// Transfer completed
    Completed,
    /// Transfer failed
    Failed { reason: String },
    /// Transfer timed out
    TimedOut,
}

/// Inter-sidechain transfer record
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterSidechainTransfer {
    /// Unique identifier for this transfer
    pub transfer_id: Hash,
    /// Source sidechain identifier
    pub source_sidechain_id: Hash,
    /// Destination sidechain identifier
    pub destination_sidechain_id: Hash,
    /// Source sidechain transaction that burns the funds
    pub source_tx: SidechainTransaction,
    /// Amount being transferred
    pub amount: u64,
    /// Asset type identifier
    pub asset_id: Hash,
    /// Recipient address on destination sidechain
    pub recipient_address: Vec<u8>,
    /// Block height on source sidechain where burn occurred
    pub source_block_height: u64,
    /// Proof of burn on source sidechain
    pub source_proof: CrossChainProof,
    /// Mainchain coordination transaction (if needed)
    pub mainchain_coordination_tx: Option<Hash>,
    /// Destination sidechain mint transaction (when completed)
    pub destination_mint_tx: Option<SidechainTransaction>,
    /// Block height on destination sidechain where mint occurred
    pub destination_block_height: Option<u64>,
    /// Federation signatures from source sidechain
    pub source_federation_signatures: Vec<FederationSignature>,
    /// Federation signatures from destination sidechain
    pub destination_federation_signatures: Vec<FederationSignature>,
    /// Current status
    pub status: InterSidechainStatus,
    /// Creation timestamp
    pub created_at: u64,
    /// Timeout timestamp
    pub timeout_at: u64,
}

/// Manager for inter-sidechain transfers
///
/// This manager handles the complete lifecycle of inter-sidechain transfers,
/// including initiation, confirmation tracking, mainchain coordination, and completion.
///
/// # Example
///
/// ```rust,no_run
/// use rusty_core::sidechain::InterSidechainTransferManager;
/// use rusty_shared_types::Hash;
///
/// let mut manager = InterSidechainTransferManager::new(
///     6,   // min_source_confirmations
///     6,   // min_destination_confirmations
///     1440, // transfer_timeout_blocks
///     100_000, // min_transfer_amount
///     1_000_000_000_000, // max_transfer_amount
/// );
/// ```
pub struct InterSidechainTransferManager {
    /// Active transfers by transfer ID
    active_transfers: HashMap<Hash, InterSidechainTransfer>,
    /// Completed transfers (for history)
    completed_transfers: HashMap<Hash, InterSidechainTransfer>,
    /// Minimum confirmations required on source sidechain
    min_source_confirmations: u32,
    /// Minimum confirmations required on destination sidechain
    min_destination_confirmations: u32,
    /// Transfer timeout in blocks
    transfer_timeout_blocks: u64,
    /// Minimum transfer amount
    min_transfer_amount: u64,
    /// Maximum transfer amount
    max_transfer_amount: u64,
}

impl InterSidechainTransferManager {
    /// Create a new inter-sidechain transfer manager
    ///
    /// # Arguments
    ///
    /// * `min_source_confirmations` - Minimum confirmations required on source sidechain before proceeding
    /// * `min_destination_confirmations` - Minimum confirmations required on destination sidechain before completion
    /// * `transfer_timeout_blocks` - Number of blocks before a transfer times out
    /// * `min_transfer_amount` - Minimum amount that can be transferred (prevents dust)
    /// * `max_transfer_amount` - Maximum amount that can be transferred (security limit)
    ///
    /// # Returns
    ///
    /// A new `InterSidechainTransferManager` instance
    pub fn new(
        min_source_confirmations: u32,
        min_destination_confirmations: u32,
        transfer_timeout_blocks: u64,
        min_transfer_amount: u64,
        max_transfer_amount: u64,
    ) -> Self {
        Self {
            active_transfers: HashMap::new(),
            completed_transfers: HashMap::new(),
            min_source_confirmations,
            min_destination_confirmations,
            transfer_timeout_blocks,
            min_transfer_amount,
            max_transfer_amount,
        }
    }

    /// Initiate an inter-sidechain transfer
    ///
    /// This method creates a new inter-sidechain transfer record and validates
    /// the source sidechain burn transaction.
    ///
    /// # Arguments
    ///
    /// * `source_sidechain_id` - Hash identifying the source sidechain
    /// * `destination_sidechain_id` - Hash identifying the destination sidechain
    /// * `source_tx` - The sidechain transaction that burns the funds
    /// * `amount` - Amount being transferred (in smallest unit)
    /// * `asset_id` - Asset type identifier
    /// * `recipient_address` - Address on destination sidechain to receive funds
    /// * `source_block_height` - Block height where burn occurred
    /// * `source_proof` - Cryptographic proof of burn on source sidechain
    /// * `source_federation_signatures` - Federation signatures from source sidechain
    ///
    /// # Returns
    ///
    /// * `Ok(Hash)` - Transfer ID if successful
    /// * `Err(String)` - Error message if validation fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Transfer amount is below minimum or above maximum
    /// - Recipient address is empty
    /// - Source and destination sidechains are the same
    /// - Source transaction is not a valid burn transaction
    /// - Transfer already exists (duplicate)
    pub fn initiate_transfer(
        &mut self,
        source_sidechain_id: Hash,
        destination_sidechain_id: Hash,
        source_tx: SidechainTransaction,
        amount: u64,
        asset_id: Hash,
        recipient_address: Vec<u8>,
        source_block_height: u64,
        source_proof: CrossChainProof,
        source_federation_signatures: Vec<FederationSignature>,
    ) -> Result<Hash, String> {
        // Validate transfer parameters
        if amount < self.min_transfer_amount {
            return Err(format!(
                "Transfer amount {} is below minimum {}",
                amount, self.min_transfer_amount
            ));
        }

        if amount > self.max_transfer_amount {
            return Err(format!(
                "Transfer amount {} exceeds maximum {}",
                amount, self.max_transfer_amount
            ));
        }

        if recipient_address.is_empty() {
            return Err("Recipient address cannot be empty".to_string());
        }

        if source_sidechain_id == destination_sidechain_id {
            return Err("Source and destination sidechains must be different".to_string());
        }

        // Verify source transaction is a burn transaction
        self.verify_burn_transaction(&source_tx, amount, &asset_id)?;

        // Generate transfer ID
        let transfer_id = self.generate_transfer_id(
            &source_sidechain_id,
            &destination_sidechain_id,
            &source_tx,
            amount,
        );

        // Check for duplicate transfer
        if self.active_transfers.contains_key(&transfer_id) {
            return Err("Transfer already exists".to_string());
        }

        // Create transfer record
        let timeout_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (self.transfer_timeout_blocks * 150); // Assuming 150s block time

        let transfer = InterSidechainTransfer {
            transfer_id,
            source_sidechain_id,
            destination_sidechain_id,
            source_tx,
            amount,
            asset_id,
            recipient_address,
            source_block_height,
            source_proof,
            mainchain_coordination_tx: None,
            destination_mint_tx: None,
            destination_block_height: None,
            source_federation_signatures,
            destination_federation_signatures: Vec::new(),
            status: InterSidechainStatus::WaitingSourceConfirmation {
                current: 0,
                required: self.min_source_confirmations,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            timeout_at,
        };

        self.active_transfers.insert(transfer_id, transfer.clone());

        info!(
            "Initiated inter-sidechain transfer {}: {} units from {:?} to {:?}",
            hex::encode(&transfer_id),
            amount,
            source_sidechain_id,
            destination_sidechain_id
        );

        Ok(transfer_id)
    }

    /// Update source sidechain confirmation count
    pub fn update_source_confirmations(
        &mut self,
        transfer_id: &Hash,
        current_height: u64,
    ) -> Result<(), String> {
        let transfer = self
            .active_transfers
            .get_mut(transfer_id)
            .ok_or("Transfer not found")?;

        match transfer.status {
            InterSidechainStatus::WaitingSourceConfirmation {
                ref mut current,
                required,
            } => {
                let confirmations =
                    (current_height.saturating_sub(transfer.source_block_height)) as u32;
                *current = confirmations;

                if confirmations >= required {
                    transfer.status = InterSidechainStatus::WaitingMainchainCoordination;
                    info!(
                        "Inter-sidechain transfer {} source confirmations complete",
                        hex::encode(transfer_id)
                    );
                }
            }
            _ => {
                return Err("Transfer is not in waiting source confirmation state".to_string());
            }
        }

        Ok(())
    }

    /// Set mainchain coordination transaction
    pub fn set_mainchain_coordination(
        &mut self,
        transfer_id: &Hash,
        coordination_tx_hash: Hash,
    ) -> Result<(), String> {
        let transfer = self
            .active_transfers
            .get_mut(transfer_id)
            .ok_or("Transfer not found")?;

        match transfer.status {
            InterSidechainStatus::WaitingMainchainCoordination => {
                transfer.mainchain_coordination_tx = Some(coordination_tx_hash);
                transfer.status = InterSidechainStatus::WaitingDestinationConfirmation {
                    current: 0,
                    required: self.min_destination_confirmations,
                };
                info!(
                    "Inter-sidechain transfer {} mainchain coordination set",
                    hex::encode(transfer_id)
                );
            }
            _ => {
                return Err("Transfer is not in waiting mainchain coordination state".to_string());
            }
        }

        Ok(())
    }

    /// Complete transfer with destination sidechain mint
    pub fn complete_transfer(
        &mut self,
        transfer_id: &Hash,
        destination_mint_tx: SidechainTransaction,
        destination_block_height: u64,
        destination_federation_signatures: Vec<FederationSignature>,
    ) -> Result<(), String> {
        let transfer_id_owned = *transfer_id;
        let mut transfer = self
            .active_transfers
            .remove(transfer_id)
            .ok_or("Transfer not found")?;

        match transfer.status {
            InterSidechainStatus::WaitingDestinationConfirmation { .. } => {
                // Verify mint transaction
                self.verify_mint_transaction(
                    &destination_mint_tx,
                    transfer.amount,
                    &transfer.asset_id,
                    &transfer.recipient_address,
                )?;

                transfer.destination_mint_tx = Some(destination_mint_tx);
                transfer.destination_block_height = Some(destination_block_height);
                transfer.destination_federation_signatures = destination_federation_signatures;
                transfer.status = InterSidechainStatus::Completed;

                self.completed_transfers.insert(transfer_id_owned, transfer);

                info!(
                    "Inter-sidechain transfer {} completed",
                    hex::encode(transfer_id)
                );

                Ok(())
            }
            _ => Err("Transfer is not ready for completion".to_string()),
        }
    }

    /// Check for timed out transfers
    pub fn check_timeouts(&mut self, current_time: u64) -> Vec<Hash> {
        let mut timed_out = Vec::new();

        for (transfer_id, transfer) in &mut self.active_transfers {
            if current_time >= transfer.timeout_at {
                transfer.status = InterSidechainStatus::TimedOut;
                timed_out.push(*transfer_id);
            }
        }

        // Move timed out transfers to completed
        for transfer_id in timed_out.clone() {
            if let Some(transfer) = self.active_transfers.remove(&transfer_id) {
                self.completed_transfers.insert(transfer_id, transfer);
            }
        }

        timed_out
    }

    /// Get transfer by ID
    pub fn get_transfer(&self, transfer_id: &Hash) -> Option<&InterSidechainTransfer> {
        self.active_transfers
            .get(transfer_id)
            .or_else(|| self.completed_transfers.get(transfer_id))
    }

    /// Generate transfer ID
    fn generate_transfer_id(
        &self,
        source_sidechain_id: &Hash,
        destination_sidechain_id: &Hash,
        source_tx: &SidechainTransaction,
        amount: u64,
    ) -> Hash {
        use blake3;
        let mut hasher = blake3::Hasher::new();
        hasher.update(source_sidechain_id);
        hasher.update(destination_sidechain_id);
        hasher.update(&bincode::serialize(source_tx).unwrap_or_default());
        hasher.update(&amount.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify that source transaction is a valid burn transaction
    fn verify_burn_transaction(
        &self,
        tx: &SidechainTransaction,
        expected_amount: u64,
        expected_asset_id: &Hash,
    ) -> Result<(), String> {
        // Check that transaction has burn outputs
        // In a real implementation, this would check for burn-specific output types
        // For now, we verify the transaction structure is valid
        if tx.outputs.is_empty() {
            return Err("Burn transaction must have outputs".to_string());
        }

        // Verify total output value matches expected amount (burned)
        let total_output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_output_value != expected_amount {
            return Err(format!(
                "Burn transaction output value {} does not match expected {}",
                total_output_value, expected_amount
            ));
        }

        Ok(())
    }

    /// Verify that destination transaction is a valid mint transaction
    fn verify_mint_transaction(
        &self,
        tx: &SidechainTransaction,
        expected_amount: u64,
        expected_asset_id: &Hash,
        expected_recipient: &[u8],
    ) -> Result<(), String> {
        // Check that transaction has mint outputs
        if tx.outputs.is_empty() {
            return Err("Mint transaction must have outputs".to_string());
        }

        // Verify total output value matches expected amount (minted)
        let total_output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_output_value != expected_amount {
            return Err(format!(
                "Mint transaction output value {} does not match expected {}",
                total_output_value, expected_amount
            ));
        }

        // Verify recipient address matches
        // In a real implementation, this would check script_pubkey matches recipient
        if !tx
            .outputs
            .iter()
            .any(|o| o.script_pubkey == expected_recipient)
        {
            return Err("Mint transaction does not match recipient address".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::{SidechainOutPoint, SidechainTxInput, SidechainTxOutput};

    fn create_test_sidechain_tx(value: u64) -> SidechainTransaction {
        SidechainTransaction {
            version: 1,
            inputs: vec![SidechainTxInput {
                previous_output: SidechainOutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
            }],
            outputs: vec![SidechainTxOutput {
                value,
                asset_id: [2u8; 32],
                script_pubkey: vec![3, 4, 5],
                data: Vec::new(),
            }],
            lock_time: 0,
            vm_data: None,
            fee: 1000,
        }
    }

    #[test]
    fn test_initiate_inter_sidechain_transfer() {
        let mut manager =
            InterSidechainTransferManager::new(6, 6, 1440, 100_000, 1_000_000_000_000);

        let source_id = [1u8; 32];
        let dest_id = [2u8; 32];
        let source_tx = create_test_sidechain_tx(5000000);
        let source_proof = CrossChainProof {
            merkle_proof: Vec::new(),
            block_header: Vec::new(),
            transaction_data: Vec::new(),
            tx_index: 0,
        };

        let transfer_id = manager
            .initiate_transfer(
                source_id,
                dest_id,
                source_tx,
                5000000,
                [2u8; 32],
                vec![1, 2, 3],
                100,
                source_proof,
                Vec::new(),
            )
            .unwrap();

        assert!(manager.get_transfer(&transfer_id).is_some());
    }

    #[test]
    fn test_transfer_status_transitions() {
        let mut manager =
            InterSidechainTransferManager::new(6, 6, 1440, 100_000, 1_000_000_000_000);

        let source_id = [1u8; 32];
        let dest_id = [2u8; 32];
        let source_tx = create_test_sidechain_tx(5000000);
        let source_proof = CrossChainProof {
            merkle_proof: Vec::new(),
            block_header: Vec::new(),
            transaction_data: Vec::new(),
            tx_index: 0,
        };

        let transfer_id = manager
            .initiate_transfer(
                source_id,
                dest_id,
                source_tx,
                5000000,
                [2u8; 32],
                vec![1, 2, 3],
                100,
                source_proof,
                Vec::new(),
            )
            .unwrap();

        // Update source confirmations
        manager
            .update_source_confirmations(&transfer_id, 106)
            .unwrap();

        let transfer = manager.get_transfer(&transfer_id).unwrap();
        assert!(matches!(
            transfer.status,
            InterSidechainStatus::WaitingMainchainCoordination
        ));
    }
}
