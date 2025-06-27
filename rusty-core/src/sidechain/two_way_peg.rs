//! Two-way peg mechanism for Rusty Coin sidechains
//! 
//! This module implements the peg-in and peg-out functionality for transferring
//! assets between the mainchain and sidechains, secured by masternode federation
//! with BLS threshold signatures as specified in the RCTB.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use log::{info, warn, error, debug};

use rusty_shared_types::{Hash, Transaction, TxInput, TxOutput, OutPoint, MasternodeID};
use crate::sidechain::{
    SidechainTransaction, CrossChainTransaction, CrossChainTxType, 
    FederationSignature, CrossChainProof, SidechainTxOutput
};

/// Configuration for two-way peg operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoWayPegConfig {
    /// Minimum confirmations required for peg-in
    pub min_peg_in_confirmations: u32,
    /// Minimum confirmations required for peg-out
    pub min_peg_out_confirmations: u32,
    /// Federation threshold for peg operations
    pub federation_threshold: u32,
    /// Minimum peg amount to prevent dust
    pub min_peg_amount: u64,
    /// Maximum peg amount for security
    pub max_peg_amount: u64,
    /// Peg operation timeout in blocks
    pub peg_timeout_blocks: u64,
    /// Fee for peg operations
    pub peg_fee_rate: u64,
}

impl Default for TwoWayPegConfig {
    fn default() -> Self {
        Self {
            min_peg_in_confirmations: 6,
            min_peg_out_confirmations: 12,
            federation_threshold: 2, // 2/3 threshold
            min_peg_amount: 100_000, // 0.001 RUST
            max_peg_amount: 1_000_000_000_000, // 10,000 RUST
            peg_timeout_blocks: 1440, // ~24 hours
            peg_fee_rate: 1000, // 0.00001 RUST
        }
    }
}

/// Status of a peg operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PegStatus {
    /// Peg operation initiated
    Initiated,
    /// Waiting for confirmations
    WaitingConfirmations { current: u32, required: u32 },
    /// Waiting for federation signatures
    WaitingFederationSignatures { received: u32, required: u32 },
    /// Peg operation completed
    Completed,
    /// Peg operation failed
    Failed { reason: String },
    /// Peg operation timed out
    TimedOut,
}

/// Peg-in transaction for moving assets from mainchain to sidechain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PegInTransaction {
    /// Unique identifier for this peg-in
    pub peg_id: Hash,
    /// Mainchain transaction that locks the funds
    pub mainchain_tx: Transaction,
    /// Target sidechain identifier
    pub target_sidechain_id: Hash,
    /// Recipient address on the sidechain
    pub sidechain_recipient: Vec<u8>,
    /// Amount being pegged in
    pub amount: u64,
    /// Asset type being pegged
    pub asset_id: Hash,
    /// Block height where mainchain tx was included
    pub mainchain_block_height: u64,
    /// Proof of inclusion in mainchain
    pub inclusion_proof: CrossChainProof,
    /// Federation signatures authorizing the peg-in
    pub federation_signatures: Vec<FederationSignature>,
    /// Current status of the peg-in
    pub status: PegStatus,
    /// Creation timestamp
    pub created_at: u64,
}

/// Peg-out transaction for moving assets from sidechain to mainchain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PegOutTransaction {
    /// Unique identifier for this peg-out
    pub peg_id: Hash,
    /// Sidechain transaction that burns the funds
    pub sidechain_tx: SidechainTransaction,
    /// Source sidechain identifier
    pub source_sidechain_id: Hash,
    /// Recipient address on the mainchain
    pub mainchain_recipient: Vec<u8>,
    /// Amount being pegged out
    pub amount: u64,
    /// Asset type being pegged
    pub asset_id: Hash,
    /// Block height where sidechain tx was included
    pub sidechain_block_height: u64,
    /// Proof of burn on sidechain
    pub burn_proof: CrossChainProof,
    /// Federation signatures authorizing the peg-out
    pub federation_signatures: Vec<FederationSignature>,
    /// Mainchain transaction that releases the funds (once created)
    pub mainchain_release_tx: Option<Transaction>,
    /// Current status of the peg-out
    pub status: PegStatus,
    /// Creation timestamp
    pub created_at: u64,
}

/// Manages two-way peg operations between mainchain and sidechains
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoWayPegManager {
    config: TwoWayPegConfig,
    /// Active peg-in operations
    active_peg_ins: HashMap<Hash, PegInTransaction>,
    /// Active peg-out operations
    active_peg_outs: HashMap<Hash, PegOutTransaction>,
    /// Completed peg operations for history
    completed_pegs: HashMap<Hash, PegOperationRecord>,
    /// Current federation members
    current_federation: Vec<MasternodeID>,
    /// Current block height for timeout tracking
    current_block_height: u64,
}

/// Record of a completed peg operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PegOperationRecord {
    pub peg_id: Hash,
    pub operation_type: PegOperationType,
    pub amount: u64,
    pub asset_id: Hash,
    pub completed_at: u64,
    pub mainchain_tx_hash: Hash,
    pub sidechain_tx_hash: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PegOperationType {
    PegIn,
    PegOut,
}

impl TwoWayPegManager {
    /// Create a new two-way peg manager
    pub fn new(config: TwoWayPegConfig) -> Self {
        Self {
            config,
            active_peg_ins: HashMap::new(),
            active_peg_outs: HashMap::new(),
            completed_pegs: HashMap::new(),
            current_federation: Vec::new(),
            current_block_height: 0,
        }
    }

    /// Initiate a peg-in operation
    pub fn initiate_peg_in(
        &mut self,
        mainchain_tx: Transaction,
        target_sidechain_id: Hash,
        sidechain_recipient: Vec<u8>,
        amount: u64,
        asset_id: Hash,
    ) -> Result<Hash, String> {
        // Validate peg-in parameters
        self.validate_peg_amount(amount)?;
        
        if sidechain_recipient.is_empty() {
            return Err("Sidechain recipient cannot be empty".to_string());
        }

        // Generate peg ID
        let peg_id = self.generate_peg_id(&mainchain_tx, &target_sidechain_id);

        // Check for duplicate peg-in
        if self.active_peg_ins.contains_key(&peg_id) {
            return Err("Peg-in already exists".to_string());
        }

        // Verify mainchain transaction locks funds correctly
        self.verify_mainchain_lock_transaction(&mainchain_tx, amount, &asset_id)?;

        // Create peg-in transaction
        let peg_in = PegInTransaction {
            peg_id,
            mainchain_tx,
            target_sidechain_id,
            sidechain_recipient,
            amount,
            asset_id,
            mainchain_block_height: self.current_block_height,
            inclusion_proof: CrossChainProof {
                merkle_proof: Vec::new(), // Will be filled when confirmed
                block_header: Vec::new(),
                transaction_data: Vec::new(),
                tx_index: 0,
            },
            federation_signatures: Vec::new(),
            status: PegStatus::Initiated,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.active_peg_ins.insert(peg_id, peg_in);

        info!("Initiated peg-in {} for {} units to sidechain {:?}", 
              hex::encode(&peg_id), amount, target_sidechain_id);

        Ok(peg_id)
    }

    /// Initiate a peg-out operation
    pub fn initiate_peg_out(
        &mut self,
        sidechain_tx: SidechainTransaction,
        source_sidechain_id: Hash,
        mainchain_recipient: Vec<u8>,
        amount: u64,
        asset_id: Hash,
    ) -> Result<Hash, String> {
        // Validate peg-out parameters
        self.validate_peg_amount(amount)?;
        
        if mainchain_recipient.is_empty() {
            return Err("Mainchain recipient cannot be empty".to_string());
        }

        // Generate peg ID
        let peg_id = self.generate_peg_id_from_sidechain(&sidechain_tx, &source_sidechain_id);

        // Check for duplicate peg-out
        if self.active_peg_outs.contains_key(&peg_id) {
            return Err("Peg-out already exists".to_string());
        }

        // Verify sidechain transaction burns funds correctly
        self.verify_sidechain_burn_transaction(&sidechain_tx, amount, &asset_id)?;

        // Create peg-out transaction
        let peg_out = PegOutTransaction {
            peg_id,
            sidechain_tx,
            source_sidechain_id,
            mainchain_recipient,
            amount,
            asset_id,
            sidechain_block_height: self.current_block_height,
            burn_proof: CrossChainProof {
                merkle_proof: Vec::new(), // Will be filled when confirmed
                block_header: Vec::new(),
                transaction_data: Vec::new(),
                tx_index: 0,
            },
            federation_signatures: Vec::new(),
            mainchain_release_tx: None,
            status: PegStatus::Initiated,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.active_peg_outs.insert(peg_id, peg_out);

        info!("Initiated peg-out {} for {} units from sidechain {:?}", 
              hex::encode(&peg_id), amount, source_sidechain_id);

        Ok(peg_id)
    }

    /// Process confirmations for peg operations
    pub fn process_confirmations(&mut self, block_height: u64) -> Result<(), String> {
        self.current_block_height = block_height;

        // Process peg-in confirmations
        let peg_in_ids: Vec<Hash> = self.active_peg_ins.keys().copied().collect();
        for peg_id in peg_in_ids {
            self.process_peg_in_confirmations(peg_id)?;
        }

        // Process peg-out confirmations
        let peg_out_ids: Vec<Hash> = self.active_peg_outs.keys().copied().collect();
        for peg_id in peg_out_ids {
            self.process_peg_out_confirmations(peg_id)?;
        }

        // Clean up timed out operations
        self.cleanup_timed_out_operations();

        Ok(())
    }

    /// Add federation signature to a peg operation
    pub fn add_federation_signature(
        &mut self,
        peg_id: Hash,
        signature: FederationSignature,
    ) -> Result<(), String> {
        // Verify signature
        signature.verify(&peg_id)?;

        // Add to peg-in if exists
        if let Some(peg_in) = self.active_peg_ins.get_mut(&peg_id) {
            peg_in.federation_signatures.push(signature);
            self.check_peg_in_completion(peg_id)?;
            return Ok(());
        }

        // Add to peg-out if exists
        if let Some(peg_out) = self.active_peg_outs.get_mut(&peg_id) {
            peg_out.federation_signatures.push(signature);
            self.check_peg_out_completion(peg_id)?;
            return Ok(());
        }

        Err("Peg operation not found".to_string())
    }

    /// Update federation members
    pub fn update_federation(&mut self, members: Vec<MasternodeID>) {
        self.current_federation = members;
        info!("Updated federation with {} members", self.current_federation.len());
    }

    /// Get peg operation status
    pub fn get_peg_status(&self, peg_id: &Hash) -> Option<PegStatus> {
        if let Some(peg_in) = self.active_peg_ins.get(peg_id) {
            return Some(peg_in.status.clone());
        }

        if let Some(peg_out) = self.active_peg_outs.get(peg_id) {
            return Some(peg_out.status.clone());
        }

        None
    }

    /// Get statistics about peg operations
    pub fn get_stats(&self) -> TwoWayPegStats {
        TwoWayPegStats {
            active_peg_ins: self.active_peg_ins.len(),
            active_peg_outs: self.active_peg_outs.len(),
            completed_pegs: self.completed_pegs.len(),
            federation_size: self.current_federation.len(),
            current_block_height: self.current_block_height,
        }
    }

    // Private helper methods

    fn validate_peg_amount(&self, amount: u64) -> Result<(), String> {
        if amount < self.config.min_peg_amount {
            return Err(format!("Amount {} below minimum {}", amount, self.config.min_peg_amount));
        }

        if amount > self.config.max_peg_amount {
            return Err(format!("Amount {} above maximum {}", amount, self.config.max_peg_amount));
        }

        Ok(())
    }

    fn generate_peg_id(&self, mainchain_tx: &Transaction, sidechain_id: &Hash) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(mainchain_tx.txid().as_ref());
        data.extend_from_slice(sidechain_id.as_ref());
        let mut height_bytes = [0u8; 32];
        height_bytes[..8].copy_from_slice(&self.current_block_height.to_le_bytes());
        data.extend_from_slice(height_bytes.as_ref());
        blake3::hash(&data).into()
    }

    fn generate_peg_id_from_sidechain(&self, sidechain_tx: &SidechainTransaction, sidechain_id: &Hash) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(sidechain_tx.hash().as_ref());
        data.extend_from_slice(sidechain_id.as_ref());
        let mut height_bytes = [0u8; 32];
        height_bytes[..8].copy_from_slice(&self.current_block_height.to_le_bytes());
        data.extend_from_slice(height_bytes.as_ref());
        blake3::hash(&data).into()
    }

    fn verify_mainchain_lock_transaction(&self, mainchain_tx: &Transaction, amount: u64, _asset_id: &Hash) -> Result<(), String> {
        // In a real implementation, this would verify:
        // 1. Transaction outputs lock the correct amount
        // 2. Funds are locked to the federation's multisig address
        // 3. Asset type matches the expected asset
        
        // Simplified validation for now
        let total_output_value: u64 = mainchain_tx.get_outputs().iter().map(|o| o.value).sum();
        if total_output_value < amount {
            return Err("Insufficient locked amount".to_string());
        }

        Ok(())
    }

    fn verify_sidechain_burn_transaction(&self, sidechain_tx: &SidechainTransaction, _amount: u64, _asset_id: &Hash) -> Result<(), String> {
        // In a real implementation, this would verify:
        // 1. Transaction burns the correct amount
        // 2. Asset type matches
        // 3. Burn is properly executed
        
        // Simplified validation for now
        let total_output_value = sidechain_tx.total_output_value();
        if total_output_value > 0 {
            return Err("Burn transaction should have no outputs".to_string());
        }

        Ok(())
    }

    fn process_peg_in_confirmations(&mut self, peg_id: Hash) -> Result<(), String> {
        let peg_in = self.active_peg_ins.get_mut(&peg_id)
            .ok_or("Peg-in not found")?;

        let confirmations = self.current_block_height.saturating_sub(peg_in.mainchain_block_height);
        
        if confirmations >= self.config.min_peg_in_confirmations as u64 {
            peg_in.status = PegStatus::WaitingFederationSignatures {
                received: peg_in.federation_signatures.len() as u32,
                required: self.config.federation_threshold,
            };
        } else {
            peg_in.status = PegStatus::WaitingConfirmations {
                current: confirmations as u32,
                required: self.config.min_peg_in_confirmations,
            };
        }

        Ok(())
    }

    fn process_peg_out_confirmations(&mut self, peg_id: Hash) -> Result<(), String> {
        let peg_out = self.active_peg_outs.get_mut(&peg_id)
            .ok_or("Peg-out not found")?;

        let confirmations = self.current_block_height.saturating_sub(peg_out.sidechain_block_height);
        
        if confirmations >= self.config.min_peg_out_confirmations as u64 {
            peg_out.status = PegStatus::WaitingFederationSignatures {
                received: peg_out.federation_signatures.len() as u32,
                required: self.config.federation_threshold,
            };
        } else {
            peg_out.status = PegStatus::WaitingConfirmations {
                current: confirmations as u32,
                required: self.config.min_peg_out_confirmations,
            };
        }

        Ok(())
    }

    fn check_peg_in_completion(&mut self, peg_id: Hash) -> Result<(), String> {
        let peg_in = self.active_peg_ins.get_mut(&peg_id)
            .ok_or("Peg-in not found")?;

        if peg_in.federation_signatures.len() >= self.config.federation_threshold as usize {
            peg_in.status = PegStatus::Completed;
            
            // Create completion record
            let record = PegOperationRecord {
                peg_id,
                operation_type: PegOperationType::PegIn,
                amount: peg_in.amount,
                asset_id: peg_in.asset_id,
                completed_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                mainchain_tx_hash: peg_in.mainchain_tx.txid(),
                sidechain_tx_hash: None,
            };

            self.completed_pegs.insert(peg_id, record);
            info!("Completed peg-in {}", hex::encode(&peg_id));
        }

        Ok(())
    }

    fn check_peg_out_completion(&mut self, peg_id: Hash) -> Result<(), String> {
        let peg_out = self.active_peg_outs.get_mut(&peg_id)
            .ok_or("Peg-out not found")?;

        if peg_out.federation_signatures.len() >= self.config.federation_threshold as usize {
            // Create mainchain release transaction
            let release_tx = TwoWayPegManager::create_mainchain_release_transaction(peg_out, self.config.peg_fee_rate)?;
            peg_out.mainchain_release_tx = Some(release_tx.clone());
            peg_out.status = PegStatus::Completed;
            
            // Create completion record
            let record = PegOperationRecord {
                peg_id,
                operation_type: PegOperationType::PegOut,
                amount: peg_out.amount,
                asset_id: peg_out.asset_id,
                completed_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                mainchain_tx_hash: release_tx.txid(),
                sidechain_tx_hash: Some(peg_out.sidechain_tx.hash()),
            };

            self.completed_pegs.insert(peg_id, record);
            info!("Completed peg-out {}", hex::encode(&peg_id));
        }

        Ok(())
    }

    fn create_mainchain_release_transaction(peg_out: &PegOutTransaction, peg_fee_rate: u64) -> Result<Transaction, String> {
        // In a real implementation, this would create a proper mainchain transaction
        // that releases the locked funds to the recipient
        
        let output = TxOutput {
            value: peg_out.amount - peg_fee_rate,
            script_pubkey: peg_out.mainchain_recipient.clone(),
            memo: None,
        };

        let tx = Transaction::Standard {
            version: 1,
            inputs: Vec::new(), // Would be federation's multisig inputs
            outputs: vec![output],
            lock_time: 0,
            fee: peg_fee_rate,
            witness: Vec::new(),
        };

        Ok(tx)
    }

    fn cleanup_timed_out_operations(&mut self) {
        let timeout_height = self.current_block_height.saturating_sub(self.config.peg_timeout_blocks);

        // Clean up timed out peg-ins
        let timed_out_peg_ins: Vec<Hash> = self.active_peg_ins
            .iter()
            .filter(|(_, peg_in)| peg_in.mainchain_block_height < timeout_height)
            .map(|(id, _)| *id)
            .collect();

        for peg_id in timed_out_peg_ins {
            if let Some(mut peg_in) = self.active_peg_ins.remove(&peg_id) {
                peg_in.status = PegStatus::TimedOut;
                warn!("Peg-in {} timed out", hex::encode(&peg_id));
            }
        }

        // Clean up timed out peg-outs
        let timed_out_peg_outs: Vec<Hash> = self.active_peg_outs
            .iter()
            .filter(|(_, peg_out)| peg_out.sidechain_block_height < timeout_height)
            .map(|(id, _)| *id)
            .collect();

        for peg_id in timed_out_peg_outs {
            if let Some(mut peg_out) = self.active_peg_outs.remove(&peg_id) {
                peg_out.status = PegStatus::TimedOut;
                warn!("Peg-out {} timed out", hex::encode(&peg_id));
            }
        }
    }
}

/// Statistics about two-way peg operations
#[derive(Debug, Clone)]
pub struct TwoWayPegStats {
    pub active_peg_ins: usize,
    pub active_peg_outs: usize,
    pub completed_pegs: usize,
    pub federation_size: usize,
    pub current_block_height: u64,
}

#[cfg(test)]
mod tests;
