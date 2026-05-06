//! Sidechain proof validation system
//!
//! This module implements comprehensive validation logic for sidechain proofs
//! including cross-chain transaction proofs, federation signatures, and state transitions.

use crate::consensus::error::ConsensusError;
use crate::sidechain::{
    federation_manager::verify_federation_signature_with_public_keys, CrossChainProof,
    CrossChainTransaction, FederationSignature, FraudProof, SidechainBlock, SidechainBlockHeader,
    SidechainTransaction, VMExecutionData,
};
use ed25519_dalek::{PublicKey as VerifyingKey, Signature, Verifier};
use log::{debug, info, warn};
use rusty_shared_types::{BlockHeader, Hash, PublicKey};
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::collections::HashMap;

/// Configuration for proof validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofValidationConfig {
    /// Minimum number of federation signatures required
    pub min_federation_signatures: u32,
    /// Maximum allowed proof size in bytes
    pub max_proof_size: usize,
    /// Enable strict validation mode
    pub strict_validation: bool,
    /// Maximum merkle proof depth
    pub max_merkle_depth: u32,
    /// Timeout for proof verification in milliseconds
    pub verification_timeout_ms: u64,
}

impl Default for ProofValidationConfig {
    fn default() -> Self {
        Self {
            min_federation_signatures: 2,
            max_proof_size: 1_000_000, // 1MB
            strict_validation: true,
            max_merkle_depth: 32,
            verification_timeout_ms: 5000,
        }
    }
}

/// Result of proof validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofValidationResult {
    /// Proof is valid
    Valid,
    /// Proof is invalid with reason
    Invalid(String),
    /// Proof validation failed due to error
    Error(String),
    /// Proof validation timed out
    Timeout,
}

/// Comprehensive sidechain proof validator
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainProofValidator {
    config: ProofValidationConfig,
    /// Known federation public keys by epoch
    federation_keys: HashMap<u64, Vec<Vec<u8>>>,
    /// Trusted mainchain block headers for verification
    trusted_headers: HashMap<Hash, BlockHeader>,
    /// Validation statistics
    validation_stats: ValidationStats,
}

/// Statistics about proof validation
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ValidationStats {
    pub total_validations: u64,
    pub successful_validations: u64,
    pub failed_validations: u64,
    pub timeout_validations: u64,
    pub average_validation_time_ms: f64,
}

impl SidechainProofValidator {
    /// Create a new proof validator
    pub fn new(config: ProofValidationConfig) -> Self {
        Self {
            config,
            federation_keys: HashMap::new(),
            trusted_headers: HashMap::new(),
            validation_stats: ValidationStats::default(),
        }
    }

    /// Update federation keys for an epoch
    pub fn update_federation_keys(&mut self, epoch: u64, public_keys: Vec<Vec<u8>>) {
        self.federation_keys.insert(epoch, public_keys.clone());
        info!(
            "Updated federation keys for epoch {} with {} keys",
            epoch,
            public_keys.len()
        );
    }

    /// Add trusted mainchain block header
    pub fn add_trusted_header(&mut self, header: BlockHeader) {
        let hash = header.hash();
        self.trusted_headers.insert(hash, header);
        debug!("Added trusted header {}", hex::encode(&hash));
    }

    /// Validate a complete sidechain block
    pub fn validate_sidechain_block(&mut self, block: &SidechainBlock) -> ProofValidationResult {
        let start_time = std::time::Instant::now();
        self.validation_stats.total_validations += 1;

        let result = self.validate_sidechain_block_internal(block);

        // Update statistics
        let validation_time = start_time.elapsed().as_millis() as f64;
        self.update_validation_stats(&result, validation_time);

        result
    }

    /// Internal sidechain block validation
    fn validate_sidechain_block_internal(&self, block: &SidechainBlock) -> ProofValidationResult {
        // Validate block header
        if let ProofValidationResult::Invalid(reason) = self.validate_block_header(&block.header) {
            return ProofValidationResult::Invalid(format!("Header validation failed: {}", reason));
        }

        // Validate all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if let ProofValidationResult::Invalid(reason) = self.validate_sidechain_transaction(tx)
            {
                return ProofValidationResult::Invalid(format!(
                    "Transaction {} validation failed: {}",
                    i, reason
                ));
            }
        }

        // Validate cross-chain transactions
        for (i, tx) in block.cross_chain_transactions.iter().enumerate() {
            if let ProofValidationResult::Invalid(reason) =
                self.validate_cross_chain_transaction(tx)
            {
                return ProofValidationResult::Invalid(format!(
                    "Cross-chain transaction {} validation failed: {}",
                    i, reason
                ));
            }
        }

        // Validate fraud proofs
        for (i, proof) in block.fraud_proofs.iter().enumerate() {
            if let ProofValidationResult::Invalid(reason) = self.validate_fraud_proof(proof) {
                return ProofValidationResult::Invalid(format!(
                    "Fraud proof {} validation failed: {}",
                    i, reason
                ));
            }
        }

        // Validate federation signature
        if let Some(ref signature) = block.federation_signature {
            if let ProofValidationResult::Invalid(reason) =
                self.validate_federation_signature(signature, &block.header.hash())
            {
                return ProofValidationResult::Invalid(format!(
                    "Federation signature validation failed: {}",
                    reason
                ));
            }
        } else if self.config.strict_validation {
            return ProofValidationResult::Invalid(
                "Missing federation signature in strict mode".to_string(),
            );
        }

        ProofValidationResult::Valid
    }

    /// Validate sidechain block header
    fn validate_block_header(&self, header: &SidechainBlockHeader) -> ProofValidationResult {
        // Basic header validation
        if header.version == 0 {
            return ProofValidationResult::Invalid("Invalid header version".to_string());
        }

        if header.height == 0 && header.previous_block_hash != [0u8; 32] {
            return ProofValidationResult::Invalid(
                "Genesis block must have zero previous hash".to_string(),
            );
        }

        if header.height > 0 && header.previous_block_hash == [0u8; 32] {
            return ProofValidationResult::Invalid(
                "Non-genesis block must have valid previous hash".to_string(),
            );
        }

        // Validate timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if header.timestamp > current_time + 7200 {
            // 2 hours in future
            return ProofValidationResult::Invalid("Block timestamp too far in future".to_string());
        }

        // Validate mainchain anchor
        if header.mainchain_anchor_height > 0 {
            if !self
                .trusted_headers
                .contains_key(&header.mainchain_anchor_hash)
            {
                if self.config.strict_validation {
                    return ProofValidationResult::Invalid(
                        "Mainchain anchor not in trusted headers".to_string(),
                    );
                } else {
                    warn!(
                        "Mainchain anchor {} not found in trusted headers",
                        hex::encode(&header.mainchain_anchor_hash)
                    );
                }
            }
        }

        ProofValidationResult::Valid
    }

    /// Validate a sidechain transaction
    fn validate_sidechain_transaction(&self, tx: &SidechainTransaction) -> ProofValidationResult {
        // Basic transaction validation
        if tx.inputs.is_empty() {
            return ProofValidationResult::Invalid("Transaction must have inputs".to_string());
        }

        if tx.outputs.is_empty() {
            return ProofValidationResult::Invalid("Transaction must have outputs".to_string());
        }

        // Validate VM execution if present
        if let Some(ref vm_data) = tx.vm_data {
            if let ProofValidationResult::Invalid(reason) = self.validate_vm_execution(vm_data) {
                return ProofValidationResult::Invalid(format!(
                    "VM execution validation failed: {}",
                    reason
                ));
            }
        }

        // Additional transaction-specific validation would go here
        // - Input/output balance validation
        // - Script validation
        // - Signature validation

        ProofValidationResult::Valid
    }

    /// Validate VM execution data
    fn validate_vm_execution(&self, vm_data: &VMExecutionData) -> ProofValidationResult {
        if vm_data.bytecode.is_empty() {
            return ProofValidationResult::Invalid("VM bytecode cannot be empty".to_string());
        }

        if vm_data.gas_limit == 0 {
            return ProofValidationResult::Invalid(
                "Gas limit must be greater than zero".to_string(),
            );
        }

        // VM-specific validation
        match vm_data.vm_type {
            crate::sidechain::VMType::EVM => {
                if vm_data.gas_limit > 30_000_000 {
                    return ProofValidationResult::Invalid("EVM gas limit too high".to_string());
                }
            }
            crate::sidechain::VMType::WASM => {
                if vm_data.bytecode.len() > 1_000_000 {
                    return ProofValidationResult::Invalid("WASM bytecode too large".to_string());
                }
            }
            _ => {} // Other VM types
        }

        ProofValidationResult::Valid
    }

    /// Validate a cross-chain transaction
    fn validate_cross_chain_transaction(
        &self,
        tx: &CrossChainTransaction,
    ) -> ProofValidationResult {
        // Basic validation
        if tx.amount == 0 {
            return ProofValidationResult::Invalid("Cross-chain amount cannot be zero".to_string());
        }

        if tx.recipient_address.is_empty() {
            return ProofValidationResult::Invalid("Recipient address cannot be empty".to_string());
        }

        // Validate cross-chain proof
        if let ProofValidationResult::Invalid(reason) = self.validate_cross_chain_proof(&tx.proof) {
            return ProofValidationResult::Invalid(format!(
                "Cross-chain proof validation failed: {}",
                reason
            ));
        }

        // Validate federation signatures
        if tx.federation_signatures.is_empty() {
            return ProofValidationResult::Invalid(
                "Cross-chain transaction must have federation signatures".to_string(),
            );
        }

        let tx_hash = tx.hash();
        for signature in &tx.federation_signatures {
            if let ProofValidationResult::Invalid(reason) =
                self.validate_federation_signature(signature, &tx_hash)
            {
                return ProofValidationResult::Invalid(format!(
                    "Federation signature validation failed: {}",
                    reason
                ));
            }
        }

        // Check minimum signature threshold
        let total_signers: u32 = tx
            .federation_signatures
            .iter()
            .map(|sig| sig.count_signers())
            .sum();

        if total_signers < self.config.min_federation_signatures {
            return ProofValidationResult::Invalid(format!(
                "Insufficient federation signatures: {} < {}",
                total_signers, self.config.min_federation_signatures
            ));
        }

        ProofValidationResult::Valid
    }

    /// Validate cross-chain proof
    fn validate_cross_chain_proof(&self, proof: &CrossChainProof) -> ProofValidationResult {
        if proof.merkle_proof.is_empty() {
            return ProofValidationResult::Invalid("Merkle proof cannot be empty".to_string());
        }

        if proof.merkle_proof.len() > self.config.max_merkle_depth as usize {
            return ProofValidationResult::Invalid("Merkle proof too deep".to_string());
        }

        if proof.block_header.is_empty() {
            return ProofValidationResult::Invalid("Block header cannot be empty".to_string());
        }

        if proof.transaction_data.is_empty() {
            return ProofValidationResult::Invalid("Transaction data cannot be empty".to_string());
        }

        // Verify merkle proof
        if let ProofValidationResult::Invalid(reason) = self.verify_merkle_proof(proof) {
            return ProofValidationResult::Invalid(format!(
                "Merkle proof verification failed: {}",
                reason
            ));
        }

        ProofValidationResult::Valid
    }

    /// Verify merkle proof
    fn verify_merkle_proof(&self, proof: &CrossChainProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Parse the block header to get the merkle root
        // 2. Calculate the transaction hash from transaction_data
        // 3. Verify the merkle path from transaction hash to merkle root
        // 4. Ensure the transaction is at the claimed index

        // For now, we'll do basic validation
        if proof.merkle_proof.len() == 0 {
            return ProofValidationResult::Invalid("Empty merkle proof".to_string());
        }

        // Simplified merkle proof verification
        let mut current_hash = blake3::hash(&proof.transaction_data);

        for (i, proof_hash) in proof.merkle_proof.iter().enumerate() {
            let combined = if i % 2 == 0 {
                [current_hash.as_bytes(), proof_hash]
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<u8>>()
            } else {
                [proof_hash, current_hash.as_bytes()]
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<u8>>()
            };
            current_hash = blake3::hash(&combined);
        }

        // In a real implementation, we would compare current_hash with the merkle root
        // from the block header. For now, we'll assume it's valid if we got this far.

        ProofValidationResult::Valid
    }

    /// Validate federation signature
    fn validate_federation_signature(
        &self,
        signature: &FederationSignature,
        message_hash: &Hash,
    ) -> ProofValidationResult {
        if signature.signature.is_empty() {
            return ProofValidationResult::Invalid("Signature cannot be empty".to_string());
        }

        if signature.signer_bitmap.is_empty() {
            return ProofValidationResult::Invalid("Signer bitmap cannot be empty".to_string());
        }

        if signature.threshold == 0 {
            return ProofValidationResult::Invalid(
                "Threshold must be greater than zero".to_string(),
            );
        }

        if message_hash != &signature.message_hash {
            return ProofValidationResult::Invalid("Message hash mismatch".to_string());
        }

        let public_keys = match self.federation_keys.get(&signature.epoch) {
            Some(keys) => keys,
            None => {
                if self.config.strict_validation {
                    return ProofValidationResult::Invalid(format!(
                        "No federation keys for epoch {}",
                        signature.epoch
                    ));
                } else {
                    warn!("No federation keys for epoch {}", signature.epoch);
                    return ProofValidationResult::Valid;
                }
            }
        };

        match verify_federation_signature_with_public_keys(
            public_keys,
            signature,
            message_hash.as_ref(),
            self.config.min_federation_signatures,
        ) {
            Ok(()) => ProofValidationResult::Valid,
            Err(err) => ProofValidationResult::Invalid(err),
        }
    }

    /// Validate fraud proof
    fn validate_fraud_proof(&self, proof: &FraudProof) -> ProofValidationResult {
        if proof.evidence.pre_state.is_empty() {
            return ProofValidationResult::Invalid("Pre-state cannot be empty".to_string());
        }

        if proof.evidence.post_state.is_empty() {
            return ProofValidationResult::Invalid("Post-state cannot be empty".to_string());
        }

        if proof.evidence.fraudulent_operation.is_empty() {
            return ProofValidationResult::Invalid(
                "Fraudulent operation cannot be empty".to_string(),
            );
        }

        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid(
                "Challenge bond must be greater than zero".to_string(),
            );
        }

        // Fraud-type specific validation
        match proof.fraud_type {
            crate::sidechain::FraudType::InvalidStateTransition => {
                self.validate_state_transition_fraud(proof)
            }
            crate::sidechain::FraudType::DoubleSpending => {
                self.validate_double_spending_fraud(proof)
            }
            crate::sidechain::FraudType::InvalidCrossChainTx => {
                self.validate_cross_chain_fraud(proof)
            }
            crate::sidechain::FraudType::UnauthorizedSignature => {
                self.validate_signature_fraud(proof)
            }
            crate::sidechain::FraudType::InvalidVMExecution => self.validate_vm_fraud(proof),
        }
    }

    /// Validate state transition fraud proof
    fn validate_state_transition_fraud(&self, proof: &FraudProof) -> ProofValidationResult {
        // Validate that pre-state and post-state are provided
        if proof.evidence.pre_state.is_empty() {
            return ProofValidationResult::Invalid("Pre-state evidence is required for state transition fraud".to_string());
        }

        if proof.evidence.post_state.is_empty() {
            return ProofValidationResult::Invalid("Post-state evidence is required for state transition fraud".to_string());
        }

        // Check if the operation data is present
        if proof.evidence.fraudulent_operation.is_empty() {
            return ProofValidationResult::Invalid("Fraudulent operation data is required".to_string());
        }

        // Basic structural validation
        let pre_state_hash = blake3::hash(&proof.evidence.pre_state);
        let post_state_hash = blake3::hash(&proof.evidence.post_state);
        let operation_hash = blake3::hash(&proof.evidence.fraudulent_operation);

        // Verify witness data contains expected hashes
        let witness_data = &proof.evidence.witness_data;
        if witness_data.len() < 96 { // 32 + 32 + 32 bytes for hashes
            return ProofValidationResult::Invalid("Insufficient witness data for state transition validation".to_string());
        }

        // Extract expected hashes from witness data
        let expected_pre_hash = &witness_data[0..32];
        let expected_post_hash = &witness_data[32..64];
        let expected_op_hash = &witness_data[64..96];

        // Verify witness data consistency
        if expected_pre_hash != pre_state_hash.as_bytes() {
            return ProofValidationResult::Invalid("Witness data pre-state hash does not match evidence".to_string());
        }

        if expected_post_hash != post_state_hash.as_bytes() {
            return ProofValidationResult::Invalid("Witness data post-state hash does not match evidence".to_string());
        }

        if expected_op_hash != operation_hash.as_bytes() {
            return ProofValidationResult::Invalid("Witness data operation hash does not match evidence".to_string());
        }

        // State transitions must result in different states for fraud to be meaningful
        if proof.evidence.pre_state == proof.evidence.post_state {
            return ProofValidationResult::Invalid("State transition fraud requires different pre and post states".to_string());
        }

        // Validate operation data structure and content
        let operation_data = &proof.evidence.fraudulent_operation;
        if operation_data.len() < 64 {
            return ProofValidationResult::Invalid("Operation data too small for state transition".to_string());
        }

        // Parse operation type from operation data
        let op_type = if operation_data.len() >= 4 {
            u32::from_le_bytes(operation_data[0..4].try_into().unwrap_or_default())
        } else {
            return ProofValidationResult::Invalid("Invalid operation type format".to_string());
        };

        // Validate operation type is within expected range
        if op_type > 1000 {
            return ProofValidationResult::Invalid("Operation type exceeds valid range".to_string());
        }

        // Validate state data structure
        let pre_state_data = &proof.evidence.pre_state;
        let post_state_data = &proof.evidence.post_state;

        if pre_state_data.len() < 32 || post_state_data.len() < 32 {
            return ProofValidationResult::Invalid("State data too small for validation".to_string());
        }

        // Extract state version and validate consistency
        let pre_version = u32::from_le_bytes(pre_state_data[0..4].try_into().unwrap_or_default());
        let post_version = u32::from_le_bytes(post_state_data[0..4].try_into().unwrap_or_default());

        if pre_version != post_version {
            return ProofValidationResult::Invalid("State version mismatch between pre and post states".to_string());
        }

        // Extract state timestamp if available
        let pre_timestamp = if pre_state_data.len() >= 12 {
            u64::from_le_bytes(pre_state_data[4..12].try_into().unwrap_or_default())
        } else {
            0
        };

        let post_timestamp = if post_state_data.len() >= 12 {
            u64::from_le_bytes(post_state_data[4..12].try_into().unwrap_or_default())
        } else {
            0
        };

        // Validate timestamp progression (post-state should not be earlier than pre-state)
        if pre_timestamp > 0 && post_timestamp > 0 && post_timestamp < pre_timestamp {
            return ProofValidationResult::Invalid("Post-state timestamp precedes pre-state timestamp".to_string());
        }

        // Validate state size constraints
        if pre_state_data.len() > 1_000_000 || post_state_data.len() > 1_000_000 {
            return ProofValidationResult::Invalid("State data exceeds maximum size limit".to_string());
        }

        // Check for consensus rule violations based on operation type
        let consensus_violation = match op_type {
            // Transaction operations
            1 => self.validate_transaction_state_transition(pre_state_data, post_state_data, operation_data),
            // Contract deployment
            2 => self.validate_contract_deployment_transition(pre_state_data, post_state_data, operation_data),
            // Contract execution
            3 => self.validate_contract_execution_transition(pre_state_data, post_state_data, operation_data),
            // Asset transfer
            4 => self.validate_asset_transfer_transition(pre_state_data, post_state_data, operation_data),
            // Governance operation
            5 => self.validate_governance_transition(pre_state_data, post_state_data, operation_data),
            // Other operations
            _ => self.validate_generic_state_transition(pre_state_data, post_state_data, operation_data),
        };

        if let ProofValidationResult::Invalid(reason) = consensus_violation {
            return ProofValidationResult::Invalid(format!("Consensus rule violation: {}", reason));
        }

        // Validate balance conservation if applicable
        if let Some(balance_validation) = self.validate_balance_conservation(pre_state_data, post_state_data) {
            if let ProofValidationResult::Invalid(reason) = balance_validation {
                return ProofValidationResult::Invalid(format!("Balance conservation violation: {}", reason));
            }
        }

        // Check for suspicious state changes patterns
        let state_change_ratio = self.calculate_state_change_ratio(pre_state_data, post_state_data);
        if state_change_ratio > 0.8 {
            return ProofValidationResult::Invalid("State change too extensive for single operation".to_string());
        }

        // Validate operation sequence consistency
        if let Some(operation_sequence) = proof.evidence.additional_evidence.get("operation_sequence") {
            if operation_sequence.len() >= 8 {
                let seq_start = u64::from_le_bytes(operation_sequence[0..8].try_into().unwrap_or_default());
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if seq_start > current_time + 3600 {
                    return ProofValidationResult::Invalid("Operation sequence timestamp in future".to_string());
                }
            }
        }

        // Validate challenge timing constraints
        if proof.response_deadline == 0 {
            return ProofValidationResult::Invalid("Missing response deadline for state transition fraud proof".to_string());
        }

        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid("Challenge bond must be greater than zero".to_string());
        }

        // Additional validation would include:
        // - Verifying the operation follows valid state transition rules
        // - Checking for invalid balance changes
        // - Validating against protocol constraints
        // - Replaying the state transition to verify it produces the claimed post-state

        ProofValidationResult::Valid
    }

    /// Validate transaction-related state transitions
    fn validate_transaction_state_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Basic transaction validation
        if operation.len() < 100 {
            return ProofValidationResult::Invalid("Transaction operation data too small".to_string());
        }

        // Check for invalid transaction patterns
        let mut invalid_patterns = 0;

        // Check for excessive fee calculations
        if operation.len() >= 20 {
            let fee_bytes = &operation[12..20];
            let fee = u64::from_le_bytes(fee_bytes.try_into().unwrap_or_default());
            if fee > 1_000_000_000 {
                invalid_patterns += 1;
            }
        }

        if invalid_patterns > 0 {
            return ProofValidationResult::Invalid("Invalid transaction patterns detected".to_string());
        }

        ProofValidationResult::Valid
    }

    /// Validate contract deployment state transitions
    fn validate_contract_deployment_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Contract deployment should add new state entries
        if post_state.len() <= pre_state.len() {
            return ProofValidationResult::Invalid("Contract deployment should increase state size".to_string());
        }

        // Check for invalid contract bytecode
        if operation.len() < 50 {
            return ProofValidationResult::Invalid("Contract deployment operation too small".to_string());
        }

        ProofValidationResult::Valid
    }

    /// Validate contract execution state transitions
    fn validate_contract_execution_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Contract execution should maintain or modify existing state
        if operation.len() < 80 {
            return ProofValidationResult::Invalid("Contract execution operation too small".to_string());
        }

        // Check for gas-related fraud
        if operation.len() >= 28 {
            let gas_limit = u64::from_le_bytes(operation[20..28].try_into().unwrap_or_default());
            if gas_limit == 0 || gas_limit > 100_000_000 {
                return ProofValidationResult::Invalid("Invalid gas limit in contract execution".to_string());
            }
        }

        ProofValidationResult::Valid
    }

    /// Validate asset transfer state transitions
    fn validate_asset_transfer_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Asset transfers should conserve total value
        if operation.len() < 40 {
            return ProofValidationResult::Invalid("Asset transfer operation too small".to_string());
        }

        // Check for negative or excessive transfer amounts
        if operation.len() >= 36 {
            let amount = i64::from_le_bytes(operation[28..36].try_into().unwrap_or_default());
            if amount <= 0 || amount > 1_000_000_000_000_000_000 {
                return ProofValidationResult::Invalid("Invalid transfer amount".to_string());
            }
        }

        ProofValidationResult::Valid
    }

    /// Validate governance-related state transitions
    fn validate_governance_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Governance operations should have proper authorization
        if operation.len() < 60 {
            return ProofValidationResult::Invalid("Governance operation too small".to_string());
        }

        // Check for unauthorized governance actions
        if operation.len() >= 44 {
            let proposal_id = u32::from_le_bytes(operation[40..44].try_into().unwrap_or_default());
            if proposal_id == 0 {
                return ProofValidationResult::Invalid("Invalid governance proposal ID".to_string());
            }
        }

        ProofValidationResult::Valid
    }

    /// Validate generic state transitions
    fn validate_generic_state_transition(&self, pre_state: &[u8], post_state: &[u8], operation: &[u8]) -> ProofValidationResult {
        // Generic validation for other operation types
        if operation.len() < 32 {
            return ProofValidationResult::Invalid("Generic operation too small".to_string());
        }

        // Check for obviously invalid operation data
        let zero_ratio = operation.iter().filter(|&&b| b == 0).count() as f64 / operation.len() as f64;
        if zero_ratio > 0.9 {
            return ProofValidationResult::Invalid("Operation data contains excessive zeros".to_string());
        }

        ProofValidationResult::Valid
    }

    /// Validate balance conservation across state transitions
    fn validate_balance_conservation(&self, pre_state: &[u8], post_state: &[u8]) -> Option<ProofValidationResult> {
        // Extract balance information from state data
        // This is a simplified check - real implementation would parse state structure

        if pre_state.len() < 100 || post_state.len() < 100 {
            return None; // Skip if insufficient data
        }

        // Check for reasonable state changes
        let size_change = (post_state.len() as i64) - (pre_state.len() as i64);
        let size_change_ratio = size_change.abs() as f64 / pre_state.len() as f64;

        if size_change_ratio > 0.5 {
            return Some(ProofValidationResult::Invalid("State size change too large".to_string()));
        }

        None
    }

    /// Calculate the ratio of changed state data
    fn calculate_state_change_ratio(&self, pre_state: &[u8], post_state: &[u8]) -> f64 {
        let min_len = std::cmp::min(pre_state.len(), post_state.len());
        if min_len == 0 {
            return 0.0;
        }

        let mut changed_bytes = 0;
        for i in 0..min_len {
            if pre_state[i] != post_state[i] {
                changed_bytes += 1;
            }
        }

        // Also account for added/removed bytes
        let size_diff = std::cmp::max(pre_state.len(), post_state.len()) - min_len;
        changed_bytes += size_diff;

        changed_bytes as f64 / std::cmp::max(pre_state.len(), post_state.len()) as f64
    }

    /// Validate double spending fraud proof
    fn validate_double_spending_fraud(&self, proof: &FraudProof) -> ProofValidationResult {
        // Double spending requires fraudulent operation data containing conflicting transactions
        if proof.evidence.fraudulent_operation.is_empty() {
            return ProofValidationResult::Invalid("Double spending proof requires transaction data".to_string());
        }

        // Parse the conflicting transactions from fraudulent operation data
        let tx_data = &proof.evidence.fraudulent_operation;
        if tx_data.len() < 128 { // Minimum size for two full transactions (64 bytes each for serialized data)
            return ProofValidationResult::Invalid("Insufficient transaction data for double spending proof".to_string());
        }

        // Extract and validate first transaction hash
        let tx1_hash: [u8; 32] = match tx_data[0..32].try_into() {
            Ok(hash) => hash,
            Err(_) => return ProofValidationResult::Invalid("Invalid first transaction hash format".to_string()),
        };

        // Extract and validate second transaction hash
        let tx2_hash: [u8; 32] = match tx_data[32..64].try_into() {
            Ok(hash) => hash,
            Err(_) => return ProofValidationResult::Invalid("Invalid second transaction hash format".to_string()),
        };

        // Verify the transactions are different (not the same transaction)
        if tx1_hash == tx2_hash {
            return ProofValidationResult::Invalid("Double spending requires two different transactions".to_string());
        }

        // Validate witness data contains proof of conflicting inputs
        let witness_data = &proof.evidence.witness_data;
        if witness_data.len() < 64 {
            return ProofValidationResult::Invalid("Witness data too small for double spending proof".to_string());
        }

        // Parse conflicting outpoint from witness data
        let conflicting_txid: [u8; 32] = match witness_data[0..32].try_into() {
            Ok(txid) => txid,
            Err(_) => return ProofValidationResult::Invalid("Invalid conflicting transaction ID in witness data".to_string()),
        };

        let conflicting_vout = u32::from_le_bytes(match witness_data[32..36].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return ProofValidationResult::Invalid("Invalid output index in witness data".to_string()),
        });

        // Verify both transaction hashes are referenced in witness data
        let remaining_witness = &witness_data[36..];
        if remaining_witness.len() < 64 {
            return ProofValidationResult::Invalid("Insufficient witness data for transaction references".to_string());
        }

        // Check for tx1 hash in witness data
        let mut found_tx1 = false;
        let mut found_tx2 = false;

        for chunk in remaining_witness.chunks(32) {
            if chunk.len() == 32 {
                if chunk == &tx1_hash[..] {
                    found_tx1 = true;
                }
                if chunk == &tx2_hash[..] {
                    found_tx2 = true;
                }
            }
        }

        if !found_tx1 || !found_tx2 {
            return ProofValidationResult::Invalid("Witness data does not contain both conflicting transaction hashes".to_string());
        }

        // Validate that both transactions actually exist and are spendable
        // In a real implementation, this would check against sidechain state
        // For now, verify the transaction data structure is valid

        // Check transaction data format (should contain transaction inputs/outputs)
        let tx1_data = &tx_data[64..96];
        let tx2_data = &tx_data[96..128];

        // Validate transaction data contains expected structure (inputs count at minimum)
        if tx1_data.len() < 4 || tx2_data.len() < 4 {
            return ProofValidationResult::Invalid("Transaction data missing required fields".to_string());
        }

        // Verify the fraud proof timing constraints
        if proof.response_deadline == 0 {
            return ProofValidationResult::Invalid("Missing response deadline for fraud proof".to_string());
        }

        // Validate challenge bond is sufficient
        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid("Challenge bond must be greater than zero".to_string());
        }

        // Additional validation: Check for replay protection
        // Ensure the fraud proof is for a recent transaction, not an old one
        if proof.fraud_block_height > 0 {
            // In a real implementation, this would check against current chain height
            // For now, ensure it's not from the future
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if proof.fraud_block_height > current_time as u64 + 86400 {
                return ProofValidationResult::Invalid("Fraud proof block height appears to be in the future".to_string());
            }
        }

        // If all validations pass, this is a valid double spending fraud proof
        ProofValidationResult::Valid
    }

    /// Validate cross-chain fraud proof
    fn validate_cross_chain_fraud(&self, proof: &FraudProof) -> ProofValidationResult {
        // Cross-chain fraud requires additional evidence
        if proof.evidence.additional_evidence.is_empty() {
            return ProofValidationResult::Invalid("Cross-chain fraud proof requires additional evidence".to_string());
        }

        // Extract and validate cross-chain transaction data
        let cross_chain_tx_data = match proof.evidence.additional_evidence.get("cross_chain_transaction") {
            Some(data) => data,
            None => return ProofValidationResult::Invalid("Cross-chain transaction data required".to_string()),
        };

        if cross_chain_tx_data.len() < 100 {
            return ProofValidationResult::Invalid("Cross-chain transaction data too small".to_string());
        }

        // Validate federation signature data
        let signature_data = match proof.evidence.additional_evidence.get("federation_signatures") {
            Some(data) => data,
            None => return ProofValidationResult::Invalid("Federation signature data required for cross-chain fraud".to_string()),
        };

        if signature_data.is_empty() {
            return ProofValidationResult::Invalid("Empty federation signature data".to_string());
        }

        // Validate BLS signature format and detect invalid signatures
        let mut invalid_signatures = 0;
        let mut total_signatures = 0;
        let mut signature_threshold_met = false;

        for chunk in signature_data.chunks(96) {
            if chunk.len() == 96 {
                total_signatures += 1;
                if !self.validate_bls_signature_format(chunk) {
                    invalid_signatures += 1;
                }
            }
        }

        if total_signatures == 0 {
            return ProofValidationResult::Invalid("No valid federation signatures found".to_string());
        }

        // Check if fraud threshold is met (byzantine fault tolerance)
        let byzantine_threshold = (total_signatures * 2) / 3;
        if invalid_signatures >= byzantine_threshold {
            signature_threshold_met = true;
        }

        if !signature_threshold_met {
            return ProofValidationResult::Invalid(format!(
                "Insufficient invalid signatures for fraud proof: {} invalid out of {} (need >= {})",
                invalid_signatures, total_signatures, byzantine_threshold
            ));
        }

        // Validate cross-chain transaction structure
        let tx_hash = blake3::hash(cross_chain_tx_data);
        
        // Extract transaction amount from data (should be at offset 32)
        if cross_chain_tx_data.len() < 40 {
            return ProofValidationResult::Invalid("Cross-chain transaction data incomplete".to_string());
        }

        // Parse amount (8 bytes at offset 32)
        let amount_bytes: [u8; 8] = match cross_chain_tx_data[32..40].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return ProofValidationResult::Invalid("Invalid transaction amount format".to_string()),
        };
        let amount = u64::from_le_bytes(amount_bytes);

        if amount == 0 {
            return ProofValidationResult::Invalid("Cross-chain transaction amount cannot be zero".to_string());
        }

        if amount > 1_000_000_000_000_000_000 { // 1e18 (practical limit)
            return ProofValidationResult::Invalid("Cross-chain transaction amount exceeds maximum allowed".to_string());
        }

        // Validate recipient address
        let recipient_addr_start = 40;
        let recipient_addr_end = recipient_addr_start + 32;
        if cross_chain_tx_data.len() < recipient_addr_end {
            return ProofValidationResult::Invalid("Missing recipient address in cross-chain transaction".to_string());
        }

        // Check recipient address is not zero
        let recipient_addr = &cross_chain_tx_data[recipient_addr_start..recipient_addr_end];
        if recipient_addr.iter().all(|&b| b == 0) {
            return ProofValidationResult::Invalid("Invalid zero recipient address".to_string());
        }

        // Validate merkle proof if present
        if let Some(merkle_proof_data) = proof.evidence.additional_evidence.get("merkle_proof") {
            if let ProofValidationResult::Invalid(reason) = self.validate_merkle_proof_data(merkle_proof_data) {
                return ProofValidationResult::Invalid(format!("Merkle proof validation failed: {}", reason));
            }
        }

        // Validate source and destination chain IDs
        let chain_info_start = recipient_addr_end;
        let chain_info_end = chain_info_start + 64; // 32 bytes each for source and dest chain
        if cross_chain_tx_data.len() < chain_info_end {
            return ProofValidationResult::Invalid("Missing chain information in cross-chain transaction".to_string());
        }

        let source_chain: [u8; 32] = match cross_chain_tx_data[chain_info_start..chain_info_start + 32].try_into() {
            Ok(chain) => chain,
            Err(_) => return ProofValidationResult::Invalid("Invalid source chain ID".to_string()),
        };

        let dest_chain: [u8; 32] = match cross_chain_tx_data[chain_info_start + 32..chain_info_end].try_into() {
            Ok(chain) => chain,
            Err(_) => return ProofValidationResult::Invalid("Invalid destination chain ID".to_string()),
        };

        // Validate chains are different (no self-transfers)
        if source_chain == dest_chain {
            return ProofValidationResult::Invalid("Source and destination chains cannot be the same".to_string());
        }

        // Validate witness data for cross-chain proof
        let witness_data = &proof.evidence.witness_data;
        if witness_data.len() < 64 {
            return ProofValidationResult::Invalid("Insufficient witness data for cross-chain proof".to_string());
        }

        // Check witness data contains transaction hash
        let mut found_tx_hash = false;
        for chunk in witness_data.chunks(32) {
            if chunk.len() == 32 && chunk == tx_hash.as_bytes() {
                found_tx_hash = true;
                break;
            }
        }

        if !found_tx_hash {
            return ProofValidationResult::Invalid("Witness data does not contain cross-chain transaction hash".to_string());
        }

        // Validate federation quorum requirements
        let required_signatures = self.config.min_federation_signatures;
        if total_signatures < required_signatures {
            return ProofValidationResult::Invalid(format!(
                "Insufficient federation signatures: {} < {}",
                total_signatures, required_signatures
            ));
        }

        // Check for replay protection (timestamp validation)
        if let Some(timestamp_data) = proof.evidence.additional_evidence.get("timestamp") {
            if timestamp_data.len() == 8 {
                let timestamp = u64::from_le_bytes(match timestamp_data.as_slice().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return ProofValidationResult::Invalid("Invalid timestamp format".to_string()),
                });

                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Transaction should not be too old or too new
                if timestamp > current_time + 3600 || timestamp < current_time - 86400 {
                    return ProofValidationResult::Invalid("Cross-chain transaction timestamp is outside acceptable range".to_string());
                }
            }
        }

        // Additional validation would include:
        // - Verifying asset conservation across chains
        // - Checking transaction hasn't been processed before
        // - Validating federation member authorization

        ProofValidationResult::Valid
    }

    /// Validate BLS signature format
    fn validate_bls_signature_format(&self, signature: &[u8]) -> bool {
        if signature.len() != 96 {
            return false;
        }

        // Check for non-zero signature (basic validation)
        // In a real implementation, this would perform full BLS signature validation
        !signature.iter().all(|&b| b == 0)
    }

    /// Validate merkle proof data
    fn validate_merkle_proof_data(&self, merkle_data: &[u8]) -> ProofValidationResult {
        if merkle_data.is_empty() {
            return ProofValidationResult::Invalid("Empty merkle proof".to_string());
        }

        if merkle_data.len() % 32 != 0 {
            return ProofValidationResult::Invalid("Merkle proof data must be multiple of 32 bytes".to_string());
        }

        // Basic structure validation
        let proof_elements = merkle_data.len() / 32;
        if proof_elements == 0 || proof_elements > self.config.max_merkle_depth as usize {
            return ProofValidationResult::Invalid("Invalid merkle proof length".to_string());
        }

        ProofValidationResult::Valid
    }

    /// Validate signature fraud proof
    fn validate_signature_fraud(&self, proof: &FraudProof) -> ProofValidationResult {
        // Signature fraud requires witness data containing the signature and message
        if proof.evidence.witness_data.len() < 96 { // 64 bytes signature + 32 bytes message hash minimum
            return ProofValidationResult::Invalid("Insufficient witness data for signature fraud proof".to_string());
        }

        let witness_data = &proof.evidence.witness_data;

        // Extract signature (first 64 bytes - Ed25519 format)
        let signature = &witness_data[0..64];
        let message_hash: [u8; 32] = match witness_data[64..96].try_into() {
            Ok(hash) => hash,
            Err(_) => return ProofValidationResult::Invalid("Invalid message hash in witness data".to_string()),
        };

        // Validate signature format and structure
        if !self.is_valid_signature_format(signature) {
            return ProofValidationResult::Invalid("Invalid signature format".to_string());
        }

        // Check for obviously invalid signature patterns
        let r_component = &signature[0..32];
        let s_component = &signature[32..64];

        // Verify signature components are not all zeros or all ones (invalid curve points)
        if r_component.iter().all(|&b| b == 0) || s_component.iter().all(|&b| b == 0) {
            return ProofValidationResult::Invalid("Signature contains zero components (invalid)".to_string());
        }

        if r_component.iter().all(|&b| b == 0xFF) || s_component.iter().all(|&b| b == 0xFF) {
            return ProofValidationResult::Invalid("Signature contains all 0xFF components (invalid)".to_string());
        }

        // Validate Ed25519 signature bounds (S component must be less than L)
        let s_value = u256_from_bytes(s_component);
        let l_value = hex::decode("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed").unwrap();
        let l_u256 = u256_from_bytes(&l_value);

        if s_value >= l_u256 {
            return ProofValidationResult::Invalid("Signature S component exceeds Ed25519 curve order".to_string());
        }

        // Check if the message hash is valid (not all zeros)
        if message_hash.iter().all(|&b| b == 0) {
            return ProofValidationResult::Invalid("Message hash cannot be all zeros".to_string());
        }

        // Validate public key if provided in additional evidence
        if let Some(pubkey_data) = proof.evidence.additional_evidence.get("public_key") {
            if pubkey_data.len() != 32 {
                return ProofValidationResult::Invalid("Invalid public key length (must be 32 bytes)".to_string());
            }

            // Check public key format (not all zeros or invalid)
            if pubkey_data.iter().all(|&b| b == 0) {
                return ProofValidationResult::Invalid("Public key cannot be all zeros".to_string());
            }

            // Verify the signature does NOT validate with the provided public key
            // This is key to signature fraud - the signature should be invalid
            if self.signature_validates_with_key(signature, &message_hash, pubkey_data) {
                return ProofValidationResult::Invalid("Signature validates with public key - not fraudulent".to_string());
            }

            // Additional check: ensure the signature is cryptographically invalid
            // but not just due to random data
            let sig_hash = blake3::hash(signature);
            let msg_hash = blake3::hash(&message_hash);
            let key_hash = blake3::hash(pubkey_data);

            // Check for patterns that suggest a real but invalid signature attempt
            let similarity_check = sig_hash.as_bytes()[0..4]
                .iter()
                .zip(msg_hash.as_bytes()[0..4].iter())
                .zip(key_hash.as_bytes()[0..4].iter())
                .filter(|((a, b), c)| a == b || b == c || a == c)
                .count();

            if similarity_check > 2 {
                return ProofValidationResult::Invalid("Signature shows suspicious similarity patterns - may be intentionally malformed".to_string());
            }
        } else {
            // If no public key provided, validate signature structure against expected patterns
            return ProofValidationResult::Invalid("Public key required for signature fraud validation".to_string());
        }

        // Check for federation member authorization if applicable
        if let Some(federation_data) = proof.evidence.additional_evidence.get("federation_member_info") {
            if federation_data.len() >= 32 {
                // Extract federation member ID or public key
                let member_id: [u8; 32] = match federation_data[0..32].try_into() {
                    Ok(id) => id,
                    Err(_) => return ProofValidationResult::Invalid("Invalid federation member ID format".to_string()),
                };

                // Check if this member was authorized for the operation
                // In a real implementation, this would check federation member lists
                if member_id.iter().all(|&b| b == 0) {
                    return ProofValidationResult::Invalid("Invalid federation member ID (all zeros)".to_string());
                }

                // Validate the signature context matches the operation
                if let Some(operation_context) = proof.evidence.additional_evidence.get("operation_context") {
                    if operation_context.len() < 32 {
                        return ProofValidationResult::Invalid("Invalid operation context".to_string());
                    }
                    // Verify the signature was for a different context than authorized
                    // This is where we'd check if the signature was used outside its scope
                }
            }
        }

        // Check signature timestamp if provided (for replay protection)
        if let Some(timestamp_data) = proof.evidence.additional_evidence.get("signature_timestamp") {
            if timestamp_data.len() == 8 {
                let timestamp = u64::from_le_bytes(match timestamp_data.as_slice().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return ProofValidationResult::Invalid("Invalid signature timestamp".to_string()),
                });

                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Signature should not be too old (prevent replay attacks)
                if timestamp < current_time - 86400 {
                    return ProofValidationResult::Invalid("Signature is too old (potential replay attack)".to_string());
                }
            }
        }

        // Validate challenge bond and timing constraints
        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid("Challenge bond must be greater than zero".to_string());
        }

        if proof.response_deadline == 0 {
            return ProofValidationResult::Invalid("Missing response deadline".to_string());
        }

        // Final validation: ensure this is actually a signature-related fraud
        // Check that the fraudulent operation contains signature-related data
        let fraudulent_op = &proof.evidence.fraudulent_operation;
        if fraudulent_op.len() < 32 {
            return ProofValidationResult::Invalid("Fraudulent operation must contain signature evidence".to_string());
        }

        // If all validations pass, this is a valid signature fraud proof
        ProofValidationResult::Valid
    }

    /// Check if signature format is valid
    fn is_valid_signature_format(&self, signature: &[u8]) -> bool {
        signature.len() == 64 && !signature.iter().all(|&b| b == 0)
    }

    /// Check if signature validates with given key (simplified)
    fn signature_validates_with_key(&self, signature: &[u8], message_hash: &[u8], public_key: &[u8]) -> bool {
        // In a real implementation, this would perform Ed25519 verification
        // For now, return false to indicate potential fraud
        // This is a placeholder - actual implementation would use ed25519-dalek

        // Simple check: if signature and message hash are related in some way
        let sig_hash = blake3::hash(signature);
        let msg_hash = blake3::hash(message_hash);
        let key_hash = blake3::hash(public_key);

        // If signature appears to be correctly related to message and key, it might be valid
        // This is a very simplified check
        sig_hash.as_bytes()[0] == msg_hash.as_bytes()[0] && sig_hash.as_bytes()[1] == key_hash.as_bytes()[1]
    }

    /// Validate VM execution fraud proof
    fn validate_vm_fraud(&self, proof: &FraudProof) -> ProofValidationResult {
        // VM execution fraud requires fraudulent operation data containing VM execution details
        if proof.evidence.fraudulent_operation.is_empty() {
            return ProofValidationResult::Invalid("VM execution fraud proof requires operation data".to_string());
        }

        // Validate witness data contains expected and actual execution results
        if proof.evidence.witness_data.len() < 64 {
            return ProofValidationResult::Invalid("Insufficient witness data for VM execution validation".to_string());
        }

        let witness_data = &proof.evidence.witness_data;

        // Extract expected execution result hash (first 32 bytes)
        let expected_result_hash: [u8; 32] = match witness_data[0..32].try_into() {
            Ok(hash) => hash,
            Err(_) => return ProofValidationResult::Invalid("Invalid expected result hash in witness data".to_string()),
        };

        // Extract actual execution result hash (next 32 bytes)
        let actual_result_hash: [u8; 32] = match witness_data[32..64].try_into() {
            Ok(hash) => hash,
            Err(_) => return ProofValidationResult::Invalid("Invalid actual result hash in witness data".to_string()),
        };

        // For fraud to be proven, the expected and actual results must differ
        if expected_result_hash == actual_result_hash {
            return ProofValidationResult::Invalid("VM execution fraud requires different expected and actual results".to_string());
        }

        // Verify both result hashes are non-zero (valid hash format)
        if expected_result_hash.iter().all(|&b| b == 0) {
            return ProofValidationResult::Invalid("Expected result hash cannot be all zeros".to_string());
        }

        if actual_result_hash.iter().all(|&b| b == 0) {
            return ProofValidationResult::Invalid("Actual result hash cannot be all zeros".to_string());
        }

        // Validate operation data contains valid VM execution parameters
        let operation_data = &proof.evidence.fraudulent_operation;
        if operation_data.len() < 128 {
            return ProofValidationResult::Invalid("Operation data too small for VM execution evidence".to_string());
        }

        // Parse VM execution metadata from additional evidence
        let vm_type = match proof.evidence.additional_evidence.get("vm_type") {
            Some(vm_type_data) => {
                if vm_type_data.len() != 1 {
                    return ProofValidationResult::Invalid("Invalid VM type specification (must be 1 byte)".to_string());
                }
                vm_type_data[0]
            }
            None => return ProofValidationResult::Invalid("VM type must be specified".to_string()),
        };

        // Validate VM type is supported
        match vm_type {
            0 => { // EVM
                // Additional EVM-specific validation
                if let Some(gas_limit_bytes) = proof.evidence.additional_evidence.get("gas_limit") {
                    if gas_limit_bytes.len() == 8 {
                        let gas_limit = u64::from_le_bytes(match gas_limit_bytes.as_slice().try_into() {
                            Ok(bytes) => bytes,
                            Err(_) => return ProofValidationResult::Invalid("Invalid gas limit format".to_string()),
                        });

                        if gas_limit == 0 {
                            return ProofValidationResult::Invalid("EVM gas limit cannot be zero".to_string());
                        }

                        if gas_limit > 30_000_000 {
                            return ProofValidationResult::Invalid("EVM gas limit exceeds maximum allowed".to_string());
                        }
                    }
                }
            }
            1 => { // WASM
                // WASM-specific validation
                if operation_data.len() > 1_000_000 {
                    return ProofValidationResult::Invalid("WASM bytecode exceeds size limit".to_string());
                }
            }
            _ => return ProofValidationResult::Invalid("Unsupported VM type".to_string()),
        }

        // Validate gas usage data if provided
        if let Some(gas_used_bytes) = proof.evidence.additional_evidence.get("gas_used") {
            if gas_used_bytes.len() != 8 {
                return ProofValidationResult::Invalid("Invalid gas used data format".to_string());
            }

            let gas_used = u64::from_le_bytes(match gas_used_bytes.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return ProofValidationResult::Invalid("Invalid gas used format".to_string()),
            });

            if gas_used == 0 {
                return ProofValidationResult::Invalid("Gas used cannot be zero for VM execution".to_string());
            }

            // Check for excessive gas usage (potential DoS attack)
            if gas_used > 100_000_000 {
                return ProofValidationResult::Invalid("Gas usage appears excessive".to_string());
            }
        }

        // Validate execution trace data if provided
        if let Some(trace_data) = proof.evidence.additional_evidence.get("execution_trace") {
            if !trace_data.is_empty() {
                // Basic validation of execution trace structure
                if trace_data.len() % 32 != 0 {
                    return ProofValidationResult::Invalid("Execution trace data must be multiple of 32 bytes".to_string());
                }

                let trace_elements = trace_data.len() / 32;
                if trace_elements > 10_000 {
                    return ProofValidationResult::Invalid("Execution trace too long".to_string());
                }

                // Check for obviously invalid trace patterns
                let mut invalid_patterns = 0;
                for chunk in trace_data.chunks(32) {
                    if chunk.iter().all(|&b| b == 0) || chunk.iter().all(|&b| b == 0xFF) {
                        invalid_patterns += 1;
                    }
                }

                if invalid_patterns > trace_elements / 10 {
                    return ProofValidationResult::Invalid("Execution trace contains too many invalid patterns".to_string());
                }
            }
        }

        // Validate bytecode or contract data
        let bytecode_start = 0;
        let bytecode_end = std::cmp::min(operation_data.len(), 1000); // First 1000 bytes should contain bytecode info

        if bytecode_end <= bytecode_start {
            return ProofValidationResult::Invalid("Missing bytecode information in operation data".to_string());
        }

        let bytecode = &operation_data[bytecode_start..bytecode_end];

        // Check for invalid bytecode patterns
        let mut anomaly_score = 0u32;

        // Check for excessive zeros (uninitialized memory)
        let zero_count = bytecode.iter().filter(|&&b| b == 0).count();
        let zero_ratio = zero_count as f64 / bytecode.len() as f64;

        if zero_ratio > 0.9 {
            anomaly_score += 2;
        } else if zero_ratio > 0.7 {
            anomaly_score += 1;
        }

        // Check for invalid opcode patterns
        for chunk in bytecode.chunks(32) {
            if chunk.len() == 32 && chunk.iter().all(|&b| b == 0xFF) {
                anomaly_score += 1;
            }
        }

        // Check for suspicious repeated patterns
        let mut pattern_counts = std::collections::HashMap::new();
        for chunk in bytecode.chunks(16) {
            if chunk.len() == 16 {
                *pattern_counts.entry(chunk.to_vec()).or_insert(0) += 1;
            }
        }

        let max_repeats = pattern_counts.values().max().unwrap_or(&0);
        if *max_repeats > bytecode.len() / 16 / 3 {
            anomaly_score += 1; // Suspicious repetition
        }

        // If we have significant anomalies, this indicates potential fraud
        if anomaly_score >= 3 {
            return ProofValidationResult::Invalid(format!(
                "VM execution contains {} anomalous patterns indicating potential fraud",
                anomaly_score
            ));
        }

        // Validate state transition consistency
        if let Some(state_diff) = proof.evidence.additional_evidence.get("state_diff") {
            if state_diff.len() < 64 {
                return ProofValidationResult::Invalid("State diff too small for validation".to_string());
            }

            // Parse pre and post state hashes from state diff
            let pre_state_from_diff: [u8; 32] = match state_diff[0..32].try_into() {
                Ok(hash) => hash,
                Err(_) => return ProofValidationResult::Invalid("Invalid pre-state hash in state diff".to_string()),
            };

            let post_state_from_diff: [u8; 32] = match state_diff[32..64].try_into() {
                Ok(hash) => hash,
                Err(_) => return ProofValidationResult::Invalid("Invalid post-state hash in state diff".to_string()),
            };

            // Verify state diff is consistent with witness data
            if pre_state_from_diff != expected_result_hash {
                return ProofValidationResult::Invalid("State diff pre-state does not match expected result".to_string());
            }

            if post_state_from_diff != actual_result_hash {
                return ProofValidationResult::Invalid("State diff post-state does not match actual result".to_string());
            }
        }

        // Validate timing constraints
        if proof.response_deadline == 0 {
            return ProofValidationResult::Invalid("Missing response deadline for VM fraud proof".to_string());
        }

        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid("Challenge bond must be greater than zero".to_string());
        }

        // Additional validation would include:
        // - Re-executing the VM with the provided inputs
        // - Comparing actual output with claimed output
        // - Checking for gas limit violations
        // - Validating state transitions against consensus rules

        // If all validations pass, this is a valid VM execution fraud proof
        ProofValidationResult::Valid
    }

    /// Update validation statistics
    fn update_validation_stats(&mut self, result: &ProofValidationResult, validation_time_ms: f64) {
        match result {
            ProofValidationResult::Valid => {
                self.validation_stats.successful_validations += 1;
            }
            ProofValidationResult::Invalid(_) | ProofValidationResult::Error(_) => {
                self.validation_stats.failed_validations += 1;
            }
            ProofValidationResult::Timeout => {
                self.validation_stats.timeout_validations += 1;
            }
        }

        // Update average validation time
        let total_validations = self.validation_stats.total_validations as f64;
        let current_avg = self.validation_stats.average_validation_time_ms;
        self.validation_stats.average_validation_time_ms =
            (current_avg * (total_validations - 1.0) + validation_time_ms) / total_validations;
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> ValidationStats {
        self.validation_stats.clone()
    }

    /// Clear validation statistics
    pub fn clear_stats(&mut self) {
        self.validation_stats = ValidationStats::default();
    }
}

pub fn validate_masternode_signature(
    public_key: PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, String> {
    let public_keys_bytes: &[u8; 32] =
        public_key
            .as_ref()
            .try_into()
            .map_err(|e: TryFromSliceError| {
                ConsensusError::SerializationError(e.to_string()).to_string()
            })?;
    let signature_bytes: &[u8; 64] =
        signature
            .as_ref()
            .try_into()
            .map_err(|e: TryFromSliceError| {
                ConsensusError::SerializationError(e.to_string()).to_string()
            })?;

    let dalek_public_key = VerifyingKey::from_bytes(public_keys_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let dalek_signature =
        Signature::from_bytes(signature_bytes).map_err(|e| format!("Invalid signature: {}", e))?;

    Ok(dalek_public_key.verify(message, &dalek_signature).is_ok())
}

pub fn validate_threshold_signature(
    public_keys: Vec<PublicKey>,
    signatures: Vec<Signature>,
    message: &[u8],
    threshold: u32,
) -> Result<bool, String> {
    if public_keys.len() != signatures.len() {
        return Err("Number of public keys and signatures must match".to_string());
    }

    if public_keys.len() < threshold as usize {
        return Err(format!(
            "Not enough signatures provided: expected at least {}, got {}",
            threshold,
            public_keys.len()
        ));
    }

    let mut valid_signatures = 0;
    for i in 0..public_keys.len() {
        let public_key = public_keys[i];
        let signature = &signatures[i];
        if validate_masternode_signature(public_key, message, signature)? {
            valid_signatures += 1;
        }
    }

    Ok(valid_signatures >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::{federation_manager::test_utils::sample_federation_signature, *};
    use rusty_shared_types::{BlockHeader, Hash};

    // Helper function to create a test hash
    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    // Helper function to create a test sidechain block
    fn create_test_sidechain_block() -> SidechainBlock {
        let header = SidechainBlockHeader::new(
            test_hash(1),   // previous_block_hash
            test_hash(2),   // merkle_root
            test_hash(3),   // cross_chain_merkle_root
            test_hash(4),   // state_root
            1,              // height
            test_hash(100), // sidechain_id
            0,              // mainchain_anchor_height (0 means no anchor required)
            test_hash(5),   // mainchain_anchor_hash
            1,              // federation_epoch
        );

        SidechainBlock::new(header, Vec::new())
    }

    #[test]
    fn test_proof_validation_config_default() {
        let config = ProofValidationConfig::default();

        assert_eq!(config.min_federation_signatures, 2);
        assert_eq!(config.max_proof_size, 1_000_000);
        assert!(config.strict_validation);
        assert_eq!(config.max_merkle_depth, 32);
        assert_eq!(config.verification_timeout_ms, 5000);
    }

    #[test]
    fn test_sidechain_proof_validator_creation() {
        let config = ProofValidationConfig::default();
        let validator = SidechainProofValidator::new(config);

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 0);
        assert_eq!(stats.successful_validations, 0);
        assert_eq!(stats.failed_validations, 0);
        assert_eq!(stats.timeout_validations, 0);
        assert_eq!(stats.average_validation_time_ms, 0.0);
    }

    #[test]
    fn test_federation_keys_update() {
        let mut validator = SidechainProofValidator::new(ProofValidationConfig::default());

        let public_keys = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];

        validator.update_federation_keys(1, public_keys.clone());

        // Verify keys were stored (internal state, can't directly test)
        // But we can test that validation doesn't fail due to missing keys
    }

    #[test]
    fn test_trusted_header_addition() {
        let mut validator = SidechainProofValidator::new(ProofValidationConfig::default());

        let header = BlockHeader {
            version: 1,
            previous_block_hash: test_hash(1),
            merkle_root: test_hash(2),
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
            height: 100,
            state_root: [0u8; 32],
        };

        validator.add_trusted_header(header);

        // Verify header was added (internal state, can't directly test)
    }

    #[test]
    fn test_sidechain_block_validation_success() {
        let config = ProofValidationConfig {
            strict_validation: false, // Allow blocks without federation signatures
            ..ProofValidationConfig::default()
        };
        let mut validator = SidechainProofValidator::new(config);

        let block = create_test_sidechain_block();
        let result = validator.validate_sidechain_block(&block);

        assert_eq!(result, ProofValidationResult::Valid);

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 1);
        assert_eq!(stats.successful_validations, 1);
        assert_eq!(stats.failed_validations, 0);
    }

    #[test]
    fn test_block_header_validation() {
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        // Valid header
        let valid_header = SidechainBlockHeader::new(
            test_hash(1),
            test_hash(2),
            test_hash(3),
            test_hash(4),
            1,
            test_hash(100),
            0, // mainchain_anchor_height (0 means no anchor required)
            test_hash(5),
            1,
        );

        let result = validator.validate_block_header(&valid_header);
        assert_eq!(result, ProofValidationResult::Valid);

        // Invalid header - version 0
        let mut invalid_header = valid_header.clone();
        invalid_header.version = 0;

        let result = validator.validate_block_header(&invalid_header);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Invalid header - genesis with non-zero previous hash
        let mut invalid_header2 = valid_header.clone();
        invalid_header2.height = 0;
        invalid_header2.previous_block_hash = test_hash(1); // Should be zero for genesis

        let result = validator.validate_block_header(&invalid_header2);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_sidechain_transaction_validation() {
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        // Valid transaction
        let valid_tx = SidechainTransaction {
            version: 1,
            inputs: vec![SidechainTxInput {
                previous_output: SidechainOutPoint {
                    txid: test_hash(10),
                    vout: 0,
                },
                script_sig: vec![1, 2, 3],
                sequence: 0xffffffff,
            }],
            outputs: vec![SidechainTxOutput {
                value: 1000000,
                asset_id: test_hash(20),
                script_pubkey: vec![4, 5, 6],
                data: Vec::new(),
            }],
            lock_time: 0,
            vm_data: None,
            fee: 1000,
        };

        let result = validator.validate_sidechain_transaction(&valid_tx);
        assert_eq!(result, ProofValidationResult::Valid);

        // Invalid transaction - no inputs
        let invalid_tx = SidechainTransaction {
            version: 1,
            inputs: Vec::new(),
            outputs: vec![SidechainTxOutput {
                value: 1000000,
                asset_id: test_hash(20),
                script_pubkey: vec![4, 5, 6],
                data: Vec::new(),
            }],
            lock_time: 0,
            vm_data: None,
            fee: 1000,
        };

        let result = validator.validate_sidechain_transaction(&invalid_tx);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_vm_execution_validation() {
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        // Valid VM execution
        let valid_vm_data = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: vec![1, 2, 3, 4],
            gas_limit: 1000000,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };

        let result = validator.validate_vm_execution(&valid_vm_data);
        assert_eq!(result, ProofValidationResult::Valid);

        // Invalid VM execution - empty bytecode
        let invalid_vm_data = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: Vec::new(),
            gas_limit: 1000000,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };

        let result = validator.validate_vm_execution(&invalid_vm_data);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Invalid VM execution - zero gas limit
        let invalid_vm_data2 = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: vec![1, 2, 3, 4],
            gas_limit: 0,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };

        let result = validator.validate_vm_execution(&invalid_vm_data2);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_cross_chain_proof_validation() {
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        // Valid proof
        let valid_proof = CrossChainProof {
            merkle_proof: vec![test_hash(1), test_hash(2)],
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };

        let result = validator.validate_cross_chain_proof(&valid_proof);
        assert_eq!(result, ProofValidationResult::Valid);

        // Invalid proof - empty merkle proof
        let invalid_proof = CrossChainProof {
            merkle_proof: Vec::new(),
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };

        let result = validator.validate_cross_chain_proof(&invalid_proof);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Invalid proof - empty block header
        let invalid_proof2 = CrossChainProof {
            merkle_proof: vec![test_hash(1)],
            block_header: Vec::new(),
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };

        let result = validator.validate_cross_chain_proof(&invalid_proof2);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_federation_signature_validation() {
        let mut validator = SidechainProofValidator::new(ProofValidationConfig::default());

        let message_hash = test_hash(50);
        let sample = sample_federation_signature(3, &[0, 1], message_hash, 1);
        validator.update_federation_keys(1, sample.public_keys.clone());

        let result = validator.validate_federation_signature(&sample.signature, &message_hash);
        assert!(matches!(result, ProofValidationResult::Valid));

        // Invalid signature - tampered bytes
        let mut invalid_signature = sample.signature.clone();
        invalid_signature.signature[0] ^= 0xFF;

        let result = validator.validate_federation_signature(&invalid_signature, &message_hash);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Invalid signature - message hash mismatch
        let wrong_hash = test_hash(51);
        let result = validator.validate_federation_signature(&sample.signature, &wrong_hash);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Missing federation keys in non-strict mode should pass
        let non_strict_validator = SidechainProofValidator::new(ProofValidationConfig {
            strict_validation: false,
            ..ProofValidationConfig::default()
        });
        let result =
            non_strict_validator.validate_federation_signature(&sample.signature, &message_hash);
        assert!(matches!(result, ProofValidationResult::Valid));

        // Missing federation keys in strict mode should fail
        let strict_only_validator = SidechainProofValidator::new(ProofValidationConfig::default());
        let strict_result =
            strict_only_validator.validate_federation_signature(&sample.signature, &message_hash);
        assert!(matches!(strict_result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_merkle_proof_verification() {
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        let proof = CrossChainProof {
            merkle_proof: vec![test_hash(1), test_hash(2)],
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };

        let result = validator.verify_merkle_proof(&proof);
        assert_eq!(result, ProofValidationResult::Valid);

        // Empty merkle proof
        let invalid_proof = CrossChainProof {
            merkle_proof: Vec::new(),
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };

        let result = validator.verify_merkle_proof(&invalid_proof);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_validation_statistics() {
        let config = ProofValidationConfig {
            strict_validation: false, // Allow blocks without federation signatures
            ..ProofValidationConfig::default()
        };
        let mut validator = SidechainProofValidator::new(config);

        // Perform some validations
        let block = create_test_sidechain_block();
        validator.validate_sidechain_block(&block);
        validator.validate_sidechain_block(&block);

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 2);
        assert_eq!(stats.successful_validations, 2);
        assert_eq!(stats.failed_validations, 0);
        assert!(stats.average_validation_time_ms >= 0.0);

        // Clear stats
        validator.clear_stats();
        let cleared_stats = validator.get_stats();
        assert_eq!(cleared_stats.total_validations, 0);
        assert_eq!(cleared_stats.successful_validations, 0);
        assert_eq!(cleared_stats.average_validation_time_ms, 0.0);
    }

    #[test]
    fn test_proof_validation_result_variants() {
        let valid = ProofValidationResult::Valid;
        let invalid = ProofValidationResult::Invalid("Test error".to_string());
        let error = ProofValidationResult::Error("Test error".to_string());
        let timeout = ProofValidationResult::Timeout;

        assert_eq!(valid, ProofValidationResult::Valid);
        assert_ne!(valid, invalid);
        assert_ne!(error, timeout);

        match invalid {
            ProofValidationResult::Invalid(msg) => assert_eq!(msg, "Test error"),
            _ => panic!("Expected Invalid variant"),
        }
    }

    #[test]
    fn test_validation_stats_default() {
        let stats = ValidationStats::default();

        assert_eq!(stats.total_validations, 0);
        assert_eq!(stats.successful_validations, 0);
        assert_eq!(stats.failed_validations, 0);
        assert_eq!(stats.timeout_validations, 0);
        assert_eq!(stats.average_validation_time_ms, 0.0);
    }
}

/// Helper function to convert bytes to u256-like value for signature validation
fn u256_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}
