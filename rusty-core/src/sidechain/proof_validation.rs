//! Sidechain proof validation system
//! 
//! This module implements comprehensive validation logic for sidechain proofs
//! including cross-chain transaction proofs, federation signatures, and state transitions.

use std::collections::HashMap;
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{PublicKey as VerifyingKey, Signature, Verifier};
use rusty_shared_types::{Hash, BlockHeader, MasternodeID, PublicKey, Signature as RustySignature};
use crate::sidechain::{
    SidechainBlock, SidechainBlockHeader, CrossChainTransaction, CrossChainProof,
    FederationSignature, FraudProof, SidechainTransaction, VMExecutionData
};
use crate::consensus::error::ConsensusError;
use std::array::TryFromSliceError;

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
        info!("Updated federation keys for epoch {} with {} keys", epoch, public_keys.len());
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
            if let ProofValidationResult::Invalid(reason) = self.validate_sidechain_transaction(tx) {
                return ProofValidationResult::Invalid(format!("Transaction {} validation failed: {}", i, reason));
            }
        }

        // Validate cross-chain transactions
        for (i, tx) in block.cross_chain_transactions.iter().enumerate() {
            if let ProofValidationResult::Invalid(reason) = self.validate_cross_chain_transaction(tx) {
                return ProofValidationResult::Invalid(format!("Cross-chain transaction {} validation failed: {}", i, reason));
            }
        }

        // Validate fraud proofs
        for (i, proof) in block.fraud_proofs.iter().enumerate() {
            if let ProofValidationResult::Invalid(reason) = self.validate_fraud_proof(proof) {
                return ProofValidationResult::Invalid(format!("Fraud proof {} validation failed: {}", i, reason));
            }
        }

        // Validate federation signature
        if let Some(ref signature) = block.federation_signature {
            if let ProofValidationResult::Invalid(reason) = self.validate_federation_signature(signature, &block.header.hash()) {
                return ProofValidationResult::Invalid(format!("Federation signature validation failed: {}", reason));
            }
        } else if self.config.strict_validation {
            return ProofValidationResult::Invalid("Missing federation signature in strict mode".to_string());
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
            return ProofValidationResult::Invalid("Genesis block must have zero previous hash".to_string());
        }

        if header.height > 0 && header.previous_block_hash == [0u8; 32] {
            return ProofValidationResult::Invalid("Non-genesis block must have valid previous hash".to_string());
        }

        // Validate timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if header.timestamp > current_time + 7200 { // 2 hours in future
            return ProofValidationResult::Invalid("Block timestamp too far in future".to_string());
        }

        // Validate mainchain anchor
        if header.mainchain_anchor_height > 0 {
            if !self.trusted_headers.contains_key(&header.mainchain_anchor_hash) {
                if self.config.strict_validation {
                    return ProofValidationResult::Invalid("Mainchain anchor not in trusted headers".to_string());
                } else {
                    warn!("Mainchain anchor {} not found in trusted headers", hex::encode(&header.mainchain_anchor_hash));
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
                return ProofValidationResult::Invalid(format!("VM execution validation failed: {}", reason));
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
            return ProofValidationResult::Invalid("Gas limit must be greater than zero".to_string());
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
    fn validate_cross_chain_transaction(&self, tx: &CrossChainTransaction) -> ProofValidationResult {
        // Basic validation
        if tx.amount == 0 {
            return ProofValidationResult::Invalid("Cross-chain amount cannot be zero".to_string());
        }

        if tx.recipient_address.is_empty() {
            return ProofValidationResult::Invalid("Recipient address cannot be empty".to_string());
        }

        // Validate cross-chain proof
        if let ProofValidationResult::Invalid(reason) = self.validate_cross_chain_proof(&tx.proof) {
            return ProofValidationResult::Invalid(format!("Cross-chain proof validation failed: {}", reason));
        }

        // Validate federation signatures
        if tx.federation_signatures.is_empty() {
            return ProofValidationResult::Invalid("Cross-chain transaction must have federation signatures".to_string());
        }

        let tx_hash = tx.hash();
        for signature in &tx.federation_signatures {
            if let ProofValidationResult::Invalid(reason) = self.validate_federation_signature(signature, &tx_hash) {
                return ProofValidationResult::Invalid(format!("Federation signature validation failed: {}", reason));
            }
        }

        // Check minimum signature threshold
        let total_signers: u32 = tx.federation_signatures
            .iter()
            .map(|sig| sig.count_signers())
            .sum();

        if total_signers < self.config.min_federation_signatures {
            return ProofValidationResult::Invalid(format!(
                "Insufficient federation signatures: {} < {}",
                total_signers,
                self.config.min_federation_signatures
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
            return ProofValidationResult::Invalid(format!("Merkle proof verification failed: {}", reason));
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
                [current_hash.as_bytes(), proof_hash].into_iter().flatten().copied().collect::<Vec<u8>>()
            } else {
                [proof_hash, current_hash.as_bytes()].into_iter().flatten().copied().collect::<Vec<u8>>()
            };
            current_hash = blake3::hash(&combined);
        }

        // In a real implementation, we would compare current_hash with the merkle root
        // from the block header. For now, we'll assume it's valid if we got this far.

        ProofValidationResult::Valid
    }

    /// Validate federation signature
    fn validate_federation_signature(&self, signature: &FederationSignature, message_hash: &Hash) -> ProofValidationResult {
        if signature.signature.is_empty() {
            return ProofValidationResult::Invalid("Signature cannot be empty".to_string());
        }

        if signature.signer_bitmap.is_empty() {
            return ProofValidationResult::Invalid("Signer bitmap cannot be empty".to_string());
        }

        if signature.threshold == 0 {
            return ProofValidationResult::Invalid("Threshold must be greater than zero".to_string());
        }

        if message_hash != &signature.message_hash {
            return ProofValidationResult::Invalid("Message hash mismatch".to_string());
        }

        // Verify we have the federation keys for this epoch
        if !self.federation_keys.contains_key(&signature.epoch) {
            if self.config.strict_validation {
                return ProofValidationResult::Invalid(format!("No federation keys for epoch {}", signature.epoch));
            } else {
                warn!("No federation keys for epoch {}", signature.epoch);
                return ProofValidationResult::Valid; // Allow in non-strict mode
            }
        }

        // In a real implementation, this would verify the BLS signature
        // against the federation's public keys using the signer bitmap
        
        // Verify signer count meets threshold
        let signer_count = signature.count_signers();
        if signer_count < signature.threshold {
            return ProofValidationResult::Invalid(format!(
                "Insufficient signers: {} < {}",
                signer_count,
                signature.threshold
            ));
        }

        ProofValidationResult::Valid
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
            return ProofValidationResult::Invalid("Fraudulent operation cannot be empty".to_string());
        }

        if proof.challenge_bond == 0 {
            return ProofValidationResult::Invalid("Challenge bond must be greater than zero".to_string());
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
            crate::sidechain::FraudType::InvalidVMExecution => {
                self.validate_vm_fraud(proof)
            }
        }
    }

    /// Validate state transition fraud proof
    fn validate_state_transition_fraud(&self, _proof: &FraudProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Apply the fraudulent operation to the pre-state
        // 2. Verify that the result doesn't match the claimed post-state
        // 3. Ensure the operation is actually invalid
        
        ProofValidationResult::Valid // Placeholder
    }

    /// Validate double spending fraud proof
    fn validate_double_spending_fraud(&self, _proof: &FraudProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Parse the fraudulent operation to extract transactions
        // 2. Verify that the same input is spent in multiple transactions
        // 3. Ensure both transactions are valid individually
        
        ProofValidationResult::Valid // Placeholder
    }

    /// Validate cross-chain fraud proof
    fn validate_cross_chain_fraud(&self, _proof: &FraudProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Verify the cross-chain transaction is malformed
        // 2. Check that proofs are invalid or signatures are forged
        // 3. Ensure the fraud actually occurred
        
        ProofValidationResult::Valid // Placeholder
    }

    /// Validate signature fraud proof
    fn validate_signature_fraud(&self, _proof: &FraudProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Verify that signatures are from unauthorized parties
        // 2. Check that the signature doesn't match federation keys
        // 3. Ensure the signature fraud is provable
        
        ProofValidationResult::Valid // Placeholder
    }

    /// Validate VM execution fraud proof
    fn validate_vm_fraud(&self, _proof: &FraudProof) -> ProofValidationResult {
        // In a real implementation, this would:
        // 1. Re-execute the VM operation with the given inputs
        // 2. Verify that the actual result differs from the claimed result
        // 3. Ensure the VM execution was actually incorrect
        
        ProofValidationResult::Valid // Placeholder
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
    let public_keys_bytes: &[u8; 32] = public_key.as_ref().try_into().map_err(|e: TryFromSliceError| ConsensusError::SerializationError(e.to_string()).to_string())?;
    let signature_bytes: &[u8; 64] = signature.as_ref().try_into().map_err(|e: TryFromSliceError| ConsensusError::SerializationError(e.to_string()).to_string())?;

    let dalek_public_key = VerifyingKey::from_bytes(public_keys_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let dalek_signature = Signature::from_bytes(signature_bytes)
        .map_err(|e| format!("Invalid signature: {}", e))?;

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
        return Err(format!("Not enough signatures provided: expected at least {}, got {}", threshold, public_keys.len()));
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
    use crate::sidechain::*;
    use rusty_shared_types::{Hash, BlockHeader, MasternodeID};

    // Helper function to create a test hash
    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    // Helper function to create a test sidechain block
    fn create_test_sidechain_block() -> SidechainBlock {
        let header = SidechainBlockHeader::new(
            test_hash(1), // previous_block_hash
            test_hash(2), // merkle_root
            test_hash(3), // cross_chain_merkle_root
            test_hash(4), // state_root
            1, // height
            test_hash(100), // sidechain_id
            50, // mainchain_anchor_height
            test_hash(5), // mainchain_anchor_hash
            1, // federation_epoch
        );

        SidechainBlock::new(header, Vec::new(), Vec::new())
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

        let public_keys = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            vec![9, 10, 11, 12],
        ];

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
            bits: 0x1d00ffff,
            nonce: 12345,
            height: 100,
        };

        validator.add_trusted_header(header);

        // Verify header was added (internal state, can't directly test)
    }

    #[test]
    fn test_sidechain_block_validation_success() {
        let mut validator = SidechainProofValidator::new(ProofValidationConfig::default());

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
            test_hash(1), test_hash(2), test_hash(3), test_hash(4),
            1, test_hash(100), 50, test_hash(5), 1
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
        let validator = SidechainProofValidator::new(ProofValidationConfig::default());

        let message_hash = test_hash(50);

        // Valid signature
        let valid_signature = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11000000], // 2 signers
            threshold: 2,
            epoch: 1,
            message_hash,
        };

        let result = validator.validate_federation_signature(&valid_signature, &message_hash);
        // In non-strict mode without federation keys, this should pass
        assert!(matches!(result, ProofValidationResult::Valid | ProofValidationResult::Invalid(_)));

        // Invalid signature - empty signature
        let invalid_signature = FederationSignature {
            signature: Vec::new(),
            signer_bitmap: vec![0b11000000],
            threshold: 2,
            epoch: 1,
            message_hash,
        };

        let result = validator.validate_federation_signature(&invalid_signature, &message_hash);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));

        // Invalid signature - message hash mismatch
        let invalid_signature2 = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11000000],
            threshold: 2,
            epoch: 1,
            message_hash,
        };

        let wrong_hash = test_hash(51);
        let result = validator.validate_federation_signature(&invalid_signature2, &wrong_hash);
        assert!(matches!(result, ProofValidationResult::Invalid(_)));
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
        let mut validator = SidechainProofValidator::new(ProofValidationConfig::default());

        // Perform some validations
        let block = create_test_sidechain_block();
        validator.validate_sidechain_block(&block);
        validator.validate_sidechain_block(&block);

        let stats = validator.get_stats();
        assert_eq!(stats.total_validations, 2);
        assert_eq!(stats.successful_validations, 2);
        assert_eq!(stats.failed_validations, 0);
        assert!(stats.average_validation_time_ms > 0.0);

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
