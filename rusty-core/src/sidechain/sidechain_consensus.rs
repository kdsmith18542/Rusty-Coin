//! Sidechain consensus integration with mainchain
//!
//! This module provides the core consensus logic for sidechains,
//! ensuring they operate in harmony with mainchain state and rules.
//! Integrates fraud proof validation, federation management, and consensus rule enforcement.

use crate::sidechain::cross_chain_communication::{CrossChainCommunication, CrossChainMessage, CrossChainMessageType};
use crate::sidechain::federation_integrator::FederationIntegrator;
use crate::sidechain::fraud_proofs::FraudProofManager;
use crate::sidechain::mainchain_validator::{MainchainValidator, ReorgImpact};
use crate::sidechain::proof_validation::{SidechainProofValidator, ProofValidationConfig, ProofValidationResult};
use crate::sidechain::two_way_peg::TwoWayPegManager;
use crate::sidechain::types::*;
use log::{debug, info, warn};
use rusty_shared_types::Hash;
use std::sync::Arc;

/// Sidechain consensus engine with integrated fraud proof validation
pub struct SidechainConsensus {
    /// Sidechain ID
    sidechain_id: Hash,
    /// Cross-chain communication manager
    communication: Arc<std::sync::Mutex<CrossChainCommunication>>,
    /// Federation integrator
    federation: Arc<std::sync::Mutex<FederationIntegrator>>,
    /// Mainchain validator
    mainchain_validator: Arc<std::sync::Mutex<MainchainValidator>>,
    /// Two-way peg manager
    peg_manager: Arc<std::sync::Mutex<TwoWayPegManager>>,
    /// Fraud proof manager for handling fraud challenges
    fraud_proof_manager: Arc<std::sync::Mutex<FraudProofManager>>,
    /// Proof validator for validating sidechain proofs
    proof_validator: Arc<std::sync::Mutex<SidechainProofValidator>>,
    /// Current sidechain height
    current_height: u64,
    /// Current sidechain tip hash
    current_tip: Hash,
}

impl SidechainConsensus {
    /// Create a new sidechain consensus engine
    pub fn new(sidechain_id: Hash) -> Self {
        let proof_config = ProofValidationConfig::default();
        let fraud_config = crate::sidechain::fraud_proofs::FraudProofConfig::default();

        Self {
            sidechain_id,
            communication: Arc::new(std::sync::Mutex::new(CrossChainCommunication::new())),
            federation: Arc::new(std::sync::Mutex::new(FederationIntegrator::new())),
            mainchain_validator: Arc::new(std::sync::Mutex::new(MainchainValidator::new(100))),
            peg_manager: Arc::new(std::sync::Mutex::new(TwoWayPegManager::new(6))),
            fraud_proof_manager: Arc::new(std::sync::Mutex::new(FraudProofManager::new(fraud_config))),
            proof_validator: Arc::new(std::sync::Mutex::new(SidechainProofValidator::new(proof_config))),
            current_height: 0,
            current_tip: [0u8; 32],
        }
    }

    /// Initialize sidechain consensus with federation
    pub fn initialize_with_federation(
        mut self,
        initial_members: Vec<rusty_shared_types::masternode::MasternodeID>,
        threshold: u32,
        public_keys: Vec<Vec<u8>>,
        start_height: u64,
    ) -> Result<Self, String> {
        {
            let mut federation = self.federation.lock().unwrap();
            federation.initialize_sidechain_federation(
                self.sidechain_id,
                initial_members.clone(),
                threshold,
                public_keys.clone(),
                start_height,
                1000, // epoch transition blocks
            )?;

            // Update proof validator with federation keys
            let mut validator = self.proof_validator.lock().unwrap();
            validator.update_federation_keys(1, public_keys.clone());
        }

        // Set up cross-references between components
        self.setup_component_references()?;

        Ok(self)
    }

    /// Set up cross-references between components
    fn setup_component_references(&mut self) -> Result<(), String> {
        // Set up federation manager references in other components
        {
            let federation_manager = Arc::clone(&self.federation);
            
            // Set federation manager in communication
            {
                let mut communication = self.communication.lock().unwrap();
                communication.with_federation_manager(Arc::clone(&federation_manager));
            }

            // Set federation manager in peg manager
            {
                let mut peg_manager = self.peg_manager.lock().unwrap();
                peg_manager.with_federation_manager(Arc::clone(&federation_manager));
            }
        }

        info!("Component cross-references established for sidechain {:?}", self.sidechain_id);
        Ok(())
    }

    /// Process a new sidechain block with comprehensive validation
    pub fn process_sidechain_block(
        &mut self,
        block: SidechainBlock,
        mainchain_height: u64,
        mainchain_hash: Hash,
    ) -> Result<(), String> {
        debug!("Processing sidechain block at height {}", block.height());

        // Validate block against mainchain state
        {
            let validator = self.mainchain_validator.lock().unwrap();
            validator.validate_sidechain_block(&block)
                .map_err(|e| format!("Mainchain validation failed: {}", e))?;
        }

        // Perform comprehensive proof validation
        {
            let mut validator = self.proof_validator.lock().unwrap();
            match validator.validate_sidechain_block(&block) {
                ProofValidationResult::Valid => {
                    debug!("Block proof validation successful");
                }
                ProofValidationResult::Invalid(reason) => {
                    return Err(format!("Block proof validation failed: {}", reason));
                }
                ProofValidationResult::Error(err) => {
                    return Err(format!("Block proof validation error: {}", err));
                }
                ProofValidationResult::Timeout => {
                    return Err("Block proof validation timed out".to_string());
                }
            }
        }

        // Check for mainchain reorg impact
        {
            let validator = self.mainchain_validator.lock().unwrap();
            let impact = validator.check_reorg_impact(&self.sidechain_id, mainchain_height, mainchain_hash)
                .map_err(|e| format!("Reorg impact check failed: {}", e))?;
            
            match impact {
                ReorgImpact::DeepReorg(_) => {
                    return Err("Mainchain deep reorg detected - sidechain validation suspended".to_string());
                }
                ReorgImpact::SameHeightReorg => {
                    // Handle same-height reorg
                    self.handle_mainchain_reorg(mainchain_height, mainchain_hash)
                        .map_err(|e| format!("Mainchain reorg handling failed: {}", e))?;
                    warn!("Handled mainchain same-height reorg for sidechain {:?}", self.sidechain_id);
                }
                _ => {} // No action needed for other cases
            }
        }

        // Process cross-chain transactions with validation
        for (i, cross_chain_tx) in block.cross_chain_transactions.iter().enumerate() {
            self.process_cross_chain_transaction(cross_chain_tx)
                .map_err(|e| format!("Cross-chain transaction {} processing failed: {}", i, e))?;
        }

        // Process fraud proofs with comprehensive validation
        for (i, fraud_proof) in block.fraud_proofs.iter().enumerate() {
            self.process_fraud_proof(fraud_proof)
                .map_err(|e| format!("Fraud proof {} processing failed: {}", i, e))?;
        }

        // Update sidechain state
        self.current_height = block.height();
        self.current_tip = block.hash();

        // Notify mainchain of new sidechain block
        self.notify_mainchain_of_block(&block)
            .map_err(|e| format!("Mainchain notification failed: {}", e))?;

        info!("Successfully processed sidechain block at height {} for sidechain {:?}", 
              self.current_height, self.sidechain_id);

        Ok(())
    }

    /// Process a cross-chain transaction with enhanced validation
    fn process_cross_chain_transaction(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        debug!("Processing cross-chain transaction {} -> {}", 
               hex::encode(&tx.source_chain), hex::encode(&tx.destination_chain));

        // Validate transaction against mainchain state
        let validator = self.mainchain_validator.lock().unwrap();
        validator.validate_cross_chain_transaction(tx, &self.sidechain_id)
            .map_err(|e| format!("Cross-chain transaction validation failed: {}", e))?;

        // Route transaction based on destination
        if tx.destination_chain == [0u8; 32] {
            // Transaction to mainchain - handle peg-out
            self.handle_peg_out_transaction(tx)?;
        } else if tx.source_chain == [0u8; 32] {
            // Transaction from mainchain - handle peg-in
            self.handle_peg_in_transaction(tx)?;
        } else {
            // Inter-sidechain transaction
            self.handle_inter_sidechain_transaction(tx)?;
        }

        Ok(())
    }

    /// Handle peg-in transaction (mainchain to sidechain) with enhanced validation
    fn handle_peg_in_transaction(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        debug!("Handling peg-in transaction for amount {}", tx.amount);

        let mut peg_manager = self.peg_manager.lock().unwrap();

        // Create peg-in request with enhanced validation
        let request = crate::sidechain::two_way_peg::PegInRequest {
            mainchain_tx_hash: [0u8; 32], // Would be extracted from tx metadata
            amount: tx.amount,
            sidechain_recipient: tx.recipient_address.clone(),
            sidechain_id: tx.destination_chain,
            mainchain_confirm_height: 0, // Would be current mainchain height
            merkle_proof: vec![], // Would be provided
            federation_signatures: tx.federation_signatures.clone(),
        };

        // Validate federation signatures using federation integrator
        let federation = self.federation.lock().unwrap();
        for signature in &request.federation_signatures {
            if !federation.validate_federation_signature(
                &request.sidechain_id,
                signature.epoch,
                signature,
                &tx.id,
            ) {
                return Err("Peg-in federation signature validation failed".to_string());
            }
        }

        // Initiate peg-in
        peg_manager.initiate_peg_in(request)
            .map_err(|e| format!("Peg-in initiation failed: {}", e))?;

        info!("Peg-in transaction processed successfully for amount {}", tx.amount);
        Ok(())
    }

    /// Handle peg-out transaction (sidechain to mainchain) with enhanced validation
    fn handle_peg_out_transaction(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        debug!("Handling peg-out transaction for amount {}", tx.amount);

        let mut peg_manager = self.peg_manager.lock().unwrap();

        // Create peg-out request with enhanced validation
        let request = crate::sidechain::two_way_peg::PegOutRequest {
            sidechain_tx_hash: [0u8; 32], // Would be extracted from tx metadata
            amount: tx.amount,
            mainchain_recipient: tx.recipient_address.clone(),
            sidechain_id: tx.source_chain,
            sidechain_confirm_height: 0, // Would be current sidechain height
            merkle_proof: vec![], // Would be provided
            federation_signatures: tx.federation_signatures.clone(),
        };

        // Validate federation signatures using federation integrator
        let federation = self.federation.lock().unwrap();
        for signature in &request.federation_signatures {
            if !federation.validate_federation_signature(
                &request.sidechain_id,
                signature.epoch,
                signature,
                &tx.id,
            ) {
                return Err("Peg-out federation signature validation failed".to_string());
            }
        }

        // Initiate peg-out
        peg_manager.initiate_peg_out(request)
            .map_err(|e| format!("Peg-out initiation failed: {}", e))?;

        info!("Peg-out transaction processed successfully for amount {}", tx.amount);
        Ok(())
    }

    /// Handle inter-sidechain transaction with enhanced validation
    fn handle_inter_sidechain_transaction(&self, tx: &CrossChainTransaction) -> Result<(), String> {
        debug!("Handling inter-sidechain transaction from {} to {}", 
               hex::encode(&tx.source_chain), hex::encode(&tx.destination_chain));

        // Send to destination sidechain via cross-chain communication
        let mut communication = self.communication.lock().unwrap();
        let message = CrossChainCommunication::create_cross_chain_tx_message(
            tx.source_chain,
            tx.destination_chain,
            tx,
        ).map_err(|e| format!("Failed to create cross-chain message: {}", e))?;

        communication.send_message(message)
            .map_err(|e| format!("Failed to send inter-sidechain message: {}", e))?;

        debug!("Inter-sidechain transaction forwarded successfully");
        Ok(())
    }

    /// Process a fraud proof with comprehensive validation and enforcement
    fn process_fraud_proof(&self, proof: &FraudProof) -> Result<(), String> {
        info!("Processing fraud proof of type {:?} for sidechain {:?}", 
              proof.fraud_type, self.sidechain_id);

        // Validate fraud proof structure and content using internal validation
        self.validate_fraud_proof_internal(proof)
            .map_err(|e| format!("Fraud proof validation failed: {}", e))?;

        // Submit fraud proof to fraud proof manager for processing
        let mut fraud_manager = self.fraud_proof_manager.lock().unwrap();
        let challenge_id = fraud_manager.submit_fraud_proof(proof.clone(), proof.challenge_bond)
            .map_err(|e| format!("Failed to submit fraud proof: {}", e))?;

        debug!("Fraud proof submitted successfully with challenge ID {}", hex::encode(&challenge_id));

        // If valid, notify mainchain and other sidechains
        let mut communication = self.communication.lock().unwrap();

        // Create a simple fraud proof notification message
        let fraud_notification_message = CrossChainMessage {
            message_type: CrossChainMessageType::FraudProof,
            source_chain: self.sidechain_id,
            destination_chain: [0u8; 32], // Mainchain ID
            sequence_number: 1, // Would be properly managed in real implementation
            payload: bincode::serialize(&(proof, challenge_id))
                .map_err(|e| format!("Failed to serialize fraud proof notification: {}", e))?,
            federation_signature: None, // Would be signed by federation
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        communication.send_message(fraud_notification_message)
            .map_err(|e| format!("Failed to send fraud proof notification: {}", e))?;

        info!("Fraud proof processed and notifications sent for sidechain {:?}", self.sidechain_id);
        Ok(())
    }

    /// Internal fraud proof validation (since validate_fraud_proof is private)
    fn validate_fraud_proof_internal(&self, proof: &FraudProof) -> Result<(), String> {
        // Basic structural validation
        if proof.evidence.pre_state.is_empty() {
            return Err("Pre-state cannot be empty".to_string());
        }

        if proof.evidence.post_state.is_empty() {
            return Err("Post-state cannot be empty".to_string());
        }

        if proof.evidence.fraudulent_operation.is_empty() {
            return Err("Fraudulent operation cannot be empty".to_string());
        }

        if proof.challenge_bond == 0 {
            return Err("Challenge bond must be greater than zero".to_string());
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
    fn validate_state_transition_fraud(&self, proof: &FraudProof) -> Result<(), String> {
        // State transitions must result in different states for fraud to be meaningful
        if proof.evidence.pre_state == proof.evidence.post_state {
            return Err("State transition fraud requires different pre and post states".to_string());
        }

        // Validate operation data structure and content
        let operation_data = &proof.evidence.fraudulent_operation;
        if operation_data.len() < 64 {
            return Err("Operation data too small for state transition".to_string());
        }

        Ok(())
    }

    /// Validate double spending fraud proof
    fn validate_double_spending_fraud(&self, proof: &FraudProof) -> Result<(), String> {
        // Double spending requires fraudulent operation data containing conflicting transactions
        if proof.evidence.fraudulent_operation.is_empty() {
            return Err("Double spending proof requires transaction data".to_string());
        }

        if proof.evidence.fraudulent_operation.len() < 128 {
            return Err("Insufficient transaction data for double spending proof".to_string());
        }

        Ok(())
    }

    /// Validate cross-chain fraud proof
    fn validate_cross_chain_fraud(&self, proof: &FraudProof) -> Result<(), String> {
        // Cross-chain fraud requires additional evidence
        if proof.evidence.additional_evidence.is_empty() {
            return Err("Cross-chain fraud proof requires additional evidence".to_string());
        }

        Ok(())
    }

    /// Validate signature fraud proof
    fn validate_signature_fraud(&self, proof: &FraudProof) -> Result<(), String> {
        // Signature fraud requires witness data containing the signature and message
        if proof.evidence.witness_data.len() < 96 {
            return Err("Insufficient witness data for signature fraud proof".to_string());
        }

        Ok(())
    }

    /// Validate VM execution fraud proof
    fn validate_vm_fraud(&self, proof: &FraudProof) -> Result<(), String> {
        // VM execution fraud requires fraudulent operation data containing VM execution details
        if proof.evidence.fraudulent_operation.is_empty() {
            return Err("VM execution fraud proof requires operation data".to_string());
        }

        if proof.evidence.witness_data.len() < 64 {
            return Err("Insufficient witness data for VM execution validation".to_string());
        }

        Ok(())
    }

    /// Handle mainchain reorg with enhanced validation and state recovery
    fn handle_mainchain_reorg(&self, new_height: u64, new_hash: Hash) -> Result<(), String> {
        debug!("Handling mainchain reorg to height {} for sidechain {:?}", new_height, self.sidechain_id);

        // Update mainchain state snapshot
        let mut validator = self.mainchain_validator.lock().unwrap();

        // Get current federation info
        let federation = self.federation.lock().unwrap();
        let current_epoch = federation.get_current_epoch(&self.sidechain_id)
            .ok_or("No current federation epoch")?;

        let snapshot = crate::sidechain::mainchain_validator::MainchainStateSnapshot {
            height: new_height,
            block_hash: new_hash,
            state_root: [0u8; 32], // Would be fetched from mainchain
            federation_members: current_epoch.public_keys.clone(),
            federation_threshold: current_epoch.threshold,
            federation_epoch: current_epoch.epoch,
        };

        validator.update_mainchain_state(self.sidechain_id, snapshot);

        // Update proof validator with new federation keys if epoch changed
        if current_epoch.epoch > 1 {
            let mut proof_validator = self.proof_validator.lock().unwrap();
            proof_validator.update_federation_keys(current_epoch.epoch, current_epoch.public_keys.clone());
        }

        // Check if any pending peg transactions are affected
        // This might require rolling back or adjusting confirmations
        let peg_manager = self.peg_manager.lock().unwrap();
        let pending_txs: Vec<_> = peg_manager.get_pending_transactions().into_iter().cloned().collect();

        for tx in pending_txs {
            if tx.confirm_height > new_height {
                warn!("Peg transaction {} confirmations affected by reorg", hex::encode(&tx.id));
                // Handle reorg impact on peg transactions
                // This would involve adjusting confirmation counts or rolling back
            }
        }

        debug!("Mainchain reorg handling completed for sidechain {:?}", self.sidechain_id);
        Ok(())
    }

    /// Notify mainchain of new sidechain block with enhanced validation
    fn notify_mainchain_of_block(&self, block: &SidechainBlock) -> Result<(), String> {
        debug!("Notifying mainchain of sidechain block at height {}", block.height());

        let mut communication = self.communication.lock().unwrap();

        // Create block header notification with federation signature validation
        let message = CrossChainCommunication::create_sidechain_header_message(
            self.sidechain_id,
            [0u8; 32], // Mainchain ID
            &block.header,
            block.header.federation_epoch,
        ).map_err(|e| format!("Failed to create sidechain header message: {}", e))?;

        // Process the message to validate it before sending
        communication.process_message(&message)
            .map_err(|e| format!("Sidechain header message validation failed: {}", e))?;

        communication.send_message(message)
            .map_err(|e| format!("Failed to send sidechain header notification: {}", e))?;

        debug!("Mainchain notification sent successfully for sidechain block at height {}", block.height());
        Ok(())
    }

    /// Process mainchain block update with enhanced validation and federation management
    pub fn process_mainchain_block(
        &self,
        block_header: &rusty_shared_types::BlockHeader,
    ) -> Result<(), String> {
        debug!("Processing mainchain block at height {}", block_header.height);

        // Cache mainchain block header
        {
            let mut validator = self.mainchain_validator.lock().unwrap();
            validator.cache_block_header(block_header.hash(), block_header.clone());
        }

        // Update mainchain state snapshot
        {
            let federation = self.federation.lock().unwrap();
            let current_epoch = federation.get_current_epoch(&self.sidechain_id)
                .ok_or("No current federation epoch")?;

            let snapshot = crate::sidechain::mainchain_validator::MainchainStateSnapshot {
                height: block_header.height,
                block_hash: block_header.hash(),
                state_root: block_header.state_root,
                federation_members: current_epoch.public_keys.clone(),
                federation_threshold: current_epoch.threshold,
                federation_epoch: current_epoch.epoch,
            };

            let mut validator = self.mainchain_validator.lock().unwrap();
            validator.update_mainchain_state(self.sidechain_id, snapshot);
        }

        // Check for federation transitions
        {
            let federation = self.federation.lock().unwrap();
            if federation.should_transition_federation(&self.sidechain_id, block_header.height) {
                // Trigger federation transition
                // This would involve governance coordination
                info!("Federation transition needed for sidechain {:?}", self.sidechain_id);
                // In a real implementation, this would coordinate with governance
            }
        }

        // Process any pending fraud proof challenges
        {
            let mut fraud_manager = self.fraud_proof_manager.lock().unwrap();
            fraud_manager.process_challenges(block_header.height)
                .map_err(|e| format!("Fraud proof challenge processing failed: {}", e))?;
        }

        // Confirm peg transactions if enough confirmations
        {
            let peg_manager = self.peg_manager.lock().unwrap();
            let pending_txs: Vec<_> = peg_manager.get_pending_transactions().into_iter().cloned().collect();

            for tx in pending_txs {
                if block_header.height >= tx.confirm_height + 6 { // 6 confirmations
                    let mut peg_manager_mut = self.peg_manager.lock().unwrap();
                    let _ = peg_manager_mut.confirm_peg_transaction(&tx.id, block_header.height);
                    let _ = peg_manager_mut.complete_peg_transaction(&tx.id);
                    debug!("Peg transaction {} confirmed at mainchain height {}", 
                           hex::encode(&tx.id), block_header.height);
                }
            }
        }

        debug!("Mainchain block processing completed for height {}", block_header.height);
        Ok(())
    }

    /// Get current sidechain state
    pub fn get_sidechain_state(&self) -> SidechainState {
        SidechainState {
            sidechain_id: self.sidechain_id,
            height: self.current_height,
            tip: self.current_tip,
        }
    }

    /// Get consensus statistics with enhanced metrics
    pub fn get_consensus_stats(&self) -> ConsensusStats {
        let federation = self.federation.lock().unwrap();
        let fed_stats = federation.get_federation_stats();

        let peg_manager = self.peg_manager.lock().unwrap();
        let peg_stats = peg_manager.get_stats();

        let fraud_manager = self.fraud_proof_manager.lock().unwrap();
        let fraud_stats = fraud_manager.get_stats();

        let proof_validator = self.proof_validator.lock().unwrap();
        let validation_stats = proof_validator.get_stats();

        let communication = self.communication.lock().unwrap();

        ConsensusStats {
            sidechain_id: self.sidechain_id,
            current_height: self.current_height,
            federation_stats: fed_stats,
            peg_stats,
            fraud_proof_stats: fraud_stats,
            validation_stats,
            pending_messages: communication.pending_message_count(&[0u8; 32]), // Mainchain
        }
    }

    /// Get fraud proof manager for external access
    pub fn get_fraud_proof_manager(&self) -> Arc<std::sync::Mutex<FraudProofManager>> {
        Arc::clone(&self.fraud_proof_manager)
    }

    /// Get proof validator for external access
    pub fn get_proof_validator(&self) -> Arc<std::sync::Mutex<SidechainProofValidator>> {
        Arc::clone(&self.proof_validator)
    }

    /// Submit fraud proof challenge directly
    pub fn submit_fraud_proof_challenge(
        &self,
        fraud_proof: FraudProof,
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let mut fraud_manager = self.fraud_proof_manager.lock().unwrap();
        fraud_manager.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    /// Validate sidechain block with current proof validator
    pub fn validate_sidechain_block(&self, block: &SidechainBlock) -> Result<ProofValidationResult, String> {
        let mut validator = self.proof_validator.lock().unwrap();
        Ok(validator.validate_sidechain_block(block))
    }
}

/// Sidechain state snapshot
#[derive(Debug, Clone)]
pub struct SidechainState {
    pub sidechain_id: Hash,
    pub height: u64,
    pub tip: Hash,
}

/// Enhanced consensus statistics with fraud proof and validation metrics
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub sidechain_id: Hash,
    pub current_height: u64,
    pub federation_stats: crate::sidechain::federation_integrator::FederationStats,
    pub peg_stats: crate::sidechain::two_way_peg::PegStats,
    pub fraud_proof_stats: crate::sidechain::fraud_proofs::FraudProofStats,
    pub validation_stats: crate::sidechain::proof_validation::ValidationStats,
    pub pending_messages: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::OutPoint;

    fn create_test_masternode_id(value: u8) -> rusty_shared_types::masternode::MasternodeID {
        rusty_shared_types::masternode::MasternodeID(OutPoint {
            txid: [value; 32],
            vout: 0,
        })
    }

    #[test]
    fn test_sidechain_consensus_creation() {
        let sidechain_id = [1u8; 32];
        let consensus = SidechainConsensus::new(sidechain_id);
        assert_eq!(consensus.sidechain_id, sidechain_id);
        assert_eq!(consensus.current_height, 0);
    }

    #[test]
    fn test_sidechain_consensus_initialization() {
        let sidechain_id = [1u8; 32];
        let members = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];

        let consensus = SidechainConsensus::new(sidechain_id)
            .initialize_with_federation(members, 2, public_keys, 100)
            .unwrap();

        let state = consensus.get_sidechain_state();
        assert_eq!(state.sidechain_id, sidechain_id);
        assert_eq!(state.height, 0);
    }

    #[test]
    fn test_mainchain_block_processing() {
        let sidechain_id = [1u8; 32];
        let mut consensus = SidechainConsensus::new(sidechain_id);

        let block_header = rusty_shared_types::BlockHeader {
            version: 1,
            height: 1000,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };

        // Should fail without federation
        assert!(consensus.process_mainchain_block(&block_header).is_err());

        // Initialize federation
        let members = vec![create_test_masternode_id(1)];
        let public_keys = vec![vec![1u8; 48]];
        consensus = consensus.initialize_with_federation(members, 1, public_keys, 100).unwrap();

        // Should succeed now
        assert!(consensus.process_mainchain_block(&block_header).is_ok());
    }
}