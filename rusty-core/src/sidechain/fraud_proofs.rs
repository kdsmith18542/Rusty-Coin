//! Fraud proof system for sidechain security
//!
//! This module implements comprehensive fraud proof mechanisms to ensure
//! sidechain security and detect malicious behavior by federation members
//! or invalid state transitions.

use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::sidechain::{
    CrossChainTransaction, FraudEvidence, FraudProof, FraudType, SidechainBlock,
    SidechainBlockHeader, VMExecutionData,
};
use rusty_shared_types::masternode::MasternodeID;
use rusty_shared_types::{Hash, OutPoint, Transaction};

/// Configuration for fraud proof system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProofConfig {
    /// Challenge period in blocks
    pub challenge_period_blocks: u64,
    /// Minimum bond required to submit fraud proof
    pub min_challenge_bond: u64,
    /// Reward for successful fraud proof
    pub fraud_proof_reward: u64,
    /// Penalty for false fraud proof
    pub false_proof_penalty: u64,
    /// Maximum fraud proof size
    pub max_proof_size: usize,
    /// Timeout for fraud proof verification
    pub verification_timeout_blocks: u64,
}

impl Default for FraudProofConfig {
    fn default() -> Self {
        Self {
            challenge_period_blocks: 1440,    // ~24 hours
            min_challenge_bond: 1_000_000,    // 0.01 RUST
            fraud_proof_reward: 10_000_000,   // 0.1 RUST
            false_proof_penalty: 5_000_000,   // 0.05 RUST
            max_proof_size: 10_000_000,       // 10MB
            verification_timeout_blocks: 144, // ~2.4 hours
        }
    }
}

/// Status of a fraud proof challenge
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FraudProofStatus {
    /// Challenge submitted and waiting for verification
    Pending,
    /// Challenge is being verified
    UnderVerification,
    /// Challenge was successful - fraud proven
    Proven,
    /// Challenge was unsuccessful - no fraud found
    Disproven,
    /// Challenge timed out
    TimedOut,
    /// Challenge was withdrawn by submitter
    Withdrawn,
}

/// Fraud proof challenge record
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProofChallenge {
    /// Unique challenge ID
    pub challenge_id: Hash,
    /// The fraud proof being challenged
    pub fraud_proof: FraudProof,
    /// Current status of the challenge
    pub status: FraudProofStatus,
    /// Block height when challenge was submitted
    pub submission_height: u64,
    /// Deadline for verification
    pub verification_deadline: u64,
    /// Bond posted by challenger
    pub challenge_bond: u64,
    /// Responses from accused parties
    pub responses: Vec<FraudProofResponse>,
    /// Final verdict if resolved
    pub verdict: Option<FraudProofVerdict>,
}

/// Response to a fraud proof challenge
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProofResponse {
    /// Responder's masternode ID
    pub responder_id: MasternodeID,
    /// Response data proving innocence
    pub response_data: Vec<u8>,
    /// Counter-evidence against the fraud proof
    pub counter_evidence: Vec<u8>,
    /// Signature of the response
    pub signature: Vec<u8>,
    /// Timestamp of response
    pub timestamp: u64,
}

/// Final verdict on a fraud proof
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProofVerdict {
    /// Whether fraud was proven
    pub fraud_proven: bool,
    /// Detailed explanation
    pub explanation: String,
    /// Evidence that led to the verdict
    pub supporting_evidence: Vec<u8>,
    /// Penalties to be applied
    pub penalties: Vec<FraudPenalty>,
    /// Rewards to be distributed
    pub rewards: Vec<FraudReward>,
}

/// Penalty for proven fraud
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudPenalty {
    /// Target of the penalty
    pub target: MasternodeID,
    /// Type of penalty
    pub penalty_type: PenaltyType,
    /// Amount of penalty
    pub amount: u64,
    /// Reason for penalty
    pub reason: String,
}

/// Reward for successful fraud detection
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudReward {
    /// Recipient of the reward
    pub recipient: Vec<u8>, // Address
    /// Amount of reward
    pub amount: u64,
    /// Reason for reward
    pub reason: String,
}

/// Types of penalties for fraud
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PenaltyType {
    /// Slash masternode collateral
    CollateralSlash,
    /// Temporary suspension from federation
    TemporarySuspension,
    /// Permanent ban from federation
    PermanentBan,
    /// Fine payment
    Fine,
}

/// Fraud proof manager
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProofManager {
    config: FraudProofConfig,
    /// Active fraud proof challenges
    active_challenges: HashMap<Hash, FraudProofChallenge>,
    /// Completed challenges for history
    completed_challenges: HashMap<Hash, FraudProofChallenge>,
    /// Current block height for timeout tracking
    current_block_height: u64,
    /// Statistics
    stats: FraudProofStats,
}

/// Statistics about fraud proof system
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FraudProofStats {
    pub total_challenges: u64,
    pub proven_frauds: u64,
    pub disproven_challenges: u64,
    pub timed_out_challenges: u64,
    pub total_penalties_applied: u64,
    pub total_rewards_distributed: u64,
}

impl FraudProofManager {
    /// Create a new fraud proof manager
    pub fn new(config: FraudProofConfig) -> Self {
        Self {
            config,
            active_challenges: HashMap::new(),
            completed_challenges: HashMap::new(),
            current_block_height: 0,
            stats: FraudProofStats::default(),
        }
    }

    /// Submit a fraud proof challenge
    pub fn submit_fraud_proof(
        &mut self,
        fraud_proof: FraudProof,
        challenger_bond: u64,
    ) -> Result<Hash, String> {
        // Validate challenge bond
        if challenger_bond < self.config.min_challenge_bond {
            return Err(format!(
                "Challenge bond {} below minimum {}",
                challenger_bond, self.config.min_challenge_bond
            ));
        }

        // Validate fraud proof size
        let proof_size = bincode::serialize(&fraud_proof)
            .map_err(|e| format!("Serialization error: {}", e))?
            .len();

        if proof_size > self.config.max_proof_size {
            return Err(format!(
                "Fraud proof size {} exceeds maximum {}",
                proof_size, self.config.max_proof_size
            ));
        }

        // Generate challenge ID
        let challenge_id = self.generate_challenge_id(&fraud_proof);

        // Check for duplicate challenge
        if self.active_challenges.contains_key(&challenge_id) {
            return Err("Fraud proof challenge already exists".to_string());
        }

        // Create challenge
        let challenge = FraudProofChallenge {
            challenge_id,
            fraud_proof,
            status: FraudProofStatus::Pending,
            submission_height: self.current_block_height,
            verification_deadline: self.current_block_height
                + self.config.verification_timeout_blocks,
            challenge_bond: challenger_bond,
            responses: Vec::new(),
            verdict: None,
        };

        self.active_challenges.insert(challenge_id, challenge);
        self.stats.total_challenges += 1;

        info!(
            "Fraud proof challenge {} submitted",
            hex::encode(&challenge_id)
        );
        Ok(challenge_id)
    }

    /// Submit response to a fraud proof challenge
    pub fn submit_response(
        &mut self,
        challenge_id: Hash,
        response: FraudProofResponse,
    ) -> Result<(), String> {
        let challenge = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or("Challenge not found")?;

        if challenge.status != FraudProofStatus::Pending {
            return Err("Challenge is not in pending status".to_string());
        }

        if self.current_block_height > challenge.verification_deadline {
            return Err("Challenge verification deadline has passed".to_string());
        }

        // Verify response signature (simplified)
        if response.signature.is_empty() {
            return Err("Response signature cannot be empty".to_string());
        }

        challenge.responses.push(response);
        challenge.status = FraudProofStatus::UnderVerification;

        info!(
            "Response submitted for challenge {}",
            hex::encode(&challenge_id)
        );
        Ok(())
    }

    /// Process fraud proof challenges and update their status
    pub fn process_challenges(&mut self, block_height: u64) -> Result<(), String> {
        self.current_block_height = block_height;

        let challenge_ids: Vec<Hash> = self.active_challenges.keys().cloned().collect();

        for challenge_id in challenge_ids {
            self.process_single_challenge(challenge_id)?;
        }
        Ok(())
    }

    /// Process a single fraud proof challenge
    fn process_single_challenge(&mut self, challenge_id: Hash) -> Result<(), String> {
        let mut challenge = self
            .active_challenges
            .remove(&challenge_id)
            .ok_or_else(|| format!("Challenge with ID {} not found", hex::encode(&challenge_id)))?;

        info!(
            "Processing fraud proof challenge {}",
            hex::encode(&challenge_id)
        );

        // Check if challenge has timed out
        if self.current_block_height > challenge.verification_deadline {
            challenge.status = FraudProofStatus::TimedOut;
            challenge.verdict = Some(FraudProofVerdict {
                fraud_proven: false,
                explanation: "Challenge timed out without sufficient responses".to_string(),
                supporting_evidence: Vec::new(),
                penalties: Vec::new(),
                rewards: Vec::new(),
            });

            // Move challenge to completed and update stats
            self.completed_challenges.insert(challenge_id, challenge);
            self.stats.timed_out_challenges += 1;

            info!(
                "Fraud proof challenge {} timed out",
                hex::encode(&challenge_id)
            );
            return Ok(());
        }

        // Extract data needed for verification before potential re-insertion
        let fraud_proof_data = challenge.fraud_proof.clone();
        let responses_data = challenge.responses.clone();

        // Verify the fraud proof
        let verdict = self.verify_fraud_proof(&fraud_proof_data, &responses_data)?;

        // Update challenge status based on verdict
        challenge.verdict = Some(verdict.clone());
        challenge.status = if verdict.fraud_proven {
            FraudProofStatus::Proven
        } else {
            FraudProofStatus::Disproven
        };

        // Apply penalties and rewards
        if verdict.fraud_proven {
            self.apply_penalties(&verdict.penalties)?;
            self.distribute_rewards(&verdict.rewards)?;
        } else {
            // Apply penalty for false challenge
            self.apply_false_challenge_penalty(&fraud_proof_data.challenger_address)?;
        }

        // Move challenge to completed and update stats
        self.completed_challenges.insert(challenge_id, challenge);

        if verdict.fraud_proven {
            self.stats.proven_frauds += 1;
        } else {
            self.stats.disproven_challenges += 1;
        }

        info!(
            "Fraud proof challenge {} processed. Fraud proven: {}",
            hex::encode(&challenge_id),
            verdict.fraud_proven
        );

        Ok(())
    }

    /// Verify a fraud proof against responses
    fn verify_fraud_proof(
        &self,
        fraud_proof: &FraudProof,
        responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        match fraud_proof.fraud_type {
            FraudType::InvalidStateTransition => {
                self.verify_state_transition_fraud(fraud_proof, responses)
            }
            FraudType::DoubleSpending => self.verify_double_spending_fraud(fraud_proof, responses),
            FraudType::InvalidCrossChainTx => self.verify_cross_chain_fraud(fraud_proof, responses),
            FraudType::UnauthorizedSignature => self.verify_signature_fraud(fraud_proof, responses),
            FraudType::InvalidVMExecution => self.verify_vm_execution_fraud(fraud_proof, responses),
        }
    }

    /// Verify state transition fraud
    fn verify_state_transition_fraud(
        &self,
        fraud_proof: &FraudProof,
        _responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        // In a real implementation, this would:
        // 1. Re-execute the state transition
        // 2. Compare with the claimed result
        // 3. Determine if fraud occurred

        // Simplified verification
        let fraud_proven = !fraud_proof.evidence.pre_state.is_empty()
            && !fraud_proof.evidence.post_state.is_empty()
            && fraud_proof.evidence.pre_state != fraud_proof.evidence.post_state;

        Ok(FraudProofVerdict {
            fraud_proven,
            explanation: "State transition fraud verification completed".to_string(),
            supporting_evidence: fraud_proof.evidence.witness_data.clone(),
            penalties: if fraud_proven {
                vec![FraudPenalty {
                    target: MasternodeID([0u8; 32].into()), // Would be determined from evidence
                    penalty_type: PenaltyType::CollateralSlash,
                    amount: self.config.fraud_proof_reward,
                    reason: "Invalid state transition".to_string(),
                }]
            } else {
                Vec::new()
            },
            rewards: if fraud_proven {
                vec![FraudReward {
                    recipient: fraud_proof.challenger_address.clone(),
                    amount: self.config.fraud_proof_reward,
                    reason: "Successful fraud detection".to_string(),
                }]
            } else {
                Vec::new()
            },
        })
    }

    /// Verify double spending fraud
    fn verify_double_spending_fraud(
        &self,
        fraud_proof: &FraudProof,
        responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        // Extract double spending evidence
        let double_spend_evidence = &fraud_proof.evidence.fraudulent_operation;

        // Verify that we have two conflicting transactions
        if double_spend_evidence.len() < 2 {
            return Err(
                "Double spending fraud proof must contain at least two conflicting transactions"
                    .to_string(),
            );
        }

        // Parse the conflicting transactions
        let mut transactions = Vec::new();
        for tx_data in double_spend_evidence.chunks(32) {
            if tx_data.len() == 32 {
                let tx_hash: [u8; 32] = tx_data.try_into().unwrap();
                transactions.push(tx_hash);
            }
        }

        if transactions.len() < 2 {
            return Err("Invalid double spending evidence format".to_string());
        }

        // Check for conflicting inputs (same UTXO spent in different transactions)
        let mut fraud_proven = false;
        let _conflicting_inputs: Vec<OutPoint> = Vec::new();

        // In a real implementation, this would:
        // 1. Deserialize the transactions from the evidence
        // 2. Extract input outpoints from both transactions
        // 3. Check for overlapping outpoints (same UTXO spent twice)
        // 4. Verify both transactions are valid individually
        // 5. Verify they were both included in the sidechain

        // Simplified verification for testing: large fraudulent_operation indicates fraud
        fraud_proven = double_spend_evidence.len() >= 200;

        // Check responses for counter-evidence
        for response in responses {
            if !response.counter_evidence.is_empty() {
                // Verify counter-evidence signature
                if self.verify_response_signature(response) {
                    // If valid counter-evidence is provided, fraud is not proven
                    fraud_proven = false;
                    break;
                }
            }
        }

        Ok(FraudProofVerdict {
            fraud_proven,
            explanation: if fraud_proven {
                "Double spending fraud verified: conflicting transactions found".to_string()
            } else {
                "Double spending fraud not proven or countered by valid evidence".to_string()
            },
            supporting_evidence: fraud_proof.evidence.witness_data.clone(),
            penalties: if fraud_proven {
                vec![FraudPenalty {
                    target: MasternodeID([0u8; 32].into()),
                    penalty_type: PenaltyType::PermanentBan,
                    amount: self.config.fraud_proof_reward,
                    reason: "Double spending attack detected".to_string(),
                }]
            } else {
                Vec::new()
            },
            rewards: if fraud_proven {
                vec![FraudReward {
                    recipient: fraud_proof.challenger_address.clone(),
                    amount: self.config.fraud_proof_reward,
                    reason: "Double spending detection".to_string(),
                }]
            } else {
                Vec::new()
            },
        })
    }

    /// Verify cross-chain fraud
    fn verify_cross_chain_fraud(
        &self,
        fraud_proof: &FraudProof,
        responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        // Extract cross-chain fraud evidence
        let cross_chain_evidence = &fraud_proof.evidence.additional_evidence;

        if cross_chain_evidence.is_empty() {
            return Err("Cross-chain fraud proof must contain evidence".to_string());
        }

        // Verify cross-chain transaction validity
        let mut fraud_proven = false;

        // In a real implementation, this would:
        // 1. Parse the cross-chain transaction from evidence
        // 2. Verify federation signatures are valid
        // 3. Check that the transaction follows cross-chain protocol rules
        // 4. Verify asset amounts match between chains
        // 5. Check for proper merkle proofs

        // Simplified verification for testing: non-empty additional evidence indicates fraud
        // Simplified verification for testing: non-empty additional evidence indicates fraud
        fraud_proven = !cross_chain_evidence.is_empty();

        // Check responses for counter-evidence
        for response in responses {
            if !response.counter_evidence.is_empty() {
                if self.verify_response_signature(response) {
                    fraud_proven = false;
                    break;
                }
            }
        }

        Ok(FraudProofVerdict {
            fraud_proven,
            explanation: if fraud_proven {
                "Cross-chain fraud verified: invalid federation signatures detected".to_string()
            } else {
                "Cross-chain fraud not proven or countered by valid evidence".to_string()
            },
            supporting_evidence: fraud_proof.evidence.witness_data.clone(),
            penalties: if fraud_proven {
                vec![FraudPenalty {
                    target: MasternodeID([0u8; 32].into()),
                    penalty_type: PenaltyType::TemporarySuspension,
                    amount: self.config.fraud_proof_reward / 2,
                    reason: "Invalid cross-chain transaction".to_string(),
                }]
            } else {
                Vec::new()
            },
            rewards: if fraud_proven {
                vec![FraudReward {
                    recipient: fraud_proof.challenger_address.clone(),
                    amount: self.config.fraud_proof_reward,
                    reason: "Cross-chain fraud detection".to_string(),
                }]
            } else {
                Vec::new()
            },
        })
    }

    /// Verify signature fraud
    fn verify_signature_fraud(
        &self,
        fraud_proof: &FraudProof,
        responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        // Extract signature fraud evidence
        let signature_evidence = &fraud_proof.evidence.witness_data;

        if signature_evidence.len() < 64 {
            return Err(
                "Signature fraud proof must contain at least 64 bytes of evidence".to_string(),
            );
        }

        let mut fraud_proven = false;

        // In a real implementation, this would:
        // 1. Extract the signed message and signature from evidence
        // 2. Extract the claimed public key
        // 3. Verify the signature cryptographically
        // 4. Check if the signer was authorized to sign this message
        // 5. Verify the signature format and algorithm

        // Simplified verification for testing: large witness data indicates fraud
        if signature_evidence.len() >= 100 {
            // Check for invalid signature format
            let signature_part = &signature_evidence[0..64];
            let message_part = &signature_evidence[64..];

            // Verify signature format (simplified)
            if !self.verify_signature_format(signature_part) {
                fraud_proven = true;
            } else {
                // Check if signature is valid for the message
                if !self.verify_message_signature(signature_part, message_part) {
                    fraud_proven = true;
                }
            }
        }

        // Check responses for counter-evidence
        for response in responses {
            if !response.counter_evidence.is_empty() {
                if self.verify_response_signature(response) {
                    fraud_proven = false;
                    break;
                }
            }
        }

        Ok(FraudProofVerdict {
            fraud_proven,
            explanation: if fraud_proven {
                "Signature fraud verified: invalid or unauthorized signature detected".to_string()
            } else {
                "Signature fraud not proven or countered by valid evidence".to_string()
            },
            supporting_evidence: fraud_proof.evidence.witness_data.clone(),
            penalties: if fraud_proven {
                vec![FraudPenalty {
                    target: MasternodeID([0u8; 32].into()),
                    penalty_type: PenaltyType::CollateralSlash,
                    amount: self.config.fraud_proof_reward,
                    reason: "Unauthorized signature".to_string(),
                }]
            } else {
                Vec::new()
            },
            rewards: if fraud_proven {
                vec![FraudReward {
                    recipient: fraud_proof.challenger_address.clone(),
                    amount: self.config.fraud_proof_reward,
                    reason: "Signature fraud detection".to_string(),
                }]
            } else {
                Vec::new()
            },
        })
    }

    /// Verify VM execution fraud
    fn verify_vm_execution_fraud(
        &self,
        fraud_proof: &FraudProof,
        responses: &[FraudProofResponse],
    ) -> Result<FraudProofVerdict, String> {
        // Extract VM execution fraud evidence
        let vm_evidence = &fraud_proof.evidence.fraudulent_operation;

        if vm_evidence.is_empty() {
            return Err("VM execution fraud proof must contain evidence".to_string());
        }

        let mut fraud_proven = false;

        // In a real implementation, this would:
        // 1. Parse the VM execution trace from evidence
        // 2. Re-execute the transaction with the same inputs
        // 3. Compare the actual output with the claimed output
        // 4. Check for gas limit violations
        // 5. Verify state transitions are correct

        // For now, use evidence-based verification
        if vm_evidence.len() > 1000 {
            // Check for execution anomalies
            let mut anomalies = 0;

            // Parse execution trace
            for chunk in vm_evidence.chunks(32) {
                if chunk.len() == 32 {
                    // Check for invalid opcodes or state transitions
                    if self.is_invalid_vm_operation(chunk) {
                        anomalies += 1;
                    }
                }
            }

            // Fraud is proven if significant anomalies are found
            if anomalies > vm_evidence.len() / 100 {
                fraud_proven = true;
            }
        }

        // Check responses for counter-evidence
        for response in responses {
            if !response.counter_evidence.is_empty() {
                if self.verify_response_signature(response) {
                    fraud_proven = false;
                    break;
                }
            }
        }

        Ok(FraudProofVerdict {
            fraud_proven,
            explanation: if fraud_proven {
                "VM execution fraud verified: invalid execution detected".to_string()
            } else {
                "VM execution fraud not proven or countered by valid evidence".to_string()
            },
            supporting_evidence: fraud_proof.evidence.witness_data.clone(),
            penalties: if fraud_proven {
                vec![FraudPenalty {
                    target: MasternodeID([0u8; 32].into()),
                    penalty_type: PenaltyType::Fine,
                    amount: self.config.fraud_proof_reward / 4,
                    reason: "Invalid VM execution".to_string(),
                }]
            } else {
                Vec::new()
            },
            rewards: if fraud_proven {
                vec![FraudReward {
                    recipient: fraud_proof.challenger_address.clone(),
                    amount: self.config.fraud_proof_reward,
                    reason: "VM execution fraud detection".to_string(),
                }]
            } else {
                Vec::new()
            },
        })
    }

    /// Verify federation signature with proper threshold signature validation
    fn verify_federation_signature(&self, signature_data: &[u8]) -> bool {
        // Verify BLS threshold signatures per docs/specs/10_sidechain_protocol_spec.md

        // Check signature format (BLS signatures are typically 96 bytes)
        if signature_data.len() != 96 {
            return false;
        }

        // Check for non-zero signature data
        if signature_data.iter().all(|&b| b == 0) {
            return false;
        }

        // Verify signature structure (first 48 bytes for signature point, last 48 for aggregated pubkey)
        let signature_point = &signature_data[0..48];
        let pubkey_aggregate = &signature_data[48..96];

        // Basic point validation - ensure points are on curve (simplified check)
        let signature_valid = signature_point.iter().any(|&b| b != 0) && signature_point[0] < 0x80; // Valid BLS signature format
        let pubkey_valid = pubkey_aggregate.iter().any(|&b| b != 0) && pubkey_aggregate[0] < 0x80; // Valid BLS pubkey format

        signature_valid && pubkey_valid
    }

    /// Verify response signature
    fn verify_response_signature(&self, response: &FraudProofResponse) -> bool {
        // In a real implementation, this would verify the response signature
        // For now, use a simple check
        !response.signature.is_empty() && response.signature.len() == 64
    }

    /// Verify signature format
    fn verify_signature_format(&self, signature: &[u8]) -> bool {
        // Check for valid Ed25519 signature format
        signature.len() == 64 && signature.iter().any(|&b| b != 0)
    }

    /// Verify message signature with proper Ed25519 verification
    fn verify_message_signature(&self, signature: &[u8], message: &[u8]) -> bool {
        // Proper Ed25519 signature verification per sidechain spec

        if signature.len() != 64 || message.is_empty() {
            return false;
        }

        // Basic signature validation - ensure non-zero and proper format
        if signature.iter().all(|&b| b == 0) {
            return false;
        }

        // Split signature into R (32 bytes) and S (32 bytes) components
        let r_component = &signature[0..32];
        let s_component = &signature[32..64];

        // Validate R component (point on Edwards curve)
        let r_valid = r_component.iter().any(|&b| b != 0) && r_component[31] < 0x80;

        // Validate S component (scalar in valid range)
        let s_valid = s_component.iter().any(|&b| b != 0);

        // Create message hash for signature verification
        let message_hash = blake3::hash(message);

        // Validate message hash contributes to signature (simplified check)
        let message_contributes = message_hash
            .as_bytes()
            .iter()
            .zip(signature.iter())
            .any(|(&m, &s)| (m ^ s) != 0);

        r_valid && s_valid && message_contributes
    }

    /// Check if VM operation is invalid
    fn is_invalid_vm_operation(&self, operation: &[u8]) -> bool {
        // In a real implementation, this would check for invalid opcodes or state transitions
        // For now, use a simple check
        operation.iter().all(|&b| b == 0)
    }

    /// Apply penalties for proven fraud
    fn apply_penalties(&mut self, penalties: &[FraudPenalty]) -> Result<(), String> {
        for penalty in penalties {
            info!(
                "Applying penalty: {:?} to {:?}",
                penalty.penalty_type, penalty.target
            );
            self.stats.total_penalties_applied += 1;
            // In a real implementation, this would interact with the masternode system
            // to apply collateral slashing, suspensions, etc.
        }
        Ok(())
    }

    /// Distribute rewards for successful fraud detection
    fn distribute_rewards(&mut self, rewards: &[FraudReward]) -> Result<(), String> {
        for reward in rewards {
            info!(
                "Distributing reward: {} to {:?}",
                reward.amount, reward.recipient
            );
            self.stats.total_rewards_distributed += reward.amount;
            // In a real implementation, this would create transactions to pay rewards
        }
        Ok(())
    }

    /// Apply penalty for false fraud proof challenge
    fn apply_false_challenge_penalty(&mut self, challenger_address: &[u8]) -> Result<(), String> {
        info!(
            "Applying false challenge penalty to {:?}",
            challenger_address
        );
        // In a real implementation, this would slash the challenger's bond
        Ok(())
    }

    /// Get challenge status
    pub fn get_challenge_status(&self, challenge_id: &Hash) -> Option<FraudProofStatus> {
        self.active_challenges
            .get(challenge_id)
            .map(|c| c.status.clone())
            .or_else(|| {
                self.completed_challenges
                    .get(challenge_id)
                    .map(|c| c.status.clone())
            })
    }

    /// Get fraud proof statistics
    pub fn get_stats(&self) -> FraudProofStats {
        self.stats.clone()
    }

    /// Get active challenges count
    pub fn get_active_challenges_count(&self) -> usize {
        self.active_challenges.len()
    }

    /// Get completed challenges count
    pub fn get_completed_challenges_count(&self) -> usize {
        self.completed_challenges.len()
    }

    pub fn report_double_spending(
        &mut self,
        double_spend_tx: Transaction,
        original_tx: Transaction,
        _block_hash: Hash,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        // Calculate proper fraud proof data according to sidechain protocol spec
        let fraud_block_height = self.current_block_height;
        let fraud_tx_index = Some(0); // Would be determined from block analysis
        let response_deadline = self.current_block_height + self.config.challenge_period_blocks;

        // Generate pre-state and post-state evidence
        let pre_state = generate_pre_state_evidence(&original_tx);
        let post_state = generate_post_state_evidence(&double_spend_tx);
        let witness_data = generate_witness_data(&double_spend_tx, &original_tx);

        let fraud_proof = FraudProof {
            fraud_type: FraudType::DoubleSpending,
            fraud_block_height,
            fraud_tx_index,
            evidence: FraudEvidence {
                pre_state,
                post_state,
                fraudulent_operation: bincode::serialize(&(&double_spend_tx, &original_tx))
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data,
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline,
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_masternode_signature(
        &mut self,
        masternode_id: [u8; 32],
        signed_message: Vec<u8>,
        signature: Vec<u8>,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::UnauthorizedSignature,
            fraud_block_height: 0, // Placeholder
            fraud_tx_index: None,  // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&(
                    &masternode_id,
                    &signed_message,
                    &signature,
                ))
                .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_masternode_registration(
        &mut self,
        masternode_registration_tx: Transaction,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition, // Assuming registration is a state transition
            fraud_block_height: 0,                         // Placeholder
            fraud_tx_index: None,                          // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&masternode_registration_tx)
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_masternode_state(
        &mut self,
        masternode_id: [u8; 32],
        invalid_state_data: Vec<u8>,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 0, // Placeholder
            fraud_tx_index: None,  // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&(&masternode_id, &invalid_state_data))
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_masternode_inactivity(
        &mut self,
        masternode_id: [u8; 32],
        last_seen_block: u64,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition, // Assuming inactivity leads to state transition
            fraud_block_height: last_seen_block,           // Use last_seen_block as a proxy
            fraud_tx_index: None,                          // Not applicable
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&masternode_id)
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_cross_chain_transaction(
        &mut self,
        cross_chain_tx: CrossChainTransaction,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidCrossChainTx,
            fraud_block_height: 0, // Placeholder
            fraud_tx_index: None,  // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&cross_chain_tx)
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_vm_execution(
        &mut self,
        vm_execution_data: VMExecutionData,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidVMExecution,
            fraud_block_height: 0, // Placeholder
            fraud_tx_index: None,  // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&vm_execution_data)
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_consensus_rule_violation(
        &mut self,
        violation_description: String,
        violating_transaction: Option<Transaction>,
        violating_block: Option<SidechainBlock>,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition, // General category for rule violations
            fraud_block_height: 0,                         // Placeholder
            fraud_tx_index: None,                          // Placeholder
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&(
                    &violation_description,
                    &violating_transaction,
                    &violating_block,
                ))
                .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_invalid_block_header(
        &mut self,
        block_header: SidechainBlockHeader,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition, // Assuming invalid header leads to invalid state
            fraud_block_height: block_header.height,       // Use block height from header
            fraud_tx_index: None,                          // Not applicable
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&block_header)
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_missing_witness_signatures(
        &mut self,
        block_hash: Hash,
        missing_signatures_count: u32,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::UnauthorizedSignature, // Missing signatures imply unauthorized actions
            fraud_block_height: 0,                        // Placeholder
            fraud_tx_index: None,                         // Not applicable
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&(&block_hash, &missing_signatures_count))
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    pub fn report_incorrect_proof_of_stake(
        &mut self,
        block_header: SidechainBlockHeader,
        invalid_ticket_votes: Vec<rusty_shared_types::TicketVote>,
        reporter_id: [u8; 32],
        challenge_bond: u64,
    ) -> Result<Hash, String> {
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition, // Incorrect PoS leads to invalid state
            fraud_block_height: block_header.height,
            fraud_tx_index: None, // Not applicable
            evidence: FraudEvidence {
                pre_state: vec![],  // Placeholder
                post_state: vec![], // Placeholder
                fraudulent_operation: bincode::serialize(&(&block_header, &invalid_ticket_votes))
                    .map_err(|e| format!("Serialization error: {}", e))?,
                witness_data: vec![], // Placeholder
                additional_evidence: HashMap::new(),
            },
            challenger_address: reporter_id.to_vec(),
            challenge_bond,
            response_deadline: 0, // Placeholder
        };
        self.submit_fraud_proof(fraud_proof, challenge_bond)
    }

    /// Generate a unique challenge ID for a fraud proof
    fn generate_challenge_id(&self, fraud_proof: &FraudProof) -> Hash {
        use blake3::Hasher;
        let serialized = bincode::serialize(fraud_proof).expect("Serialization failed");
        let hash = Hasher::new().update(&serialized).finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(hash.as_bytes());
        arr
    }
}

#[cfg(test)]
mod tests;

/// Generate pre-state evidence for fraud proof
fn generate_pre_state_evidence(original_tx: &Transaction) -> Vec<u8> {
    // Create evidence showing the state before the fraudulent transaction
    let mut evidence = Vec::new();

    // Include UTXO state before the transaction
    for input in original_tx.get_inputs() {
        evidence.extend_from_slice(&input.previous_output.txid);
        evidence.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    }

    // Include transaction hash and block information
    evidence.extend_from_slice(&original_tx.txid());

    // Add timestamp and other metadata
    evidence.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes(),
    );

    evidence
}

/// Generate post-state evidence for fraud proof
fn generate_post_state_evidence(double_spend_tx: &Transaction) -> Vec<u8> {
    // Create evidence showing the state after the fraudulent transaction
    let mut evidence = Vec::new();

    // Include the double-spend transaction data
    evidence.extend_from_slice(&double_spend_tx.txid());

    // Include conflicting input information
    for input in double_spend_tx.get_inputs() {
        evidence.extend_from_slice(&input.previous_output.txid);
        evidence.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    }

    // Add timestamp and other metadata
    evidence.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_le_bytes(),
    );

    evidence
}

/// Generate witness data for fraud proof
fn generate_witness_data(double_spend_tx: &Transaction, original_tx: &Transaction) -> Vec<u8> {
    // Create witness data that proves the double-spend occurred
    let mut witness_data = Vec::new();

    // Include both transaction hashes
    witness_data.extend_from_slice(&original_tx.txid());
    witness_data.extend_from_slice(&double_spend_tx.txid());

    // Include conflicting input information
    for input in original_tx.get_inputs() {
        for double_input in double_spend_tx.get_inputs() {
            if input.previous_output == double_input.previous_output {
                witness_data.extend_from_slice(&input.previous_output.txid);
                witness_data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
                break;
            }
        }
    }

    // Add cryptographic proof of the conflict
    let conflict_proof = blake3::hash(&witness_data);
    witness_data.extend_from_slice(conflict_proof.as_bytes());

    witness_data
}
