//! Unit tests for fraud proof system

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::fraud_proofs::*;
    use crate::sidechain::{FraudProof, FraudType, FraudEvidence};
    use rusty_shared_types::{Hash, MasternodeID};
    use std::collections::HashMap;

    // Helper function to create a test hash
    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    // Helper function to create a test masternode ID
    fn test_masternode_id(value: u8) -> MasternodeID {
        MasternodeID([value; 32])
    }

    // Helper function to create a test fraud proof
    fn create_test_fraud_proof(fraud_type: FraudType) -> FraudProof {
        FraudProof {
            fraud_type,
            fraud_block_height: 100,
            fraud_tx_index: Some(5),
            evidence: FraudEvidence {
                pre_state: vec![1, 2, 3],
                post_state: vec![4, 5, 6],
                fraudulent_operation: vec![7, 8, 9],
                witness_data: vec![10, 11, 12],
                additional_evidence: HashMap::new(),
            },
            challenger_address: vec![13, 14, 15],
            challenge_bond: 1000000,
            response_deadline: 200,
        }
    }

    #[test]
    fn test_fraud_proof_config_default() {
        let config = FraudProofConfig::default();
        
        assert_eq!(config.challenge_period_blocks, 1440);
        assert_eq!(config.min_challenge_bond, 1_000_000);
        assert_eq!(config.fraud_proof_reward, 10_000_000);
        assert_eq!(config.false_proof_penalty, 5_000_000);
        assert_eq!(config.max_proof_size, 10_000_000);
        assert_eq!(config.verification_timeout_blocks, 144);
    }

    #[test]
    fn test_fraud_proof_manager_creation() {
        let config = FraudProofConfig::default();
        let manager = FraudProofManager::new(config);
        
        let stats = manager.get_stats();
        assert_eq!(stats.total_challenges, 0);
        assert_eq!(stats.proven_frauds, 0);
        assert_eq!(stats.disproven_challenges, 0);
        assert_eq!(stats.timed_out_challenges, 0);
        assert_eq!(stats.total_penalties_applied, 0);
        assert_eq!(stats.total_rewards_distributed, 0);
        
        assert_eq!(manager.get_active_challenges_count(), 0);
        assert_eq!(manager.get_completed_challenges_count(), 0);
    }

    #[test]
    fn test_fraud_proof_submission() {
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let challenger_bond = 2_000_000;
        
        let result = manager.submit_fraud_proof(fraud_proof, challenger_bond);
        assert!(result.is_ok());
        
        let challenge_id = result.unwrap();
        assert_ne!(challenge_id, [0u8; 32]);
        
        let stats = manager.get_stats();
        assert_eq!(stats.total_challenges, 1);
        assert_eq!(manager.get_active_challenges_count(), 1);
        
        let status = manager.get_challenge_status(&challenge_id);
        assert_eq!(status, Some(FraudProofStatus::Pending));
    }

    #[test]
    fn test_fraud_proof_submission_validation() {
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        
        // Test insufficient bond
        let result1 = manager.submit_fraud_proof(fraud_proof.clone(), 500_000);
        assert!(result1.is_err());
        assert!(result1.unwrap_err().contains("below minimum"));
        
        // Test valid submission
        let result2 = manager.submit_fraud_proof(fraud_proof.clone(), 2_000_000);
        assert!(result2.is_ok());
        
        // Test duplicate submission
        let result3 = manager.submit_fraud_proof(fraud_proof, 2_000_000);
        assert!(result3.is_err());
        assert!(result3.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_fraud_proof_response_submission() {
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let challenge_id = manager.submit_fraud_proof(fraud_proof, 2_000_000).unwrap();
        
        let response = FraudProofResponse {
            responder_id: test_masternode_id(1),
            response_data: vec![20, 21, 22],
            counter_evidence: vec![23, 24, 25],
            signature: vec![26, 27, 28],
            timestamp: 1234567890,
        };
        
        let result = manager.submit_response(challenge_id, response);
        assert!(result.is_ok());
        
        let status = manager.get_challenge_status(&challenge_id);
        assert_eq!(status, Some(FraudProofStatus::UnderVerification));
    }

    #[test]
    fn test_fraud_proof_response_validation() {
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let challenge_id = manager.submit_fraud_proof(fraud_proof, 2_000_000).unwrap();
        
        // Test response with empty signature
        let invalid_response = FraudProofResponse {
            responder_id: test_masternode_id(1),
            response_data: vec![20, 21, 22],
            counter_evidence: vec![23, 24, 25],
            signature: Vec::new(), // Empty signature
            timestamp: 1234567890,
        };
        
        let result = manager.submit_response(challenge_id, invalid_response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
        
        // Test response to non-existent challenge
        let fake_challenge_id = test_hash(255);
        let valid_response = FraudProofResponse {
            responder_id: test_masternode_id(1),
            response_data: vec![20, 21, 22],
            counter_evidence: vec![23, 24, 25],
            signature: vec![26, 27, 28],
            timestamp: 1234567890,
        };
        
        let result2 = manager.submit_response(fake_challenge_id, valid_response);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_fraud_proof_challenge_processing() {
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let challenge_id = manager.submit_fraud_proof(fraud_proof, 2_000_000).unwrap();
        
        // Submit response
        let response = FraudProofResponse {
            responder_id: test_masternode_id(1),
            response_data: vec![20, 21, 22],
            counter_evidence: vec![23, 24, 25],
            signature: vec![26, 27, 28],
            timestamp: 1234567890,
        };
        
        manager.submit_response(challenge_id, response).unwrap();
        
        // Process challenges
        let result = manager.process_challenges(150);
        assert!(result.is_ok());
        
        // Challenge should be completed
        assert_eq!(manager.get_active_challenges_count(), 0);
        assert_eq!(manager.get_completed_challenges_count(), 1);
    }

    #[test]
    fn test_fraud_proof_timeout() {
        let mut config = FraudProofConfig::default();
        config.verification_timeout_blocks = 10;
        let mut manager = FraudProofManager::new(config);
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let challenge_id = manager.submit_fraud_proof(fraud_proof, 2_000_000).unwrap();
        
        // Process challenges after timeout
        let result = manager.process_challenges(20); // Beyond timeout
        assert!(result.is_ok());
        
        let status = manager.get_challenge_status(&challenge_id);
        assert_eq!(status, Some(FraudProofStatus::TimedOut));
        
        let stats = manager.get_stats();
        assert_eq!(stats.timed_out_challenges, 1);
    }

    #[test]
    fn test_fraud_proof_status_variants() {
        let pending = FraudProofStatus::Pending;
        let under_verification = FraudProofStatus::UnderVerification;
        let proven = FraudProofStatus::Proven;
        let disproven = FraudProofStatus::Disproven;
        let timed_out = FraudProofStatus::TimedOut;
        let withdrawn = FraudProofStatus::Withdrawn;
        
        assert_eq!(pending, FraudProofStatus::Pending);
        assert_ne!(pending, under_verification);
        assert_ne!(proven, disproven);
        assert_ne!(timed_out, withdrawn);
    }

    #[test]
    fn test_fraud_proof_verdict() {
        let verdict = FraudProofVerdict {
            fraud_proven: true,
            explanation: "Test fraud detected".to_string(),
            supporting_evidence: vec![1, 2, 3],
            penalties: vec![FraudPenalty {
                target: test_masternode_id(1),
                penalty_type: PenaltyType::CollateralSlash,
                amount: 1000000,
                reason: "Invalid state transition".to_string(),
            }],
            rewards: vec![FraudReward {
                recipient: vec![4, 5, 6],
                amount: 500000,
                reason: "Successful fraud detection".to_string(),
            }],
        };
        
        assert!(verdict.fraud_proven);
        assert_eq!(verdict.penalties.len(), 1);
        assert_eq!(verdict.rewards.len(), 1);
        assert_eq!(verdict.penalties[0].penalty_type, PenaltyType::CollateralSlash);
    }

    #[test]
    fn test_penalty_types() {
        let collateral_slash = PenaltyType::CollateralSlash;
        let temporary_suspension = PenaltyType::TemporarySuspension;
        let permanent_ban = PenaltyType::PermanentBan;
        let fine = PenaltyType::Fine;
        
        assert_eq!(collateral_slash, PenaltyType::CollateralSlash);
        assert_ne!(collateral_slash, temporary_suspension);
        assert_ne!(permanent_ban, fine);
    }

    #[test]
    fn test_fraud_penalty() {
        let penalty = FraudPenalty {
            target: test_masternode_id(1),
            penalty_type: PenaltyType::CollateralSlash,
            amount: 5000000,
            reason: "Double spending detected".to_string(),
        };
        
        assert_eq!(penalty.target, test_masternode_id(1));
        assert_eq!(penalty.penalty_type, PenaltyType::CollateralSlash);
        assert_eq!(penalty.amount, 5000000);
        assert_eq!(penalty.reason, "Double spending detected");
    }

    #[test]
    fn test_fraud_reward() {
        let reward = FraudReward {
            recipient: vec![1, 2, 3, 4],
            amount: 2000000,
            reason: "Cross-chain fraud detection".to_string(),
        };
        
        assert_eq!(reward.recipient, vec![1, 2, 3, 4]);
        assert_eq!(reward.amount, 2000000);
        assert_eq!(reward.reason, "Cross-chain fraud detection");
    }

    #[test]
    fn test_fraud_proof_response() {
        let response = FraudProofResponse {
            responder_id: test_masternode_id(5),
            response_data: vec![10, 20, 30],
            counter_evidence: vec![40, 50, 60],
            signature: vec![70, 80, 90],
            timestamp: 1234567890,
        };
        
        assert_eq!(response.responder_id, test_masternode_id(5));
        assert_eq!(response.response_data, vec![10, 20, 30]);
        assert_eq!(response.counter_evidence, vec![40, 50, 60]);
        assert_eq!(response.signature, vec![70, 80, 90]);
        assert_eq!(response.timestamp, 1234567890);
    }

    #[test]
    fn test_fraud_proof_challenge() {
        let fraud_proof = create_test_fraud_proof(FraudType::DoubleSpending);
        let challenge = FraudProofChallenge {
            challenge_id: test_hash(1),
            fraud_proof: fraud_proof.clone(),
            status: FraudProofStatus::Pending,
            submission_height: 100,
            verification_deadline: 244,
            challenge_bond: 2000000,
            responses: Vec::new(),
            verdict: None,
        };
        
        assert_eq!(challenge.challenge_id, test_hash(1));
        assert_eq!(challenge.fraud_proof, fraud_proof);
        assert_eq!(challenge.status, FraudProofStatus::Pending);
        assert_eq!(challenge.submission_height, 100);
        assert_eq!(challenge.verification_deadline, 244);
        assert_eq!(challenge.challenge_bond, 2000000);
        assert!(challenge.responses.is_empty());
        assert!(challenge.verdict.is_none());
    }

    #[test]
    fn test_fraud_proof_stats() {
        let stats = FraudProofStats {
            total_challenges: 10,
            proven_frauds: 3,
            disproven_challenges: 5,
            timed_out_challenges: 2,
            total_penalties_applied: 8,
            total_rewards_distributed: 15000000,
        };
        
        assert_eq!(stats.total_challenges, 10);
        assert_eq!(stats.proven_frauds, 3);
        assert_eq!(stats.disproven_challenges, 5);
        assert_eq!(stats.timed_out_challenges, 2);
        assert_eq!(stats.total_penalties_applied, 8);
        assert_eq!(stats.total_rewards_distributed, 15000000);
    }

    #[test]
    fn test_fraud_type_variants() {
        let invalid_state = FraudType::InvalidStateTransition;
        let double_spending = FraudType::DoubleSpending;
        let invalid_cross_chain = FraudType::InvalidCrossChainTx;
        let unauthorized_sig = FraudType::UnauthorizedSignature;
        let invalid_vm = FraudType::InvalidVMExecution;
        
        assert_eq!(invalid_state, FraudType::InvalidStateTransition);
        assert_ne!(invalid_state, double_spending);
        assert_ne!(invalid_cross_chain, unauthorized_sig);
        assert_ne!(invalid_vm, invalid_state);
    }

    #[test]
    fn test_fraud_proof_verification_state_transition() {
        let manager = FraudProofManager::new(FraudProofConfig::default());
        
        let fraud_proof = create_test_fraud_proof(FraudType::InvalidStateTransition);
        let responses = Vec::new();
        
        let result = manager.verify_fraud_proof(&fraud_proof, &responses);
        assert!(result.is_ok());
        
        let verdict = result.unwrap();
        assert!(verdict.fraud_proven); // Simplified verification always returns true for non-empty states
    }

    #[test]
    fn test_fraud_proof_verification_double_spending() {
        let manager = FraudProofManager::new(FraudProofConfig::default());
        
        let mut fraud_proof = create_test_fraud_proof(FraudType::DoubleSpending);
        fraud_proof.evidence.fraudulent_operation = vec![0u8; 200]; // Large operation
        let responses = Vec::new();
        
        let result = manager.verify_fraud_proof(&fraud_proof, &responses);
        assert!(result.is_ok());
        
        let verdict = result.unwrap();
        assert!(verdict.fraud_proven); // Simplified verification based on operation size
    }

    #[test]
    fn test_fraud_proof_verification_cross_chain() {
        let manager = FraudProofManager::new(FraudProofConfig::default());
        
        let mut fraud_proof = create_test_fraud_proof(FraudType::InvalidCrossChainTx);
        fraud_proof.evidence.additional_evidence.insert("test".to_string(), vec![1, 2, 3]);
        let responses = Vec::new();
        
        let result = manager.verify_fraud_proof(&fraud_proof, &responses);
        assert!(result.is_ok());
        
        let verdict = result.unwrap();
        assert!(verdict.fraud_proven); // Simplified verification based on additional evidence
    }

    #[test]
    fn test_fraud_proof_verification_signature() {
        let manager = FraudProofManager::new(FraudProofConfig::default());
        
        let mut fraud_proof = create_test_fraud_proof(FraudType::UnauthorizedSignature);
        fraud_proof.evidence.witness_data = vec![0u8; 100]; // Large witness data
        let responses = Vec::new();
        
        let result = manager.verify_fraud_proof(&fraud_proof, &responses);
        assert!(result.is_ok());
        
        let verdict = result.unwrap();
        assert!(verdict.fraud_proven); // Simplified verification based on witness data size
    }

    #[test]
    fn test_fraud_proof_verification_vm_execution() {
        let manager = FraudProofManager::new(FraudProofConfig::default());
        
        let mut fraud_proof = create_test_fraud_proof(FraudType::InvalidVMExecution);
        fraud_proof.evidence.fraudulent_operation = vec![0u8; 2000]; // Large operation
        let responses = Vec::new();
        
        let result = manager.verify_fraud_proof(&fraud_proof, &responses);
        assert!(result.is_ok());
        
        let verdict = result.unwrap();
        assert!(verdict.fraud_proven); // Simplified verification based on operation size
    }
}
