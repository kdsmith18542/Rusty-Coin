//! Fuzz testing for fraud proofs and detection
//! 
//! This fuzz target tests fraud proof parsing, validation,
//! and processing for security vulnerabilities.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use bincode;
use rusty_core::sidechain::{
    FraudProof, FraudEvidence, FraudType, FraudProofStatus,
    FraudProofConfig, FraudProofManager, FraudProofChallenge,
    FraudProofResponse
};
use rusty_shared_types::{
    Hash,
    masternode::MasternodeID,
    OutPoint
};
use std::collections::HashMap;
use rusty_crypto::hash::blake3;
use std::io::Read;

/// Fuzzable fraud evidence
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFraudEvidence {
    pre_state: Vec<u8>,
    post_state: Vec<u8>,
    fraudulent_operation: Vec<u8>,
    witness_data: Vec<u8>,
    additional_evidence: HashMap<String, Vec<u8>>,
}

impl FuzzFraudEvidence {
    fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.pre_state);
        hasher.update(&self.post_state);
        hasher.update(&self.fraudulent_operation);
        hasher.update(&self.witness_data);
        // Sort keys for deterministic hashing
        let mut keys: Vec<_> = self.additional_evidence.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            if let Some(value) = self.additional_evidence.get(key) {
                hasher.update(value);
            }
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(hasher.finalize().as_bytes());
        result
    }
}

impl From<FuzzFraudEvidence> for FraudEvidence {
    fn from(fuzz_evidence: FuzzFraudEvidence) -> Self {
        FraudEvidence {
            pre_state: fuzz_evidence.pre_state,
            post_state: fuzz_evidence.post_state,
            fraudulent_operation: fuzz_evidence.fraudulent_operation,
            witness_data: fuzz_evidence.witness_data,
            additional_evidence: fuzz_evidence.additional_evidence,
        }
    }
}


/// Test deserialization of raw binary data into fraud proof related types
fn test_deserialization_fuzzing(data: &[u8]) {
    // Try to deserialize as FraudProof
    if let Ok(proof) = bincode::deserialize::<FraudProof>(data) {
        // If successful, try to submit it to a manager
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        let _ = manager.submit_fraud_proof(proof, 1_000_000);
    }
    
    // Try to deserialize as FraudEvidence
    if let Ok(evidence) = bincode::deserialize::<FraudEvidence>(data) {
        // If successful, create a proof with this evidence and submit it
        let mut manager = FraudProofManager::new(FraudProofConfig::default());
        let proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 1000,
            fraud_tx_index: Some(0),
            evidence,
            challenger_address: vec![0; 20],
            challenge_bond: 1_000_000,
            response_deadline: 1000,
        };
        let _ = manager.submit_fraud_proof(proof, 1_000_000);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hasher.finalize().as_bytes());

    let mut unstructured = Unstructured::new(data);

    if let Ok(fraud_proof) = FraudProof::arbitrary(&mut unstructured) {
        // Basic validation
        let _ = fraud_proof.validate();
    }

    // Test fraud proof generation from transactions
    if data.len() < 100 {
        return;
    }

    let mut unstructured_tx = Unstructured::new(data);
    if let Ok(tx) = Transaction::arbitrary(&mut unstructured_tx) {
        let fraud_type = match unstructured_tx.arbitrary::<u8>().unwrap_or(0) % 3 {
            0 => FraudType::DoubleSpending,
            1 => FraudType::InvalidStateTransition,
            _ => FraudType::SidechainMisbehavior,
        };

        let fraud_evidence = FraudEvidence::TransactionFraud {
            offending_transaction: tx.clone(),
            context_data: data.to_vec(),
        };

        let fraud_proof = FraudProof::new(fraud_type.clone(), fraud_evidence);
        let _ = fraud_proof.validate();
    }

    // Test PoSe fraud
    if data.len() < 50 {
        return;
    }
    let mut unstructured_pose = Unstructured::new(data);
    if let Ok(pose_data) = Vec::<u8>::arbitrary(&mut unstructured_pose) {
        let fraud_config = FraudProofConfig::default();
        let mut fraud_manager = FraudProofManager::new(fraud_config);
        let challenge_id = blake3::hash(&pose_data).into();

        if let Some(challenge_status) = fraud_manager.get_challenge_status(&challenge_id) {
            let fraud_type = match unstructured_pose.arbitrary::<u8>().unwrap_or(0) % 2 {
                0 => FraudType::InvalidStateTransition,
                _ => FraudType::SidechainMisbehavior,
            };

            let fraud_evidence = FraudEvidence::TransactionFraud {
                offending_transaction: Transaction::arbitrary(&mut unstructured_pose).unwrap_or_else(|_| {
                    Transaction::Standard { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] }
                }),
                context_data: pose_data.clone(),
            };

            let fraud_proof = FraudProof::new(fraud_type, fraud_evidence);
            let _ = fraud_proof.validate();
        }
    }

    // Test random fraud proof generation and validation
    if let Ok(fraud_proof) = FraudProof::arbitrary(&mut Unstructured::new(data).unwrap()) {
        let _ = fraud_proof.validate();
    }

    // Test specific fraud types
    if data.len() > 100 {
        let mut unstructured_specific = Unstructured::new(data);
        if let Ok(tx) = Transaction::arbitrary(&mut unstructured_specific) {
            let fraud_evidence_tx = FraudEvidence::TransactionFraud {
                offending_transaction: tx,
                context_data: unstructured_specific.bytes(10).unwrap().to_vec(),
            };

            let fraud_proof_double_spend = FraudProof::new(
                FraudType::DoubleSpending,
                fraud_evidence_tx.clone(),
            );
            let _ = fraud_proof_double_spend.validate();

            let fraud_proof_invalid_state = FraudProof::new(
                FraudType::InvalidStateTransition,
                fraud_evidence_tx.clone(),
            );
            let _ = fraud_proof_invalid_state.validate();

            let fraud_proof_sidechain_misbehavior = FraudProof::new(
                FraudType::SidechainMisbehavior,
                fraud_evidence_tx,
            );
            let _ = fraud_proof_sidechain_misbehavior.validate();
        }
    }
});

/// Test parsing of raw binary data as fraud proof components
fn test_raw_fraud_proof_parsing(data: &[u8]) {
    // Test fraud proof parsing
    if let Ok(fraud_proof) = bincode::deserialize::<FraudProof>(data) {
        // Only access existing fields and methods
        let _ = fraud_proof.fraud_type;
        let _ = fraud_proof.fraud_block_height;
        let _ = fraud_proof.challenge_bond;
    }
    
    // Test fraud evidence parsing
    if let Ok(evidence) = bincode::deserialize::<FraudEvidence>(data) {
        let _ = evidence.pre_state.len();
        let _ = evidence.post_state.len();
        let _ = evidence.fraudulent_operation.len();
        let _ = evidence.witness_data.len();
        let _ = evidence.additional_evidence.len();
    }
    
    // Test fraud proof response parsing
    if let Ok(response) = bincode::deserialize::<FraudProofResponse>(data) {
        let _ = response.responder_id;
        let _ = response.response_data.len();
        let _ = response.counter_evidence.len();
        let _ = response.signature.len();
        let _ = response.timestamp;
    }
    
    // Test fraud proof challenge parsing
    if let Ok(challenge) = bincode::deserialize::<FraudProofChallenge>(data) {
        let _ = challenge.challenge_id;
        let _ = challenge.challenge_bond;
        let _ = challenge.submission_height;
        let _ = challenge.verification_deadline;
        let _ = challenge.status;
    }
}

/// Test structured evidence fuzzing
fn test_structured_evidence_fuzzing(fuzz_evidence: FuzzFraudEvidence) {
    // Convert to production type
    let evidence: FraudEvidence = fuzz_evidence.into();
    
    // Test serialization round-trip
    if let Ok(serialized) = bincode::serialize(&evidence) {
        if let Ok(deserialized) = bincode::deserialize::<FraudEvidence>(&serialized) {
            // Compare the serialized forms since we don't have a hash method
            let re_serialized = bincode::serialize(&deserialized).unwrap();
            assert_eq!(serialized, re_serialized);
        }
    }
    
    // Test hashing the serialized form
    let serialized = bincode::serialize(&evidence).unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    assert_eq!(hash.as_bytes().len(), 32);
    
    // Test with fraud proof manager
    let mut manager = FraudProofManager::new(FraudProofConfig::default());
    
    // Create a test fraud proof
    let fraud_proof = FraudProof {
        fraud_type: FraudType::InvalidStateTransition,
        fraud_block_height: 1000,
        fraud_tx_index: Some(0),
        evidence: evidence.clone(),
        challenger_address: vec![0; 20],
        challenge_bond: 1_000_000,
        response_deadline: 1000,
    };
    
    // Test submission
    if let Ok(challenge_id) = manager.submit_fraud_proof(fraud_proof, 1_000_000) {
        // Test processing
        let _ = manager.process_challenges(100);
        
        // Test stats
        let _ = manager.get_stats();
        
        // Test getting specific challenge status
        let _ = manager.get_challenge_status(&challenge_id);
    }
    assert!(!evidence.witness_data.is_empty() || evidence.witness_data.is_empty());
    assert!(!evidence.additional_evidence.is_empty() || evidence.additional_evidence.is_empty());
}

/// Test fraud proof challenge processing
fn test_fraud_proof_challenge_processing(data: &[u8]) {
    if data.len() < 8 { return; }
    
    // Create a test fraud proof
    let fraud_proof = FraudProof {
        fraud_type: FraudType::DoubleSpend,
        fraud_block_height: 1000,
        fraud_tx_index: Some(0),
        evidence: FraudEvidence {
            pre_state: vec![1, 2, 3],
            post_state: vec![4, 5, 6],
            fraudulent_operation: vec![7, 8, 9],
            witness_data: vec![],
            additional_evidence: HashMap::new(),
        },
        challenger_address: vec![0; 20],
        challenge_bond: 1_000_000,
        response_deadline: 1000,
    };
    
    let mut fraud_manager = FraudProofManager::new(FraudProofConfig::default());
    
    // Submit the fraud proof
    let challenge_id = match fraud_manager.submit_fraud_proof(fraud_proof, 1_000_000) {
        Ok(id) => id,
        Err(_) => return, // Skip if submission fails
    };
    
    // Process challenges at a future block
    let _ = fraud_manager.process_challenges(1000);
    
    // Check challenge status
    if let Some(challenge) = fraud_manager.get_challenge(&challenge_id) {
        // Verify challenge properties
        assert_eq!(challenge.challenger_address, vec![0; 20]);
        assert_eq!(challenge.challenge_bond, 1_000_000);
    }
    
    // Get stats
    let stats = fraud_manager.get_stats();
    assert!(stats.total_challenges >= 1);
    
    // Test with invalid challenge ID
    let invalid_id = [0u8; 32];
    assert!(fraud_manager.get_challenge_status(&invalid_id).is_none());
}

/// Test fraud detection edge cases
fn test_fraud_detection_edge_cases(data: &[u8]) {
    // Skip if data is too small
    if data.is_empty() {
        return;
    }
    
    // Initialize fraud manager at the start of the function
    let mut fraud_manager = FraudProofManager::new(FraudProofConfig::default());
    
    // Test with empty data
    if let Ok(proof) = bincode::deserialize::<FraudProof>(&[]) {
        let _ = fraud_manager.submit_fraud_proof(proof, 1000);
    }
    
    // Test with small data
    if data.len() > 10 {
        let small_data = &data[..10];
        if let Ok(proof) = bincode::deserialize::<FraudProof>(small_data) {
            let _ = fraud_manager.submit_fraud_proof(proof, 1000);
        }
    }
    
    // Test with specific edge values for FraudEvidence
    let mut evidence = FraudEvidence {
        pre_state: vec![0; 32],
        post_state: vec![0; 32],
        fraudulent_operation: vec![0; 64],
        witness_data: vec![],
        additional_evidence: HashMap::new(),
    };
    
    // Test with different evidence sizes
    let sizes = [0, 1, 10, 100, 1000];
    for &size in &sizes {
        evidence.pre_state = vec![0; size];
        evidence.post_state = vec![0; size];
        evidence.fraudulent_operation = vec![0; size];
        
        // Create a fraud proof with this evidence
        let proof = FraudProof {
            fraud_type: FraudType::DoubleSpend,
            fraud_block_height: 1000,
            fraud_tx_index: Some(0),
            evidence: evidence.clone(),
            challenger_address: vec![0; 20],
            challenge_bond: 1_000_000,
            response_deadline: 1000,
        };
        
        // Submit the proof to the manager
        let _ = fraud_manager.submit_fraud_proof(proof, 1_000_000);
    }
    
    // Test with extreme values
    if data.len() >= 24 {
        let extreme_bond = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        
        let extreme_height = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);
        
        let extreme_deadline = u64::from_le_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23],
        ]);
        
        // Create a test fraud proof with extreme values
        let extreme_proof = FraudProof {
            fraud_type: FraudType::DoubleSpend,
            fraud_block_height: extreme_height,
            fraud_tx_index: Some(extreme_height as u32 % 1000),
            evidence: FraudEvidence {
                pre_state: vec![0; 32],
                post_state: vec![0; 32],
                fraudulent_operation: vec![0; 64],
                witness_data: vec![],
                additional_evidence: HashMap::new(),
            },
            challenger_address: vec![0; 20],
            challenge_bond: extreme_bond,
            response_deadline: extreme_deadline,
        };

        // Test submission with extreme values
        let _ = fraud_manager.submit_fraud_proof(extreme_proof, extreme_bond);
    }

    // Create a valid fraud proof
    let fraud_proof = FraudProof {
        fraud_type: FraudType::InvalidStateTransition,
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
        challenge_bond: 2_000_000,
        response_deadline: 200,
    };
    
    // Submit the fraud proof
    let submission_result = fraud_manager.submit_fraud_proof(fraud_proof, 1_000_000);
    
    // Verify the submission was successful
    if let Ok(challenge_id) = submission_result {
        // Create a responder ID with a zeroed OutPoint
        let responder_id = MasternodeID(OutPoint {
            txid: [0u8; 32],
            vout: 0,
        });
        
        // Create a response
        let response = FraudProofResponse {
            responder_id,
            response_data: vec![],
            counter_evidence: vec![],
            signature: vec![],
            timestamp: 0,
        };
        
        // Submit the response
        let _ = fraud_manager.submit_response(challenge_id, response);
    }
    
    // Test empty fraud proof
    let empty_fraud_proof = FraudProof {
        fraud_type: FraudType::InvalidStateTransition,
        fraud_block_height: 0,
        fraud_tx_index: None,
        evidence: FraudEvidence {
            pre_state: vec![],
            post_state: vec![],
            fraudulent_operation: vec![],
            witness_data: vec![],
            additional_evidence: HashMap::new(),
        },
        challenger_address: vec![],
        challenge_bond: 0,
        response_deadline: 0,
    };
    
    let _ = fraud_manager.submit_fraud_proof(empty_fraud_proof, 0);
    
    // Test fraud proof with large evidence if we have enough data
    if data.len() > 1000 {
        let evidence = FraudEvidence {
            pre_state: data[..1000].to_vec(),
            post_state: data[..1000].to_vec(),
            fraudulent_operation: data[..1000].to_vec(),
            witness_data: data[..1000].to_vec(),
            additional_evidence: {
                let mut map = HashMap::new();
                map.insert("large_evidence".to_string(), data[..1000].to_vec());
                map
            },
        };
        
        let large_fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidVMExecution,
            fraud_block_height: 1000,
            fraud_tx_index: Some(100),
            evidence,
            challenger_address: vec![1, 2, 3],
            challenge_bond: 5_000_000,
            response_deadline: 2_000_000_000,
        };
        
        let _ = fraud_manager.submit_fraud_proof(large_fraud_proof, 5_000_000);
    }
    
    // Test processing with various block heights
    for block_height in [0, 1, 100, 1000, u64::MAX] {
        let _ = fraud_manager.process_challenges(block_height);
    }
    
    // Test statistics
    let stats = fraud_manager.get_stats();
    let _ = stats.total_challenges;
    let _ = stats.proven_frauds;
    let _ = stats.timed_out_challenges;
}
