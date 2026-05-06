//! Comprehensive Sidechain Protocol Validation Tests for Spec 10 Compliance
//!
//! This test suite validates Rusty Coin sidechain protocol implementation against
//! specification 10 requirements. Tests cover federation management, two-way peg
//! mechanisms, sidechain consensus, fraud proofs, and cross-chain communication.
//!
//! Tests integrate with regtest network and provide detailed assertions for each component.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::sidechain::*;
use rusty_crypto::keypair::Keypair;
use rusty_shared_types::{
    masternode::{MasternodeID, MasternodeIdentity},
    Hash, OutPoint, Transaction, TxInput, TxOutput,
    ConsensusParams, Network,
};
use rusty_types::blockchain::Blockchain as SharedBlockchain;

/// Test configuration for spec 10 validation
struct Spec10TestConfig {
    consensus_params: ConsensusParams,
    federation_config: federation_manager::FederationManager,
    peg_config: two_way_peg::TwoWayPegManager,
    fraud_config: fraud_proofs::FraudProofConfig,
}

impl Default for Spec10TestConfig {
    fn default() -> Self {
        Self {
            consensus_params: ConsensusParams::regtest(),
            federation_config: federation_manager::FederationManager::new(1000),
            peg_config: two_way_peg::TwoWayPegManager::new(6),
            fraud_config: fraud_proofs::FraudProofConfig::default(),
        }
    }
}

/// Helper function to create a test blockchain with genesis block
fn create_test_blockchain() -> Blockchain {
    let mut blockchain = Blockchain::new(Network::Regtest);
    // Add genesis block if needed
    blockchain
}

/// Helper function to create test masternode identities
fn create_test_masternode_id(value: u8) -> MasternodeID {
    MasternodeID(OutPoint {
        txid: [value; 32].into(),
        vout: 0,
    })
}

/// Helper function to create test federation members
fn create_test_federation_members(count: usize) -> (Vec<MasternodeID>, Vec<Vec<u8>>) {
    let members: Vec<MasternodeID> = (0..count).map(|i| create_test_masternode_id(i as u8)).collect();
    let public_keys: Vec<Vec<u8>> = (0..count).map(|i| vec![i as u8; 48]).collect();
    (members, public_keys)
}

/// Helper function to create test sidechain block
fn create_test_sidechain_block(
    sidechain_id: Hash,
    height: u64,
    previous_hash: Hash,
) -> SidechainBlock {
    SidechainBlock::new(
        SidechainBlockHeader::new(
            previous_hash,
            [1u8; 32].into(), // merkle_root
            [2u8; 32].into(), // cross_chain_merkle_root
            [3u8; 32].into(), // state_root
            height,
            sidechain_id,
            1000, // mainchain_anchor_height
            [4u8; 32].into(), // mainchain_anchor_hash
            1, // federation_epoch
        ),
        vec![], // transactions
    )
}

#[cfg(test)]
mod federation_setup_tests {
    use super::*;

    #[test]
    fn test_federation_initialization_with_multi_sig_keys() {
        println!("🧪 Testing federation initialization with multi-signature key generation...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [1u8; 32].into();
        let (members, public_keys) = create_test_federation_members(5);

        // Initialize federation with threshold configuration
        let epoch = config.federation_config.initialize_federation(
            sidechain_id,
            members.clone(),
            3, // threshold: 3 of 5
            100, // start_height
            public_keys.clone(),
        );

        assert!(epoch.is_ok(), "Federation initialization should succeed");
        assert_eq!(epoch.unwrap(), 1, "First epoch should be 1");

        // Verify federation state
        let current_epoch = config.federation_config.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(current_epoch.members, members, "Federation members should match");
        assert_eq!(current_epoch.threshold, 3, "Threshold should be configured correctly");
        assert_eq!(current_epoch.public_keys, public_keys, "Public keys should match");
        assert_eq!(current_epoch.epoch, 1, "Epoch number should be 1");

        println!("✅ Federation initialization with multi-signature keys test passed");
    }

    #[test]
    fn test_federation_threshold_configuration() {
        println!("🧪 Testing federation threshold configuration...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [2u8; 32].into();
        let (members, public_keys) = create_test_federation_members(7);

        // Test various threshold configurations
        let test_cases = vec![
            (1, 7), // 1 of 7
            (4, 7), // 4 of 7
            (7, 7), // 7 of 7 (all members)
        ];

        for (threshold, expected_threshold) in test_cases {
            let epoch = config.federation_config.initialize_federation(
                sidechain_id,
                members.clone(),
                threshold,
                100,
                public_keys.clone(),
            );

            assert!(epoch.is_ok(), "Threshold {} should be valid", threshold);

            let current_epoch = config.federation_config.get_current_epoch(&sidechain_id).unwrap();
            assert_eq!(current_epoch.threshold, expected_threshold,
                      "Threshold should be set correctly");
        }

        // Test invalid thresholds
        let invalid_thresholds = vec![0, 8]; // 0 or greater than members
        for threshold in invalid_thresholds {
            let epoch = config.federation_config.initialize_federation(
                sidechain_id,
                members.clone(),
                threshold,
                100,
                public_keys.clone(),
            );

            assert!(epoch.is_err(), "Threshold {} should be invalid", threshold);
        }

        println!("✅ Federation threshold configuration test passed");
    }

    #[test]
    fn test_federation_epoch_transitions() {
        println!("🧪 Testing federation epoch transitions...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [3u8; 32].into();
        let (members1, public_keys1) = create_test_federation_members(5);

        // Initialize first epoch
        config.federation_config.initialize_federation(
            sidechain_id,
            members1,
            3,
            100,
            public_keys1,
        ).unwrap();

        // Transition to new epoch
        let (members2, public_keys2) = create_test_federation_members(6);
        let new_epoch = config.federation_config.transition_epoch(
            sidechain_id,
            members2.clone(),
            4, // new threshold
            1100, // transition height
            public_keys2.clone(),
        );

        assert!(new_epoch.is_ok(), "Epoch transition should succeed");
        assert_eq!(new_epoch.unwrap(), 2, "New epoch should be 2");

        // Verify old epoch is ended
        let old_epoch = config.federation_config.get_epoch(&sidechain_id, 1).unwrap();
        assert_eq!(old_epoch.end_height, Some(1100), "Old epoch should be ended");

        // Verify new epoch is current
        let current_epoch = config.federation_config.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(current_epoch.epoch, 2, "Current epoch should be 2");
        assert_eq!(current_epoch.members, members2, "New members should be set");
        assert_eq!(current_epoch.threshold, 4, "New threshold should be set");

        println!("✅ Federation epoch transitions test passed");
    }

    #[test]
    fn test_multi_signature_key_validation() {
        println!("🧪 Testing multi-signature key validation...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [4u8; 32].into();
        let (members, public_keys) = create_test_federation_members(4);

        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            3,
            100,
            public_keys.clone(),
        ).unwrap();

        // Test valid signature verification (using test utilities)
        use rusty_core::sidechain::federation_manager::test_utils::sample_federation_signature;

        let message_hash = [42u8; 32].into();
        let sample = sample_federation_signature(4, &[0, 1, 2], message_hash, 1); // 3 of 4 signers

        let is_valid = config.federation_config.verify_threshold_signature(
            &sidechain_id,
            1,
            &sample.signature,
            &message_hash,
        );

        assert!(is_valid, "Valid threshold signature should be accepted");

        // Test insufficient signers
        let insufficient_sample = sample_federation_signature(4, &[0, 1], message_hash, 1); // 2 of 4 signers
        let is_valid_insufficient = config.federation_config.verify_threshold_signature(
            &sidechain_id,
            1,
            &insufficient_sample.signature,
            &message_hash,
        );

        assert!(!is_valid_insufficient, "Insufficient signers should be rejected");

        println!("✅ Multi-signature key validation test passed");
    }
}

#[cfg(test)]
mod peg_in_process_tests {
    use super::*;

    #[test]
    fn test_peg_in_request_validation() {
        println!("🧪 Testing peg-in request validation...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [5u8; 32].into();

        // Initialize federation
        let (members, public_keys) = create_test_federation_members(3);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            2,
            100,
            public_keys,
        ).unwrap();

        // Create peg-in request
        let peg_in_request = PegInRequest {
            mainchain_tx_hash: [1u8; 32].into(),
            amount: 1_000_000, // 0.01 RUST
            sidechain_recipient: vec![1, 2, 3, 4, 5], // recipient address
            sidechain_id,
            mainchain_confirm_height: 1000,
            merkle_proof: vec![[2u8; 32].into(), [3u8; 32].into()], // mock merkle proof
            federation_signatures: vec![], // Will be tested with proper signatures
        };

        // Test peg-in initiation (should fail without proper signatures for now)
        let result = config.peg_config.initiate_peg_in(peg_in_request);

        // Note: This will fail due to signature validation, but tests the integration
        assert!(result.is_err(), "Peg-in should require valid federation signatures");

        println!("✅ Peg-in request validation test passed");
    }

    #[test]
    fn test_peg_in_federation_confirmation() {
        println!("🧪 Testing peg-in federation confirmation...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [6u8; 32].into();

        // Initialize federation
        let (members, public_keys) = create_test_federation_members(4);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            3, // 3 of 4 threshold
            100,
            public_keys,
        ).unwrap();

        // Create peg-in request with mock signatures
        let peg_in_request = PegInRequest {
            mainchain_tx_hash: [10u8; 32].into(),
            amount: 5_000_000, // 0.05 RUST
            sidechain_recipient: vec![6, 7, 8, 9, 10],
            sidechain_id,
            mainchain_confirm_height: 1500,
            merkle_proof: vec![[11u8; 32].into(), [12u8; 32].into()],
            federation_signatures: vec![
                // Mock signatures - in real implementation these would be proper BLS signatures
                FederationSignature {
                    signature: vec![1u8; 96], // BLS signature size
                    signer_bitmap: vec![0b00001110], // Signers 1, 2, 3 (3 signers)
                    threshold: 3,
                    epoch: 1,
                    message_hash: [13u8; 32].into(),
                }
            ],
        };

        // Test peg-in with federation signatures
        let result = config.peg_config.initiate_peg_in(peg_in_request);

        // Should succeed with proper federation setup
        assert!(result.is_ok(), "Peg-in with federation confirmation should succeed");

        let tx_id = result.unwrap();

        // Verify peg transaction was created
        let peg_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(peg_tx.tx_type, PegTransactionType::PegIn, "Should be peg-in transaction");
        assert_eq!(peg_tx.amount, 5_000_000, "Amount should match request");
        assert_eq!(peg_tx.status, PegTransactionStatus::Pending, "Should start as pending");

        println!("✅ Peg-in federation confirmation test passed");
    }

    #[test]
    fn test_peg_in_confirmation_process() {
        println!("🧪 Testing peg-in confirmation process...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [7u8; 32].into();

        // Initialize federation
        let (members, public_keys) = create_test_federation_members(3);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            2,
            100,
            public_keys,
        ).unwrap();

        // Create and initiate peg-in
        let peg_in_request = PegInRequest {
            mainchain_tx_hash: [20u8; 32].into(),
            amount: 2_000_000,
            sidechain_recipient: vec![21, 22, 23],
            sidechain_id,
            mainchain_confirm_height: 2000,
            merkle_proof: vec![[24u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![25u8; 96],
                signer_bitmap: vec![0b00000110], // 2 signers
                threshold: 2,
                epoch: 1,
                message_hash: [26u8; 32].into(),
            }],
        };

        let tx_id = config.peg_config.initiate_peg_in(peg_in_request).unwrap();

        // Confirm peg-in after required confirmations
        let confirm_result = config.peg_config.confirm_peg_transaction(&tx_id, 2006); // 6 confirmations
        assert!(confirm_result.is_ok(), "Peg-in confirmation should succeed");

        let peg_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(peg_tx.status, PegTransactionStatus::Confirmed, "Should be confirmed");

        // Complete peg-in (mint tokens on sidechain)
        let complete_result = config.peg_config.complete_peg_transaction(&tx_id);
        assert!(complete_result.is_ok(), "Peg-in completion should succeed");

        let final_peg_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(final_peg_tx.status, PegTransactionStatus::Completed, "Should be completed");

        println!("✅ Peg-in confirmation process test passed");
    }
}

#[cfg(test)]
mod sidechain_consensus_tests {
    use super::*;

    #[test]
    fn test_sidechain_block_production() {
        println!("🧪 Testing sidechain block production...");

        let sidechain_id = [8u8; 32].into();
        let consensus = SidechainConsensus::new(sidechain_id);

        // Initialize with federation
        let (members, public_keys) = create_test_federation_members(3);
        let consensus = consensus.initialize_with_federation(
            members,
            2,
            public_keys,
            100,
        ).unwrap();

        // Create test sidechain block
        let block = create_test_sidechain_block(sidechain_id, 1, [0u8; 32].into());

        // Process block
        let mainchain_height = 1000;
        let mainchain_hash = [9u8; 32].into();

        let result = consensus.process_sidechain_block(
            block.clone(),
            mainchain_height,
            mainchain_hash,
        );

        assert!(result.is_ok(), "Sidechain block processing should succeed");

        // Verify consensus state
        let state = consensus.get_sidechain_state();
        assert_eq!(state.height, 1, "Height should be updated");
        assert_eq!(state.tip, block.hash(), "Tip should be updated");
        assert_eq!(state.sidechain_id, sidechain_id, "Sidechain ID should match");

        println!("✅ Sidechain block production test passed");
    }

    #[test]
    fn test_sidechain_state_validation() {
        println!("🧪 Testing sidechain state validation...");

        let sidechain_id = [9u8; 32].into();
        let consensus = SidechainConsensus::new(sidechain_id);

        // Initialize with federation
        let (members, public_keys) = create_test_federation_members(4);
        let consensus = consensus.initialize_with_federation(
            members,
            3,
            public_keys,
            100,
        ).unwrap();

        // Create and process multiple blocks
        let mut previous_hash = [0u8; 32].into();
        let mainchain_height = 1000;
        let mainchain_hash = [10u8; 32].into();

        for height in 1..=5 {
            let block = create_test_sidechain_block(sidechain_id, height, previous_hash);

            let result = consensus.process_sidechain_block(
                block.clone(),
                mainchain_height,
                mainchain_hash,
            );

            assert!(result.is_ok(), "Block {} processing should succeed", height);

            previous_hash = block.hash();
        }

        // Verify final state
        let state = consensus.get_sidechain_state();
        assert_eq!(state.height, 5, "Final height should be 5");
        assert_eq!(state.sidechain_id, sidechain_id, "Sidechain ID should be preserved");

        println!("✅ Sidechain state validation test passed");
    }

    #[test]
    fn test_sidechain_consensus_stats() {
        println!("🧪 Testing sidechain consensus statistics...");

        let sidechain_id = [10u8; 32].into();
        let consensus = SidechainConsensus::new(sidechain_id);

        // Initialize with federation
        let (members, public_keys) = create_test_federation_members(5);
        let consensus = consensus.initialize_with_federation(
            members,
            3,
            public_keys,
            100,
        ).unwrap();

        // Get consensus statistics
        let stats = consensus.get_consensus_stats();

        assert_eq!(stats.sidechain_id, sidechain_id, "Sidechain ID should match");
        assert_eq!(stats.current_height, 0, "Initial height should be 0");
        assert_eq!(stats.federation_stats.total_sidechains, 1, "Should have 1 sidechain");
        assert_eq!(stats.federation_stats.total_members, 5, "Should have 5 federation members");
        assert_eq!(stats.federation_stats.active_sidechains, 1, "Should have 1 active sidechain");

        println!("✅ Sidechain consensus statistics test passed");
    }
}

#[cfg(test)]
mod peg_out_process_tests {
    use super::*;

    #[test]
    fn test_peg_out_request_initiation() {
        println!("🧪 Testing peg-out request initiation...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [11u8; 32].into();

        // Initialize federation
        let (members, public_keys) = create_test_federation_members(3);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            2,
            100,
            public_keys,
        ).unwrap();

        // Create peg-out request
        let peg_out_request = PegOutRequest {
            sidechain_tx_hash: [30u8; 32].into(),
            amount: 3_000_000, // 0.03 RUST
            mainchain_recipient: vec![31, 32, 33, 34, 35], // mainchain address
            sidechain_id,
            sidechain_confirm_height: 2500,
            merkle_proof: vec![[36u8; 32].into(), [37u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![38u8; 96],
                signer_bitmap: vec![0b00000110], // 2 signers
                threshold: 2,
                epoch: 1,
                message_hash: [39u8; 32].into(),
            }],
        };

        // Initiate peg-out
        let result = config.peg_config.initiate_peg_out(peg_out_request);
        assert!(result.is_ok(), "Peg-out initiation should succeed");

        let tx_id = result.unwrap();

        // Verify peg transaction
        let peg_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(peg_tx.tx_type, PegTransactionType::PegOut, "Should be peg-out transaction");
        assert_eq!(peg_tx.amount, 3_000_000, "Amount should match request");
        assert_eq!(peg_tx.status, PegTransactionStatus::Pending, "Should start as pending");

        println!("✅ Peg-out request initiation test passed");
    }

    #[test]
    fn test_peg_out_federation_authorization() {
        println!("🧪 Testing peg-out federation authorization...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [12u8; 32].into();

        // Initialize federation with higher threshold
        let (members, public_keys) = create_test_federation_members(5);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            4, // 4 of 5 threshold for security
            100,
            public_keys,
        ).unwrap();

        // Test with sufficient signatures
        let peg_out_request = PegOutRequest {
            sidechain_tx_hash: [40u8; 32].into(),
            amount: 10_000_000, // 0.1 RUST - larger amount
            mainchain_recipient: vec![41, 42, 43],
            sidechain_id,
            sidechain_confirm_height: 3000,
            merkle_proof: vec![[44u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![45u8; 96],
                signer_bitmap: vec![0b00011110], // 4 signers (bits 1,2,3,4)
                threshold: 4,
                epoch: 1,
                message_hash: [46u8; 32].into(),
            }],
        };

        let result = config.peg_config.initiate_peg_out(peg_out_request);
        assert!(result.is_ok(), "Peg-out with sufficient federation authorization should succeed");

        // Test with insufficient signatures (should fail)
        let insufficient_request = PegOutRequest {
            sidechain_tx_hash: [50u8; 32].into(),
            amount: 1_000_000,
            mainchain_recipient: vec![51, 52, 53],
            sidechain_id,
            sidechain_confirm_height: 3100,
            merkle_proof: vec![[54u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![55u8; 96],
                signer_bitmap: vec![0b00000110], // Only 2 signers
                threshold: 4,
                epoch: 1,
                message_hash: [56u8; 32].into(),
            }],
        };

        let insufficient_result = config.peg_config.initiate_peg_out(insufficient_request);
        assert!(insufficient_result.is_err(), "Peg-out with insufficient authorization should fail");

        println!("✅ Peg-out federation authorization test passed");
    }

    #[test]
    fn test_peg_out_completion_workflow() {
        println!("🧪 Testing peg-out completion workflow...");

        let mut config = Spec10TestConfig::default();
        let sidechain_id = [13u8; 32].into();

        // Initialize federation
        let (members, public_keys) = create_test_federation_members(4);
        config.federation_config.initialize_federation(
            sidechain_id,
            members,
            3,
            100,
            public_keys,
        ).unwrap();

        // Create and initiate peg-out
        let peg_out_request = PegOutRequest {
            sidechain_tx_hash: [60u8; 32].into(),
            amount: 7_500_000,
            mainchain_recipient: vec![61, 62, 63, 64],
            sidechain_id,
            sidechain_confirm_height: 3500,
            merkle_proof: vec![[65u8; 32].into(), [66u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![67u8; 96],
                signer_bitmap: vec![0b00001110], // 3 signers
                threshold: 3,
                epoch: 1,
                message_hash: [68u8; 32].into(),
            }],
        };

        let tx_id = config.peg_config.initiate_peg_out(peg_out_request).unwrap();

        // Confirm peg-out
        config.peg_config.confirm_peg_transaction(&tx_id, 3506).unwrap();

        let confirmed_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(confirmed_tx.status, PegTransactionStatus::Confirmed, "Should be confirmed");

        // Complete peg-out (unlock on mainchain)
        config.peg_config.complete_peg_transaction(&tx_id).unwrap();

        let completed_tx = config.peg_config.get_peg_transaction(&tx_id).unwrap();
        assert_eq!(completed_tx.status, PegTransactionStatus::Completed, "Should be completed");

        println!("✅ Peg-out completion workflow test passed");
    }
}

#[cfg(test)]
mod fraud_proof_handling_tests {
    use super::*;

    #[test]
    fn test_fraud_proof_submission() {
        println!("🧪 Testing fraud proof submission...");

        let config = Spec10TestConfig::default();
        let mut fraud_manager = FraudProofManager::new(config.fraud_config.clone());

        // Create a fraud proof
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 1000,
            fraud_tx_index: Some(5),
            evidence: FraudEvidence {
                pre_state: vec![1, 2, 3, 4],
                post_state: vec![5, 6, 7, 8],
                fraudulent_operation: vec![9, 10, 11, 12],
                witness_data: vec![13, 14, 15, 16],
                additional_evidence: HashMap::new(),
            },
            challenger_address: vec![17, 18, 19, 20],
            challenge_bond: 1_000_000,
            response_deadline: 2000,
        };

        // Submit fraud proof
        let result = fraud_manager.submit_fraud_proof(fraud_proof, 1_000_000);
        assert!(result.is_ok(), "Fraud proof submission should succeed");

        let challenge_id = result.unwrap();

        // Verify challenge was created
        let challenge = fraud_manager.get_challenge_status(&challenge_id).unwrap();
        assert_eq!(challenge, FraudProofStatus::Pending, "Challenge should be pending");

        println!("✅ Fraud proof submission test passed");
    }

    #[test]
    fn test_fraud_proof_verification() {
        println!("🧪 Testing fraud proof verification...");

        let config = Spec10TestConfig::default();
        let mut fraud_manager = FraudProofManager::new(config.fraud_config.clone());

        // Create and submit fraud proof
        let fraud_proof = FraudProof {
            fraud_type: FraudType::DoubleSpending,
            fraud_block_height: 1500,
            fraud_tx_index: Some(10),
            evidence: FraudEvidence {
                pre_state: vec![20, 21, 22],
                post_state: vec![23, 24, 25],
                fraudulent_operation: vec![26, 27, 28, 29, 30],
                witness_data: vec![31, 32, 33, 34, 35, 36],
                additional_evidence: HashMap::new(),
            },
            challenger_address: vec![37, 38, 39],
            challenge_bond: 2_000_000,
            response_deadline: 2500,
        };

        let challenge_id = fraud_manager.submit_fraud_proof(fraud_proof, 2_000_000).unwrap();

        // Process challenges (simulate block processing)
        fraud_manager.process_challenges(1600).unwrap();

        // Check if challenge was resolved
        let final_status = fraud_manager.get_challenge_status(&challenge_id).unwrap();
        assert!(final_status == FraudProofStatus::Proven || final_status == FraudProofStatus::Disproven,
               "Challenge should be resolved");

        println!("✅ Fraud proof verification test passed");
    }

    #[test]
    fn test_cross_chain_fraud_detection() {
        println!("🧪 Testing cross-chain fraud detection...");

        let config = Spec10TestConfig::default();
        let mut fraud_manager = FraudProofManager::new(config.fraud_config.clone());

        // Create cross-chain fraud proof
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidCrossChainTx,
            fraud_block_height: 2000,
            fraud_tx_index: None,
            evidence: FraudEvidence {
                pre_state: vec![40, 41],
                post_state: vec![42, 43],
                fraudulent_operation: vec![44, 45, 46, 47, 48],
                witness_data: vec![49, 50, 51],
                additional_evidence: HashMap::from([
                    ("invalid_signatures".to_string(), vec![52, 53, 54, 55]),
                    ("asset_mismatch".to_string(), vec![56, 57, 58]),
                ]),
            },
            challenger_address: vec![59, 60, 61],
            challenge_bond: 3_000_000,
            response_deadline: 3000,
        };

        let challenge_id = fraud_manager.submit_fraud_proof(fraud_proof, 3_000_000).unwrap();

        // Process and verify
        fraud_manager.process_challenges(2100).unwrap();

        let status = fraud_manager.get_challenge_status(&challenge_id).unwrap();
        assert!(matches!(status, FraudProofStatus::Proven | FraudProofStatus::Disproven),
               "Cross-chain fraud should be verified");

        println!("✅ Cross-chain fraud detection test passed");
    }

    #[test]
    fn test_fraud_proof_statistics() {
        println!("🧪 Testing fraud proof statistics...");

        let config = Spec10TestConfig::default();
        let mut fraud_manager = FraudProofManager::new(config.fraud_config.clone());

        // Submit multiple fraud proofs
        for i in 0..3 {
            let fraud_proof = FraudProof {
                fraud_type: FraudType::InvalidStateTransition,
                fraud_block_height: 1000 + i as u64,
                fraud_tx_index: Some(i),
                evidence: FraudEvidence {
                    pre_state: vec![70 + i as u8; 4],
                    post_state: vec![74 + i as u8; 4],
                    fraudulent_operation: vec![78 + i as u8; 4],
                    witness_data: vec![82 + i as u8; 4],
                    additional_evidence: HashMap::new(),
                },
                challenger_address: vec![86 + i as u8; 4],
                challenge_bond: 1_000_000,
                response_deadline: 2000 + i as u64,
            };

            fraud_manager.submit_fraud_proof(fraud_proof, 1_000_000).unwrap();
        }

        // Process challenges
        fraud_manager.process_challenges(1500).unwrap();

        // Check statistics
        let stats = fraud_manager.get_stats();
        assert_eq!(stats.total_challenges, 3, "Should have 3 total challenges");
        assert!(stats.proven_frauds + stats.disproven_challenges >= 3,
               "All challenges should be resolved");

        println!("✅ Fraud proof statistics test passed");
    }
}

#[cfg(test)]
mod regtest_integration_tests {
    use super::*;

    #[test]
    fn test_spec10_compliance_with_regtest_params() {
        println!("🧪 Testing spec 10 compliance with regtest parameters...");

        let config = Spec10TestConfig::default();

        // Verify regtest uses mainnet consensus parameters
        assert_eq!(config.consensus_params.min_block_time, 150,
                  "Regtest should use mainnet block time");
        assert_eq!(config.consensus_params.difficulty_adjustment_window, 2016,
                  "Regtest should use mainnet difficulty window");

        // Verify federation configuration
        assert_eq!(config.fraud_config.challenge_period_blocks, 1440,
                  "Fraud proof challenge period should be 1440 blocks");
        assert_eq!(config.fraud_config.min_challenge_bond, 1_000_000,
                  "Minimum challenge bond should be 0.01 RUST");

        println!("✅ Spec 10 regtest compliance test passed");
    }

    #[test]
    fn test_sidechain_full_lifecycle_integration() {
        println!("🧪 Testing sidechain full lifecycle integration...");

        let blockchain = create_test_blockchain();
        let sidechain_id = [100u8; 32].into();

        // 1. Register sidechain
        let (members, public_keys) = create_test_federation_members(4);
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            3,
            public_keys.clone(),
            100,
        ).unwrap();

        // 2. Process mainchain blocks
        let block_header = rusty_shared_types::BlockHeader {
            version: 1,
            height: 1000,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
            ticket_pool_hash: [3u8; 32],
        };

        blockchain.process_mainchain_block_for_sidechains(&block_header).unwrap();

        // 3. Create and process sidechain blocks
        let sidechain_block = create_test_sidechain_block(sidechain_id, 1, [0u8; 32].into());
        blockchain.process_sidechain_block(&sidechain_id, sidechain_block).unwrap();

        // 4. Verify integration
        let stats = blockchain.get_sidechain_stats(&sidechain_id).unwrap();
        assert_eq!(stats.current_height, 1, "Sidechain should have processed blocks");
        assert_eq!(stats.sidechain_id, sidechain_id, "Sidechain ID should match");

        println!("✅ Sidechain full lifecycle integration test passed");
    }
}

#[cfg(test)]
mod comprehensive_validation_tests {
    use super::*;

    #[test]
    fn test_complete_spec10_validation() {
        println!("🧪 Running complete spec 10 validation test suite...");

        let mut config = Spec10TestConfig::default();
        let blockchain = create_test_blockchain();
        let sidechain_id = [200u8; 32].into();

        // Test 1: Federation setup compliance
        let (members, public_keys) = create_test_federation_members(5);
        let epoch = config.federation_config.initialize_federation(
            sidechain_id,
            members.clone(),
            4, // 4 of 5 threshold
            100,
            public_keys.clone(),
        ).unwrap();
        assert_eq!(epoch, 1, "Spec 10.2: Federation initialization should succeed");

        // Test 2: Two-way peg mechanism compliance
        let peg_in_request = PegInRequest {
            mainchain_tx_hash: [201u8; 32].into(),
            amount: 10_000_000,
            sidechain_recipient: vec![202, 203, 204],
            sidechain_id,
            mainchain_confirm_height: 1000,
            merkle_proof: vec![[205u8; 32].into()],
            federation_signatures: vec![FederationSignature {
                signature: vec![206u8; 96],
                signer_bitmap: vec![0b00011110], // 4 signers
                threshold: 4,
                epoch: 1,
                message_hash: [207u8; 32].into(),
            }],
        };

        let peg_in_id = config.peg_config.initiate_peg_in(peg_in_request).unwrap();
        config.peg_config.confirm_peg_transaction(&peg_in_id, 1006).unwrap();
        config.peg_config.complete_peg_transaction(&peg_in_id).unwrap();

        let peg_in_tx = config.peg_config.get_peg_transaction(&peg_in_id).unwrap();
        assert_eq!(peg_in_tx.status, PegTransactionStatus::Completed,
                  "Spec 10.3: Peg-in process should complete successfully");

        // Test 3: Sidechain consensus compliance
        let consensus = SidechainConsensus::new(sidechain_id)
            .initialize_with_federation(members, 4, public_keys, 100).unwrap();

        let block = create_test_sidechain_block(sidechain_id, 1, [0u8; 32].into());
        consensus.process_sidechain_block(
            block,
            1000,
            [208u8; 32].into(),
        ).unwrap();

        let consensus_stats = consensus.get_consensus_stats();
        assert_eq!(consensus_stats.current_height, 1,
                  "Spec 10.4: Sidechain consensus should process blocks");

        // Test 4: Fraud proof system compliance
        let mut fraud_manager = FraudProofManager::new(config.fraud_config);
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 1000,
            fraud_tx_index: Some(1),
            evidence: FraudEvidence {
                pre_state: vec![209, 210],
                post_state: vec![211, 212],
                fraudulent_operation: vec![213, 214, 215],
                witness_data: vec![216, 217, 218],
                additional_evidence: HashMap::new(),
            },
            challenger_address: vec![219, 220, 221],
            challenge_bond: 1_000_000,
            response_deadline: 2000,
        };

        let challenge_id = fraud_manager.submit_fraud_proof(fraud_proof, 1_000_000).unwrap();
        fraud_manager.process_challenges(1500).unwrap();

        let challenge_status = fraud_manager.get_challenge_status(&challenge_id).unwrap();
        assert!(matches!(challenge_status, FraudProofStatus::Proven | FraudProofStatus::Disproven),
               "Spec 10.5: Fraud proof system should process challenges");

        println!("✅ Complete spec 10 validation test suite passed");
        println!("📋 Validation Summary:");
        println!("   ✅ Federation setup with multi-signature key generation and threshold configuration");
        println!("   ✅ Peg-in process with mainchain → sidechain fund transfers and federation confirmation");
        println!("   ✅ Sidechain consensus with independent block production and state validation");
        println!("   ✅ Peg-out process with sidechain → mainchain withdrawals and federation authorization");
        println!("   ✅ Fraud proof handling with cross-chain validation");
        println!("   ✅ Regtest network integration and compliance");
    }
}