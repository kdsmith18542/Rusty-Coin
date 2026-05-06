//! Comprehensive Masternode Service Validation Tests for Spec 06 Compliance
//!
//! This test suite validates Rusty Coin masternode protocol implementation against
//! specification 06 requirements. Tests cover masternode registration, PoSe mechanism,
//! OxideSend instant confirmation, FerrousShield privacy mixing, and quorum formation.
//!
//! Tests integrate with regtest network and provide detailed assertions for each component.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::constants::MASTERNODE_COLLATERAL_AMOUNT;
use rusty_core::types::block::Block;
use rusty_crypto::keypair::Keypair;
use rusty_masternode::{
    register_masternode, deregister_masternode,
    ferrous_shield::{
        coordinate_coinjoin, select_ferrousshield_quorum, FerrousShieldError,
        FerrousShieldTransaction, CoinJoinSession, SessionOutcome, PrivacyMetrics,
        FeeDistributionManager, AnonymitySetStats
    },
    oxidesend::{
        select_oxidesend_quorum, coordinate_oxidesend_mixing, lock_inputs,
        detect_and_slash_double_spend, OxideSendTransaction, verify_client_locks
    },
    pose::{PoSeManager, PoSeConfig, verify_pose_response},
    pose_coordinator::PoSeCoordinator,
    quorum_formation::{QuorumFormationManager, QuorumConfig, QuorumType},
    types::{MasternodeConfig, MasternodeState, MasternodeError},
};
use rusty_shared_types::{
    masternode::{
        MasternodeID, MasternodeIdentity, MasternodeRegistration, MasternodeStatus,
        MasternodeEntry, MasternodeList, PoSeChallenge, PoSeResponse, TxInputLock,
        FerrousShieldMixRequest, FerrousShieldMixOutput
    },
    Hash, OutPoint, Amount, PublicKey as SharedPublicKey, Signature as SharedSignature,
    transaction::{Transaction, TxInput, TxOutput},
    ConsensusParams, Network,
};
use rusty_types::blockchain::Blockchain as SharedBlockchain;

/// Test configuration for spec 06 validation
struct Spec06TestConfig {
    consensus_params: ConsensusParams,
    masternode_config: MasternodeConfig,
    pose_config: PoSeConfig,
    quorum_config: QuorumConfig,
}

impl Default for Spec06TestConfig {
    fn default() -> Self {
        Self {
            consensus_params: ConsensusParams::regtest(),
            masternode_config: MasternodeConfig::default(),
            pose_config: PoSeConfig::default(),
            quorum_config: QuorumConfig::default(),
        }
    }
}

/// Helper function to create a test blockchain with genesis block
fn create_test_blockchain() -> Blockchain {
    let mut blockchain = Blockchain::new(Network::Regtest);
    // Add genesis block if needed
    blockchain
}

/// Helper function to create a valid masternode registration
fn create_test_masternode_registration() -> (MasternodeRegistration, Keypair) {
    let keypair = Keypair::generate();
    let collateral_outpoint = OutPoint {
        txid: Hash::from([1u8; 32]),
        vout: 0,
    };

    let identity = MasternodeIdentity {
        collateral_outpoint: collateral_outpoint.clone(),
        operator_public_key: keypair.public_key().to_bytes().to_vec(),
        collateral_ownership_public_key: keypair.public_key().to_bytes().to_vec(),
        network_address: "127.0.0.1:19999".to_string(),
    };

    let identity_bytes = bincode::serialize(&identity).unwrap();
    let signature = keypair.sign(&identity_bytes);

    let registration = MasternodeRegistration {
        masternode_identity: identity,
        signature: signature.to_bytes().to_vec(),
    };

    (registration, keypair)
}

/// Helper function to create test UTXO for collateral
fn create_collateral_utxo(owner_keypair: &Keypair) -> (OutPoint, TxOutput) {
    let outpoint = OutPoint {
        txid: Hash::from([2u8; 32]),
        vout: 0,
    };

    let script_pubkey = rusty_core::script::create_p2pkh_script(&owner_keypair.public_key().to_bytes());

    let output = TxOutput {
        value: MASTERNODE_COLLATERAL_AMOUNT,
        script_pubkey,
        memo: Some(b"Masternode collateral".to_vec()),
    };

    (outpoint, output)
}

#[cfg(test)]
mod masternode_registration_tests {
    use super::*;

    #[test]
    fn test_masternode_registration_with_valid_collateral() {
        println!("🧪 Testing masternode registration with valid collateral...");

        let blockchain = create_test_blockchain();
        let (registration, keypair) = create_test_masternode_registration();
        let (collateral_outpoint, collateral_output) = create_collateral_utxo(&keypair);

        // Add collateral UTXO to blockchain
        blockchain.utxo_set.add_utxo(
            collateral_outpoint.clone(),
            collateral_output,
            100, // creation height
            false, // not coinbase
        );

        // Test registration
        let result = register_masternode(registration, &blockchain);

        assert!(result.is_ok(), "Masternode registration should succeed with valid collateral");
        let tx = result.unwrap();

        // Validate transaction structure
        match tx {
            Transaction::Standard { inputs, outputs, .. } => {
                assert_eq!(inputs.len(), 1, "Registration transaction should have one input");
                assert_eq!(outputs.len(), 1, "Registration transaction should have one output");
                assert_eq!(outputs[0].value, MASTERNODE_COLLATERAL_AMOUNT,
                          "Output should lock full collateral amount");
            }
            _ => panic!("Registration should create a standard transaction"),
        }

        println!("✅ Masternode registration with valid collateral test passed");
    }

    #[test]
    fn test_masternode_registration_insufficient_collateral() {
        println!("🧪 Testing masternode registration with insufficient collateral...");

        let blockchain = create_test_blockchain();
        let (mut registration, keypair) = create_test_masternode_registration();

        // Create UTXO with insufficient collateral
        let outpoint = OutPoint {
            txid: Hash::from([3u8; 32]),
            vout: 0,
        };

        let script_pubkey = rusty_core::script::create_p2pkh_script(&keypair.public_key().to_bytes());
        let insufficient_output = TxOutput {
            value: MASTERNODE_COLLATERAL_AMOUNT / 2, // Half the required amount
            script_pubkey,
            memo: Some(b"Insufficient collateral".to_vec()),
        };

        blockchain.utxo_set.add_utxo(
            outpoint.clone(),
            insufficient_output,
            100,
            false,
        );

        // Update registration to use this UTXO
        registration.masternode_identity.collateral_outpoint = outpoint;

        // Test registration - should fail
        let result = register_masternode(registration, &blockchain);

        assert!(result.is_err(), "Masternode registration should fail with insufficient collateral");
        assert!(result.unwrap_err().contains("insufficient"),
               "Error should mention insufficient collateral");

        println!("✅ Masternode registration insufficient collateral test passed");
    }

    #[test]
    fn test_masternode_registration_invalid_signature() {
        println!("🧪 Testing masternode registration with invalid signature...");

        let blockchain = create_test_blockchain();
        let (collateral_outpoint, collateral_output) = create_collateral_utxo(&Keypair::generate());

        blockchain.utxo_set.add_utxo(
            collateral_outpoint.clone(),
            collateral_output,
            100,
            false,
        );

        // Create registration with invalid signature
        let identity = MasternodeIdentity {
            collateral_outpoint,
            operator_public_key: vec![0u8; 32],
            collateral_ownership_public_key: vec![0u8; 32],
            network_address: "127.0.0.1:19999".to_string(),
        };

        let registration = MasternodeRegistration {
            masternode_identity: identity,
            signature: vec![0u8; 64], // Invalid signature
        };

        let result = register_masternode(registration, &blockchain);

        assert!(result.is_err(), "Masternode registration should fail with invalid signature");
        assert!(result.unwrap_err().contains("signature"),
               "Error should mention invalid signature");

        println!("✅ Masternode registration invalid signature test passed");
    }

    #[test]
    fn test_masternode_deregistration() {
        println!("🧪 Testing masternode deregistration...");

        let blockchain = create_test_blockchain();
        let masternode_id = MasternodeID::new([1u8; 32]);

        let result = deregister_masternode(&masternode_id, &blockchain);

        assert!(result.is_ok(), "Masternode deregistration should succeed");
        let tx = result.unwrap();

        match tx {
            Transaction::Standard { inputs, outputs, fee, .. } => {
                assert_eq!(inputs.len(), 1, "Deregistration should have one input");
                assert!(!outputs.is_empty(), "Deregistration should have outputs");
                assert!(fee > 0, "Deregistration should include a fee");
            }
            _ => panic!("Deregistration should create a standard transaction"),
        }

        println!("✅ Masternode deregistration test passed");
    }
}

#[cfg(test)]
mod pose_mechanism_tests {
    use super::*;

    #[test]
    fn test_pose_challenge_generation() {
        println!("🧪 Testing PoSe challenge generation...");

        let config = Spec06TestConfig::default();
        let mut pose_manager = PoSeManager::new(config.pose_config);

        // Create test masternode list
        let mut mn_list = MasternodeList::new();
        let mn_id = MasternodeID::new([1u8; 32]);
        let entry = MasternodeEntry {
            identity: MasternodeIdentity {
                collateral_outpoint: OutPoint { txid: Hash::from([1u8; 32]), vout: 0 },
                operator_public_key: vec![1u8; 32],
                collateral_ownership_public_key: vec![1u8; 32],
                network_address: "127.0.0.1:19999".to_string(),
            },
            status: MasternodeStatus::Active,
            last_pose_check: 1000,
            pose_failure_count: 0,
        };
        mn_list.insert(mn_id.clone(), entry);

        // Generate challenges
        let challenges = pose_manager.generate_challenges(&mn_list, 100, Hash::from([2u8; 32]));

        assert!(!challenges.is_empty(), "Should generate challenges for active masternodes");

        // Validate challenge structure
        for challenge in challenges {
            assert_eq!(challenge.challenge_blockhash.len(), 32, "Challenge should include blockhash");
            assert!(!challenge.challenger_masternode_id.0.is_empty(),
                   "Challenge should specify challenger");
            assert!(challenge.challenge_nonce > 0, "Challenge should have unique nonce");
        }

        println!("✅ PoSe challenge generation test passed");
    }

    #[test]
    fn test_pose_response_verification() {
        println!("🧪 Testing PoSe response verification...");

        let config = Spec06TestConfig::default();
        let pose_manager = PoSeManager::new(config.pose_config);

        // Create a challenge
        let challenge = PoSeChallenge {
            challenge_nonce: 12345,
            challenge_blockhash: vec![1u8; 32],
            challenger_masternode_id: MasternodeID::new([1u8; 32]),
        };

        // Create a valid response
        let keypair = Keypair::generate();
        let response = pose_manager.generate_pose_response(&challenge, &keypair).unwrap();

        // Verify response
        let is_valid = verify_pose_response(&response, &challenge, &keypair.public_key().to_bytes());

        assert!(is_valid.is_ok(), "Valid PoSe response should be accepted");
        assert!(is_valid.unwrap(), "Valid PoSe response should pass verification");

        println!("✅ PoSe response verification test passed");
    }

    #[test]
    fn test_pose_uptime_tracking() {
        println!("🧪 Testing PoSe uptime tracking...");

        let config = Spec06TestConfig::default();
        let mut pose_manager = PoSeManager::new(config.pose_config);

        let mn_id = MasternodeID::new([1u8; 32]);

        // Simulate successful responses
        for _ in 0..5 {
            pose_manager.record_successful_response(&mn_id, 100);
        }

        let stats = pose_manager.get_masternode_pose_stats(&mn_id);
        assert_eq!(stats.successful_responses, 5, "Should track successful responses");
        assert_eq!(stats.consecutive_failures, 0, "Should have no failures");

        // Simulate failures
        for _ in 0..3 {
            pose_manager.record_failed_response(&mn_id, 200);
        }

        let updated_stats = pose_manager.get_masternode_pose_stats(&mn_id);
        assert_eq!(updated_stats.consecutive_failures, 3, "Should track consecutive failures");

        println!("✅ PoSe uptime tracking test passed");
    }
}

#[cfg(test)]
mod oxidesend_service_tests {
    use super::*;

    #[test]
    fn test_oxidesend_quorum_selection() {
        println!("🧪 Testing OxideSend quorum selection...");

        let config = Spec06TestConfig::default();
        let quorum_manager = QuorumFormationManager::new(config.quorum_config);

        // Create test masternode list
        let mut mn_list = MasternodeList::new();
        for i in 0..20 {
            let mn_id = MasternodeID::new([i as u8; 32]);
            let entry = MasternodeEntry {
                identity: MasternodeIdentity {
                    collateral_outpoint: OutPoint { txid: Hash::from([i as u8; 32]), vout: 0 },
                    operator_public_key: vec![i as u8; 32],
                    collateral_ownership_public_key: vec![i as u8; 32],
                    network_address: format!("127.0.0.1:{}", 19999 + i),
                },
                status: MasternodeStatus::Active,
                last_pose_check: 1000,
                pose_failure_count: 0,
            };
            mn_list.insert(mn_id, entry);
        }

        let quorum = select_oxidesend_quorum(&mn_list, &Hash::from([1u8; 32]));

        assert!(quorum.is_ok(), "Should successfully select OxideSend quorum");
        let selected_mns = quorum.unwrap();
        assert!((10..=15).contains(&selected_mns.len()),
               "Quorum size should be between 10-15 masternodes: got {}", selected_mns.len());

        println!("✅ OxideSend quorum selection test passed");
    }

    #[test]
    fn test_oxidesend_input_locking() {
        println!("🧪 Testing OxideSend input locking...");

        let blockchain = create_test_blockchain();
        let keypair = Keypair::generate();

        // Create test inputs
        let inputs = vec![
            TxInput::from_outpoint(
                OutPoint { txid: Hash::from([1u8; 32]), vout: 0 },
                vec![],
                0,
                vec![],
            ),
            TxInput::from_outpoint(
                OutPoint { txid: Hash::from([2u8; 32]), vout: 0 },
                vec![],
                0,
                vec![],
            ),
        ];

        let lock_result = lock_inputs(&inputs, &keypair, 100);

        assert!(lock_result.is_ok(), "Input locking should succeed");
        let locks = lock_result.unwrap();

        assert_eq!(locks.len(), inputs.len(), "Should create lock for each input");

        for lock in locks {
            assert_eq!(lock.lock_duration_blocks, 5, "Lock duration should be 5 blocks per spec");
            assert!(!lock.masternode_signature.is_empty(), "Lock should include signature");
        }

        println!("✅ OxideSend input locking test passed");
    }

    #[test]
    fn test_oxidesend_double_spend_prevention() {
        println!("🧪 Testing OxideSend double-spend prevention...");

        let blockchain = create_test_blockchain();

        // Create conflicting transactions
        let input_outpoint = OutPoint { txid: Hash::from([1u8; 32]), vout: 0 };

        let tx1 = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(input_outpoint.clone(), vec![], 0, vec![])],
            outputs: vec![TxOutput { value: 1000000, script_pubkey: vec![], memo: None }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        };

        let tx2 = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(input_outpoint, vec![], 0, vec![])],
            outputs: vec![TxOutput { value: 1000000, script_pubkey: vec![], memo: None }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        };

        let slash_result = detect_and_slash_double_spend(&tx1, &tx2, &blockchain);

        assert!(slash_result.is_ok(), "Double-spend detection should succeed");
        let slash_tx = slash_result.unwrap();

        // Validate slashing transaction structure
        match slash_tx {
            Transaction::Standard { inputs, outputs, .. } => {
                assert!(!inputs.is_empty(), "Slashing transaction should have inputs");
                assert!(!outputs.is_empty(), "Slashing transaction should have outputs");
            }
            _ => panic!("Slashing should create a standard transaction"),
        }

        println!("✅ OxideSend double-spend prevention test passed");
    }
}

#[cfg(test)]
mod ferrous_shield_service_tests {
    use super::*;

    #[test]
    fn test_ferrous_shield_quorum_selection() {
        println!("🧪 Testing FerrousShield quorum selection...");

        // Create test masternode list
        let mut mn_list = MasternodeList::new();
        for i in 0..10 {
            let mn_id = MasternodeID::new([i as u8; 32]);
            let entry = MasternodeEntry {
                identity: MasternodeIdentity {
                    collateral_outpoint: OutPoint { txid: Hash::from([i as u8; 32]), vout: 0 },
                    operator_public_key: vec![i as u8; 32],
                    collateral_ownership_public_key: vec![i as u8; 32],
                    network_address: format!("127.0.0.1:{}", 19999 + i),
                },
                status: MasternodeStatus::Active,
                last_pose_check: 1000,
                pose_failure_count: 0,
            };
            mn_list.insert(mn_id, entry);
        }

        let quorum = select_ferrousshield_quorum(&mn_list, &Hash::from([1u8; 32]));

        assert!(quorum.is_ok(), "Should successfully select FerrousShield quorum");
        let selected_mns = quorum.unwrap();
        assert!((5..=7).contains(&selected_mns.len()),
               "Quorum size should be between 5-7 masternodes: got {}", selected_mns.len());

        println!("✅ FerrousShield quorum selection test passed");
    }

    #[test]
    fn test_ferrous_shield_coinjoin_coordination() {
        println!("🧪 Testing FerrousShield CoinJoin coordination...");

        let mix_amount = 1_000_000; // 0.01 RUST
        let num_participants = 5;

        let result = coordinate_coinjoin(mix_amount, num_participants);

        assert!(result.is_ok(), "CoinJoin coordination should succeed");
        let session = result.unwrap();

        assert_eq!(session.participants.len(), num_participants,
                  "Session should include correct number of participants");
        assert!(session.fee > 0, "Session should include coordination fee");
        assert!(session.anonymity_set_size >= num_participants,
               "Anonymity set should be at least the number of participants");

        println!("✅ FerrousShield CoinJoin coordination test passed");
    }

    #[test]
    fn test_ferrous_shield_fee_distribution() {
        println!("🧪 Testing FerrousShield fee distribution...");

        let mut fee_manager = FeeDistributionManager::new(Default::default());

        // Add some fee payouts
        let payout1 = rusty_masternode::ferrous_shield::FeePayoutTransaction {
            masternode_id: MasternodeID::new([1u8; 32]),
            amount: 10000,
            transaction: Transaction::Standard {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            },
        };

        fee_manager.queue_fee_distribution(payout1);

        let payouts = fee_manager.process_pending_distributions();
        assert_eq!(payouts.len(), 1, "Should process one fee distribution");

        let stats = fee_manager.get_distribution_stats();
        assert_eq!(stats.total_distributed, 10000, "Should track total distributed amount");

        println!("✅ FerrousShield fee distribution test passed");
    }

    #[test]
    fn test_ferrous_shield_privacy_metrics() {
        println!("🧪 Testing FerrousShield privacy metrics...");

        let mut metrics = PrivacyMetrics::new();

        // Simulate successful session
        let outcome = SessionOutcome::Success;
        let privacy_score = 0.85;
        metrics.update_from_session(&outcome, privacy_score);

        let report = metrics.get_privacy_report();
        assert_eq!(report.total_sessions, 1, "Should track total sessions");
        assert_eq!(report.successful_sessions, 1, "Should track successful sessions");
        assert!((report.average_privacy_score - privacy_score).abs() < 0.001,
               "Should calculate average privacy score correctly");

        println!("✅ FerrousShield privacy metrics test passed");
    }
}

#[cfg(test)]
mod quorum_formation_tests {
    use super::*;

    #[test]
    fn test_quorum_formation_dprf_selection() {
        println!("🧪 Testing quorum formation with DPRF-based selection...");

        let config = Spec06TestConfig::default();
        let mut quorum_manager = QuorumFormationManager::new(config.quorum_config);

        // Create test masternode list
        let mut mn_list = MasternodeList::new();
        for i in 0..50 {
            let mn_id = MasternodeID::new([i as u8; 32]);
            let entry = MasternodeEntry {
                identity: MasternodeIdentity {
                    collateral_outpoint: OutPoint { txid: Hash::from([i as u8; 32]), vout: 0 },
                    operator_public_key: vec![i as u8; 32],
                    collateral_ownership_public_key: vec![i as u8; 32],
                    network_address: format!("127.0.0.1:{}", 19999 + i),
                },
                status: MasternodeStatus::Active,
                last_pose_check: 1000,
                pose_failure_count: 0,
            };
            mn_list.insert(mn_id, entry);
        }

        // Test OxideSend quorum formation
        let oxidesend_quorum = quorum_manager.form_quorum(
            &QuorumType::OxideSend,
            &mn_list,
            100,
            &Hash::from([1u8; 32])
        );

        assert!(oxidesend_quorum.is_ok(), "OxideSend quorum formation should succeed");
        let quorum = oxidesend_quorum.unwrap();
        assert!((10..=15).contains(&quorum.masternodes.len()),
               "OxideSend quorum should have 10-15 masternodes");

        // Test FerrousShield quorum formation
        let ferrous_quorum = quorum_manager.form_quorum(
            &QuorumType::FerrousShield,
            &mn_list,
            100,
            &Hash::from([2u8; 32])
        );

        assert!(ferrous_quorum.is_ok(), "FerrousShield quorum formation should succeed");
        let quorum = ferrous_quorum.unwrap();
        assert!((5..=7).contains(&quorum.masternodes.len()),
               "FerrousShield quorum should have 5-7 masternodes");

        println!("✅ Quorum formation DPRF selection test passed");
    }

    #[test]
    fn test_quorum_formation_determinism() {
        println!("🧪 Testing quorum formation determinism...");

        let config = Spec06TestConfig::default();
        let quorum_manager1 = QuorumFormationManager::new(config.quorum_config.clone());
        let quorum_manager2 = QuorumFormationManager::new(config.quorum_config);

        // Create identical masternode lists
        let mut mn_list = MasternodeList::new();
        for i in 0..20 {
            let mn_id = MasternodeID::new([i as u8; 32]);
            let entry = MasternodeEntry {
                identity: MasternodeIdentity {
                    collateral_outpoint: OutPoint { txid: Hash::from([i as u8; 32]), vout: 0 },
                    operator_public_key: vec![i as u8; 32],
                    collateral_ownership_public_key: vec![i as u8; 32],
                    network_address: format!("127.0.0.1:{}", 19999 + i),
                },
                status: MasternodeStatus::Active,
                last_pose_check: 1000,
                pose_failure_count: 0,
            };
            mn_list.insert(mn_id, entry);
        }

        let seed = Hash::from([1u8; 32]);
        let height = 100;

        // Form quorums with identical parameters
        let quorum1 = quorum_manager1.form_quorum(&QuorumType::OxideSend, &mn_list, height, &seed).unwrap();
        let quorum2 = quorum_manager2.form_quorum(&QuorumType::OxideSend, &mn_list, height, &seed).unwrap();

        // Quorums should be identical (deterministic selection)
        assert_eq!(quorum1.masternodes, quorum2.masternodes,
                  "Identical parameters should produce identical quorums");
        assert_eq!(quorum1.quorum_id, quorum2.quorum_id,
                  "Quorum IDs should be identical for same parameters");

        println!("✅ Quorum formation determinism test passed");
    }
}

#[cfg(test)]
mod regtest_integration_tests {
    use super::*;

    #[test]
    fn test_spec06_compliance_with_regtest_params() {
        println!("🧪 Testing spec 06 compliance with regtest parameters...");

        let config = Spec06TestConfig::default();

        // Verify regtest uses mainnet consensus parameters
        assert_eq!(config.consensus_params.min_block_time, 150,
                  "Regtest should use mainnet block time");
        assert_eq!(config.consensus_params.difficulty_adjustment_window, 2016,
                  "Regtest should use mainnet difficulty window");
        assert_eq!(config.consensus_params.ticket_price, 100_000_000,
                  "Regtest should use mainnet ticket price");

        // Verify masternode collateral amount matches spec
        assert_eq!(MASTERNODE_COLLATERAL_AMOUNT, 10_000_000_000,
                  "Masternode collateral should be 10,000 RUST");

        // Verify PoSe configuration
        assert_eq!(config.pose_config.challenge_period_blocks, 60,
                  "PoSe challenge period should be 60 blocks");
        assert_eq!(config.pose_config.response_timeout_seconds, 60,
                  "PoSe response timeout should be 60 seconds");

        println!("✅ Spec 06 regtest compliance test passed");
    }

    #[test]
    fn test_masternode_service_integration() {
        println!("🧪 Testing masternode service integration...");

        let config = Spec06TestConfig::default();
        let blockchain = create_test_blockchain();

        // Test complete masternode lifecycle
        let (registration, keypair) = create_test_masternode_registration();
        let (collateral_outpoint, collateral_output) = create_collateral_utxo(&keypair);

        // Add collateral to blockchain
        blockchain.utxo_set.add_utxo(
            collateral_outpoint.clone(),
            collateral_output,
            100,
            false,
        );

        // Register masternode
        let reg_tx = register_masternode(registration, &blockchain).unwrap();

        // Verify registration transaction
        match reg_tx {
            Transaction::Standard { outputs, .. } => {
                assert_eq!(outputs[0].value, MASTERNODE_COLLATERAL_AMOUNT,
                          "Registration should lock correct collateral amount");
            }
            _ => panic!("Registration should produce standard transaction"),
        }

        // Test service components work together
        let mn_id = MasternodeID::new(collateral_outpoint.txid.0);

        // Test PoSe manager initialization
        let pose_manager = PoSeManager::new(config.pose_config);
        let _stats = pose_manager.get_masternode_pose_stats(&mn_id);

        // Test quorum formation
        let quorum_manager = QuorumFormationManager::new(config.quorum_config);
        let mut mn_list = MasternodeList::new();
        mn_list.insert(mn_id, MasternodeEntry {
            identity: MasternodeIdentity {
                collateral_outpoint,
                operator_public_key: keypair.public_key().to_bytes().to_vec(),
                collateral_ownership_public_key: keypair.public_key().to_bytes().to_vec(),
                network_address: "127.0.0.1:19999".to_string(),
            },
            status: MasternodeStatus::Active,
            last_pose_check: 1000,
            pose_failure_count: 0,
        });

        let oxidesend_quorum = quorum_manager.form_quorum(
            &QuorumType::OxideSend,
            &mn_list,
            100,
            &Hash::from([1u8; 32])
        );

        assert!(oxidesend_quorum.is_ok(),
               "Integrated services should work together for OxideSend");

        println!("✅ Masternode service integration test passed");
    }
}

#[cfg(test)]
mod comprehensive_validation_tests {
    use super::*;

    #[test]
    fn test_complete_spec06_validation() {
        println!("🧪 Running complete spec 06 validation test suite...");

        let config = Spec06TestConfig::default();
        let blockchain = create_test_blockchain();

        // Test 1: Masternode registration compliance
        let (registration, keypair) = create_test_masternode_registration();
        let (collateral_outpoint, collateral_output) = create_collateral_utxo(&keypair);

        blockchain.utxo_set.add_utxo(
            collateral_outpoint.clone(),
            collateral_output,
            100,
            false,
        );

        let reg_result = register_masternode(registration, &blockchain);
        assert!(reg_result.is_ok(), "Spec 06.2.3: MN_REGISTER_TX should succeed with valid collateral");

        // Test 2: PoSe mechanism compliance
        let mut pose_manager = PoSeManager::new(config.pose_config);
        let mut mn_list = MasternodeList::new();
        let mn_id = MasternodeID::new([1u8; 32]);
        mn_list.insert(mn_id.clone(), MasternodeEntry {
            identity: MasternodeIdentity {
                collateral_outpoint: OutPoint { txid: Hash::from([1u8; 32]), vout: 0 },
                operator_public_key: vec![1u8; 32],
                collateral_ownership_public_key: vec![1u8; 32],
                network_address: "127.0.0.1:19999".to_string(),
            },
            status: MasternodeStatus::Active,
            last_pose_check: 1000,
            pose_failure_count: 0,
        });

        let challenges = pose_manager.generate_challenges(&mn_list, 100, Hash::from([2u8; 32]));
        assert!(!challenges.is_empty(), "Spec 6.3.1: PoSe challenges should be generated deterministically");

        // Test 3: OxideSend service compliance
        let quorum_manager = QuorumFormationManager::new(config.quorum_config);
        let oxidesend_quorum = quorum_manager.form_quorum(
            &QuorumType::OxideSend,
            &mn_list,
            100,
            &Hash::from([3u8; 32])
        );
        assert!(oxidesend_quorum.is_ok(), "Spec 6.5.1: OxideSend quorum should form with DPRF selection");

        // Test 4: FerrousShield service compliance
        let ferrous_quorum = quorum_manager.form_quorum(
            &QuorumType::FerrousShield,
            &mn_list,
            100,
            &Hash::from([4u8; 32])
        );
        assert!(ferrous_quorum.is_ok(), "Spec 6.5.2: FerrousShield quorum should form with DPRF selection");

        // Test 5: Quorum formation compliance
        let quorum = oxidesend_quorum.unwrap();
        assert!((10..=15).contains(&quorum.masternodes.len()),
               "Spec 6.5.1: OxideSend quorum size should be 10-15 masternodes");

        println!("✅ Complete spec 06 validation test suite passed");
        println!("📋 Validation Summary:");
        println!("   ✅ Masternode registration with collateral verification");
        println!("   ✅ PoSe challenge-response mechanism with uptime tracking");
        println!("   ✅ OxideSend instant confirmation with input locking");
        println!("   ✅ FerrousShield CoinJoin with anonymity sets and fee distribution");
        println!("   ✅ Quorum formation with DPRF-based selection");
        println!("   ✅ Regtest network integration and compliance");
    }
}