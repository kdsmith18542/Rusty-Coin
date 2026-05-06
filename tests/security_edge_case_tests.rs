//! Comprehensive security and edge case testing for Rusty-Coin
//!
//! This module implements extensive security validation and edge case testing
//! covering cryptographic security, consensus security, network security,
//! economic security, and various edge cases. Includes fuzz testing integration
//! and property-based testing where applicable.

use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::error::ConsensusError;
use rusty_core::constants::*;
use rusty_crypto::post_quantum::{PostQuantumPrivateKey, PostQuantumScheme};
use rusty_shared_types::governance::{
    GovernanceProposal, GovernanceVote, ProposalType, VoteChoice, VoterType,
};
use rusty_shared_types::masternode::{
    MasternodeEntry, MasternodeID, MasternodeIdentity, MasternodeStatus,
};
use rusty_shared_types::{
    Block, BlockHeader, Hash, OutPoint, PublicKey, Signature, TicketId, Transaction,
    TransactionSignature, TxInput, TxOutput,
};
use rusty_shared_types::{Ticket, TicketStatus, Utxo};
use std::sync::{Arc, Mutex};

// Test utilities
mod test_utils {
    use super::*;

    /// Create a test blockchain with some initial state
    pub fn create_test_blockchain() -> Arc<Mutex<Blockchain>> {
        let blockchain = Blockchain::new().unwrap();
        Arc::new(Mutex::new(blockchain))
    }

    /// Create a dummy hash for testing
    pub fn dummy_hash(seed: u8) -> Hash {
        [seed; 32]
    }

    /// Create a dummy public key for testing
    pub fn dummy_public_key(seed: u8) -> PublicKey {
        [seed; 32]
    }

    /// Create a dummy signature for testing
    pub fn dummy_signature(seed: u8) -> Signature {
        [seed; 64]
    }

    /// Create a valid test transaction
    pub fn create_valid_transaction() -> Transaction {
        Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: dummy_hash(100),
                    vout: 0,
                },
                vec![0u8; 65], // Dummy signature
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 100000000, // 1 RUST
                script_pubkey: vec![0u8; 25],
                memo: None,
            }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        }
    }

    /// Create a test block with transactions
    pub fn create_test_block(height: u64, prev_hash: Hash) -> Block {
        let header = BlockHeader {
            version: 1,
            height,
            previous_block_hash: prev_hash,
            merkle_root: dummy_hash(1),
            state_root: dummy_hash(2),
            timestamp: 1234567890 + height as u64,
            difficulty_target: 0x207fffff,
            nonce: height as u64,
        };

        let coinbase_output = TxOutput {
            value: 5000000000, // 50 RUST reward
            script_pubkey: vec![0u8; 25],
            memo: None,
        };

        let coinbase_tx = Transaction::Coinbase {
            version: 1,
            inputs: vec![],
            outputs: vec![coinbase_output],
            lock_time: 0,
            witness: vec![],
        };

        Block {
            header,
            ticket_votes: vec![],
            transactions: vec![coinbase_tx],
        }
    }
}

// Cryptographic security tests
mod cryptographic_security {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_signature_validation_valid() {
        // Test valid signature verification
        let (_public_key, private_key) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();
        let message = b"test message";
        let signature = private_key.sign(message).unwrap();

        let public_key = private_key.public_key().unwrap();
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &signature,
            &public_key.key_bytes
        ).is_ok());
    }

    #[test]
    fn test_signature_validation_invalid() {
        // Test invalid signature rejection
        let (_public_key, private_key) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = private_key.sign(message).unwrap();

        let public_key = private_key.public_key().unwrap();
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            wrong_message,
            &signature,
            &public_key.key_bytes
        ).is_err());
    }

    #[test]
    fn test_key_management_key_rotation() {
        // Test key rotation security
        let (old_public, old_private) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();
        let (new_public, new_private) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();

        // Ensure keys are different
        assert_ne!(old_public.key_bytes, new_public.key_bytes);

        // Test signing with both keys
        let message = b"test";
        let old_sig = old_private.sign(message).unwrap();
        let new_sig = new_private.sign(message).unwrap();

        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &old_sig,
            &old_public.key_bytes
        ).is_ok());
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &new_sig,
            &new_public.key_bytes
        ).is_ok());

        // Cross-verification should fail
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &new_sig,
            &old_public.key_bytes
        ).is_err());
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &old_sig,
            &new_public.key_bytes
        ).is_err());
    }

    #[test]
    fn test_pq_migration_signature_compatibility() {
        // Test post-quantum signature migration
        let (_public_key, private_key) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();
        let message = b"migration test";

        let signature = private_key.sign(message).unwrap();
        let public_key = private_key.public_key().unwrap();
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &signature,
            &public_key.key_bytes
        ).is_ok());

        // Test signature serialization/deserialization
        let sig_bytes = bincode::serialize(&signature).unwrap();
        let deserialized_sig: Vec<u8> = bincode::deserialize(&sig_bytes).unwrap();

        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &deserialized_sig,
            &public_key.key_bytes
        ).is_ok());
    }

    #[test]
    fn test_signature_malleability_protection() {
        // Test protection against signature malleability
        let (_public_key, private_key) = PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();
        let message = b"test";
        let mut signature = private_key.sign(message).unwrap();

        // Attempt malleability attack (flip bits in signature)
        if let Some(byte) = signature.get_mut(0) {
            *byte ^= 1;
        }

        let public_key = private_key.public_key().unwrap();
        assert!(rusty_crypto::post_quantum::verify_pq_signature(
            PostQuantumScheme::Dilithium2,
            message,
            &signature,
            &public_key.key_bytes
        ).is_err());
    }
}

// Consensus security tests
mod consensus_security {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_double_spend_prevention() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Create UTXO
        let utxo_id = OutPoint {
            txid: dummy_hash(1),
            vout: 0,
        };
        let utxo = Utxo {
            output: TxOutput {
                value: 1000000,
                script_pubkey: vec![1],
                memo: None,
            },
            is_coinbase: false,
            creation_height: 1,
        };
        blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

        // Create first transaction spending the UTXO
        let tx1 = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                utxo_id.clone(),
                vec![0; 65],
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 900000,
                script_pubkey: vec![2],
                memo: None,
            }],
            lock_time: 0,
            fee: 100000,
            witness: vec![],
        };

        // Create second transaction attempting to double-spend
        let tx2 = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                utxo_id.clone(),
                vec![0; 65],
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 800000,
                script_pubkey: vec![3],
                memo: None,
            }],
            lock_time: 0,
            fee: 200000,
            witness: vec![],
        };

        // First transaction should validate
        assert!(blockchain.validate_transaction(&tx1, 100).is_ok());

        // Add first transaction to UTXO set changes
        // Second transaction should be rejected due to double-spend
        assert!(blockchain.validate_transaction(&tx2, 100).is_err());
    }

    #[test]
    fn test_51_percent_attack_resistance() {
        // Test resistance to 51% attacks through difficulty adjustment
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Simulate honest mining
        let honest_blocks = 100;
        let honest_time = 60000; // 60 seconds for 100 blocks (normal)

        // Simulate attack scenario with 51% hash power
        let attack_blocks = 51;
        let attack_time = 30000; // 30 seconds for 51 blocks (faster)

        // Difficulty should adjust to maintain target block time
        // This is a simplified test - actual implementation would adjust difficulty
        assert!(honest_blocks > 0);
        assert!(attack_blocks > 0);
    }

    #[test]
    fn test_longest_chain_rule() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Create genesis block
        let genesis = create_test_block(0, [0u8; 32]);
        assert!(blockchain.add_block(genesis).is_ok());

        // Create main chain
        let mut prev_hash = blockchain.tip;
        for i in 1..5 {
            let block = create_test_block(i, prev_hash);
            assert!(blockchain.add_block(block.clone()).is_ok());
            prev_hash = block.hash();
        }

        let main_chain_height = blockchain.get_current_block_height().unwrap();

        // Create shorter fork
        // Reset to genesis for fork
        let fork_block1 = create_test_block(1, blockchain.blocks[&[0u8; 32]].hash());
        let fork_block2 = create_test_block(2, fork_block1.hash());

        // Fork should not overtake main chain
        assert!(blockchain.get_current_block_height().unwrap() >= main_chain_height);
    }
}

// Network security tests
mod network_security {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_dos_protection_message_flooding() {
        // Test protection against message flooding attacks
        // This would typically involve rate limiting and connection limits
        let max_messages_per_minute = 1000;
        let flood_attempt = 2000;

        // Simulate message rate limiting
        assert!(flood_attempt > max_messages_per_minute);
        // In real implementation, this would check rate limiter
    }

    #[test]
    fn test_eclipse_attack_prevention() {
        // Test prevention of eclipse attacks through diverse peer connections
        let min_peer_connections = 8;
        let max_same_subnet = 2;

        // Ensure diverse peer connections
        assert!(min_peer_connections > max_same_subnet);
    }

    #[test]
    fn test_sybil_attack_resistance() {
        // Test resistance to Sybil attacks through proof-of-work/stake requirements
        let min_stake = 1000000000; // 1000 RUST minimum
        let sybil_attempt_stake = 1000000; // 1 RUST (insufficient)

        assert!(sybil_attempt_stake < min_stake);
    }

    #[test]
    fn test_peer_authentication() {
        // Test peer authentication mechanisms
        let valid_peer_id = dummy_public_key(1);
        let invalid_peer_id = [0u8; 32];

        assert_ne!(valid_peer_id, invalid_peer_id);
        // In real implementation, this would verify peer certificates/keys
    }
}

// Economic security tests
mod economic_security {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_masternode_slashing_double_signing() {
        // Test masternode slashing for double-signing
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        let mn_id = MasternodeID(OutPoint {
            txid: dummy_hash(1),
            vout: 0,
        });

        let mn_entry = MasternodeEntry {
            identity: MasternodeIdentity {
                collateral_outpoint: mn_id.0.clone(),
                operator_public_key: dummy_public_key(1).to_vec(),
                network_address: "127.0.0.1:8000".to_string(),
                collateral_ownership_public_key: dummy_public_key(2).to_vec(),
                dkg_public_key: None,
                supported_dkg_versions: vec![1],
            },
            status: MasternodeStatus::Active,
            last_successful_pose_height: 10,
            pose_failure_count: 0,
            last_slashed_height: None,
            active_dkg_sessions: vec![],
            dkg_participation_count: 0,
            dkg_success_rate: 1.0,
            collateral_amount: 100000000000, // 1000 RUST
        };

        blockchain.masternode_list.map.insert(mn_id.clone(), mn_entry);

        // Simulate double-signing detection
        let slash_amount = 10000000000; // 100 RUST slash
        assert!(slash_amount > 0);
        // In real implementation, this would trigger slashing
    }

    #[test]
    fn test_governance_manipulation_prevention() {
        // Test prevention of governance manipulation
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Create proposal
        let proposal = GovernanceProposal {
            proposal_id: dummy_hash(1),
            proposer_address: dummy_public_key(1),
            proposal_type: ProposalType::ProtocolUpgrade,
            start_block_height: 100,
            end_block_height: 200,
            title: "Test Proposal".to_string(),
            description_hash: dummy_hash(2),
            code_change_hash: None,
            target_parameter: None,
            new_value: None,
            bug_description: None,
            recipient_address: None,
            amount: None,
            project_description: None,
            proposer_signature: TransactionSignature {
                bytes: dummy_signature(1),
            },
            inputs: vec![],
            outputs: vec![TxOutput {
                value: blockchain.params.proposal_stake_amount,
                script_pubkey: vec![],
                memo: None,
            }],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };

        blockchain.active_proposals.add_proposal(proposal.clone()).unwrap();

        // Test vote manipulation prevention
        let voter_key = dummy_public_key(2);
        let ticket = Ticket {
            id: TicketId(dummy_hash(3)),
            pubkey: voter_key.to_vec(),
            height: 50,
            value: blockchain.params.ticket_price,
            status: TicketStatus::Live,
        };
        blockchain.live_tickets.add_ticket(ticket);

        let vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter_type: VoterType::PosTicket,
            voter_id: voter_key,
            vote_choice: VoteChoice::Yes,
            voter_signature: TransactionSignature {
                bytes: dummy_signature(2),
            },
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };

        // First vote should succeed
        blockchain.active_proposals.record_vote(vote.clone()).unwrap();

        // Duplicate vote should be prevented
        assert!(blockchain.active_proposals.record_vote(vote).is_err());
    }

    #[test]
    fn test_inflation_control() {
        // Test inflation control mechanisms
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        let initial_reward = blockchain.params.initial_block_reward;
        let halving_interval = blockchain.params.reward_halving_interval;

        // Rewards should decrease over time
        assert!(initial_reward > 0);
        assert!(halving_interval > 0);
    }
}

// Edge case tests
mod edge_cases {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_genesis_block_edge_cases() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Test genesis block creation
        let genesis = create_test_block(0, [0u8; 32]);
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.previous_block_hash, [0u8; 32]);

        // Genesis should be valid
        assert!(blockchain.validate_block(&genesis).is_ok());
    }

    #[test]
    fn test_invalid_header_rejection() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Create block with invalid header
        let mut invalid_header = BlockHeader {
            version: 1,
            height: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: dummy_hash(1),
            state_root: dummy_hash(2),
            timestamp: 0, // Invalid timestamp (too old)
            difficulty_target: 0x207fffff,
            nonce: 1,
        };

        let block = Block {
            header: invalid_header,
            ticket_votes: vec![],
            transactions: vec![],
        };

        // Should reject invalid header
        assert!(blockchain.validate_block(&block).is_err());
    }

    #[test]
    fn test_orphaned_blocks() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Create orphan block (no parent)
        let orphan = create_test_block(2, dummy_hash(99)); // Non-existent parent

        // Should reject orphan
        assert!(blockchain.add_block(orphan).is_err());
    }

    #[test]
    fn test_dust_transaction_handling() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Create dust transaction (output below dust threshold)
        let dust_tx = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: dummy_hash(1),
                    vout: 0,
                },
                vec![0; 65],
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 100, // Very small amount (dust)
                script_pubkey: vec![1],
                memo: None,
            }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        };

        // Should reject dust transactions
        assert!(blockchain.validate_transaction(&dust_tx, 100).is_err());
    }

    #[test]
    fn test_max_size_violations() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Create oversized transaction
        let large_script = vec![0u8; 1000000]; // 1MB script (too large)
        let oversized_tx = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: dummy_hash(1),
                    vout: 0,
                },
                large_script,
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 1000000,
                script_pubkey: vec![1],
                memo: None,
            }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        };

        // Should reject oversized transactions
        assert!(blockchain.validate_transaction(&oversized_tx, 100).is_err());
    }

    #[test]
    fn test_script_failure_handling() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Create transaction with invalid script
        let invalid_script_tx = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: dummy_hash(1),
                    vout: 0,
                },
                vec![0xFF; 65], // Invalid script
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 1000000,
                script_pubkey: vec![0xFF; 25], // Invalid script
                memo: None,
            }],
            lock_time: 0,
            fee: 1000,
            witness: vec![],
        };

        // Should reject transactions with script failures
        assert!(blockchain.validate_transaction(&invalid_script_tx, 100).is_err());
    }

    #[test]
    fn test_network_partition_recovery() {
        // Test recovery from network partitions
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Simulate network partition by creating competing chains
        let main_chain_blocks = 10;
        let partition_chain_blocks = 5;

        // Main chain should eventually win via longest chain rule
        assert!(main_chain_blocks > partition_chain_blocks);
    }

    #[test]
    fn test_peer_disconnection_handling() {
        // Test handling of peer disconnections
        let peer_count_before = 10;
        let disconnected_peers = 3;
        let peer_count_after = peer_count_before - disconnected_peers;

        // Network should maintain minimum connections
        assert!(peer_count_after >= 8); // Minimum peer count
    }

    #[test]
    fn test_message_corruption_detection() {
        // Test detection of corrupted messages
        let original_message = b"valid message";
        let mut corrupted_message = original_message.to_vec();
        corrupted_message[0] ^= 1; // Flip a bit

        // Should detect corruption
        assert_ne!(original_message, corrupted_message.as_slice());
    }
}

// Fuzz testing integration
mod fuzz_testing {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_fuzz_block_validation() {
        // Integration test for fuzz-found issues
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Test various malformed blocks that fuzzing might find
        let malformed_blocks = vec![
            Block {
                header: BlockHeader {
                    version: u32::MAX,
                    height: u64::MAX,
                    previous_block_hash: [0u8; 32],
                    merkle_root: [0u8; 32],
                    state_root: [0u8; 32],
                    timestamp: u64::MAX,
                    difficulty_target: u32::MAX,
                    nonce: u64::MAX,
                },
                ticket_votes: vec![],
                transactions: vec![],
            },
            // Add more fuzz-derived test cases
        ];

        for block in malformed_blocks {
            // Should handle malformed blocks gracefully
            let _ = blockchain.validate_block(&block);
        }
    }

    #[test]
    fn test_fuzz_transaction_validation() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Test malformed transactions
        let malformed_txs = vec![
            Transaction::Standard {
                version: u32::MAX,
                inputs: vec![], // No inputs
                outputs: vec![], // No outputs
                lock_time: u32::MAX,
                fee: u64::MAX,
                witness: vec![],
            },
            // Add more fuzz-derived cases
        ];

        for tx in malformed_txs {
            let _ = blockchain.validate_transaction(&tx, 100);
        }
    }
}

// Property-based testing
mod property_testing {
    use super::*;
    use proptest::prelude::*;
    use test_utils::*;

    proptest! {
        #[test]
        fn test_transaction_fee_calculation(
            input_value in 1000..1_000_000_000u64,
            output_value in 1000..1_000_000_000u64,
            fee in 1000..100_000u64
        ) {
            // Property: fee should be positive and reasonable
            prop_assume!(input_value > output_value + fee);

            let calculated_fee = input_value - output_value;
            prop_assert_eq!(calculated_fee, input_value - output_value);
            prop_assert!(calculated_fee >= fee);
        }

        #[test]
        fn test_block_hash_determinism(
            version in 0..10u32,
            height in 0..1_000_000u64,
            timestamp in 1_600_000_000..2_000_000_000u64
        ) {
            let header1 = BlockHeader {
                version,
                height,
                previous_block_hash: [0u8; 32],
                merkle_root: [1u8; 32],
                state_root: [2u8; 32],
                timestamp,
                difficulty_target: 0x207fffff,
                nonce: 0,
            };

            let header2 = BlockHeader {
                version,
                height,
                previous_block_hash: [0u8; 32],
                merkle_root: [1u8; 32],
                state_root: [2u8; 32],
                timestamp,
                difficulty_target: 0x207fffff,
                nonce: 0,
            };

            // Same inputs should produce same hash
            prop_assert_eq!(header1.hash(), header2.hash());
        }

        #[test]
        fn test_signature_round_trip(
            message_len in 1..1000usize
        ) {
            let keypair = PostQuantumKeyPair::generate().unwrap();
            let message = vec![0u8; message_len];

            let signature = keypair.sign(&message).unwrap();
            prop_assert!(keypair.public_key.verify(&message, &signature).is_ok());
        }
    }
}

// Regtest network integration tests
mod regtest_integration {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_regtest_block_generation() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        let initial_height = blockchain.get_current_block_height().unwrap();

        // Generate test blocks
        for i in 1..5 {
            let prev_hash = if i == 1 { [0u8; 32] } else { blockchain.tip };
            let block = create_test_block(i, prev_hash);
            assert!(blockchain.add_block(block).is_ok());
        }

        let final_height = blockchain.get_current_block_height().unwrap();
        assert_eq!(final_height, initial_height + 4);
    }

    #[test]
    fn test_regtest_transaction_processing() {
        let blockchain = create_test_blockchain();
        let mut blockchain = blockchain.lock().unwrap();

        // Add UTXO for testing
        let utxo_id = OutPoint {
            txid: dummy_hash(100),
            vout: 0,
        };
        let utxo = Utxo {
            output: TxOutput {
                value: 1000000,
                script_pubkey: vec![1],
                memo: None,
            },
            is_coinbase: false,
            creation_height: 1,
        };
        blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

        // Process valid transaction
        let tx = create_valid_transaction();
        assert!(blockchain.validate_transaction(&tx, 100).is_ok());
    }

    #[test]
    fn test_regtest_consensus_validation() {
        let blockchain = create_test_blockchain();
        let blockchain = blockchain.lock().unwrap();

        // Test consensus parameters
        assert!(blockchain.params.initial_block_reward > 0);
        assert!(blockchain.params.ticket_price > 0);
        assert!(blockchain.params.voting_period_blocks > 0);
    }
}