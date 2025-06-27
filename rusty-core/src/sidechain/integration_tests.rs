//! Integration tests for sidechain system

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::*;
    use rusty_shared_types::{Hash, Transaction, TxInput, TxOutput, OutPoint, MasternodeID};

    // Helper function to create a test hash
    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    // Helper function to create a test masternode ID
    fn test_masternode_id(value: u8) -> MasternodeID {
        MasternodeID([value; 32])
    }

    // Helper function to create a complete test sidechain setup
    fn create_test_sidechain_setup() -> SidechainState {
        let mut state = SidechainState::new();
        
        // Register a test sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![
                test_masternode_id(1),
                test_masternode_id(2),
                test_masternode_id(3),
            ],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 2,
        };
        
        state.register_sidechain(sidechain_info).unwrap();
        
        // Update federation
        let federation_members = vec![
            test_masternode_id(1),
            test_masternode_id(2),
            test_masternode_id(3),
        ];
        state.update_federation(1, federation_members).unwrap();
        
        state
    }

    // Helper function to create a test mainchain transaction
    fn create_test_mainchain_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                previous_output: OutPoint {
                    txid: test_hash(1),
                    vout: 0,
                },
                script_sig: vec![1, 2, 3],
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value: 5000000,
                script_pubkey: vec![4, 5, 6],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn test_complete_sidechain_setup() {
        let state = create_test_sidechain_setup();
        
        let stats = state.get_stats();
        assert_eq!(stats.registered_sidechains, 1);
        assert_eq!(stats.federation_epochs, 1);
        assert_eq!(stats.active_blocks, 0);
        assert_eq!(stats.pending_cross_chain_txs, 0);
        assert_eq!(stats.active_fraud_proofs, 0);
    }

    #[test]
    fn test_end_to_end_peg_in_flow() {
        let mut state = create_test_sidechain_setup();
        
        // Step 1: Initiate peg-in
        let mainchain_tx = create_test_mainchain_tx();
        let peg_id = state.initiate_peg_in(
            mainchain_tx,
            test_hash(100), // target_sidechain_id
            vec![10, 11, 12], // sidechain_recipient
            5000000, // amount
            test_hash(200), // asset_id
        ).unwrap();
        
        // Verify peg-in was created
        let status = state.get_peg_status(&peg_id);
        assert_eq!(status, Some(PegStatus::Initiated));
        
        // Step 2: Process confirmations
        state.process_peg_confirmations(10).unwrap();
        
        // Step 3: Add federation signatures
        let signature = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11100000], // 3 signers
            threshold: 2,
            epoch: 1,
            message_hash: peg_id,
        };
        
        state.add_peg_federation_signature(peg_id, signature).unwrap();
        
        // Verify final stats
        let stats = state.get_stats();
        assert!(stats.active_peg_ins > 0 || stats.completed_pegs > 0);
    }

    #[test]
    fn test_end_to_end_peg_out_flow() {
        let mut state = create_test_sidechain_setup();
        
        // Step 1: Create sidechain burn transaction
        let sidechain_tx = SidechainTransaction {
            version: 1,
            inputs: vec![SidechainTxInput {
                previous_output: SidechainOutPoint {
                    txid: test_hash(10),
                    vout: 0,
                },
                script_sig: vec![7, 8, 9],
                sequence: 0xffffffff,
            }],
            outputs: Vec::new(), // Burn transaction has no outputs
            lock_time: 0,
            vm_data: None,
            fee: 1000,
        };
        
        // Step 2: Initiate peg-out
        let peg_id = state.initiate_peg_out(
            sidechain_tx,
            test_hash(100), // source_sidechain_id
            vec![20, 21, 22], // mainchain_recipient
            3000000, // amount
            test_hash(200), // asset_id
        ).unwrap();
        
        // Verify peg-out was created
        let status = state.get_peg_status(&peg_id);
        assert_eq!(status, Some(PegStatus::Initiated));
        
        // Step 3: Process confirmations
        state.process_peg_confirmations(20).unwrap();
        
        // Verify stats
        let stats = state.get_stats();
        assert!(stats.active_peg_outs > 0 || stats.completed_pegs > 0);
    }

    #[test]
    fn test_cross_chain_transaction_validation_flow() {
        let mut state = create_test_sidechain_setup();
        
        // Create a cross-chain transaction
        let cross_chain_tx = CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            test_hash(1), // source_chain_id (mainchain)
            test_hash(100), // destination_chain_id (sidechain)
            5000000, // amount
            test_hash(200), // asset_id
            vec![30, 31, 32], // recipient_address
            vec![40, 41, 42], // data
        );
        
        // Validate the cross-chain transaction
        let validation_result = state.validate_cross_chain_proof(&cross_chain_tx);
        
        // Should fail due to missing federation signatures
        assert!(matches!(validation_result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_fraud_proof_submission_and_processing() {
        let mut state = create_test_sidechain_setup();
        
        // Create a fraud proof
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 100,
            fraud_tx_index: Some(5),
            evidence: FraudEvidence {
                pre_state: vec![1, 2, 3],
                post_state: vec![4, 5, 6],
                fraudulent_operation: vec![7, 8, 9],
                witness_data: vec![10, 11, 12],
                additional_evidence: std::collections::HashMap::new(),
            },
            challenger_address: vec![13, 14, 15],
            challenge_bond: 2000000,
            response_deadline: 200,
        };
        
        // Submit fraud proof
        let challenge_id = state.submit_fraud_proof(fraud_proof, 2000000).unwrap();
        
        // Verify challenge was created
        let status = state.get_fraud_proof_status(&challenge_id);
        assert_eq!(status, Some(FraudProofStatus::Pending));
        
        // Submit response
        let response = FraudProofResponse {
            responder_id: test_masternode_id(1),
            response_data: vec![20, 21, 22],
            counter_evidence: vec![23, 24, 25],
            signature: vec![26, 27, 28],
            timestamp: 1234567890,
        };
        
        state.submit_fraud_proof_response(challenge_id, response).unwrap();
        
        // Process challenges
        state.process_fraud_proof_challenges(150).unwrap();
        
        // Verify stats
        let fraud_stats = state.get_fraud_proof_stats();
        assert!(fraud_stats.total_challenges > 0);
    }

    #[test]
    fn test_sidechain_block_processing_flow() {
        let mut state = create_test_sidechain_setup();
        
        // Create a test sidechain block
        let header = SidechainBlockHeader::new(
            [0u8; 32], // previous_block_hash (genesis)
            test_hash(2), // merkle_root
            test_hash(3), // cross_chain_merkle_root
            test_hash(4), // state_root
            1, // height
            test_hash(100), // sidechain_id
            50, // mainchain_anchor_height
            test_hash(5), // mainchain_anchor_hash
            1, // federation_epoch
        );
        
        let transactions = vec![SidechainTransaction {
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
        }];
        
        let cross_chain_transactions = vec![CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            test_hash(1),
            test_hash(100),
            2000000,
            test_hash(200),
            vec![7, 8, 9],
            Vec::new(),
        )];
        
        let mut block = SidechainBlock::new(header.clone(), transactions, cross_chain_transactions);
        
        // Fix merkle roots
        block.header.merkle_root = block.calculate_merkle_root();
        block.header.cross_chain_merkle_root = block.calculate_cross_chain_merkle_root();
        
        // Add federation signature
        let federation_signature = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11100000], // 3 signers
            threshold: 2,
            epoch: 1,
            message_hash: block.header.hash(),
        };
        block.federation_signature = Some(federation_signature);
        
        // Process the block - this should fail due to missing federation signatures on cross-chain tx
        let result = state.process_sidechain_block(block);
        assert!(result.is_err()); // Expected to fail validation
    }

    #[test]
    fn test_multiple_sidechains_management() {
        let mut state = SidechainState::new();
        
        // Register multiple sidechains
        for i in 1..=3 {
            let sidechain_info = SidechainInfo {
                sidechain_id: test_hash(100 + i),
                name: format!("Test Sidechain {}", i),
                peg_address: vec![i, i+1, i+2, i+3],
                federation_members: vec![test_masternode_id(i)],
                current_epoch: 1,
                vm_type: VMType::EVM,
                genesis_block_hash: test_hash(101 + i),
                creation_timestamp: 1234567890,
                min_federation_threshold: 1,
            };
            
            state.register_sidechain(sidechain_info).unwrap();
        }
        
        // Update federation for each
        for i in 1..=3 {
            let members = vec![test_masternode_id(i)];
            state.update_federation(i as u64, members).unwrap();
        }
        
        let stats = state.get_stats();
        assert_eq!(stats.registered_sidechains, 3);
        assert_eq!(stats.federation_epochs, 3);
    }

    #[test]
    fn test_cross_chain_transaction_builder_integration() {
        let state = create_test_sidechain_setup();
        
        // Test peg-in transaction creation
        let peg_in = CrossChainTxBuilder::build_peg_in(
            test_hash(1), // mainchain_id
            test_hash(100), // sidechain_id
            5000000, // amount
            test_hash(200), // asset_id
            vec![1, 2, 3], // recipient
        );
        
        assert_eq!(peg_in.tx_type, CrossChainTxType::PegIn);
        assert_eq!(peg_in.amount, 5000000);
        
        // Test peg-out transaction creation
        let peg_out = CrossChainTxBuilder::build_peg_out(
            test_hash(100), // sidechain_id
            test_hash(1), // mainchain_id
            3000000, // amount
            test_hash(200), // asset_id
            vec![4, 5, 6], // recipient
        );
        
        assert_eq!(peg_out.tx_type, CrossChainTxType::PegOut);
        assert_eq!(peg_out.amount, 3000000);
        
        // Test inter-sidechain transaction creation
        let inter_sidechain = CrossChainTxBuilder::build_inter_sidechain(
            test_hash(100), // source_sidechain_id
            test_hash(101), // destination_sidechain_id
            2000000, // amount
            test_hash(200), // asset_id
            vec![7, 8, 9], // recipient
        ).unwrap();
        
        assert_eq!(inter_sidechain.tx_type, CrossChainTxType::SidechainToSidechain);
        assert_eq!(inter_sidechain.amount, 2000000);
    }

    #[test]
    fn test_comprehensive_statistics_tracking() {
        let mut state = create_test_sidechain_setup();
        
        // Perform various operations
        let mainchain_tx = create_test_mainchain_tx();
        let _peg_id = state.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        ).unwrap();
        
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 100,
            fraud_tx_index: Some(5),
            evidence: FraudEvidence {
                pre_state: vec![1, 2, 3],
                post_state: vec![4, 5, 6],
                fraudulent_operation: vec![7, 8, 9],
                witness_data: vec![10, 11, 12],
                additional_evidence: std::collections::HashMap::new(),
            },
            challenger_address: vec![13, 14, 15],
            challenge_bond: 2000000,
            response_deadline: 200,
        };
        
        let _challenge_id = state.submit_fraud_proof(fraud_proof, 2000000).unwrap();
        
        // Get comprehensive stats
        let stats = state.get_stats();
        let peg_stats = state.peg_manager.get_stats();
        let fraud_stats = state.get_fraud_proof_stats();
        let validation_stats = state.get_proof_validation_stats();
        
        // Verify all stats are tracked
        assert_eq!(stats.registered_sidechains, 1);
        assert_eq!(stats.federation_epochs, 1);
        assert!(stats.active_peg_ins > 0);
        assert!(fraud_stats.total_challenges > 0);
        assert_eq!(peg_stats.federation_size, 3);
        assert_eq!(validation_stats.total_validations, 0); // No validations performed yet
    }

    #[test]
    fn test_error_handling_and_validation() {
        let mut state = create_test_sidechain_setup();
        
        // Test invalid peg-in (amount too small)
        let mainchain_tx = create_test_mainchain_tx();
        let result = state.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            50, // Below minimum
            test_hash(200),
        );
        assert!(result.is_err());
        
        // Test invalid fraud proof (insufficient bond)
        let fraud_proof = FraudProof {
            fraud_type: FraudType::InvalidStateTransition,
            fraud_block_height: 100,
            fraud_tx_index: Some(5),
            evidence: FraudEvidence {
                pre_state: vec![1, 2, 3],
                post_state: vec![4, 5, 6],
                fraudulent_operation: vec![7, 8, 9],
                witness_data: vec![10, 11, 12],
                additional_evidence: std::collections::HashMap::new(),
            },
            challenger_address: vec![13, 14, 15],
            challenge_bond: 2000000,
            response_deadline: 200,
        };
        
        let result = state.submit_fraud_proof(fraud_proof, 500_000); // Below minimum
        assert!(result.is_err());
        
        // Test duplicate sidechain registration
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100), // Same as existing
            name: "Duplicate Sidechain".to_string(),
            peg_address: vec![5, 6, 7, 8],
            federation_members: vec![test_masternode_id(4)],
            current_epoch: 1,
            vm_type: VMType::WASM,
            genesis_block_hash: test_hash(102),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        let result = state.register_sidechain(sidechain_info);
        assert!(result.is_err());
    }
}
