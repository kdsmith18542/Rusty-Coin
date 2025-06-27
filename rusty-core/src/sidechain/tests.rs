//! Comprehensive unit tests for sidechain functionality

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::*;
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

    // Helper function to create a test sidechain block header
    fn create_test_header(height: u64, sidechain_id: Hash) -> SidechainBlockHeader {
        SidechainBlockHeader::new(
            test_hash(1), // previous_block_hash
            test_hash(2), // merkle_root
            test_hash(3), // cross_chain_merkle_root
            test_hash(4), // state_root
            height,
            sidechain_id,
            100, // mainchain_anchor_height
            test_hash(5), // mainchain_anchor_hash
            1, // federation_epoch
        )
    }

    // Helper function to create a test sidechain transaction
    fn create_test_transaction() -> SidechainTransaction {
        SidechainTransaction {
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
        }
    }

    // Helper function to create a test cross-chain transaction
    fn create_test_cross_chain_tx() -> CrossChainTransaction {
        CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            test_hash(30), // source_chain_id
            test_hash(31), // destination_chain_id
            5000000, // amount
            test_hash(32), // asset_id
            vec![7, 8, 9], // recipient_address
            vec![10, 11, 12], // data
        )
    }

    #[test]
    fn test_sidechain_block_creation() {
        let header = create_test_header(1, test_hash(100));
        let transactions = vec![create_test_transaction()];
        let cross_chain_transactions = vec![create_test_cross_chain_tx()];

        let block = SidechainBlock::new(header.clone(), transactions.clone(), cross_chain_transactions.clone());

        assert_eq!(block.header, header);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.cross_chain_transactions.len(), 1);
        assert!(block.fraud_proofs.is_empty());
        assert!(block.federation_signature.is_none());
    }

    #[test]
    fn test_sidechain_block_hash() {
        let header = create_test_header(1, test_hash(100));
        let block = SidechainBlock::new(header, Vec::new(), Vec::new());
        
        let hash1 = block.hash();
        let hash2 = block.hash();
        
        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_sidechain_block_merkle_root_calculation() {
        let header = create_test_header(1, test_hash(100));
        let transactions = vec![
            create_test_transaction(),
            create_test_transaction(),
        ];
        
        let block = SidechainBlock::new(header, transactions, Vec::new());
        let merkle_root = block.calculate_merkle_root();
        
        assert_ne!(merkle_root, [0u8; 32]);
        
        // Empty transactions should return zero hash
        let empty_block = SidechainBlock::new(create_test_header(1, test_hash(100)), Vec::new(), Vec::new());
        assert_eq!(empty_block.calculate_merkle_root(), [0u8; 32]);
    }

    #[test]
    fn test_sidechain_block_verification() {
        let mut header = create_test_header(1, test_hash(100));
        let transactions = vec![create_test_transaction()];
        let cross_chain_transactions = vec![create_test_cross_chain_tx()];
        
        // Set correct merkle roots
        let block = SidechainBlock::new(header.clone(), transactions.clone(), cross_chain_transactions.clone());
        header.merkle_root = block.calculate_merkle_root();
        header.cross_chain_merkle_root = block.calculate_cross_chain_merkle_root();
        
        let valid_block = SidechainBlock {
            header,
            transactions,
            cross_chain_transactions,
            fraud_proofs: Vec::new(),
            federation_signature: None,
        };
        
        assert!(valid_block.verify().is_ok());
    }

    #[test]
    fn test_sidechain_transaction_validation() {
        let tx = create_test_transaction();
        assert!(tx.verify().is_ok());
        
        // Test transaction with no inputs
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
        
        assert!(invalid_tx.verify().is_err());
    }

    #[test]
    fn test_cross_chain_transaction_creation() {
        let tx = create_test_cross_chain_tx();
        
        assert_eq!(tx.tx_type, CrossChainTxType::PegIn);
        assert_eq!(tx.amount, 5000000);
        assert!(!tx.recipient_address.is_empty());
        assert!(tx.federation_signatures.is_empty());
    }

    #[test]
    fn test_cross_chain_transaction_validation() {
        let tx = create_test_cross_chain_tx();
        
        // Should fail validation due to empty federation signatures
        assert!(tx.verify().is_err());
        
        // Test with zero amount
        let mut invalid_tx = tx.clone();
        invalid_tx.amount = 0;
        assert!(invalid_tx.verify().is_err());
        
        // Test with empty recipient
        let mut invalid_tx2 = tx.clone();
        invalid_tx2.recipient_address = Vec::new();
        assert!(invalid_tx2.verify().is_err());
    }

    #[test]
    fn test_cross_chain_tx_builder() {
        let peg_in = CrossChainTxBuilder::build_peg_in(
            test_hash(1), // mainchain_id
            test_hash(2), // sidechain_id
            1000000, // amount
            test_hash(3), // asset_id
            vec![1, 2, 3], // recipient
        );
        
        assert_eq!(peg_in.tx_type, CrossChainTxType::PegIn);
        assert_eq!(peg_in.source_chain_id, test_hash(1));
        assert_eq!(peg_in.destination_chain_id, test_hash(2));
        assert_eq!(peg_in.amount, 1000000);
        
        let peg_out = CrossChainTxBuilder::build_peg_out(
            test_hash(2), // sidechain_id
            test_hash(1), // mainchain_id
            2000000, // amount
            test_hash(3), // asset_id
            vec![4, 5, 6], // recipient
        );
        
        assert_eq!(peg_out.tx_type, CrossChainTxType::PegOut);
        assert_eq!(peg_out.source_chain_id, test_hash(2));
        assert_eq!(peg_out.destination_chain_id, test_hash(1));
        assert_eq!(peg_out.amount, 2000000);
    }

    #[test]
    fn test_cross_chain_tx_utils() {
        let transactions = vec![
            CrossChainTxBuilder::build_peg_in(test_hash(1), test_hash(2), 1000000, test_hash(3), vec![1]),
            CrossChainTxBuilder::build_peg_out(test_hash(2), test_hash(1), 2000000, test_hash(3), vec![2]),
            CrossChainTxBuilder::build_inter_sidechain(test_hash(4), test_hash(5), 3000000, test_hash(3), vec![3]).unwrap(),
        ];
        
        // Test batch value calculation
        let total_value = CrossChainTxUtils::calculate_batch_value(&transactions, &test_hash(3));
        assert_eq!(total_value, 6000000);
        
        // Test grouping by type
        let groups = CrossChainTxUtils::group_by_type(&transactions);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[&CrossChainTxType::PegIn].len(), 1);
        assert_eq!(groups[&CrossChainTxType::PegOut].len(), 1);
        assert_eq!(groups[&CrossChainTxType::SidechainToSidechain].len(), 1);
        
        // Test filtering by chain
        let chain_txs = CrossChainTxUtils::filter_by_chain(&transactions, &test_hash(1));
        assert_eq!(chain_txs.len(), 2); // peg_in and peg_out involve chain 1
    }

    #[test]
    fn test_sidechain_state_creation() {
        let state = SidechainState::new();
        
        assert!(state.registered_sidechains.is_empty());
        assert!(state.current_blocks.is_empty());
        assert!(state.pending_cross_chain_txs.is_empty());
        assert!(state.active_fraud_proofs.is_empty());
        assert!(state.federation_epochs.is_empty());
    }

    #[test]
    fn test_sidechain_registration() {
        let mut state = SidechainState::new();
        
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3],
            federation_members: vec![test_masternode_id(1), test_masternode_id(2)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 2,
        };
        
        // Register sidechain
        assert!(state.register_sidechain(sidechain_info.clone()).is_ok());
        assert_eq!(state.registered_sidechains.len(), 1);
        
        // Try to register duplicate
        assert!(state.register_sidechain(sidechain_info).is_err());
    }

    #[test]
    fn test_federation_update() {
        let mut state = SidechainState::new();
        
        let members = vec![test_masternode_id(1), test_masternode_id(2), test_masternode_id(3)];
        
        assert!(state.update_federation(1, members.clone()).is_ok());
        assert_eq!(state.federation_epochs.len(), 1);
        assert_eq!(state.get_federation_members(1), Some(&members));
        
        // Test empty federation
        assert!(state.update_federation(2, Vec::new()).is_err());
    }

    #[test]
    fn test_sidechain_stats() {
        let mut state = SidechainState::new();
        
        // Register a sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        state.register_sidechain(sidechain_info).unwrap();
        state.update_federation(1, vec![test_masternode_id(1)]).unwrap();
        
        let stats = state.get_stats();
        assert_eq!(stats.registered_sidechains, 1);
        assert_eq!(stats.federation_epochs, 1);
        assert_eq!(stats.active_blocks, 0);
    }

    #[test]
    fn test_vm_execution_data_validation() {
        let valid_vm_data = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: vec![1, 2, 3, 4],
            gas_limit: 1000000,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };
        
        assert!(valid_vm_data.verify().is_ok());
        
        // Test with empty bytecode
        let invalid_vm_data = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: Vec::new(),
            gas_limit: 1000000,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };
        
        assert!(invalid_vm_data.verify().is_err());
        
        // Test with zero gas limit
        let invalid_vm_data2 = VMExecutionData {
            vm_type: VMType::EVM,
            bytecode: vec![1, 2, 3, 4],
            gas_limit: 0,
            gas_price: 20,
            input_data: vec![5, 6, 7],
        };
        
        assert!(invalid_vm_data2.verify().is_err());
    }

    #[test]
    fn test_federation_signature() {
        let signature = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11110000], // 4 signers
            threshold: 3,
            epoch: 1,
            message_hash: test_hash(50),
        };
        
        assert_eq!(signature.count_signers(), 4);
        assert!(signature.verify(&test_hash(50)).is_ok());
        assert!(signature.verify(&test_hash(51)).is_err()); // Wrong message hash
    }

    #[test]
    fn test_fraud_proof_creation() {
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
            challenge_bond: 1000000,
            response_deadline: 200,
        };
        
        assert!(fraud_proof.verify().is_ok());
        assert_ne!(fraud_proof.hash(), [0u8; 32]);
    }

    #[test]
    fn test_cross_chain_proof_validation() {
        let proof = CrossChainProof {
            merkle_proof: vec![test_hash(1), test_hash(2)],
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };
        
        assert!(proof.verify().is_ok());
        
        // Test with empty merkle proof
        let invalid_proof = CrossChainProof {
            merkle_proof: Vec::new(),
            block_header: vec![1, 2, 3, 4],
            transaction_data: vec![5, 6, 7, 8],
            tx_index: 0,
        };
        
        assert!(invalid_proof.verify().is_err());
    }
}
