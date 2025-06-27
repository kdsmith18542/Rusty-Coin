//! Unit tests for two-way peg functionality

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::two_way_peg::*;
    use rusty_shared_types::{Hash, Transaction, TxInput, TxOutput, OutPoint};

    // Helper function to create a test hash
    fn test_hash(value: u8) -> Hash {
        [value; 32]
    }

    // Helper function to create a test transaction
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

    // Helper function to create a test sidechain transaction
    fn create_test_sidechain_tx() -> crate::sidechain::SidechainTransaction {
        crate::sidechain::SidechainTransaction {
            version: 1,
            inputs: vec![crate::sidechain::SidechainTxInput {
                previous_output: crate::sidechain::SidechainOutPoint {
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
        }
    }

    #[test]
    fn test_two_way_peg_config_default() {
        let config = TwoWayPegConfig::default();
        
        assert_eq!(config.min_peg_in_confirmations, 6);
        assert_eq!(config.min_peg_out_confirmations, 12);
        assert_eq!(config.federation_threshold, 2);
        assert_eq!(config.min_peg_amount, 100_000);
        assert_eq!(config.max_peg_amount, 1_000_000_000_000);
        assert_eq!(config.peg_timeout_blocks, 1440);
        assert_eq!(config.peg_fee_rate, 1000);
    }

    #[test]
    fn test_two_way_peg_manager_creation() {
        let config = TwoWayPegConfig::default();
        let manager = TwoWayPegManager::new(config);
        
        let stats = manager.get_stats();
        assert_eq!(stats.active_peg_ins, 0);
        assert_eq!(stats.active_peg_outs, 0);
        assert_eq!(stats.completed_pegs, 0);
        assert_eq!(stats.federation_size, 0);
        assert_eq!(stats.current_block_height, 0);
    }

    #[test]
    fn test_peg_in_initiation() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let mainchain_tx = create_test_mainchain_tx();
        let target_sidechain_id = test_hash(100);
        let sidechain_recipient = vec![1, 2, 3, 4];
        let amount = 5000000;
        let asset_id = test_hash(200);
        
        let result = manager.initiate_peg_in(
            mainchain_tx,
            target_sidechain_id,
            sidechain_recipient,
            amount,
            asset_id,
        );
        
        assert!(result.is_ok());
        let peg_id = result.unwrap();
        assert_ne!(peg_id, [0u8; 32]);
        
        let stats = manager.get_stats();
        assert_eq!(stats.active_peg_ins, 1);
    }

    #[test]
    fn test_peg_in_validation() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let mainchain_tx = create_test_mainchain_tx();
        let target_sidechain_id = test_hash(100);
        let amount = 50; // Below minimum
        let asset_id = test_hash(200);
        
        // Test amount below minimum
        let result = manager.initiate_peg_in(
            mainchain_tx.clone(),
            target_sidechain_id,
            vec![1, 2, 3],
            amount,
            asset_id,
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
        
        // Test empty recipient
        let result2 = manager.initiate_peg_in(
            mainchain_tx,
            target_sidechain_id,
            Vec::new(), // Empty recipient
            5000000,
            asset_id,
        );
        
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_peg_out_initiation() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let sidechain_tx = create_test_sidechain_tx();
        let source_sidechain_id = test_hash(100);
        let mainchain_recipient = vec![5, 6, 7, 8];
        let amount = 3000000;
        let asset_id = test_hash(200);
        
        let result = manager.initiate_peg_out(
            sidechain_tx,
            source_sidechain_id,
            mainchain_recipient,
            amount,
            asset_id,
        );
        
        assert!(result.is_ok());
        let peg_id = result.unwrap();
        assert_ne!(peg_id, [0u8; 32]);
        
        let stats = manager.get_stats();
        assert_eq!(stats.active_peg_outs, 1);
    }

    #[test]
    fn test_peg_out_validation() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let sidechain_tx = create_test_sidechain_tx();
        let source_sidechain_id = test_hash(100);
        let amount = 50; // Below minimum
        let asset_id = test_hash(200);
        
        // Test amount below minimum
        let result = manager.initiate_peg_out(
            sidechain_tx.clone(),
            source_sidechain_id,
            vec![1, 2, 3],
            amount,
            asset_id,
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
        
        // Test empty recipient
        let result2 = manager.initiate_peg_out(
            sidechain_tx,
            source_sidechain_id,
            Vec::new(), // Empty recipient
            3000000,
            asset_id,
        );
        
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_peg_status_tracking() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let mainchain_tx = create_test_mainchain_tx();
        let peg_id = manager.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        ).unwrap();
        
        let status = manager.get_peg_status(&peg_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap(), PegStatus::Initiated);
        
        // Test non-existent peg
        let fake_peg_id = test_hash(255);
        let fake_status = manager.get_peg_status(&fake_peg_id);
        assert!(fake_status.is_none());
    }

    #[test]
    fn test_federation_update() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let members = vec![
            rusty_shared_types::MasternodeID([1u8; 32]),
            rusty_shared_types::MasternodeID([2u8; 32]),
            rusty_shared_types::MasternodeID([3u8; 32]),
        ];
        
        manager.update_federation(members.clone());
        
        let stats = manager.get_stats();
        assert_eq!(stats.federation_size, 3);
    }

    #[test]
    fn test_peg_confirmations_processing() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        // Initiate a peg-in
        let mainchain_tx = create_test_mainchain_tx();
        let peg_id = manager.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        ).unwrap();
        
        // Process confirmations - not enough yet
        assert!(manager.process_confirmations(5).is_ok());
        let status = manager.get_peg_status(&peg_id).unwrap();
        assert!(matches!(status, PegStatus::WaitingConfirmations { .. }));
        
        // Process confirmations - enough confirmations
        assert!(manager.process_confirmations(10).is_ok());
        let status = manager.get_peg_status(&peg_id).unwrap();
        assert!(matches!(status, PegStatus::WaitingFederationSignatures { .. }));
    }

    #[test]
    fn test_federation_signature_addition() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        // Initiate a peg-in
        let mainchain_tx = create_test_mainchain_tx();
        let peg_id = manager.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        ).unwrap();
        
        // Create a federation signature
        let signature = crate::sidechain::FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11000000], // 2 signers
            threshold: 2,
            epoch: 1,
            message_hash: peg_id,
        };
        
        let result = manager.add_federation_signature(peg_id, signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_peg_operation_record() {
        let record = PegOperationRecord {
            peg_id: test_hash(1),
            operation_type: PegOperationType::PegIn,
            amount: 5000000,
            asset_id: test_hash(2),
            completed_at: 1234567890,
            mainchain_tx_hash: test_hash(3),
            sidechain_tx_hash: Some(test_hash(4)),
        };
        
        assert_eq!(record.operation_type, PegOperationType::PegIn);
        assert_eq!(record.amount, 5000000);
        assert!(record.sidechain_tx_hash.is_some());
    }

    #[test]
    fn test_peg_status_variants() {
        let initiated = PegStatus::Initiated;
        let waiting_confirmations = PegStatus::WaitingConfirmations { current: 3, required: 6 };
        let waiting_signatures = PegStatus::WaitingFederationSignatures { received: 1, required: 2 };
        let completed = PegStatus::Completed;
        let failed = PegStatus::Failed { reason: "Test failure".to_string() };
        let timed_out = PegStatus::TimedOut;
        
        assert_eq!(initiated, PegStatus::Initiated);
        assert_ne!(waiting_confirmations, waiting_signatures);
        assert_ne!(completed, failed);
        assert_ne!(failed, timed_out);
    }

    #[test]
    fn test_peg_in_transaction_fields() {
        let mainchain_tx = create_test_mainchain_tx();
        let peg_in = PegInTransaction {
            peg_id: test_hash(1),
            mainchain_tx: mainchain_tx.clone(),
            target_sidechain_id: test_hash(2),
            sidechain_recipient: vec![1, 2, 3],
            amount: 5000000,
            asset_id: test_hash(3),
            mainchain_block_height: 100,
            inclusion_proof: crate::sidechain::CrossChainProof {
                merkle_proof: Vec::new(),
                block_header: Vec::new(),
                transaction_data: Vec::new(),
                tx_index: 0,
            },
            federation_signatures: Vec::new(),
            status: PegStatus::Initiated,
            created_at: 1234567890,
        };
        
        assert_eq!(peg_in.mainchain_tx, mainchain_tx);
        assert_eq!(peg_in.amount, 5000000);
        assert_eq!(peg_in.status, PegStatus::Initiated);
        assert!(peg_in.federation_signatures.is_empty());
    }

    #[test]
    fn test_peg_out_transaction_fields() {
        let sidechain_tx = create_test_sidechain_tx();
        let peg_out = PegOutTransaction {
            peg_id: test_hash(1),
            sidechain_tx: sidechain_tx.clone(),
            source_sidechain_id: test_hash(2),
            mainchain_recipient: vec![4, 5, 6],
            amount: 3000000,
            asset_id: test_hash(3),
            sidechain_block_height: 200,
            burn_proof: crate::sidechain::CrossChainProof {
                merkle_proof: Vec::new(),
                block_header: Vec::new(),
                transaction_data: Vec::new(),
                tx_index: 0,
            },
            federation_signatures: Vec::new(),
            mainchain_release_tx: None,
            status: PegStatus::Initiated,
            created_at: 1234567890,
        };
        
        assert_eq!(peg_out.sidechain_tx, sidechain_tx);
        assert_eq!(peg_out.amount, 3000000);
        assert_eq!(peg_out.status, PegStatus::Initiated);
        assert!(peg_out.mainchain_release_tx.is_none());
    }

    #[test]
    fn test_two_way_peg_stats() {
        let stats = TwoWayPegStats {
            active_peg_ins: 5,
            active_peg_outs: 3,
            completed_pegs: 10,
            federation_size: 7,
            current_block_height: 1000,
        };
        
        assert_eq!(stats.active_peg_ins, 5);
        assert_eq!(stats.active_peg_outs, 3);
        assert_eq!(stats.completed_pegs, 10);
        assert_eq!(stats.federation_size, 7);
        assert_eq!(stats.current_block_height, 1000);
    }

    #[test]
    fn test_duplicate_peg_prevention() {
        let mut manager = TwoWayPegManager::new(TwoWayPegConfig::default());
        
        let mainchain_tx = create_test_mainchain_tx();
        
        // First peg-in should succeed
        let result1 = manager.initiate_peg_in(
            mainchain_tx.clone(),
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        );
        assert!(result1.is_ok());
        
        // Duplicate peg-in should fail
        let result2 = manager.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        );
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_peg_amount_limits() {
        let mut config = TwoWayPegConfig::default();
        config.min_peg_amount = 1000;
        config.max_peg_amount = 10000;
        
        let mut manager = TwoWayPegManager::new(config);
        
        let mainchain_tx = create_test_mainchain_tx();
        
        // Amount too small
        let result1 = manager.initiate_peg_in(
            mainchain_tx.clone(),
            test_hash(100),
            vec![1, 2, 3],
            500, // Below minimum
            test_hash(200),
        );
        assert!(result1.is_err());
        
        // Amount too large
        let result2 = manager.initiate_peg_in(
            mainchain_tx.clone(),
            test_hash(100),
            vec![1, 2, 3],
            20000, // Above maximum
            test_hash(200),
        );
        assert!(result2.is_err());
        
        // Valid amount
        let result3 = manager.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000, // Within range
            test_hash(200),
        );
        assert!(result3.is_ok());
    }
}
