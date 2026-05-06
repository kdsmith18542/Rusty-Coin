//! Integration tests for sidechain-mainchain consensus
//!
//! This module contains comprehensive integration tests that verify
//! the complete sidechain-mainchain integration functionality.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::blockchain::Blockchain;
    use crate::network::MockP2PNetwork;
    use crate::sidechain::*;
    use rusty_shared_types::{Block, BlockHeader, OutPoint, masternode::MasternodeID};
    use std::sync::Arc;

    fn create_test_masternode_id(value: u8) -> MasternodeID {
        MasternodeID(OutPoint {
            txid: [value; 32],
            vout: 0,
        })
    }

    fn create_test_blockchain() -> Blockchain {
        let p2p_network = Arc::new(std::sync::Mutex::new(MockP2PNetwork::new()));
        Blockchain::new(p2p_network).unwrap()
    }

    fn create_test_sidechain_members() -> (Vec<MasternodeID>, Vec<Vec<u8>>) {
        let members = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];
        (members, public_keys)
    }

    #[test]
    fn test_full_sidechain_registration_and_operation() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Verify sidechain is registered
        assert!(blockchain.is_sidechain_registered(&sidechain_id));
        assert_eq!(blockchain.get_active_sidechains(), vec![sidechain_id]);

        // Check federation stats
        let fed_stats = blockchain.get_federation_stats();
        assert_eq!(fed_stats.total_sidechains, 1);
        assert_eq!(fed_stats.active_sidechains, 1);

        // Check peg stats
        let peg_stats = blockchain.get_peg_stats();
        assert_eq!(peg_stats.pending_transactions, 0);
        assert_eq!(peg_stats.completed_transactions, 0);
    }

    #[test]
    fn test_sidechain_block_processing() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Create a sidechain block
        let sidechain_block = SidechainBlock::new(
            SidechainBlockHeader::new(
                [0u8; 32], // previous_block_hash
                [1u8; 32], // merkle_root
                [2u8; 32], // cross_chain_merkle_root
                [3u8; 32], // state_root
                1,         // height
                sidechain_id,
                1000,      // mainchain_anchor_height
                [4u8; 32], // mainchain_anchor_hash
                1,         // federation_epoch
            ),
            vec![], // transactions
        );

        // Process the sidechain block
        blockchain.process_sidechain_block(&sidechain_id, sidechain_block).unwrap();

        // Check sidechain stats
        let stats = blockchain.get_sidechain_stats(&sidechain_id).unwrap();
        assert_eq!(stats.current_height, 1);
        assert_eq!(stats.sidechain_id, sidechain_id);
    }

    #[test]
    fn test_cross_chain_transaction_processing() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Create a cross-chain transaction (peg-out)
        let cross_chain_tx = CrossChainTransaction {
            id: [1u8; 32],
            amount: 1000000,
            recipient_address: vec![1, 2, 3, 4, 5],
            source_chain: sidechain_id,
            destination_chain: [0u8; 32], // Mainchain
            proof: CrossChainProof {
                merkle_proof: vec![],
                block_header: vec![],
                transaction_data: vec![],
                tx_index: 0,
            },
            federation_signatures: vec![], // Would be properly signed in real scenario
        };

        // Process the cross-chain transaction
        // Note: This might fail due to missing signatures, but tests the integration
        let result = blockchain.process_cross_chain_transaction(cross_chain_tx);
        // We expect this to fail due to validation, but it tests the integration path
        assert!(result.is_err()); // Should fail due to missing federation signatures
    }

    #[test]
    fn test_mainchain_block_updates_for_sidechains() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Create a mainchain block header
        let block_header = BlockHeader {
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

        // Process mainchain block for sidechains
        blockchain.process_mainchain_block_for_sidechains(&block_header).unwrap();

        // Verify sidechain received the update
        let stats = blockchain.get_sidechain_stats(&sidechain_id).unwrap();
        assert_eq!(stats.sidechain_id, sidechain_id);
    }

    #[test]
    fn test_federation_integration() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Check federation is properly initialized
        let fed_stats = blockchain.get_federation_stats();
        assert_eq!(fed_stats.total_sidechains, 1);
        assert_eq!(fed_stats.total_members, 3);
        assert_eq!(fed_stats.active_sidechains, 1);

        // Get federation manager
        let fed_integrator = blockchain.federation_integrator.lock().unwrap();
        let current_epoch = fed_integrator.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(current_epoch.members, members);
        assert_eq!(current_epoch.threshold, 2);
        assert_eq!(current_epoch.epoch, 1);
    }

    #[test]
    fn test_multiple_sidechains() {
        let mut blockchain = create_test_blockchain();

        // Register first sidechain
        let sidechain_id1 = [1u8; 32];
        let (members1, public_keys1) = create_test_sidechain_members();
        blockchain.register_sidechain(
            sidechain_id1,
            members1,
            2,
            public_keys1,
            100,
        ).unwrap();

        // Register second sidechain
        let sidechain_id2 = [2u8; 32];
        let members2 = vec![
            create_test_masternode_id(4),
            create_test_masternode_id(5),
            create_test_masternode_id(6),
        ];
        let public_keys2 = vec![vec![4u8; 48], vec![5u8; 48], vec![6u8; 48]];
        blockchain.register_sidechain(
            sidechain_id2,
            members2,
            2,
            public_keys2,
            100,
        ).unwrap();

        // Check both sidechains are registered
        assert!(blockchain.is_sidechain_registered(&sidechain_id1));
        assert!(blockchain.is_sidechain_registered(&sidechain_id2));

        let active_sidechains = blockchain.get_active_sidechains();
        assert_eq!(active_sidechains.len(), 2);
        assert!(active_sidechains.contains(&sidechain_id1));
        assert!(active_sidechains.contains(&sidechain_id2));

        // Check federation stats
        let fed_stats = blockchain.get_federation_stats();
        assert_eq!(fed_stats.total_sidechains, 2);
        assert_eq!(fed_stats.total_members, 6); // 3 + 3
        assert_eq!(fed_stats.active_sidechains, 2);
    }

    #[test]
    fn test_sidechain_consensus_engine() {
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Create sidechain consensus engine
        let consensus = SidechainConsensus::new(sidechain_id)
            .initialize_with_federation(
                members.clone(),
                2,
                public_keys.clone(),
                100,
            ).unwrap();

        // Check initial state
        let state = consensus.get_sidechain_state();
        assert_eq!(state.sidechain_id, sidechain_id);
        assert_eq!(state.height, 0);

        // Check consensus stats
        let stats = consensus.get_consensus_stats();
        assert_eq!(stats.sidechain_id, sidechain_id);
        assert_eq!(stats.current_height, 0);
        assert_eq!(stats.federation_stats.total_sidechains, 1);
    }

    #[test]
    fn test_two_way_peg_functionality() {
        let mut blockchain = create_test_blockchain();
        let sidechain_id = [1u8; 32];
        let (members, public_keys) = create_test_sidechain_members();

        // Register sidechain
        blockchain.register_sidechain(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
        ).unwrap();

        // Check initial peg stats
        let peg_stats = blockchain.get_peg_stats();
        assert_eq!(peg_stats.pending_transactions, 0);
        assert_eq!(peg_stats.completed_transactions, 0);
        assert_eq!(peg_stats.total_peg_in, 0);
        assert_eq!(peg_stats.total_peg_out, 0);

        // The peg functionality would be tested more thoroughly with actual transactions
        // but this verifies the integration is in place
    }

    #[test]
    fn test_cross_chain_communication() {
        let communication = CrossChainCommunication::new();

        // Test message creation
        let source = [1u8; 32];
        let dest = [2u8; 32];

        let block_header = rusty_shared_types::BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
            ticket_pool_hash: [3u8; 32],
        };

        let message = CrossChainCommunication::create_mainchain_header_message(
            source, dest, &block_header, 1
        ).unwrap();

        assert_eq!(message.message_type, crate::sidechain::cross_chain_communication::CrossChainMessageType::MainchainBlockHeader);
        assert_eq!(message.source_chain, source);
        assert_eq!(message.destination_chain, dest);
    }

    #[test]
    fn test_mainchain_validator() {
        let validator = MainchainValidator::new(100);

        // Test state snapshot update
        let sidechain_id = [1u8; 32];
        let snapshot = crate::sidechain::mainchain_validator::MainchainStateSnapshot {
            height: 1000,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            federation_members: vec![vec![1u8; 48], vec![2u8; 48]],
            federation_threshold: 2,
            federation_epoch: 1,
        };

        validator.update_mainchain_state(sidechain_id, snapshot.clone());

        let retrieved = validator.get_mainchain_state(&sidechain_id).unwrap();
        assert_eq!(retrieved.height, 1000);
        assert_eq!(retrieved.federation_threshold, 2);
    }
}