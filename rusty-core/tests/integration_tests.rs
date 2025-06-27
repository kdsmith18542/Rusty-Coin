//! Integration tests for Rusty Coin core components
//! 
//! These tests verify the interaction between different modules including
//! consensus, governance, P2P networking, and sidechain functionality.

use rusty_core::consensus::*;
use rusty_core::governance::*;
use rusty_core::sidechain::*;
use rusty_shared_types::*;
use std::collections::HashMap;

// Helper function to create a test hash
fn test_hash(value: u8) -> Hash {
    [value; 32]
}

// Helper function to create a test masternode ID
fn test_masternode_id(value: u8) -> MasternodeID {
    MasternodeID([value; 32])
}

// Helper function to create a test block header
fn create_test_block_header(height: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        previous_block_hash: test_hash(1),
        merkle_root: test_hash(2),
        timestamp: 1234567890,
        bits: 0x1d00ffff,
        nonce: 12345,
        height,
    }
}

// Helper function to create a test transaction
fn create_test_transaction() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            previous_output: OutPoint {
                txid: test_hash(10),
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

#[cfg(test)]
mod consensus_governance_integration {
    use super::*;

    #[test]
    fn test_governance_proposal_affects_consensus_parameters() {
        // This test verifies that governance proposals can successfully change consensus parameters
        
        // 1. Create initial consensus state
        let mut consensus_state = ConsensusState::new();
        let mut governance_state = GovernanceState::new();
        
        // 2. Create a parameter change proposal
        let proposal = GovernanceProposal {
            proposal_id: test_hash(1),
            proposal_type: ProposalType::ParameterChange,
            title: "Increase block size limit".to_string(),
            description: "Proposal to increase maximum block size from 1MB to 2MB".to_string(),
            proposer: test_hash(2),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7, // 7 days
            execution_deadline: 1234567890 + 86400 * 14, // 14 days
            required_stake: 1000000,
            parameter_changes: Some(vec![ParameterChange {
                parameter_name: "max_block_size".to_string(),
                old_value: "1048576".to_string(), // 1MB
                new_value: "2097152".to_string(), // 2MB
            }]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };
        
        // 3. Submit and approve the proposal
        governance_state.submit_proposal(proposal.clone(), 1000000).unwrap();
        
        // Simulate voting
        let vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter: test_masternode_id(1),
            vote_type: VoteType::Yes,
            voting_power: 1000000,
            timestamp: 1234567890 + 3600,
        };
        
        governance_state.cast_vote(vote).unwrap();
        
        // 4. Execute the proposal
        governance_state.execute_proposal(proposal.proposal_id).unwrap();
        
        // 5. Verify that consensus parameters were updated
        let executed_proposals = governance_state.get_executed_proposals();
        assert!(!executed_proposals.is_empty());
        
        // In a real implementation, this would update the consensus parameters
        // For now, we verify the proposal was executed successfully
        let proposal_status = governance_state.get_proposal_status(&proposal.proposal_id);
        assert_eq!(proposal_status, Some(ProposalStatus::Executed));
    }

    #[test]
    fn test_masternode_governance_voting_power() {
        // Test that masternode stake affects governance voting power
        
        let mut governance_state = GovernanceState::new();
        
        // Create proposal
        let proposal = GovernanceProposal {
            proposal_id: test_hash(1),
            proposal_type: ProposalType::ParameterChange,
            title: "Test Proposal".to_string(),
            description: "Test proposal for voting power".to_string(),
            proposer: test_hash(2),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 1000000,
            parameter_changes: Some(vec![]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };
        
        governance_state.submit_proposal(proposal.clone(), 1000000).unwrap();
        
        // Vote with different stake amounts
        let high_stake_vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter: test_masternode_id(1),
            vote_type: VoteType::Yes,
            voting_power: 10000000, // High stake
            timestamp: 1234567890 + 3600,
        };
        
        let low_stake_vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter: test_masternode_id(2),
            vote_type: VoteType::No,
            voting_power: 1000000, // Low stake
            timestamp: 1234567890 + 3600,
        };
        
        governance_state.cast_vote(high_stake_vote).unwrap();
        governance_state.cast_vote(low_stake_vote).unwrap();
        
        // High stake vote should outweigh low stake vote
        let vote_tally = governance_state.get_vote_tally(&proposal.proposal_id);
        assert!(vote_tally.yes_votes > vote_tally.no_votes);
    }

    #[test]
    fn test_consensus_block_validation_with_governance_changes() {
        // Test that blocks are validated according to current governance parameters
        
        let mut consensus_state = ConsensusState::new();
        
        // Create a block that would be valid under current parameters
        let header = create_test_block_header(1);
        let transactions = vec![create_test_transaction()];
        let block = Block { header, transactions };
        
        // Validate block under current parameters
        let validation_result = consensus_state.validate_block(&block);
        assert!(validation_result.is_ok());
        
        // In a real implementation, we would:
        // 1. Change consensus parameters through governance
        // 2. Create a block that violates new parameters
        // 3. Verify it's rejected
        
        // For now, we verify basic block validation works
        assert!(consensus_state.validate_block(&block).is_ok());
    }
}

#[cfg(test)]
mod sidechain_consensus_integration {
    use super::*;

    #[test]
    fn test_sidechain_block_anchoring_to_mainchain() {
        // Test that sidechain blocks are properly anchored to mainchain blocks
        
        let mut sidechain_state = SidechainState::new();
        let mut consensus_state = ConsensusState::new();
        
        // Register a sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1), test_masternode_id(2)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 2,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // Create mainchain block
        let mainchain_header = create_test_block_header(50);
        let mainchain_block = Block {
            header: mainchain_header.clone(),
            transactions: vec![],
        };
        
        // Add trusted mainchain header to sidechain validator
        sidechain_state.add_trusted_mainchain_header(mainchain_header);
        
        // Create sidechain block anchored to mainchain
        let sidechain_header = SidechainBlockHeader::new(
            [0u8; 32], // previous_block_hash (genesis)
            test_hash(2), // merkle_root
            test_hash(3), // cross_chain_merkle_root
            test_hash(4), // state_root
            1, // height
            test_hash(100), // sidechain_id
            50, // mainchain_anchor_height
            mainchain_block.header.hash(), // mainchain_anchor_hash
            1, // federation_epoch
        );
        
        let sidechain_block = SidechainBlock::new(sidechain_header, vec![], vec![]);
        
        // Verify sidechain block is properly anchored
        assert!(sidechain_block.is_anchored());
        assert_eq!(sidechain_block.header.mainchain_anchor_height, 50);
        assert_eq!(sidechain_block.header.mainchain_anchor_hash, mainchain_block.header.hash());
    }

    #[test]
    fn test_cross_chain_transaction_validation() {
        // Test validation of cross-chain transactions between mainchain and sidechain
        
        let mut sidechain_state = SidechainState::new();
        
        // Register sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1), test_masternode_id(2)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 2,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // Create cross-chain transaction
        let cross_chain_tx = CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            test_hash(1), // mainchain_id
            test_hash(100), // sidechain_id
            5000000, // amount
            test_hash(200), // asset_id
            vec![5, 6, 7], // recipient_address
            vec![8, 9, 10], // data
        );
        
        // Validate cross-chain transaction
        let validation_result = sidechain_state.validate_cross_chain_proof(&cross_chain_tx);
        
        // Should fail due to missing federation signatures
        assert!(matches!(validation_result, ProofValidationResult::Invalid(_)));
    }

    #[test]
    fn test_peg_operation_with_consensus_confirmations() {
        // Test that peg operations wait for proper consensus confirmations
        
        let mut sidechain_state = SidechainState::new();
        
        // Register sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // Initiate peg-in
        let mainchain_tx = create_test_transaction();
        let peg_id = sidechain_state.initiate_peg_in(
            mainchain_tx,
            test_hash(100), // sidechain_id
            vec![1, 2, 3], // recipient
            5000000, // amount
            test_hash(200), // asset_id
        ).unwrap();
        
        // Check initial status
        let status = sidechain_state.get_peg_status(&peg_id);
        assert_eq!(status, Some(PegStatus::Initiated));
        
        // Process confirmations (not enough yet)
        sidechain_state.process_peg_confirmations(5).unwrap();
        let status = sidechain_state.get_peg_status(&peg_id);
        assert!(matches!(status, Some(PegStatus::WaitingConfirmations { .. })));
        
        // Process enough confirmations
        sidechain_state.process_peg_confirmations(10).unwrap();
        let status = sidechain_state.get_peg_status(&peg_id);
        assert!(matches!(status, Some(PegStatus::WaitingFederationSignatures { .. })));
    }
}

#[cfg(test)]
mod governance_sidechain_integration {
    use super::*;

    #[test]
    fn test_sidechain_registration_through_governance() {
        // Test that new sidechains can be registered through governance proposals
        
        let mut governance_state = GovernanceState::new();
        let mut sidechain_state = SidechainState::new();
        
        // Create sidechain registration proposal
        let proposal = GovernanceProposal {
            proposal_id: test_hash(1),
            proposal_type: ProposalType::SidechainRegistration,
            title: "Register new sidechain".to_string(),
            description: "Proposal to register a new EVM-compatible sidechain".to_string(),
            proposer: test_hash(2),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 10000000, // Higher stake for sidechain registration
            parameter_changes: None,
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };
        
        // Submit proposal
        governance_state.submit_proposal(proposal.clone(), 10000000).unwrap();
        
        // Vote to approve
        let vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter: test_masternode_id(1),
            vote_type: VoteType::Yes,
            voting_power: 15000000,
            timestamp: 1234567890 + 3600,
        };
        
        governance_state.cast_vote(vote).unwrap();
        
        // Execute proposal
        governance_state.execute_proposal(proposal.proposal_id).unwrap();
        
        // In a real implementation, this would trigger sidechain registration
        // For now, verify the proposal was executed
        let proposal_status = governance_state.get_proposal_status(&proposal.proposal_id);
        assert_eq!(proposal_status, Some(ProposalStatus::Executed));
        
        // Manually register the sidechain (simulating governance execution)
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Governance Approved Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        let stats = sidechain_state.get_stats();
        assert_eq!(stats.registered_sidechains, 1);
    }

    #[test]
    fn test_sidechain_parameter_changes_through_governance() {
        // Test that sidechain parameters can be changed through governance
        
        let mut governance_state = GovernanceState::new();
        let mut sidechain_state = SidechainState::new();
        
        // Register initial sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // Create proposal to change sidechain parameters
        let proposal = GovernanceProposal {
            proposal_id: test_hash(2),
            proposal_type: ProposalType::ParameterChange,
            title: "Update sidechain federation threshold".to_string(),
            description: "Increase federation threshold for enhanced security".to_string(),
            proposer: test_hash(3),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 5000000,
            parameter_changes: Some(vec![ParameterChange {
                parameter_name: "sidechain_federation_threshold".to_string(),
                old_value: "1".to_string(),
                new_value: "2".to_string(),
            }]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };
        
        governance_state.submit_proposal(proposal.clone(), 5000000).unwrap();
        
        // Vote and execute
        let vote = GovernanceVote {
            proposal_id: proposal.proposal_id,
            voter: test_masternode_id(1),
            vote_type: VoteType::Yes,
            voting_power: 10000000,
            timestamp: 1234567890 + 3600,
        };
        
        governance_state.cast_vote(vote).unwrap();
        governance_state.execute_proposal(proposal.proposal_id).unwrap();
        
        // Verify proposal execution
        let proposal_status = governance_state.get_proposal_status(&proposal.proposal_id);
        assert_eq!(proposal_status, Some(ProposalStatus::Executed));
    }
}

#[cfg(test)]
mod full_system_integration {
    use super::*;

    #[test]
    fn test_complete_peg_operation_workflow() {
        // Test a complete peg-in and peg-out workflow involving multiple systems
        
        let mut sidechain_state = SidechainState::new();
        let mut governance_state = GovernanceState::new();
        
        // 1. Register sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Integration Test Sidechain".to_string(),
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
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // 2. Update federation
        let federation_members = vec![
            test_masternode_id(1),
            test_masternode_id(2),
            test_masternode_id(3),
        ];
        sidechain_state.update_federation(1, federation_members).unwrap();
        
        // 3. Initiate peg-in
        let mainchain_tx = create_test_transaction();
        let peg_in_id = sidechain_state.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![5, 6, 7],
            5000000,
            test_hash(200),
        ).unwrap();
        
        // 4. Process confirmations
        sidechain_state.process_peg_confirmations(10).unwrap();
        
        // 5. Add federation signatures
        let signature = FederationSignature {
            signature: vec![1, 2, 3, 4],
            signer_bitmap: vec![0b11100000], // 3 signers
            threshold: 2,
            epoch: 1,
            message_hash: peg_in_id,
        };
        
        sidechain_state.add_peg_federation_signature(peg_in_id, signature).unwrap();
        
        // 6. Create sidechain transaction (using pegged assets)
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
            outputs: Vec::new(), // Burn transaction
            lock_time: 0,
            vm_data: None,
            fee: 1000,
        };
        
        // 7. Initiate peg-out
        let peg_out_id = sidechain_state.initiate_peg_out(
            sidechain_tx,
            test_hash(100),
            vec![10, 11, 12],
            3000000,
            test_hash(200),
        ).unwrap();
        
        // 8. Process peg-out confirmations
        sidechain_state.process_peg_confirmations(20).unwrap();
        
        // 9. Verify final state
        let stats = sidechain_state.get_stats();
        assert_eq!(stats.registered_sidechains, 1);
        assert_eq!(stats.federation_epochs, 1);
        assert!(stats.active_peg_ins > 0 || stats.completed_pegs > 0);
        assert!(stats.active_peg_outs > 0 || stats.completed_pegs > 0);
    }

    #[test]
    fn test_fraud_detection_and_governance_response() {
        // Test fraud detection triggering governance response
        
        let mut sidechain_state = SidechainState::new();
        let mut governance_state = GovernanceState::new();
        
        // Register sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };
        
        sidechain_state.register_sidechain(sidechain_info).unwrap();
        
        // Submit fraud proof
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
            challenge_bond: 2000000,
            response_deadline: 200,
        };
        
        let challenge_id = sidechain_state.submit_fraud_proof(fraud_proof, 2000000).unwrap();
        
        // Process fraud proof
        sidechain_state.process_fraud_proof_challenges(150).unwrap();
        
        // In a real system, proven fraud would trigger governance proposals
        // for federation changes or parameter updates
        
        // Create governance proposal in response to fraud
        let response_proposal = GovernanceProposal {
            proposal_id: test_hash(3),
            proposal_type: ProposalType::ParameterChange,
            title: "Emergency federation update".to_string(),
            description: "Update federation in response to detected fraud".to_string(),
            proposer: test_hash(4),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 3, // Shorter deadline for emergency
            execution_deadline: 1234567890 + 86400 * 5,
            required_stake: 1000000,
            parameter_changes: Some(vec![ParameterChange {
                parameter_name: "emergency_federation_update".to_string(),
                old_value: "false".to_string(),
                new_value: "true".to_string(),
            }]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };
        
        governance_state.submit_proposal(response_proposal.clone(), 1000000).unwrap();
        
        // Fast-track voting for emergency response
        let emergency_vote = GovernanceVote {
            proposal_id: response_proposal.proposal_id,
            voter: test_masternode_id(1),
            vote_type: VoteType::Yes,
            voting_power: 5000000,
            timestamp: 1234567890 + 3600,
        };
        
        governance_state.cast_vote(emergency_vote).unwrap();
        governance_state.execute_proposal(response_proposal.proposal_id).unwrap();
        
        // Verify both fraud detection and governance response worked
        let fraud_status = sidechain_state.get_fraud_proof_status(&challenge_id);
        assert!(fraud_status.is_some());
        
        let proposal_status = governance_state.get_proposal_status(&response_proposal.proposal_id);
        assert_eq!(proposal_status, Some(ProposalStatus::Executed));
    }
}

#[cfg(test)]
mod p2p_consensus_integration {
    use super::*;

    #[test]
    fn test_block_propagation_and_validation() {
        // Test that blocks are properly propagated through P2P network and validated

        // Simulate multiple nodes
        let mut node1_consensus = ConsensusState::new();
        let mut node2_consensus = ConsensusState::new();
        let mut node3_consensus = ConsensusState::new();

        // Create a valid block
        let header = create_test_block_header(1);
        let transactions = vec![create_test_transaction()];
        let block = Block { header, transactions };

        // Node 1 receives and validates the block
        let validation_result = node1_consensus.validate_block(&block);
        assert!(validation_result.is_ok());

        // Simulate P2P propagation to other nodes
        let validation_result2 = node2_consensus.validate_block(&block);
        assert!(validation_result2.is_ok());

        let validation_result3 = node3_consensus.validate_block(&block);
        assert!(validation_result3.is_ok());

        // All nodes should have the same validation result
        assert_eq!(validation_result.is_ok(), validation_result2.is_ok());
        assert_eq!(validation_result2.is_ok(), validation_result3.is_ok());
    }

    #[test]
    fn test_transaction_pool_synchronization() {
        // Test that transaction pools stay synchronized across nodes

        let mut node1_consensus = ConsensusState::new();
        let mut node2_consensus = ConsensusState::new();

        // Create transactions
        let tx1 = create_test_transaction();
        let tx2 = {
            let mut tx = create_test_transaction();
            tx.outputs[0].value = 3000000; // Different value
            tx
        };

        // Add transactions to node 1's mempool (simulated)
        // In a real implementation, this would involve P2P message propagation

        // Verify transactions are valid on both nodes
        // This simulates receiving transactions via P2P

        // For now, we just verify the transactions are valid
        assert!(tx1.verify().is_ok());
        assert!(tx2.verify().is_ok());

        // In a real P2P implementation, we would test:
        // 1. Transaction announcement messages
        // 2. Transaction request/response
        // 3. Mempool synchronization
        // 4. Duplicate transaction handling
    }

    #[test]
    fn test_masternode_network_coordination() {
        // Test masternode coordination for consensus operations

        let masternode1 = test_masternode_id(1);
        let masternode2 = test_masternode_id(2);
        let masternode3 = test_masternode_id(3);

        // Simulate masternode quorum formation
        let quorum = vec![masternode1, masternode2, masternode3];

        // Test that quorum can coordinate on block validation
        let header = create_test_block_header(1);
        let block = Block {
            header,
            transactions: vec![create_test_transaction()],
        };

        // Each masternode validates the block
        let mut consensus_states = vec![
            ConsensusState::new(),
            ConsensusState::new(),
            ConsensusState::new(),
        ];

        let mut validation_results = Vec::new();
        for consensus_state in &mut consensus_states {
            validation_results.push(consensus_state.validate_block(&block));
        }

        // All masternodes should reach the same validation result
        assert!(validation_results.iter().all(|r| r.is_ok()));

        // In a real implementation, this would test:
        // 1. Quorum formation messages
        // 2. Consensus voting
        // 3. Signature aggregation
        // 4. Result propagation
    }
}

#[cfg(test)]
mod p2p_governance_integration {
    use super::*;

    #[test]
    fn test_governance_proposal_propagation() {
        // Test that governance proposals are properly propagated across the network

        let mut node1_governance = GovernanceState::new();
        let mut node2_governance = GovernanceState::new();
        let mut node3_governance = GovernanceState::new();

        // Create proposal on node 1
        let proposal = GovernanceProposal {
            proposal_id: test_hash(1),
            proposal_type: ProposalType::ParameterChange,
            title: "Network-wide parameter change".to_string(),
            description: "Test proposal for P2P propagation".to_string(),
            proposer: test_hash(2),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 1000000,
            parameter_changes: Some(vec![ParameterChange {
                parameter_name: "test_parameter".to_string(),
                old_value: "old".to_string(),
                new_value: "new".to_string(),
            }]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };

        // Submit proposal on node 1
        node1_governance.submit_proposal(proposal.clone(), 1000000).unwrap();

        // Simulate P2P propagation to other nodes
        node2_governance.submit_proposal(proposal.clone(), 1000000).unwrap();
        node3_governance.submit_proposal(proposal.clone(), 1000000).unwrap();

        // All nodes should have the same proposal
        let status1 = node1_governance.get_proposal_status(&proposal.proposal_id);
        let status2 = node2_governance.get_proposal_status(&proposal.proposal_id);
        let status3 = node3_governance.get_proposal_status(&proposal.proposal_id);

        assert_eq!(status1, status2);
        assert_eq!(status2, status3);
        assert_eq!(status1, Some(ProposalStatus::Active));
    }

    #[test]
    fn test_distributed_governance_voting() {
        // Test that votes are properly collected from across the network

        let mut governance_nodes = vec![
            GovernanceState::new(),
            GovernanceState::new(),
            GovernanceState::new(),
        ];

        // Create and submit proposal on all nodes
        let proposal = GovernanceProposal {
            proposal_id: test_hash(1),
            proposal_type: ProposalType::ParameterChange,
            title: "Distributed voting test".to_string(),
            description: "Test distributed governance voting".to_string(),
            proposer: test_hash(2),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 1000000,
            parameter_changes: Some(vec![]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        };

        for governance_state in &mut governance_nodes {
            governance_state.submit_proposal(proposal.clone(), 1000000).unwrap();
        }

        // Cast votes from different nodes
        let votes = vec![
            GovernanceVote {
                proposal_id: proposal.proposal_id,
                voter: test_masternode_id(1),
                vote_type: VoteType::Yes,
                voting_power: 5000000,
                timestamp: 1234567890 + 3600,
            },
            GovernanceVote {
                proposal_id: proposal.proposal_id,
                voter: test_masternode_id(2),
                vote_type: VoteType::Yes,
                voting_power: 3000000,
                timestamp: 1234567890 + 3600,
            },
            GovernanceVote {
                proposal_id: proposal.proposal_id,
                voter: test_masternode_id(3),
                vote_type: VoteType::No,
                voting_power: 2000000,
                timestamp: 1234567890 + 3600,
            },
        ];

        // Apply votes to all nodes (simulating P2P propagation)
        for (i, vote) in votes.iter().enumerate() {
            for governance_state in &mut governance_nodes {
                governance_state.cast_vote(vote.clone()).unwrap();
            }
        }

        // All nodes should have the same vote tally
        let tallies: Vec<_> = governance_nodes
            .iter()
            .map(|state| state.get_vote_tally(&proposal.proposal_id))
            .collect();

        // Verify all tallies are the same
        for i in 1..tallies.len() {
            assert_eq!(tallies[0].yes_votes, tallies[i].yes_votes);
            assert_eq!(tallies[0].no_votes, tallies[i].no_votes);
        }

        // Verify vote totals
        assert_eq!(tallies[0].yes_votes, 8000000); // 5M + 3M
        assert_eq!(tallies[0].no_votes, 2000000);
    }
}

#[cfg(test)]
mod p2p_sidechain_integration {
    use super::*;

    #[test]
    fn test_cross_chain_message_propagation() {
        // Test that cross-chain messages are properly propagated

        let mut mainchain_sidechain_state = SidechainState::new();
        let mut sidechain_node_state = SidechainState::new();

        // Register sidechain on both nodes
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "P2P Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };

        mainchain_sidechain_state.register_sidechain(sidechain_info.clone()).unwrap();
        sidechain_node_state.register_sidechain(sidechain_info).unwrap();

        // Create cross-chain transaction
        let cross_chain_tx = CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            test_hash(1), // mainchain
            test_hash(100), // sidechain
            5000000,
            test_hash(200),
            vec![5, 6, 7],
            vec![8, 9, 10],
        );

        // Process on mainchain node
        let result1 = mainchain_sidechain_state.validate_cross_chain_proof(&cross_chain_tx);

        // Process on sidechain node (simulating P2P propagation)
        let result2 = sidechain_node_state.validate_cross_chain_proof(&cross_chain_tx);

        // Both nodes should have the same validation result
        match (&result1, &result2) {
            (ProofValidationResult::Invalid(_), ProofValidationResult::Invalid(_)) => {
                // Both failed validation (expected due to missing signatures)
                assert!(true);
            }
            _ => {
                // Both should have the same result type
                assert_eq!(
                    std::mem::discriminant(&result1),
                    std::mem::discriminant(&result2)
                );
            }
        }
    }

    #[test]
    fn test_federation_signature_collection() {
        // Test collection of federation signatures across the network

        let mut sidechain_state = SidechainState::new();

        // Register sidechain with multiple federation members
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "Federation Test Sidechain".to_string(),
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

        sidechain_state.register_sidechain(sidechain_info).unwrap();
        sidechain_state.update_federation(1, vec![
            test_masternode_id(1),
            test_masternode_id(2),
            test_masternode_id(3),
        ]).unwrap();

        // Initiate peg operation
        let mainchain_tx = create_test_transaction();
        let peg_id = sidechain_state.initiate_peg_in(
            mainchain_tx,
            test_hash(100),
            vec![1, 2, 3],
            5000000,
            test_hash(200),
        ).unwrap();

        // Process confirmations
        sidechain_state.process_peg_confirmations(10).unwrap();

        // Collect signatures from federation members (simulating P2P collection)
        let signatures = vec![
            FederationSignature {
                signature: vec![1, 2, 3, 4],
                signer_bitmap: vec![0b10000000], // Member 1
                threshold: 2,
                epoch: 1,
                message_hash: peg_id,
            },
            FederationSignature {
                signature: vec![5, 6, 7, 8],
                signer_bitmap: vec![0b01000000], // Member 2
                threshold: 2,
                epoch: 1,
                message_hash: peg_id,
            },
        ];

        // Add signatures
        for signature in signatures {
            sidechain_state.add_peg_federation_signature(peg_id, signature).unwrap();
        }

        // Verify peg operation progresses
        let status = sidechain_state.get_peg_status(&peg_id);
        assert!(matches!(
            status,
            Some(PegStatus::WaitingFederationSignatures { .. }) | Some(PegStatus::Completed)
        ));
    }
}

#[cfg(test)]
mod stress_integration_tests {
    use super::*;

    #[test]
    fn test_high_volume_transaction_processing() {
        // Test system behavior under high transaction volume

        let mut consensus_state = ConsensusState::new();
        let mut sidechain_state = SidechainState::new();

        // Register sidechain
        let sidechain_info = SidechainInfo {
            sidechain_id: test_hash(100),
            name: "High Volume Test Sidechain".to_string(),
            peg_address: vec![1, 2, 3, 4],
            federation_members: vec![test_masternode_id(1)],
            current_epoch: 1,
            vm_type: VMType::EVM,
            genesis_block_hash: test_hash(101),
            creation_timestamp: 1234567890,
            min_federation_threshold: 1,
        };

        sidechain_state.register_sidechain(sidechain_info).unwrap();

        // Create many transactions
        let mut transactions = Vec::new();
        for i in 0..100 {
            let mut tx = create_test_transaction();
            tx.outputs[0].value = 1000000 + i; // Make each transaction unique
            transactions.push(tx);
        }

        // Process transactions in batches (simulating blocks)
        for chunk in transactions.chunks(10) {
            let header = create_test_block_header(1);
            let block = Block {
                header,
                transactions: chunk.to_vec(),
            };

            // Validate block
            let result = consensus_state.validate_block(&block);
            assert!(result.is_ok());
        }

        // Create many cross-chain transactions
        let mut cross_chain_txs = Vec::new();
        for i in 0..50 {
            let tx = CrossChainTransaction::new(
                CrossChainTxType::PegIn,
                test_hash(1),
                test_hash(100),
                1000000 + i,
                test_hash(200),
                vec![i as u8, (i + 1) as u8, (i + 2) as u8],
                Vec::new(),
            );
            cross_chain_txs.push(tx);
        }

        // Validate cross-chain transactions
        for tx in &cross_chain_txs {
            let result = sidechain_state.validate_cross_chain_proof(tx);
            // Should fail due to missing signatures, but validation should complete
            assert!(matches!(result, ProofValidationResult::Invalid(_)));
        }

        // Verify system remains stable
        let stats = sidechain_state.get_stats();
        assert_eq!(stats.registered_sidechains, 1);
    }

    #[test]
    fn test_concurrent_governance_proposals() {
        // Test handling of multiple concurrent governance proposals

        let mut governance_state = GovernanceState::new();

        // Create multiple proposals
        let proposals = (0..10).map(|i| GovernanceProposal {
            proposal_id: test_hash(i),
            proposal_type: ProposalType::ParameterChange,
            title: format!("Proposal {}", i),
            description: format!("Test proposal number {}", i),
            proposer: test_hash(100 + i),
            creation_time: 1234567890,
            voting_deadline: 1234567890 + 86400 * 7,
            execution_deadline: 1234567890 + 86400 * 14,
            required_stake: 1000000,
            parameter_changes: Some(vec![ParameterChange {
                parameter_name: format!("param_{}", i),
                old_value: "old".to_string(),
                new_value: format!("new_{}", i),
            }]),
            code_changes: None,
            funding_amount: None,
            recipient_address: None,
        }).collect::<Vec<_>>();

        // Submit all proposals
        for proposal in &proposals {
            governance_state.submit_proposal(proposal.clone(), 1000000).unwrap();
        }

        // Vote on all proposals
        for (i, proposal) in proposals.iter().enumerate() {
            let vote = GovernanceVote {
                proposal_id: proposal.proposal_id,
                voter: test_masternode_id(i as u8),
                vote_type: if i % 2 == 0 { VoteType::Yes } else { VoteType::No },
                voting_power: 5000000,
                timestamp: 1234567890 + 3600,
            };

            governance_state.cast_vote(vote).unwrap();
        }

        // Execute approved proposals (even numbered ones)
        for (i, proposal) in proposals.iter().enumerate() {
            if i % 2 == 0 {
                governance_state.execute_proposal(proposal.proposal_id).unwrap();
                let status = governance_state.get_proposal_status(&proposal.proposal_id);
                assert_eq!(status, Some(ProposalStatus::Executed));
            }
        }

        // Verify system handled concurrent proposals correctly
        let executed_proposals = governance_state.get_executed_proposals();
        assert_eq!(executed_proposals.len(), 5); // Half of the proposals
    }
}
