use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::ConsensusError;
use rusty_core::types::{
    Block, BlockHeader, Transaction, TxInput, TxOutput,
    Hash, PublicKey, Signature, TicketId, OutPoint
};
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote, ProposalType, VoterType, VoteChoice};
use rusty_core::constants::{COINBASE_MATURITY_PERIOD_BLOCKS, DUST_LIMIT};
use rusty_core::masternode::{MasternodeID, MasternodeEntry, MasternodeStatus};
use rusty_core::consensus::pos::LiveTicketsPool;
use rusty_core::consensus::utxo_set::UtxoSet;
use rusty_shared_types::ConsensusParams;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Helper functions for creating dummy data
fn dummy_hash(seed: u8) -> Hash {
    [seed; 32]
}

fn dummy_public_key(seed: u8) -> PublicKey {
    [seed; 32]
}

fn dummy_signature(seed: u8) -> Signature {
    [seed; 64]
}

fn create_test_blockchain() -> Blockchain {
    let data_dir = tempfile::tempdir().unwrap();
    Blockchain::new(data_dir.path()).unwrap()
}

// Tests for Blockchain::validate_transaction

#[test]
fn test_validate_standard_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let utxo_id = OutPoint { txid: dummy_hash(100), vout: 0 };
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: 10000, script_pubkey: vec![1] },
        is_coinbase: false,
        creation_height: 1,
    };
    blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

    let tx = Transaction::Standard {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id.clone(),
            script_sig: vec![0; 65], // Dummy signature
            sequence: 0,
        }],
        outputs: vec![TxOutput { value: 9000, script_pubkey: vec![2] }],
        lock_time: 0,
        fee: 1000,
    };

    // Assume a block height sufficient for coinbase maturity checks to pass if the UTXO were coinbase.
    // Since it's not coinbase, maturity isn't an issue here.
    let current_block_height = 100; 
    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_standard_transaction_insufficient_fee() {
    let mut blockchain = create_test_blockchain();
    let utxo_id = OutPoint { txid: dummy_hash(101), vout: 0 };
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: 10000, script_pubkey: vec![1] },
        is_coinbase: false,
        creation_height: 1,
    };
    blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

    let tx = Transaction::Standard {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id.clone(),
            script_sig: vec![0; 65], // Dummy signature
            sequence: 0,
        }],
        outputs: vec![TxOutput { value: 9500, script_pubkey: vec![2] }],
        lock_time: 0,
        fee: 100, // Insufficient fee (input 10000 - output 9500 = 500, fee is 100)
    };

    let current_block_height = 100; 
    let err = blockchain.validate_transaction(&tx, current_block_height).unwrap_err();
    assert!(matches!(err, ConsensusError::InsufficientFee(_, _)));
}

#[test]
fn test_validate_governance_proposal_valid() {
    let blockchain = create_test_blockchain();
    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(1),
        proposer_address: dummy_public_key(2),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 100,
        end_block_height: 100 + blockchain.params.voting_period_blocks -1,
        title: "Test Proposal".to_string(),
        description_hash: dummy_hash(3),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(4),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
    };
    let tx = Transaction::GovernanceProposal(proposal);

    assert!(blockchain.validate_transaction(&tx, 99).is_ok());
}

#[test]
fn test_validate_governance_proposal_insufficient_stake() {
    let blockchain = create_test_blockchain();
    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(1),
        proposer_address: dummy_public_key(2),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 100,
        end_block_height: 100 + blockchain.params.voting_period_blocks -1,
        title: "Test Proposal".to_string(),
        description_hash: dummy_hash(3),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(4),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount - 1, script_pubkey: vec![] }],
        lock_time: 0,
    };
    let tx = Transaction::GovernanceProposal(proposal);

    let err = blockchain.validate_transaction(&tx, 99).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidTransaction(_)));
}

#[test]
fn test_validate_coinbase_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let current_block_height = COINBASE_MATURITY_PERIOD_BLOCKS; // Ensure maturity for potential future spends

    let tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![], // Coinbase transactions have no inputs
        outputs: vec![
            TxOutput { value: blockchain.params.initial_block_reward, script_pubkey: blockchain.params.miner_address.clone() },
        ],
        lock_time: 0,
    };

    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_masternode_register_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let current_block_height = 100;

    let mn_identity = rusty_core::masternode::MasternodeIdentity {
        collateral_outpoint: OutPoint { txid: dummy_hash(1), vout: 0 },
        operator_public_key: dummy_public_key(2).to_vec(),
        collateral_ownership_public_key: dummy_public_key(3).to_vec(),
        network_address: "127.0.0.1:9000".to_string(),
    };

    let tx = Transaction::MasternodeRegister {
        masternode_identity: mn_identity,
        signature: dummy_signature(4),
        lock_time: 0,
        inputs: vec![], // MasternodeRegister doesn't have regular inputs that spend UTXOs
        outputs: vec![], // MasternodeRegister doesn't create new UTXOs for itself.
    };

    // Note: Full validation of MasternodeRegister would involve checking collateral UTXO existence and maturity, which is beyond this unit test's scope.
    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_masternode_collateral_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let current_block_height = 100;

    let utxo_id = OutPoint { txid: dummy_hash(100), vout: 0 };
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: 10000, script_pubkey: vec![1] },
        is_coinbase: false,
        creation_height: 1,
    };
    blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

    let mn_identity = rusty_core::masternode::MasternodeIdentity {
        collateral_outpoint: utxo_id.clone(),
        operator_public_key: dummy_public_key(2).to_vec(),
        collateral_ownership_public_key: dummy_public_key(3).to_vec(),
        network_address: "127.0.0.1:9000".to_string(),
    };

    let tx = Transaction::MasternodeCollateral {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id.clone(),
            script_sig: vec![0; 65], // Dummy signature
            sequence: 0,
        }],
        outputs: vec![
            TxOutput { value: 9000, script_pubkey: vec![2] },
            TxOutput { value: 1000, script_pubkey: vec![3] }, // Change output
        ],
        masternode_identity: mn_identity,
        collateral_amount: 10000, // This should match the input value
        lock_time: 0,
    };

    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_ticket_purchase_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let current_block_height = 100;

    let utxo_id = OutPoint { txid: dummy_hash(100), vout: 0 };
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: blockchain.params.ticket_price, script_pubkey: vec![1] },
        is_coinbase: false,
        creation_height: 1,
    };
    blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

    let tx = Transaction::TicketPurchase {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id.clone(),
            script_sig: vec![0; 65],
            sequence: 0,
        }],
        outputs: vec![
            TxOutput { value: blockchain.params.ticket_price, script_pubkey: vec![2] },
        ],
        ticket_id: dummy_hash(101),
        locked_amount: blockchain.params.ticket_price,
        lock_time: 0,
        fee: 0,
        ticket_address: dummy_public_key(3).to_vec(),
    };

    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_ticket_redemption_transaction_valid() {
    let mut blockchain = create_test_blockchain();
    let current_block_height = 100;

    let ticket_id = TicketId(dummy_hash(102));
    let outpoint = OutPoint { txid: dummy_hash(103), vout: 0 };
    let ticket_value = blockchain.params.ticket_price;
    let ticket_public_key = dummy_public_key(104);

    // Add a matured and non-expired ticket to the live tickets pool
    let ticket = Ticket {
        id: ticket_id.clone(),
        outpoint: outpoint.clone(),
        commitment: dummy_hash(105),
        value: ticket_value,
        purchase_block_height: current_block_height - blockchain.params.ticket_maturity as u64,
        locked_amount: ticket_value,
        public_key: ticket_public_key,
    };
    blockchain.live_tickets.add_ticket(ticket);

    // Add the UTXO for the ticket to the UTXO set (so it can be spent)
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: ticket_value, script_pubkey: vec![1] },
        is_coinbase: false,
        creation_height: current_block_height - blockchain.params.ticket_maturity as u64,
    };
    blockchain.utxo_set.add_utxo(outpoint.clone(), utxo);

    let tx = Transaction::TicketRedemption {
        version: 1,
        inputs: vec![TxInput {
            previous_output: outpoint.clone(),
            script_sig: vec![0; 65], // Dummy signature
            sequence: 0,
        }],
        outputs: vec![
            TxOutput { value: ticket_value - 10, script_pubkey: vec![2] }, // Output value less fee
            TxOutput { value: 10, script_pubkey: vec![3] }, // Fee output or change
        ],
        ticket_id: ticket_id.0,
        lock_time: 0,
        fee: 10,
    };

    assert!(blockchain.validate_transaction(&tx, current_block_height).is_ok());
}

#[test]
fn test_validate_governance_vote_valid() {
    let mut blockchain = create_test_blockchain();
    
    // Add a dummy proposal to active_proposals
    let proposal_id = dummy_hash(1);
    let proposal = GovernanceProposal {
        proposal_id: proposal_id,
        proposer_address: dummy_public_key(2),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 100,
        end_block_height: 200,
        title: "Test Proposal".to_string(),
        description_hash: dummy_hash(3),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(4),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
    };
    blockchain.active_proposals.add_proposal(proposal.clone()).unwrap();

    // Add a dummy live ticket for PoS voting
    let pos_voter_public_key = dummy_public_key(5);
    let ticket = Ticket {
        id: TicketId(dummy_hash(6)),
        outpoint: OutPoint { txid: dummy_hash(7), vout: 0 },
        commitment: dummy_hash(8),
        value: blockchain.params.ticket_price,
        purchase_block_height: 50,
        locked_amount: blockchain.params.ticket_price,
        public_key: pos_voter_public_key,
    };
    blockchain.live_tickets.add_ticket(ticket);

    // Add a dummy active masternode for MN voting
    let mn_operator_public_key = dummy_public_key(9);
    let mn_id = MasternodeID(OutPoint { txid: dummy_hash(10), vout: 0 });
    let mn_entry = MasternodeEntry {
        identity: rusty_core::masternode::MasternodeIdentity {
            collateral_outpoint: mn_id.0.clone(),
            operator_public_key: mn_operator_public_key.to_vec(),
            network_address: "127.0.0.1:8000".to_string(),
            collateral_ownership_public_key: dummy_public_key(11).to_vec(),
        },
        status: MasternodeStatus::Active,
        last_successful_pose_height: 10,
        pose_failure_count: 0,
    };
    blockchain.masternode_list.map.insert(mn_id.clone(), mn_entry);

    // Test PoS vote
    let pos_vote = GovernanceVote {
        proposal_id: proposal_id,
        voter_type: VoterType::POS_TICKET,
        voter_id: pos_voter_public_key,
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(12),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx_pos_vote = Transaction::GovernanceVote(pos_vote);
    assert!(blockchain.validate_transaction(&tx_pos_vote, 150).is_ok());

    // Test Masternode vote
    let mn_vote = GovernanceVote {
        proposal_id: proposal_id,
        voter_type: VoterType::MASTERNODE,
        voter_id: mn_operator_public_key,
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(13),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx_mn_vote = Transaction::GovernanceVote(mn_vote);
    assert!(blockchain.validate_transaction(&tx_mn_vote, 150).is_ok());
}

#[test]
fn test_validate_governance_vote_duplicate() {
    let mut blockchain = create_test_blockchain();
    let proposal_id = dummy_hash(1);
    let proposer_public_key = dummy_public_key(2);

    let proposal = GovernanceProposal {
        proposal_id: proposal_id,
        proposer_address: proposer_public_key,
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 100,
        end_block_height: 200,
        title: "Test Proposal".to_string(),
        description_hash: dummy_hash(3),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(4),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
    };
    blockchain.active_proposals.add_proposal(proposal.clone()).unwrap();

    let voter_public_key = dummy_public_key(5);
    let ticket = Ticket {
        id: TicketId(dummy_hash(6)),
        outpoint: OutPoint { txid: dummy_hash(7), vout: 0 },
        commitment: dummy_hash(8),
        value: blockchain.params.ticket_price,
        purchase_block_height: 50,
        locked_amount: blockchain.params.ticket_price,
        public_key: voter_public_key,
    };
    blockchain.live_tickets.add_ticket(ticket);

    let first_vote = GovernanceVote {
        proposal_id: proposal_id,
        voter_type: VoterType::POS_TICKET,
        voter_id: voter_public_key,
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(12),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx_first_vote = Transaction::GovernanceVote(first_vote.clone());
    blockchain.validate_transaction(&tx_first_vote, 150).unwrap();
    blockchain.active_proposals.record_vote(first_vote).unwrap(); // Record the first vote

    // Attempt to cast a second vote with the same voter_id
    let second_vote = GovernanceVote {
        proposal_id: proposal_id,
        voter_type: VoterType::POS_TICKET,
        voter_id: voter_public_key,
        vote_choice: VoteChoice::NO,
        voter_signature: dummy_signature(13),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx_second_vote = Transaction::GovernanceVote(second_vote);

    let err = blockchain.validate_transaction(&tx_second_vote, 150).unwrap_err();
    assert!(matches!(err, ConsensusError::RuleViolation(_)));
}

// Tests for Blockchain::add_block (basic tests, more comprehensive ones would need a full chain setup)

#[test]
fn test_add_block_with_governance_proposal() {
    let mut blockchain = create_test_blockchain();
    let current_height = blockchain.get_current_block_height().unwrap();

    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(20),
        proposer_address: dummy_public_key(21),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: current_height + 1,
        end_block_height: current_height + 1 + blockchain.params.voting_period_blocks -1,
        title: "Block Proposal".to_string(),
        description_hash: dummy_hash(22),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(23),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
    };
    let tx_proposal = Transaction::GovernanceProposal(proposal.clone());

    let block_header = BlockHeader {
        version: 0,
        previous_block_hash: blockchain.tip,
        merkle_root: dummy_hash(24),
        state_root: dummy_hash(25),
        timestamp: 1678886400,
        bits: 0x1d00ffff,
        nonce: 0,
        height: current_height + 1,
    };

    let mut block = Block {
        header: block_header,
        transactions: vec![Transaction::Coinbase {
            version: 0, inputs: vec![], outputs: vec![TxOutput { value: 50_000_000_000, script_pubkey: vec![0u8; 20] }], lock_time: 0
        }, tx_proposal],
        ticket_votes: vec![],
    };

    // Since `add_block` expects the merkle root to be correct, we need to calculate it.
    block.header.merkle_root = block.calculate_merkle_root();
    block.header.state_root = blockchain.state.calculate_state_root(&blockchain.utxo_set, &blockchain.live_tickets, &blockchain.state.masternode_list, &blockchain.active_proposals).unwrap();

    let initial_proposal_count = blockchain.active_proposals.proposals.len();
    assert!(blockchain.add_block(block.clone()).is_ok());
    assert_eq!(blockchain.active_proposals.proposals.len(), initial_proposal_count + 1);
    assert!(blockchain.active_proposals.get_proposal(&proposal.proposal_id).is_some());
}

#[test]
fn test_add_block_with_governance_vote() {
    let mut blockchain = create_test_blockchain();
    let current_height = blockchain.get_current_block_height().unwrap();

    // Add a dummy proposal first
    let proposal_id = dummy_hash(30);
    let proposer_public_key = dummy_public_key(31);
    let proposal = GovernanceProposal {
        proposal_id: proposal_id,
        proposer_address: proposer_public_key,
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: current_height + 1,
        end_block_height: current_height + 1 + blockchain.params.voting_period_blocks -1,
        title: "Vote Test Proposal".to_string(),
        description_hash: dummy_hash(32),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(33),
        inputs: vec![],
        outputs: vec![TxOutput { value: blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
    };
    blockchain.active_proposals.add_proposal(proposal.clone()).unwrap();

    // Add a dummy live ticket for PoS voting
    let pos_voter_public_key = dummy_public_key(34);
    let ticket = Ticket {
        id: TicketId(dummy_hash(35)),
        outpoint: OutPoint { txid: dummy_hash(36), vout: 0 },
        commitment: dummy_hash(37),
        value: blockchain.params.ticket_price,
        purchase_block_height: 50,
        locked_amount: blockchain.params.ticket_price,
        public_key: pos_voter_public_key,
    };
    blockchain.live_tickets.add_ticket(ticket);

    let vote = GovernanceVote {
        proposal_id: proposal_id,
        voter_type: VoterType::POS_TICKET,
        voter_id: pos_voter_public_key,
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(38),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    let tx_vote = Transaction::GovernanceVote(vote.clone());

    let block_header = BlockHeader {
        version: 0,
        previous_block_hash: blockchain.tip,
        merkle_root: dummy_hash(39),
        state_root: dummy_hash(40),
        timestamp: 1678886500,
        bits: 0x1d00ffff,
        nonce: 0,
        height: current_height + 1,
    };

    let mut block = Block {
        header: block_header,
        transactions: vec![Transaction::Coinbase {
            version: 0, inputs: vec![], outputs: vec![TxOutput { value: 50_000_000_000, script_pubkey: vec![0u8; 20] }], lock_time: 0
        }, tx_vote],
        ticket_votes: vec![],
    };

    block.header.merkle_root = block.calculate_merkle_root();
    block.header.state_root = blockchain.state.calculate_state_root(&blockchain.utxo_set, &blockchain.live_tickets, &blockchain.state.masternode_list, &blockchain.active_proposals).unwrap();

    let initial_vote_count = blockchain.active_proposals.get_votes_for_proposal(&proposal_id).unwrap().len();
    assert!(blockchain.add_block(block.clone()).is_ok());
    assert_eq!(blockchain.active_proposals.get_votes_for_proposal(&proposal_id).unwrap().len(), initial_vote_count + 1);
    assert!(blockchain.active_proposals.get_votes_for_proposal(&proposal_id).unwrap().contains_key(&vote.voter_id));
} 