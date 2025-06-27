use rusty_shared_types::{Transaction, TxInput, TxOutput, Hash, PublicKey, Signature};
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote, ProposalType, VoterType, VoteChoice};
use bincode::{self};

// Helper function to create a dummy hash
fn dummy_hash(seed: u8) -> Hash {
    [seed; 32]
}

// Helper function to create a dummy public key
fn dummy_public_key(seed: u8) -> PublicKey {
    [seed; 32]
}

// Helper function to create a dummy signature
fn dummy_signature(seed: u8) -> Signature {
    [seed; 64]
}

#[test]
fn test_tx_input_serialization() {
    let input = TxInput {
        previous_output: rusty_shared_types::OutPoint {
            txid: dummy_hash(1),
            vout: 0,
        },
        script_sig: vec![1, 2, 3, 4],
        sequence: 0xFFFFFFFF,
        witness: vec![vec![10, 20], vec![30, 40]],
    };

    let encoded = bincode::encode_to_vec(&input, bincode::config::standard()).unwrap();
    let (decoded, _): (TxInput, usize) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(input, decoded);
    println!("TxInput serialization test passed.");
}

#[test]
fn test_tx_output_serialization() {
    let output = TxOutput {
        value: 100_000_000,
        script_pubkey: vec![5, 6, 7, 8],
        memo: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let encoded = bincode::encode_to_vec(&output, bincode::config::standard()).unwrap();
    let (decoded, _): (TxOutput, usize) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(output, decoded);
    println!("TxOutput serialization test passed.");
}

#[test]
fn test_governance_proposal_serialization() {
    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(2),
        proposer_address: dummy_public_key(3),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 1000,
        end_block_height: 2000,
        title: "Test Protocol Upgrade".to_string(),
        description_hash: dummy_hash(4),
        code_change_hash: Some(dummy_hash(5)),
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(6),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
    };

    let encoded = bincode::encode_to_vec(&proposal, bincode::config::standard()).unwrap();
    let (decoded, _): (GovernanceProposal, usize) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(proposal, decoded);
    println!("GovernanceProposal serialization test passed.");
}

#[test]
fn test_governance_vote_serialization() {
    let vote = GovernanceVote {
        proposal_id: dummy_hash(7),
        voter_type: VoterType::POS_TICKET,
        voter_id: dummy_public_key(8),
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(9),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
    };

    let encoded = bincode::encode_to_vec(&vote, bincode::config::standard()).unwrap();
    let (decoded, _): (GovernanceVote, usize) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(vote, decoded);
    println!("GovernanceVote serialization test passed.");
}

#[test]
fn test_transaction_enum_serialization() {
    // Test a Standard transaction variant
    let standard_tx = Transaction::Standard {
        version: 1,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(10), vout: 0 },
            script_sig: vec![11],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 5000, script_pubkey: vec![12], memo: None }],
        lock_time: 0,
        fee: 100,
        witness: vec![vec![2,2]],
    };
    let encoded_standard = bincode::encode_to_vec(&standard_tx, bincode::config::standard()).unwrap();
    let (decoded_standard, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_standard, bincode::config::standard()).unwrap();
    assert_eq!(standard_tx, decoded_standard);
    println!("Standard Transaction enum serialization test passed.");

    // Test a Coinbase transaction variant
    let coinbase_tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(20), vout: 0 },
            script_sig: vec![21],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 5000, script_pubkey: vec![22], memo: None }],
        lock_time: 0,
        witness: vec![vec![2,2]],
    };
    let encoded_coinbase = bincode::encode_to_vec(&coinbase_tx, bincode::config::standard()).unwrap();
    let (decoded_coinbase, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_coinbase, bincode::config::standard()).unwrap();
    assert_eq!(coinbase_tx, decoded_coinbase);
    println!("Coinbase Transaction enum serialization test passed.");

    // Test a MasternodeRegister transaction variant
    let masternode_register_tx = Transaction::MasternodeRegister {
        masternode_identity: rusty_shared_types::MasternodeIdentity {
            collateral_outpoint: rusty_shared_types::OutPoint { txid: dummy_hash(30), vout: 0 },
            operator_public_key: dummy_public_key(31),
            collateral_ownership_public_key: dummy_public_key(32),
            network_address: "127.0.0.1:9000".to_string(),
        },
        signature: dummy_signature(33),
        lock_time: 0,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(34), vout: 0 },
            script_sig: vec![35],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 10000, script_pubkey: vec![36], memo: None }],
        witness: vec![vec![2,2]],
    };
    let encoded_mn_register = bincode::encode_to_vec(&masternode_register_tx, bincode::config::standard()).unwrap();
    let (decoded_mn_register, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_mn_register, bincode::config::standard()).unwrap();
    assert_eq!(masternode_register_tx, decoded_mn_register);
    println!("MasternodeRegister Transaction enum serialization test passed.");

    // Test a MasternodeCollateral transaction variant
    let masternode_collateral_tx = Transaction::MasternodeCollateral {
        version: 1,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(40), vout: 0 },
            script_sig: vec![41],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 10000, script_pubkey: vec![42], memo: None }],
        masternode_identity: rusty_shared_types::MasternodeIdentity {
            collateral_outpoint: rusty_shared_types::OutPoint { txid: dummy_hash(43), vout: 0 },
            operator_public_key: dummy_public_key(44),
            collateral_ownership_public_key: dummy_public_key(45),
            network_address: "127.0.0.1:9001".to_string(),
        },
        collateral_amount: 10000,
        lock_time: 0,
        witness: vec![vec![2,2]],
    };
    let encoded_mn_collateral = bincode::encode_to_vec(&masternode_collateral_tx, bincode::config::standard()).unwrap();
    let (decoded_mn_collateral, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_mn_collateral, bincode::config::standard()).unwrap();
    assert_eq!(masternode_collateral_tx, decoded_mn_collateral);
    println!("MasternodeCollateral Transaction enum serialization test passed.");

    // Test a GovernanceProposal transaction variant
    let governance_proposal_tx = Transaction::GovernanceProposal(
        GovernanceProposal {
            proposal_id: dummy_hash(13),
            proposer_address: dummy_public_key(14),
            proposal_type: ProposalType::PARAMETER_CHANGE,
            start_block_height: 500,
            end_block_height: 1500,
            title: "Test Parameter Change".to_string(),
            description_hash: dummy_hash(15),
            code_change_hash: None,
            target_parameter: Some("DUST_LIMIT".to_string()),
            new_value: Some("100".to_string()),
            proposer_signature: dummy_signature(16),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![vec![1,1]],
        }
    );
    let encoded_proposal = bincode::encode_to_vec(&governance_proposal_tx, bincode::config::standard()).unwrap();
    let (decoded_proposal, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_proposal, bincode::config::standard()).unwrap();
    assert_eq!(governance_proposal_tx, decoded_proposal);
    println!("GovernanceProposal Transaction enum serialization test passed.");

    // Test a GovernanceVote transaction variant
    let vote = GovernanceVote {
        proposal_id: dummy_hash(17),
        voter_type: VoterType::MASTERNODE,
        voter_id: dummy_public_key(18),
        vote_choice: VoteChoice::NO,
        voter_signature: dummy_signature(19),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![vec![1,1]],
    };
    let encoded_vote = bincode::encode_to_vec(&vote, bincode::config::standard()).unwrap();
    let (decoded_vote, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_vote, bincode::config::standard()).unwrap();
    assert_eq!(vote, decoded_vote);
    println!("GovernanceVote serialization test passed.");

    // Test a TicketPurchase transaction variant
    let ticket_purchase_tx = Transaction::TicketPurchase {
        version: 1,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(50), vout: 0 },
            script_sig: vec![51],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 1000, script_pubkey: vec![52], memo: None }],
        ticket_id: dummy_hash(53),
        locked_amount: 1000,
        lock_time: 0,
        fee: 10,
        ticket_address: vec![54,55,56],
        witness: vec![vec![2,2]],
    };
    let encoded_ticket_purchase = bincode::encode_to_vec(&ticket_purchase_tx, bincode::config::standard()).unwrap();
    let (decoded_ticket_purchase, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_ticket_purchase, bincode::config::standard()).unwrap();
    assert_eq!(ticket_purchase_tx, decoded_ticket_purchase);
    println!("TicketPurchase Transaction enum serialization test passed.");

    // Test a TicketRedemption transaction variant
    let ticket_redemption_tx = Transaction::TicketRedemption {
        version: 1,
        inputs: vec![TxInput {
            previous_output: rusty_shared_types::OutPoint { txid: dummy_hash(60), vout: 0 },
            script_sig: vec![61],
            sequence: 0,
            witness: vec![vec![1,1]],
        }],
        outputs: vec![TxOutput { value: 1000, script_pubkey: vec![62], memo: None }],
        ticket_id: dummy_hash(63),
        lock_time: 0,
        fee: 5,
        witness: vec![vec![2,2]],
    };
    let encoded_ticket_redemption = bincode::encode_to_vec(&ticket_redemption_tx, bincode::config::standard()).unwrap();
    let (decoded_ticket_redemption, _): (Transaction, usize) = bincode::decode_from_slice(&encoded_ticket_redemption, bincode::config::standard()).unwrap();
    assert_eq!(ticket_redemption_tx, decoded_ticket_redemption);
    println!("TicketRedemption Transaction enum serialization test passed.");
} 