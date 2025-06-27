use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::types::{
    Block, BlockHeader, Transaction, TxInput, TxOutput,
    Hash, PublicKey, Signature, TicketId, OutPoint
};
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote, ProposalType, VoterType, VoteChoice};
use rusty_shared_types::ConsensusParams;
use std::path::Path;
use tempfile::tempdir;

// Helper functions (copied from unit tests, consider a common test_utils crate for real projects)
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
    let data_dir = tempdir().unwrap();
    Blockchain::new(data_dir.path()).unwrap()
}

fn create_standard_transaction(utxo_id_seed: u8, output_value: u64, fee: u64) -> Transaction {
    let utxo_id = OutPoint { txid: dummy_hash(utxo_id_seed), vout: 0 };
    Transaction::Standard {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id,
            script_sig: vec![0; 65],
            sequence: 0,
        }],
        outputs: vec![TxOutput { value: output_value, script_pubkey: vec![2] }],
        lock_time: 0,
        fee,
    }
}

fn create_coinbase_transaction(reward_value: u64, miner_address: Vec<u8>) -> Transaction {
    Transaction::Coinbase {
        version: 1,
        inputs: vec![], // Coinbase transactions have no inputs
        outputs: vec![
            TxOutput { value: reward_value, script_pubkey: miner_address, memo: None },
        ],
        lock_time: 0,
        witness: vec![],
    }
}

fn create_masternode_register_transaction(mn_id_seed: u8) -> Transaction {
    let mn_identity = rusty_shared_types::MasternodeIdentity {
        collateral_outpoint: OutPoint { txid: dummy_hash(mn_id_seed), vout: 0 },
        operator_public_key: dummy_public_key(mn_id_seed + 1).to_vec(),
        collateral_ownership_public_key: dummy_public_key(mn_id_seed + 2).to_vec(),
        network_address: format!("127.0.0.1:{}", 9000 + mn_id_seed),
    };
    Transaction::MasternodeRegister {
        masternode_identity: mn_identity,
        signature: dummy_signature(mn_id_seed + 3),
        lock_time: 0,
        inputs: vec![],
        outputs: vec![],
        witness: vec![],
    }
}

fn create_masternode_collateral_transaction(utxo_id_seed: u8, collateral_amount: u64, mn_id_seed: u8) -> Transaction {
    let utxo_id = OutPoint { txid: dummy_hash(utxo_id_seed), vout: 0 };
    let mn_identity = rusty_shared_types::MasternodeIdentity {
        collateral_outpoint: utxo_id.clone(),
        operator_public_key: dummy_public_key(mn_id_seed + 1).to_vec(),
        collateral_ownership_public_key: dummy_public_key(mn_id_seed + 2).to_vec(),
        network_address: format!("127.0.0.1:{}", 9000 + mn_id_seed),
    };
    Transaction::MasternodeCollateral {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id,
            script_sig: vec![0; 65],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![
            TxOutput { value: collateral_amount, script_pubkey: vec![1], memo: None },
        ],
        masternode_identity: mn_identity,
        collateral_amount,
        lock_time: 0,
        witness: vec![],
    }
}

fn create_ticket_purchase_transaction(utxo_id_seed: u8, ticket_price: u64, ticket_address_seed: u8) -> Transaction {
    let utxo_id = OutPoint { txid: dummy_hash(utxo_id_seed), vout: 0 };
    Transaction::TicketPurchase {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id,
            script_sig: vec![0; 65],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![
            TxOutput { value: ticket_price, script_pubkey: vec![1], memo: None },
        ],
        ticket_id: dummy_hash(ticket_address_seed + 1),
        locked_amount: ticket_price,
        lock_time: 0,
        fee: 0,
        ticket_address: dummy_public_key(ticket_address_seed).to_vec(),
        witness: vec![],
    }
}

fn create_ticket_redemption_transaction(utxo_id_seed: u8, ticket_id_seed: u8, redeemed_value: u64) -> Transaction {
    let utxo_id = OutPoint { txid: dummy_hash(utxo_id_seed), vout: 0 };
    Transaction::TicketRedemption {
        version: 1,
        inputs: vec![TxInput {
            previous_output: utxo_id,
            script_sig: vec![0; 65],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![
            TxOutput { value: redeemed_value, script_pubkey: vec![1], memo: None },
        ],
        ticket_id: dummy_hash(ticket_id_seed),
        lock_time: 0,
        fee: 10,
        witness: vec![],
    }
}

fn create_governance_proposal_transaction(proposal_id_seed: u8, stake_amount: u64) -> Transaction {
    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(proposal_id_seed),
        proposer_address: dummy_public_key(proposal_id_seed + 10),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: 100,
        end_block_height: 200,
        title: "Test Proposal".to_string(),
        description_hash: dummy_hash(proposal_id_seed + 20),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(proposal_id_seed + 30),
        inputs: vec![],
        outputs: vec![TxOutput { value: stake_amount, script_pubkey: vec![] }],
        lock_time: 0,
        witness: vec![],
    };
    Transaction::GovernanceProposal(proposal)
}

fn create_governance_vote_transaction(proposal_id_seed: u8, voter_id_seed: u8) -> Transaction {
    let vote = GovernanceVote {
        proposal_id: dummy_hash(proposal_id_seed),
        voter_type: VoterType::POS_TICKET,
        voter_id: dummy_public_key(voter_id_seed),
        vote_choice: VoteChoice::YES,
        voter_signature: dummy_signature(voter_id_seed + 40),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
    };
    Transaction::GovernanceVote(vote)
}

fn create_dummy_block(blockchain: &mut Blockchain, height: u64, transactions: Vec<Transaction>) -> Block {
    let previous_block_hash = blockchain.tip;
    let current_height = blockchain.get_current_block_height().unwrap();

    let block_header = BlockHeader {
        version: 0,
        previous_block_hash,
        merkle_root: dummy_hash(0),
        state_root: dummy_hash(0),
        timestamp: 1678886400 + height,
        bits: 0x1d00ffff,
        nonce: 0,
        height,
    };

    let mut block = Block {
        header: block_header,
        transactions,
        ticket_votes: vec![],
    };

    block.header.merkle_root = block.calculate_merkle_root();
    block.header.state_root = blockchain.state.calculate_state_root(
        &blockchain.utxo_set,
        &blockchain.live_tickets,
        &blockchain.state.masternode_list,
        &blockchain.active_proposals,
    ).unwrap();
    block
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut blockchain = create_test_blockchain();
    let current_height = 1000;

    // Setup for transaction validation benchmarks
    let utxo_id = OutPoint { txid: dummy_hash(100), vout: 0 };
    let utxo = rusty_shared_types::Utxo {
        output: TxOutput { value: 10000_000_000, script_pubkey: vec![1], memo: None },
        is_coinbase: false,
        creation_height: 1,
    };
    blockchain.utxo_set.add_utxo(utxo_id.clone(), utxo);

    let standard_tx = create_standard_transaction(1, 9_000_000_000, 1_000_000_000);
    let governance_proposal_tx = create_governance_proposal_transaction(2, blockchain.params.proposal_stake_amount);
    let governance_vote_tx = create_governance_vote_transaction(3, 4);

    let coinbase_tx_val = create_coinbase_transaction(blockchain.params.initial_block_reward, blockchain.params.miner_address.clone());
    let masternode_register_tx_val = create_masternode_register_transaction(5);
    let masternode_collateral_tx_val = create_masternode_collateral_transaction(6, 10000, 7);
    let ticket_purchase_tx_val = create_ticket_purchase_transaction(8, blockchain.params.ticket_price, 9);
    let ticket_redemption_tx_val = create_ticket_redemption_transaction(10, 11, blockchain.params.ticket_price - 10);

    c.bench_function("validate_standard_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&standard_tx, current_height)))
    });

    c.bench_function("validate_governance_proposal_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&governance_proposal_tx, current_height)))
    });

    c.bench_function("validate_governance_vote_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&governance_vote_tx, current_height)))
    });

    c.bench_function("validate_coinbase_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&coinbase_tx_val, current_height)))
    });

    c.bench_function("validate_masternode_register_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&masternode_register_tx_val, current_height)))
    });

    c.bench_function("validate_masternode_collateral_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&masternode_collateral_tx_val, current_height)))
    });

    c.bench_function("validate_ticket_purchase_transaction", |b| {
        b.iter(|| black_box(blockchain.validate_transaction(&ticket_purchase_tx_val, current_height)))
    });

    c.bench_function("validate_ticket_redemption_transaction", |b| {
        // Setup for ticket redemption: needs a live ticket and corresponding UTXO
        let mut temp_blockchain = create_test_blockchain();
        let ticket_id_for_bench = rusty_shared_types::TicketId(dummy_hash(100));
        let outpoint_for_bench = rusty_shared_types::OutPoint { txid: dummy_hash(101), vout: 0 };
        let ticket_value_for_bench = temp_blockchain.params.ticket_price;
        let ticket_public_key_for_bench = dummy_public_key(102);
        let ticket_for_bench = rusty_shared_types::Ticket {
            id: ticket_id_for_bench.clone(),
            outpoint: outpoint_for_bench.clone(),
            commitment: dummy_hash(103),
            value: ticket_value_for_bench,
            purchase_block_height: current_height - temp_blockchain.params.ticket_maturity as u64,
            locked_amount: ticket_value_for_bench,
            public_key: ticket_public_key_for_bench,
        };
        temp_blockchain.live_tickets.add_ticket(ticket_for_bench);
        let utxo_for_bench = rusty_shared_types::Utxo {
            output: TxOutput { value: ticket_value_for_bench, script_pubkey: vec![1], memo: None },
            is_coinbase: false,
            creation_height: current_height - temp_blockchain.params.ticket_maturity as u64,
        };
        temp_blockchain.utxo_set.add_utxo(outpoint_for_bench.clone(), utxo_for_bench);

        let tx = create_ticket_redemption_transaction(outpoint_for_bench.txid[0], ticket_id_for_bench.0[0], ticket_value_for_bench - 10);

        b.iter(|| black_box(temp_blockchain.validate_transaction(&tx, current_height)))
    });

    // Setup for add_block benchmarks
    let coinbase_tx = create_coinbase_transaction(blockchain.params.initial_block_reward, blockchain.params.miner_address.clone());
    let standard_tx_for_block = create_standard_transaction(100, 9_000_000_000, 1_000_000_000);
    let governance_proposal_tx_for_block = create_governance_proposal_transaction(200, blockchain.params.proposal_stake_amount);
    let governance_vote_tx_for_block = create_governance_vote_transaction(300, 400);
    let masternode_register_tx_for_block = create_masternode_register_transaction(500);
    let masternode_collateral_tx_for_block = create_masternode_collateral_transaction(600, 10000, 700);
    let ticket_purchase_tx_for_block = create_ticket_purchase_transaction(800, blockchain.params.ticket_price, 900);
    let ticket_redemption_tx_for_block = create_ticket_redemption_transaction(1000, 1100, blockchain.params.ticket_price - 10);

    let block_with_standard_tx = create_dummy_block(
        &mut blockchain,
        current_height + 1,
        vec![coinbase_tx.clone(), standard_tx_for_block.clone()],
    );
    let block_with_governance_proposal_tx = create_dummy_block(
        &mut blockchain,
        current_height + 2,
        vec![coinbase_tx.clone(), governance_proposal_tx_for_block.clone()],
    );
    let block_with_governance_vote_tx = create_dummy_block(
        &mut blockchain,
        current_height + 3,
        vec![coinbase_tx.clone(), governance_vote_tx_for_block.clone()],
    );
    let block_with_masternode_register_tx = create_dummy_block(
        &mut blockchain,
        current_height + 4,
        vec![coinbase_tx.clone(), masternode_register_tx_for_block.clone()],
    );
    let block_with_masternode_collateral_tx = create_dummy_block(
        &mut blockchain,
        current_height + 5,
        vec![coinbase_tx.clone(), masternode_collateral_tx_for_block.clone()],
    );
    let block_with_ticket_purchase_tx = create_dummy_block(
        &mut blockchain,
        current_height + 6,
        vec![coinbase_tx.clone(), ticket_purchase_tx_for_block.clone()],
    );
    let block_with_ticket_redemption_tx = create_dummy_block(
        &mut blockchain,
        current_height + 7,
        vec![coinbase_tx.clone(), ticket_redemption_tx_for_block.clone()],
    );

    c.bench_function("add_block_with_standard_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain(); // Each benchmark needs a fresh blockchain
        b.iter(|| black_box(temp_blockchain.add_block(block_with_standard_tx.clone())))
    });

    c.bench_function("add_block_with_governance_proposal_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        b.iter(|| black_box(temp_blockchain.add_block(block_with_governance_proposal_tx.clone())))
    });

    c.bench_function("add_block_with_governance_vote_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        // To successfully add a block with a governance vote, the proposal must exist in the blockchain's active_proposals
        // This setup is simplified for benchmarking; in a real scenario, the proposal would be added by a previous block.
        let proposal_id_for_vote = dummy_hash(3);
        let proposal_for_vote = GovernanceProposal {
            proposal_id: proposal_id_for_vote,
            proposer_address: dummy_public_key(14),
            proposal_type: ProposalType::PROTOCOL_UPGRADE,
            start_block_height: current_height + 1,
            end_block_height: current_height + 1 + temp_blockchain.params.voting_period_blocks -1,
            title: "Benchmark Vote Proposal".to_string(),
            description_hash: dummy_hash(15),
            code_change_hash: None,
            target_parameter: None,
            new_value: None,
            proposer_signature: dummy_signature(16),
            inputs: vec![],
            outputs: vec![TxOutput { value: temp_blockchain.params.proposal_stake_amount, script_pubkey: vec![] }],
            lock_time: 0,
            witness: vec![],
        };
        temp_blockchain.active_proposals.add_proposal(proposal_for_vote).unwrap();

        b.iter(|| black_box(temp_blockchain.add_block(block_with_governance_vote_tx.clone())))
    });

    c.bench_function("add_block_with_masternode_register_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        b.iter(|| black_box(temp_blockchain.add_block(block_with_masternode_register_tx.clone())))
    });

    c.bench_function("add_block_with_masternode_collateral_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        // To validate MasternodeCollateralTx, the UTXO must exist in the UTXO set.
        let utxo_id_for_bench = OutPoint { txid: dummy_hash(100), vout: 0 };
        let utxo_for_bench = rusty_shared_types::Utxo {
            output: TxOutput { value: 10000, script_pubkey: vec![1], memo: None },
            is_coinbase: false,
            creation_height: 1,
        };
        temp_blockchain.utxo_set.add_utxo(utxo_id_for_bench, utxo_for_bench);
        b.iter(|| black_box(temp_blockchain.add_block(block_with_masternode_collateral_tx.clone())))
    });

    c.bench_function("add_block_with_ticket_purchase_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        // To validate TicketPurchaseTx, the UTXO must exist in the UTXO set.
        let utxo_id_for_bench = OutPoint { txid: dummy_hash(800), vout: 0 };
        let utxo_for_bench = rusty_shared_types::Utxo {
            output: TxOutput { value: temp_blockchain.params.ticket_price, script_pubkey: vec![1], memo: None },
            is_coinbase: false,
            creation_height: 1,
        };
        temp_blockchain.utxo_set.add_utxo(utxo_id_for_bench, utxo_for_bench);
        b.iter(|| black_box(temp_blockchain.add_block(block_with_ticket_purchase_tx.clone())))
    });

    c.bench_function("add_block_with_ticket_redemption_transaction", |b| {
        let mut temp_blockchain = create_test_blockchain();
        // Setup for ticket redemption: needs a live ticket and corresponding UTXO
        let ticket_id_for_bench = rusty_shared_types::TicketId(dummy_hash(1000));
        let outpoint_for_bench = rusty_shared_types::OutPoint { txid: dummy_hash(1001), vout: 0 };
        let ticket_value_for_bench = temp_blockchain.params.ticket_price;
        let ticket_public_key_for_bench = dummy_public_key(1002);
        let ticket_for_bench = rusty_shared_types::Ticket {
            id: ticket_id_for_bench.clone(),
            outpoint: outpoint_for_bench.clone(),
            commitment: dummy_hash(1003),
            value: ticket_value_for_bench,
            purchase_block_height: current_height - temp_blockchain.params.ticket_maturity as u64,
            locked_amount: ticket_value_for_bench,
            public_key: ticket_public_key_for_bench,
        };
        temp_blockchain.live_tickets.add_ticket(ticket_for_bench);
        let utxo_for_bench = rusty_shared_types::Utxo {
            output: TxOutput { value: ticket_value_for_bench, script_pubkey: vec![1], memo: None },
            is_coinbase: false,
            creation_height: current_height - temp_blockchain.params.ticket_maturity as u64,
        };
        temp_blockchain.utxo_set.add_utxo(outpoint_for_bench.clone(), utxo_for_bench);

        b.iter(|| black_box(temp_blockchain.add_block(block_with_ticket_redemption_tx.clone())))
    });

}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);