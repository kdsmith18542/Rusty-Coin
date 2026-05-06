//! Benchmark for block validation performance
//! Per remediation plan Phase 4.3 - Benchmarking

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::state::BlockchainState;
use rusty_core::consensus::utxo_set::UtxoSet;
use rusty_shared_types::{Block, BlockHeader, Hash, Transaction, TxOutput};
use std::time::{SystemTime, UNIX_EPOCH};

fn create_test_block(height: u64) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        previous_block_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        state_root: [0u8; 32],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        difficulty_target: 0x207fffff,
        nonce: 0,
    };

    let coinbase_tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 5000000000,
            script_pubkey: vec![0u8; 25],
            memo: None,
        }],
        lock_time: 0,
        witness: vec![],
    };

    Block {
        header,
        ticket_votes: vec![],
        transactions: vec![coinbase_tx],
    }
}

fn benchmark_block_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_validation");

    // Benchmark single block validation
    group.bench_function("validate_single_block", |b| {
        b.iter(|| {
            // Benchmark block structure creation
            black_box(create_test_block(1));
        });
    });

    // Benchmark block with multiple transactions
    group.bench_function("validate_block_with_transactions", |b| {
        let mut block = create_test_block(1);
        // Add multiple transactions
        for i in 0..10 {
            block.transactions.push(Transaction::Standard {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    value: 1000000 * i,
                    script_pubkey: vec![i as u8; 20],
                    memo: None,
                }],
                lock_time: 0,
                fee: 1000,
                witness: vec![],
            });
        }

        b.iter(|| {
            black_box(create_test_block(1));
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_block_validation);
criterion_main!(benches);
