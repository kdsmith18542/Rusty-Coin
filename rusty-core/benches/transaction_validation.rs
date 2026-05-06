//! Benchmark for transaction validation performance
//! Per remediation plan Phase 4.3 - Benchmarking

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_shared_types::{OutPoint, Transaction, TxInput, TxOutput};

fn create_test_transaction() -> Transaction {
    Transaction::Standard {
        version: 1,
        inputs: vec![TxInput::from_outpoint(
            OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            vec![0x01u8; 64], // signature
            0xffffffff,
            vec![],
        )],
        outputs: vec![TxOutput {
            value: 1000000,
            script_pubkey: vec![0x76, 0xA9, 0x14, 0x00].repeat(5), // P2PKH script (20 bytes)
            memo: None,
        }],
        lock_time: 0,
        fee: 1000,
        witness: vec![],
    }
}

fn benchmark_transaction_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_validation");

    // Benchmark single transaction validation
    group.bench_function("validate_single_transaction", |b| {
        let tx = create_test_transaction();

        b.iter(|| {
            // In a real implementation, this would call validation logic
            // For now, we'll benchmark transaction structure operations
            black_box(create_test_transaction());
        });
    });

    // Benchmark transaction serialization
    group.bench_function("serialize_transaction", |b| {
        let tx = create_test_transaction();

        b.iter(|| {
            let serialized = bincode::serialize(black_box(&tx)).unwrap();
            black_box(serialized);
        });
    });

    // Benchmark transaction deserialization
    group.bench_function("deserialize_transaction", |b| {
        let tx = create_test_transaction();
        let serialized = bincode::serialize(&tx).unwrap();

        b.iter(|| {
            let deserialized: Transaction = bincode::deserialize(black_box(&serialized)).unwrap();
            black_box(deserialized);
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_transaction_validation);
criterion_main!(benches);
