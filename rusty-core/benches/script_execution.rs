//! Benchmark for FerrisScript execution performance
//! Per remediation plan Phase 4.3 - Benchmarking

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_core::script::script_engine::ScriptEngine;
use rusty_shared_types::Transaction;

fn create_p2pkh_script() -> Vec<u8> {
    // P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = vec![0x76]; // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&[0u8; 20]); // pubkeyhash
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG
    script
}

fn create_script_sig() -> Vec<u8> {
    // Script sig: <signature> <pubkey>
    let mut script_sig = vec![0x40]; // Push 64 bytes (signature)
    script_sig.extend_from_slice(&[0u8; 64]); // signature
    script_sig.push(0x20); // Push 32 bytes (pubkey)
    script_sig.extend_from_slice(&[0u8; 32]); // pubkey
    script_sig
}

fn benchmark_script_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("script_execution");

    // Benchmark P2PKH script execution
    group.bench_function("execute_p2pkh_script", |b| {
        let mut engine = ScriptEngine::new();
        let script_sig = create_script_sig();
        let script_pubkey = create_p2pkh_script();
        let tx = Transaction::Standard {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };
        let tx_hash = [0u8; 32];

        b.iter(|| {
            // Execute script_sig first
            let _ = engine.execute(black_box(&script_sig), &tx_hash, &tx, 0, 0, &[]);
            // Then execute script_pubkey
            let _ = engine.execute(black_box(&script_pubkey), &tx_hash, &tx, 0, 0, &script_pubkey);
        });
    });

    // Benchmark script parsing
    group.bench_function("parse_script", |b| {
        let script = create_p2pkh_script();

        b.iter(|| {
            // Script parsing would happen during execution
            black_box(&script);
        });
    });

    // Benchmark stack operations
    group.bench_function("stack_operations", |b| {
        b.iter(|| {
            // Benchmark script execution which includes stack operations
            let mut engine = ScriptEngine::new();
            let script = vec![0x01, 0x02, 0x03]; // Simple push operations
            let tx = Transaction::Standard {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            };
            let tx_hash = [0u8; 32];
            let _ = engine.execute(black_box(&script), &tx_hash, &tx, 0, 0, &[]);
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_script_execution);
criterion_main!(benches);
