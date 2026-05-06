//! Benchmark for cryptographic hash operations
//! Per remediation plan Phase 4.3 - Benchmarking

use blake3;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_hash_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_operations");

    // Benchmark BLAKE3 hashing
    group.bench_function("blake3_hash_small", |b| {
        let data = vec![0u8; 32];

        b.iter(|| {
            let hash = blake3::hash(black_box(&data));
            black_box(hash);
        });
    });

    group.bench_function("blake3_hash_medium", |b| {
        let data = vec![0u8; 1024];

        b.iter(|| {
            let hash = blake3::hash(black_box(&data));
            black_box(hash);
        });
    });

    group.bench_function("blake3_hash_large", |b| {
        let data = vec![0u8; 1024 * 1024]; // 1MB

        b.iter(|| {
            let hash = blake3::hash(black_box(&data));
            black_box(hash);
        });
    });

    // Benchmark incremental hashing
    group.bench_function("blake3_incremental", |b| {
        let data = vec![0u8; 1024];

        b.iter(|| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(black_box(&data));
            let hash = hasher.finalize();
            black_box(hash);
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_hash_operations);
criterion_main!(benches);
