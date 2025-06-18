use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_coin_core::crypto::oxide_hash::oxide_hash_impl;

fn oxide_hash_benchmark(c: &mut Criterion) {
    let test_data = vec![0u8; 80]; // Standard block header size
    
    c.benchmark_group("OxideHash")
        .sample_size(10) // Fewer samples due to long runtime
        .measurement_time(std::time::Duration::from_secs(30))
        .bench_function("full_hash", |b| {
            b.iter(|| oxide_hash_impl(black_box(&test_data)))
        });
}

criterion_group! {
    name = benches;
    config = Criterion::default().warm_up_time(std::time::Duration::from_secs(5));
    targets = oxide_hash_benchmark
}

criterion_main!(benches);