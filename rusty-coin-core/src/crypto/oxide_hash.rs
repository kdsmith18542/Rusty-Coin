//! OxideHash algorithm implementation for Rusty Coin.

use blake3;
use crate::crypto::Hash;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rand_core::RngCore;
use std::sync::{Arc, Mutex};
use std::thread;

const SCRATCHPAD_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB
const NUM_ITERATIONS: u64 = 1_000_000;
const NUM_THREADS: usize = 4; // Optimized for modern CPUs

pub fn oxide_hash_impl(header: &[u8]) -> Hash {
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];

    // 1. Hash the block header with BLAKE3 to produce a 32-byte seed.
    let seed_bytes: [u8; 32] = *blake3::hash(header).as_bytes();

    // 2. Deterministically generate the 1 GiB pseudo-random dataset
    let mut rng = ChaCha8Rng::from_seed(seed_bytes);
    rng.fill_bytes(&mut scratchpad);

    // 3. Memory-hard mixing (parallel version)
    let scratchpad_arc = Arc::new(Mutex::new(scratchpad));
    let mut handles = vec![];

    for i in 0..NUM_THREADS {
        let scratchpad = Arc::clone(&scratchpad_arc);
        let start = i * (SCRATCHPAD_SIZE / NUM_THREADS);
        let end = (i + 1) * (SCRATCHPAD_SIZE / NUM_THREADS);
        
        handles.push(thread::spawn(move || {
            let mut local_rng = ChaCha8Rng::from_seed(seed_bytes);
            let mut mixer = [0u8; 32];
            
            for _ in 0..NUM_ITERATIONS/NUM_THREADS as u64 {
                // Read-modify-write pattern
                let idx = (local_rng.next_u64() as usize) % (end - start);
                let addr = start + idx;
                
                let mut scratchpad_lock = scratchpad.lock().unwrap();
                // XOR with random data
                for i in 0..32 {
                    scratchpad_lock[addr + i] ^= mixer[i];
                    mixer[i] = mixer[i].wrapping_add(scratchpad_lock[addr + i]);
                }
            }
        }));
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // 4. Final hash with BLAKE3
    let scratchpad = Arc::try_unwrap(scratchpad_arc).unwrap().into_inner().unwrap();
    let final_hash = blake3::hash(&scratchpad);
    
    Hash::from_slice(final_hash.as_bytes()).expect("Failed to create hash from slice")
}