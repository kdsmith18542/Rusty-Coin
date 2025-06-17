//! OxideHash algorithm implementation for Rusty Coin.

use blake3;
use crate::crypto::Hash;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rand_core::RngCore;

const SCRATCHPAD_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB
const NUM_ITERATIONS: u64 = 1_000_000; // Placeholder for millions of iterations

pub fn oxide_hash_impl(header: &[u8]) -> Hash {
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];

    // 1. Hash the block header with BLAKE3 to produce a 32-byte seed.
    let seed_bytes: [u8; 32] = *blake3::hash(header).as_bytes();

    // Deterministically generate the 1 GiB pseudo-random dataset (Scratchpad)
    let mut rng = ChaCha8Rng::from_seed(seed_bytes);
    rng.fill_bytes(&mut scratchpad);

    // Initialize an index based on the seed, to make the access patterns dependent
    let mut current_byte_index = u64::from_le_bytes(seed_bytes[0..8].try_into().unwrap()) as usize % SCRATCHPAD_SIZE;

    for i in 0..NUM_ITERATIONS {
        // Ensure current_byte_index is within bounds for reading 8 bytes
        let read_offset = current_byte_index % (SCRATCHPAD_SIZE - 8);
        let value = u64::from_le_bytes(scratchpad[read_offset..read_offset + 8].try_into().unwrap());

        // Perform some operation (addition, rotation)
        let new_value = value.wrapping_add(i) // Add iteration number for more dynamism
                             .rotate_left((value % 64) as u32); // Rotate based on value

        let new_value_bytes = new_value.to_le_bytes();

        // Write to a new location derived from the new_value
        let write_offset = (new_value as usize) % (SCRATCHPAD_SIZE - 8);
        scratchpad[write_offset..write_offset + 8].copy_from_slice(&new_value_bytes);

        // Update the current_byte_index based on the modified value
        current_byte_index = (new_value as usize) % SCRATCHPAD_SIZE;
    }

    // After millions of iterations, the final state is hashed one last time with BLAKE3
    Hash::blake3(&scratchpad)
} 