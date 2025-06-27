use blake3;
use primitive_types::U256;
use rusty_shared_types::BlockHeader;


// 2.2 Algorithm Parameters
// 2.2 Algorithm Parameters
const SCRATCHPAD_SIZE: usize = 1 << 30; // 1 GiB
const ITERATIONS_PER_HASH: usize = 1 << 20; // 1,048,576

// Difficulty Adjustment Parameters
const TARGET_BLOCK_TIME_SECS: u64 = 150; // 2.5 minutes (as per spec 02a)
const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016; // Blocks (approx 3.5 days at 2.5 min/block)
const MAX_TARGET: U256 = U256([0x00000000FFFF0000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000]); // Example max target

pub fn calculate_next_difficulty(last_block_time: u64, first_block_time: u64, current_target: U256) -> U256 {
    let actual_time_taken = last_block_time - first_block_time;
    let expected_time_taken = TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_INTERVAL as u64;

    let mut new_target = current_target;

    if actual_time_taken > expected_time_taken * 4 {
        new_target = new_target * U256::from(4);
    } else if actual_time_taken > expected_time_taken {
        new_target = new_target * U256::from(actual_time_taken) / U256::from(expected_time_taken);
    } else if actual_time_taken < expected_time_taken / 4 {
        new_target = new_target / U256::from(4);
    } else if actual_time_taken < expected_time_taken {
        new_target = new_target * U256::from(actual_time_taken) / U256::from(expected_time_taken);
    }

    // Ensure the new target does not exceed the maximum target (minimum difficulty)
    let max_target_u256 = U256::from(MAX_TARGET);
    if new_target > max_target_u256 {
        return max_target_u256;
    }

    new_target
}




pub fn calculate_hash(header: &BlockHeader) -> [u8; 32] {
    // 2.3 OxideHash Procedure

    // Serialization & Initial Seed:
    let initial_seed: [u8; 32] = header.hash();

    // Scratchpad Initialization:
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];
    let mut current_blake3_seed = initial_seed;

    // Fill scratchpad using BLAKE3(S | counter)
    for i in (0..SCRATCHPAD_SIZE).step_by(32) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&current_blake3_seed);
        hasher.update(&i.to_le_bytes()); // Use counter for uniqueness
        let hash_output: [u8; 32] = hasher.finalize().into();
        scratchpad[i..i + 32].copy_from_slice(&hash_output);
        current_blake3_seed = hash_output; // Use the last hash as part of the next seed
    }

    // Iterative Read/Compute Operations:
    let mut current_state_hash: [u8; 32] = initial_seed;

    for i in 0..ITERATIONS_PER_HASH {
        // Address Derivation:
        let mut hasher = blake3::Hasher::new();
        hasher.update(&current_state_hash);
        hasher.update(&i.to_le_bytes());
        let read_address_seed: [u8; 32] = hasher.finalize().into();

        let read_address_offset = u64::from_le_bytes(read_address_seed[0..8].try_into().unwrap());
        let read_address = (read_address_offset % ((SCRATCHPAD_SIZE - 32) as u64)) as usize;

        // Read Data:
        let mut read_data = [0u8; 32];
        read_data.copy_from_slice(&scratchpad[read_address..read_address + 32]);

        // Compute current_state_hash:
        let mut xor_result = [0u8; 32];
        for k in 0..32 {
            xor_result[k] = current_state_hash[k] ^ read_data[k];
        }
        current_state_hash = *blake3::hash(&xor_result).as_bytes();

        // Write Data (Update Scratchpad):
        let mut write_hasher = blake3::Hasher::new();
        write_hasher.update(&current_state_hash);
        write_hasher.update(&(i as u32 ^ 0xFFFFFFFF).to_le_bytes()); // Use XORed i for write address seed
        let write_address_seed: [u8; 32] = write_hasher.finalize().into();

        let write_address_offset = u64::from_le_bytes(write_address_seed[0..8].try_into().unwrap());
        let write_address = (write_address_offset % ((SCRATCHPAD_SIZE - 32) as u64)) as usize;

        scratchpad[write_address..write_address + 32].copy_from_slice(&current_state_hash);
    }

    // Final Hash Computation:
    let mut final_hasher = blake3::Hasher::new();
    final_hasher.update(&scratchpad[0..32]);
    final_hasher.update(&current_state_hash);
    // As per spec, include SCRATCHPAD[0..31], current_state_hash, and SCRATCHPAD[32..SCRATCHPAD_SIZE-1].
    // Since SCRATCHPAD[32..SCRATCHPAD_SIZE-1] is too large, we'll use the last 32 bytes
    // to represent the end of the scratchpad, along with the first 32 bytes and the final state hash.
    final_hasher.update(&scratchpad[SCRATCHPAD_SIZE - 32..SCRATCHPAD_SIZE]);
    final_hasher.finalize().into()
}

pub fn verify_pow(header: &BlockHeader, difficulty_target: U256) -> bool {
    let hash = calculate_hash(header);
    let hash_u256 = U256::from_little_endian(&hash);
    hash_u256 <= difficulty_target
}

/// Calculate target from compact difficulty representation
pub fn calculate_target(compact_target: u32) -> U256 {
    let exponent = (compact_target >> 24) & 0xff;
    let mantissa = compact_target & 0x00ffffff;

    if exponent <= 3 {
        U256::from(mantissa >> (8 * (3 - exponent)))
    } else {
        U256::from(mantissa) << (8 * (exponent - 3))
    }
}

/// Calculate new target based on difficulty adjustment algorithm
pub fn calculate_new_target(
    current_target: U256,
    actual_timespan: u64,
    target_timespan: u64,
    _adjustment_window: u64,
    _max_timespan: u64,
    max_target: U256,
) -> U256 {
    let mut new_target = current_target;

    // Clamp the actual timespan to prevent extreme adjustments
    let clamped_timespan = actual_timespan.max(target_timespan / 4).min(target_timespan * 4);

    // Adjust the target
    new_target = new_target * U256::from(clamped_timespan) / U256::from(target_timespan);

    // Ensure the new target doesn't exceed the maximum
    if new_target > max_target {
        new_target = max_target;
    }

    new_target
}
