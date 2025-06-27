//! Hashing algorithms for Rusty Coin.

use blake3::Hasher as Blake3Hasher;
use blake3::Hash as Blake3Hash;
use sha2::Digest;
use std::convert::TryInto;
use std::boxed::Box;

/// Size of the OxideHash scratchpad in bytes (1 GiB).
const SCRATCHPAD_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

/// Number of iterative read/compute operations per hash.
const ITERATIONS_PER_HASH: u32 = 1_048_576; // 2^20

/// Implements the OxideHash Proof-of-Work algorithm.
///
/// OxideHash is a memory-hard hashing algorithm designed to be GPU-friendly
/// and ASIC-resistant. It uses a large scratchpad and unpredictable memory
/// access patterns.
pub struct OxideHasher {
    scratchpad: Box<[u8; SCRATCHPAD_SIZE]>,
}

impl OxideHasher {
    pub fn new() -> Self {
        OxideHasher {
            scratchpad: Box::new([0u8; SCRATCHPAD_SIZE]),
        }
    }

    /// Computes the OxideHash of a given block header.
    ///
    /// # Arguments
    /// * `header_bytes` - The canonical serialized bytes of the BlockHeader (excluding nonce).
    /// * `nonce` - The nonce value to be included in the final hash calculation.
    ///
    /// # Returns
    /// A 32-byte BLAKE3 hash.
    pub fn calculate_oxide_hash(&mut self, header_bytes: &[u8], nonce: u64) -> Blake3Hash {
        // 1. Serialization & Initial Seed
        let initial_seed = Blake3Hasher::new()
            .update(header_bytes)
            .update(&nonce.to_le_bytes())
            .finalize();

        // 2. Scratchpad Initialization
        for i in (0..SCRATCHPAD_SIZE).step_by(32) {
            let block_seed = Blake3Hasher::new()
                .update(initial_seed.as_bytes())
                .update(&(i as u32).to_le_bytes())
                .finalize();
            self.scratchpad[i..i + 32].copy_from_slice(block_seed.as_bytes());
        }

        // 3. Iterative Read/Compute Operations
        let mut current_state_hash = initial_seed;

        for i in 0..ITERATIONS_PER_HASH {
            // Address Derivation
            let read_address_offset_bytes = Blake3Hasher::new()
                .update(current_state_hash.as_bytes())
                .update(&i.to_le_bytes())
                .finalize();
            let read_address_offset = u64::from_le_bytes(
                read_address_offset_bytes.as_bytes()[0..8]
                    .try_into()
                    .unwrap(),
            );
            let read_address = (read_address_offset % ((SCRATCHPAD_SIZE - 32) as u64)) as usize;

            // Read Data
            let mut read_data = [0u8; 32];
            read_data.copy_from_slice(&self.scratchpad[read_address..read_address + 32]);

            // Compute current_state_hash
            let mut xored_data = [0u8; 32];
            for k in 0..32 {
                xored_data[k] = current_state_hash.as_bytes()[k] ^ read_data[k];
            }
            current_state_hash = Blake3Hasher::new().update(&xored_data).finalize();

            // Write Data (Update Scratchpad)
            let write_address_offset_bytes = Blake3Hasher::new()
                .update(current_state_hash.as_bytes())
                .update(&(!i).to_le_bytes()) // i XOR 0xFFFFFFFF
                .finalize();
            let write_address_offset = u64::from_le_bytes(
                write_address_offset_bytes.as_bytes()[0..8]
                    .try_into()
                    .unwrap(),
            );
            let write_address = (write_address_offset % ((SCRATCHPAD_SIZE - 32) as u64)) as usize;

            self.scratchpad[write_address..write_address + 32]
                .copy_from_slice(current_state_hash.as_bytes());
        }

        // 4. Final Hash Computation
        let final_hash = Blake3Hasher::new()
            .update(&self.scratchpad[0..32])
            .update(current_state_hash.as_bytes())
            .update(&self.scratchpad[32..SCRATCHPAD_SIZE])
            .finalize();

        final_hash
    }
}

/// Calculate SHA256 hash of input data
pub fn calculate_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Represents a Merkle Tree.
pub struct MerkleTree {
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Constructs a Merkle Tree from a list of data blocks.
    pub fn new(data_blocks: &[&[u8]]) -> Self {
        if data_blocks.is_empty() {
            return MerkleTree { nodes: Vec::new() };
        }

        let leaves: Vec<[u8; 32]> = data_blocks
            .iter()
            .map(|block| Blake3Hasher::new().update(block).finalize().into())
            .collect();

        let mut nodes = Vec::new();
        nodes.extend_from_slice(&leaves);

        let mut current_level = leaves;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left // Duplicate last hash if odd number of leaves
                };
                let combined_hash = Blake3Hasher::new()
                    .update(&left)
                    .update(&right)
                    .finalize()
                    .into();
                next_level.push(combined_hash);
                nodes.push(combined_hash);
                i += 2;
            }
            current_level = next_level;
        }

        MerkleTree { nodes }
    }

    /// Returns the Merkle root of the tree.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.nodes.last().cloned()
    }

    /// Computes the Merkle root directly from a list of data blocks without building the full tree.
    pub fn calculate_merkle_root(data_blocks: &[&[u8]]) -> Option<[u8; 32]> {
        if data_blocks.is_empty() {
            return None;
        }

        let leaves: Vec<[u8; 32]> = data_blocks
            .iter()
            .map(|block| Blake3Hasher::new().update(block).finalize().into())
            .collect();

        let mut current_level = leaves;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left // Duplicate last hash if odd number of leaves
                };
                let combined_hash = Blake3Hasher::new()
                    .update(&left)
                    .update(&right)
                    .finalize()
                    .into();
                next_level.push(combined_hash);
                i += 2;
            }
            current_level = next_level;
        }

        current_level.first().cloned()
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::calculate_sha256;

    #[test]
    fn test_calculate_sha256() {
        // Empty input
        let hash = calculate_sha256(&[]);
        assert_eq!(
            hash,
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );

        // Short input
        let hash = calculate_sha256(b"hello");
        assert_eq!(
            hash,
            hex!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );

        // Long input
        let hash = calculate_sha256(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.");
        assert_eq!(
            hash,
            [9, 168, 226, 207, 178, 12, 86, 148, 198, 184, 255, 50, 200, 137, 194, 123, 146, 104, 137, 254, 217, 21, 171, 69, 103, 149, 125, 18, 140, 33, 98, 66]
        );
    }
}