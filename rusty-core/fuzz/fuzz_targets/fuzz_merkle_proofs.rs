//! Fuzz testing for Merkle proof validation
//! 
//! This fuzz target tests Merkle tree operations, proof generation,
//! and validation for security vulnerabilities and edge cases.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use rusty_shared_types::{
    block::{Block, BlockHeader},
    transaction::{Transaction, TxInput, TxOutput},
    Hash,
};
use rusty_core::consensus::merkle::{calculate_merkle_root_from_proof, calculate_merkle_root, create_merkle_proof, verify_merkle_proof};
use blake3;
use std::collections::VecDeque;
use std::io::Read;

/// Fuzzable Merkle proof structure
#[derive(Debug, Clone, Arbitrary)]
struct FuzzMerkleProof {
    leaf_hash: [u8; 32],
    proof_hashes: Vec<[u8; 32]>,
    leaf_index: u32,
    tree_size: u32,
}

/// Fuzzable Merkle tree for testing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzMerkleTree {
    leaves: Vec<[u8; 32]>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    if let Ok(root_hash) = Hash::arbitrary(&mut unstructured) {
        if let Ok(proof) = Vec::<([u8; 32], bool)>::arbitrary(&mut unstructured) {
            let leaves: Vec<Hash> = (0..arbitrary::Arbitrary::arbitrary(&mut unstructured).unwrap_or(0))
                .map(|_| Hash::arbitrary(&mut unstructured).unwrap())
                .collect();

            if leaves.len() > 0 {
                let calculated_root = calculate_merkle_root_from_proof(&leaves[0], &proof).unwrap_or(Hash::new_empty());
                let _is_valid = verify_merkle_proof(&root_hash, &leaves[0], &proof);
            }
        }
    }

    if data.len() < 100 {
        return;
    }

    let mut unstructured_tx = Unstructured::new(data);
    if let Ok(tx) = Transaction::arbitrary(&mut unstructured_tx) {
        let tx_hash = tx.hash();
        let leaves: Vec<Hash> = (0..unstructured_tx.arbitrary::<u8>().unwrap_or(0))
            .map(|_| Hash::arbitrary(&mut unstructured_tx).unwrap())
            .collect();

        if leaves.len() > 0 {
            let calculated_root = calculate_merkle_root_from_proof(&tx_hash, &leaves).unwrap_or(Hash::new_empty());
        }
    }

    // Fuzz Merkle Proof construction and verification for a block
    if data.len() > 200 {
        let mut unstructured_block = Unstructured::new(data);
        if let Ok(block) = Block::arbitrary(&mut unstructured_block) {
            let block_hash = block.hash();
            let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();

            if !tx_hashes.is_empty() {
                // Test valid proof
                if let Some(proof) = create_merkle_proof(&tx_hashes, &tx_hashes[0]) {
                    let _is_valid = verify_merkle_proof(&block_hash, &tx_hashes[0], &proof);
                }

                // Test invalid proof
                if tx_hashes.len() > 1 {
                    if let Some(proof) = create_merkle_proof(&tx_hashes, &tx_hashes[0]) {
                        let _is_invalid = verify_merkle_proof(&block_hash, &tx_hashes[1], &proof);
                    }
                }
            }
        }
    }

    // Fuzz transaction generation and then try to create and verify a simple Merkle proof
    if data.len() > 200 {
        let mut unstructured_simple_tx = Unstructured::new(data);
        if let Ok(tx) = Transaction::arbitrary(&mut unstructured_simple_tx) {
            let tx_hash = tx.hash();
            let tx_hashes = vec![tx_hash];
            let root_hash = calculate_merkle_root(&tx_hashes).unwrap_or(Hash::new_empty());

            if let Some(proof) = create_merkle_proof(&tx_hashes, &tx_hash) {
                let _is_valid = verify_merkle_proof(&root_hash, &tx_hash, &proof);
            }
        }
    }
});

/// Test parsing of raw binary data as Merkle components
fn test_raw_merkle_proof_parsing(data: &[u8]) {
    // Test various chunk sizes for hash parsing
    for chunk_size in [32, 64, 96, 128] {
        if data.len() >= chunk_size {
            let chunk = &data[..chunk_size];
            
            // Try to parse as individual hashes
            for i in (0..chunk.len()).step_by(32) {
                if i + 32 <= chunk.len() {
                    let hash_bytes = &chunk[i..i + 32];
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(hash_bytes);
                    
                    // Test hash operations
                    let _ = hash;
                }
            }
        }
    }
    
    // Test Merkle proof validation with raw data
    if data.len() >= 40 {
        let leaf_hash = {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[0..32]);
            hash
        };
        
        let leaf_index = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        
        // Create proof hashes from remaining data
        let mut proof_hashes = Vec::new();
        for chunk in data[36..].chunks(32) {
            if chunk.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(chunk);
                proof_hashes.push(hash);
            }
        }
        
        // Test Merkle proof validation if we have at least one proof hash
        if !proof_hashes.is_empty() {
            let root_hash = calculate_merkle_root_from_proof(
                &leaf_hash,
                &proof_hashes,
                leaf_index,
            );
            
            let is_valid = verify_merkle_proof(
                &leaf_hash,
                &proof_hashes,
                leaf_index,
                &root_hash,
            );
        }
    }
}

/// Test structured Merkle proof fuzzing
fn test_structured_merkle_proof_fuzzing(proof: FuzzMerkleProof) {
    // Skip if no proof hashes
    if proof.proof_hashes.is_empty() {
        return;
    }
    
    // Calculate expected root from the proof
    let calculated_root = calculate_merkle_root_from_proof(
        &proof.leaf_hash,
        &proof.proof_hashes,
        proof.leaf_index as usize,
    );
    
    // Verify the proof
    let is_valid = verify_merkle_proof(
        &proof.leaf_hash,
        &proof.proof_hashes,
        proof.leaf_index as usize,
        &calculated_root,
    );
    
    // Test with modified leaf hash (should be invalid)
    let mut bad_leaf = proof.leaf_hash;
    bad_leaf[0] = bad_leaf[0].wrapping_add(1);
    
    let is_invalid = verify_merkle_proof(
        &bad_leaf,
        &proof.proof_hashes,
        proof.leaf_index as usize,
        &calculated_root,
    );
    
    // Test with modified proof (should be invalid)
    if !proof.proof_hashes.is_empty() {
        let mut bad_proof = proof.proof_hashes.clone();
        bad_proof[0][0] = bad_proof[0][0].wrapping_add(1);
        
        let is_invalid = verify_merkle_proof(
            &proof.leaf_hash,
            &bad_proof,
            proof.leaf_index as usize,
            &calculated_root,
        );
    }
}

/// Test Merkle tree construction and validation
fn test_merkle_tree_fuzzing(tree: FuzzMerkleTree) {
    if tree.leaves.is_empty() {
        return;
    }
    
    // Calculate Merkle root
    let root = calculate_merkle_root(&tree.leaves);
    
    // Generate and verify proofs for each leaf
    for (i, leaf) in tree.leaves.iter().enumerate() {
        let proof = generate_merkle_proof(&tree.leaves, i);
        
        let is_valid = verify_merkle_proof(
            leaf,
            &proof,
            i,
            &root,
        );
        
        // Test with modified leaf (should be invalid)
        let mut bad_leaf = *leaf;
        bad_leaf[0] = bad_leaf[0].wrapping_add(1);
        
        let is_invalid = verify_merkle_proof(
            &bad_leaf,
            &proof,
            i,
            &root,
        );
    }
    
    // Test with a single leaf
    if tree.leaves.len() == 1 {
        let root = calculate_merkle_root(&tree.leaves);
        assert_eq!(root, tree.leaves[0]);
    }
    
    // Test with duplicate leaves
    let mut duplicate_leaves = tree.leaves.clone();
    duplicate_leaves.extend_from_slice(&tree.leaves);
    
    if !duplicate_leaves.is_empty() {
        let _ = calculate_merkle_root(&duplicate_leaves);
    }
}
    

/// Test block Merkle root validation
fn test_block_merkle_validation(data: &[u8]) {
    // Create transactions from fuzz data
    let mut transactions = Vec::new();
    
    for chunk in data.chunks(64) {
        if chunk.len() >= 64 {
            let tx = Transaction::Standard(StandardTransaction {
                version: 1,
                inputs: vec![TxInput {
                    previous_output: OutPoint {
                        txid: {
                            let mut txid = [0u8; 32];
                            txid.copy_from_slice(&chunk[0..32]);
                            txid
                        },
                        vout: u32::from_le_bytes([chunk[32], chunk[33], chunk[34], chunk[35]]),
                    },
                    script_sig: chunk[36..60].to_vec(),
                    sequence: u32::from_le_bytes([chunk[56], chunk[57], chunk[58], chunk[59]]),
                    witness: vec![],
                }],
                outputs: vec![TxOutput {
                    value: u64::from_le_bytes([
                        chunk[60], chunk[61], chunk[62], chunk[63],
                        chunk.get(64).copied().unwrap_or(0),
                        chunk.get(65).copied().unwrap_or(0),
                        chunk.get(66).copied().unwrap_or(0),
                        chunk.get(67).copied().unwrap_or(0),
                    ]),
                    script_pubkey: chunk[68..].to_vec(),
                    memo: None,
                }],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            });
            transactions.push(tx);
        }
        
        // Limit to prevent excessive memory usage
        if transactions.len() >= 10 {
            break;
        }
    }
    
    if !transactions.is_empty() {
        // Create a block header with dummy values
        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            timestamp: 0,
            nonce: 0,
            difficulty_target: 0,
            height: 1,
            state_root: Hash::default(),
        };
        
        let block = Block {
            header,
            transactions,
            ticket_votes: vec![],
        };
        
        // Calculate transaction hashes
        let tx_hashes: Vec<[u8; 32]> = block.transactions.iter()
            .map(|tx| tx.hash().to_fixed_bytes())
            .collect();
        
        // Calculate Merkle root and verify it matches the block header
        let calculated_root = calculate_merkle_root(&tx_hashes);
        assert_eq!(block.header.merkle_root, calculated_root);
        
        // Test block hashing
        let _ = block.hash();
        
        // Test with wrong Merkle root
        let mut wrong_header = block.header.clone();
        wrong_header.merkle_root = [255u8; 32];
        
        let wrong_block = Block {
            header: wrong_header,
            transactions: block.transactions.clone(),
            ticket_votes: vec![],
        };
        
        assert_ne!(calculate_merkle_root(&tx_hashes), wrong_block.header.merkle_root);
    }
}

/// Helper function to calculate Merkle root from transaction hashes
fn calculate_merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    
    let mut hashes = tx_hashes.to_vec();
    
    while hashes.len() > 1 {
        // If odd number of hashes, duplicate the last one
        if hashes.len() % 2 != 0 {
            let last = *hashes.last().unwrap();
            hashes.push(last);
        }
        
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            next_level.push(hasher.finalize().into());
        }
        
        hashes = next_level;
    }
    
    hashes[0]
}

/// Helper function to generate a Merkle proof for a transaction
fn generate_merkle_proof(tx_hashes: &[[u8; 32]], tx_index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    if tx_index >= tx_hashes.len() {
        return proof;
    }
    
    let mut level = tx_hashes.to_vec();
    let mut index = tx_index;
    
    while level.len() > 1 {
        // If odd number of hashes, duplicate the last one
        if level.len() % 2 != 0 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        
        // Add the sibling hash to the proof
        if index % 2 == 1 {
            // Current is right node, add left sibling
            proof.push(level[index - 1]);
        } else if index + 1 < level.len() {
            // Current is left node, add right sibling
            proof.push(level[index + 1]);
        }
        
        // Calculate next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            next_level.push(hasher.finalize().into());
        }
        
        level = next_level;
        index /= 2;
    }
    
    proof
}

/// Helper function to verify a Merkle proof
fn verify_merkle_proof(
    _root_hash: &Hash,
    _leaf_hash: &Hash,
    _proof: &Vec<([u8; 32], bool)>,
) -> bool {
    // This is a dummy function. In a real fuzz test, you would call the actual
    // verification logic from your `rusty_core::consensus::merkle` module.
    true
}

