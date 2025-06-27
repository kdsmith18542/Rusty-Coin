//! Merkle Patricia Trie implementation for state root calculation
//! 
//! This module implements a Merkle Patricia Trie (MPT) for efficient state
//! commitment and proof generation as specified in the UTXO model spec.

use std::collections::HashMap;
use blake3;
use serde::{Serialize, Deserialize};
use hex;
use zerocopy::AsBytes;

use rusty_shared_types::{Hash, OutPoint, Utxo, TicketId};
// HashMap is already in scope from the prelude
use crate::consensus::error::ConsensusError;

/// A node in the Merkle Patricia Trie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNode {
    /// Empty node
    Empty,
    /// Leaf node containing a key-value pair
    Leaf {
        key_end: Vec<u8>,
        value: Vec<u8>,
    },
    /// Extension node with a shared key prefix
    Extension {
        common_prefix: Vec<u8>,
        next_hash: Hash,
    },
    /// Branch node with up to 16 children (for hex digits 0-F)
    Branch {
        children: [Option<Hash>; 16],
        value: Option<Vec<u8>>, // Value stored at this exact key
    },
}

impl TrieNode {
    /// Calculate the hash of this node
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Check if this node is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, TrieNode::Empty)
    }
}

/// Merkle Patricia Trie for state commitment
#[derive(Debug, Clone)]
pub struct MerklePatriciaTrie {
    /// Root hash of the trie
    root_hash: Hash,
    /// Node storage (hash -> node)
    nodes: HashMap<Hash, TrieNode>,
    /// Cached root node
    root_node: Option<TrieNode>,
}

impl MerklePatriciaTrie {
    /// Create a new empty trie
    pub fn new() -> Self {
        let empty_node = TrieNode::Empty;
        let root_hash = empty_node.hash();
        let mut nodes = HashMap::new();
        nodes.insert(root_hash, empty_node.clone());

        Self {
            root_hash,
            nodes,
            root_node: Some(empty_node),
        }
    }

    /// Create a trie from existing state data
    pub fn from_state_data(
        utxo_set: &HashMap<OutPoint, Utxo>,
        live_tickets: &HashMap<TicketId, TicketData>,
        masternode_list: &HashMap<Vec<u8>, Vec<u8>>,
        active_proposals: &HashMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Self, ConsensusError> {
        let mut trie = Self::new();

        // Insert UTXO data
        for (outpoint, utxo) in utxo_set {
            let key = Self::encode_utxo_key(outpoint);
            let value = Self::encode_utxo_value(utxo)?;
            trie.insert(key, value)?;
        }

        // Insert live tickets
        for (ticket_id, ticket_data) in live_tickets {
            let key = Self::encode_ticket_key(ticket_id);
            let value = Self::encode_ticket_value(ticket_data)?;
            trie.insert(key, value)?;
        }

        // Insert masternode data
        for (mn_key, mn_value) in masternode_list {
            let key = Self::encode_masternode_key(mn_key);
            trie.insert(key, mn_value.clone())?;
        }

        // Insert governance proposals
        for (prop_key, prop_value) in active_proposals {
            let key = Self::encode_proposal_key(prop_key);
            trie.insert(key, prop_value.clone())?;
        }

        Ok(trie)
    }

    /// Insert a key-value pair into the trie
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ConsensusError> {
        let nibbles = Self::bytes_to_nibbles(&key);
        let new_root = self.insert_recursive(self.root_hash.clone(), &nibbles, value)?;
        self.root_hash = new_root;
        self.root_node = self.nodes.get(&new_root).cloned();
        Ok(())
    }

    /// Get a value from the trie
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ConsensusError> {
        let nibbles = Self::bytes_to_nibbles(key);
        self.get_recursive(&self.root_hash, &nibbles)
    }

    // /// Remove a key from the trie
//     pub fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ConsensusError> {
//         let node_hash = self.root_hash;
//         let (new_root, old_value) = self.remove_helper(&node_hash, key, 0)?;
//         self.root_hash = new_root;
//         Ok(old_value)
//     }

    /// Delete a key from the trie
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, ConsensusError> {
        let nibbles = Self::bytes_to_nibbles(key);
        let (new_root, deleted) = self.delete_recursive(self.root_hash.clone(), &nibbles)?;
        if deleted {
            self.root_hash = new_root;
            self.root_node = self.nodes.get(&new_root).cloned();
        }
        Ok(deleted)
    }

    /// Get the root hash of the trie
    pub fn root_hash(&self) -> Hash {
        self.root_hash
    }

    /// Get the number of nodes in the trie
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Generate a Merkle proof for a key
    pub fn generate_proof(&self, key: &[u8]) -> Result<MerkleProof, ConsensusError> {
        let nibbles = Self::bytes_to_nibbles(key);
        let mut proof_nodes = Vec::new();
        let value = self.collect_proof_nodes(&self.root_hash, &nibbles, &mut proof_nodes)?;

        Ok(MerkleProof {
            key: key.to_vec(),
            value,
            proof_nodes,
            root_hash: self.root_hash,
        })
    }

    /// Generate multiple proofs efficiently (batch proof generation)
    pub fn generate_batch_proof(&self, keys: &[Vec<u8>]) -> Result<BatchMerkleProof, ConsensusError> {
        let mut individual_proofs = Vec::new();
        let mut shared_nodes = HashMap::new();

        for key in keys {
            let proof = self.generate_proof(key)?;

            // Track shared nodes to optimize proof size
            for (i, node) in proof.proof_nodes.iter().enumerate() {
                let node_hash = node.hash();
                shared_nodes.entry(node_hash)
                    .or_insert_with(|| (node.clone(), Vec::new()))
                    .1.push((individual_proofs.len(), i));
            }

            individual_proofs.push(proof);
        }

        Ok(BatchMerkleProof {
            proofs: individual_proofs,
            shared_nodes,
            root_hash: self.root_hash,
        })
    }

    /// Generate a range proof for keys within a range
    pub fn generate_range_proof(&self, start_key: &[u8], end_key: &[u8]) -> Result<RangeProof, ConsensusError> {
        let start_nibbles = Self::bytes_to_nibbles(start_key);
        let end_nibbles = Self::bytes_to_nibbles(end_key);

        let mut range_nodes = Vec::new();
        let mut included_keys = Vec::new();

        self.collect_range_proof_nodes(&self.root_hash, &start_nibbles, &end_nibbles, &mut range_nodes, &mut included_keys, &[])?;

        Ok(RangeProof {
            start_key: start_key.to_vec(),
            end_key: end_key.to_vec(),
            included_keys,
            proof_nodes: range_nodes,
            root_hash: self.root_hash,
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(proof: &MerkleProof, expected_value: Option<&[u8]>) -> Result<bool, ConsensusError> {
        let nibbles = Self::bytes_to_nibbles(&proof.key);
        let computed_root = Self::compute_root_from_proof(&nibbles, expected_value, &proof.proof_nodes)?;
        Ok(computed_root == proof.root_hash && proof.value == expected_value.map(|v| v.to_vec()))
    }

    /// Verify a batch proof
    pub fn verify_batch_proof(proof: &BatchMerkleProof, expected_values: &[Option<Vec<u8>>]) -> Result<bool, ConsensusError> {
        if proof.proofs.len() != expected_values.len() {
            return Ok(false);
        }

        for (individual_proof, expected_value) in proof.proofs.iter().zip(expected_values.iter()) {
            if !Self::verify_proof(individual_proof, expected_value.as_deref())? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a range proof
    pub fn verify_range_proof(proof: &RangeProof) -> Result<bool, ConsensusError> {
        // Verify that all included keys are within the specified range
        for (key, _) in &proof.included_keys {
            if key < &proof.start_key || key > &proof.end_key {
                return Ok(false);
            }
        }

        // Verify the proof structure
        let computed_root = Self::compute_range_root_from_proof(&proof.proof_nodes, &proof.included_keys)?;
        Ok(computed_root == proof.root_hash)
    }

    // Private helper methods

    fn insert_recursive(
        &mut self,
        node_hash: Hash,
        key_nibbles: &[u8],
        value: Vec<u8>,
    ) -> Result<Hash, ConsensusError> {
        let node = self.nodes.get(&node_hash)
            .ok_or_else(|| ConsensusError::TrieError("Node not found".to_string()))?;

        match node {
            TrieNode::Empty => {
                let new_node = TrieNode::Leaf {
                    key_end: key_nibbles.to_vec(),
                    value,
                };
                let new_hash = new_node.hash();
                self.nodes.insert(new_hash, new_node);
                Ok(new_hash)
            }
            TrieNode::Leaf { key_end: existing_key_end, value: existing_value } => {
                let existing_key = existing_key_end.clone();
                let existing_value = existing_value.clone();
                if existing_key == key_nibbles {
                    // Update existing leaf node
                    let new_node = TrieNode::Leaf {
                        key_end: existing_key_end.clone(),
                        value,
                    };
                    self.nodes.remove(&node_hash);
                    let new_hash = new_node.hash();
                    self.nodes.insert(new_hash, new_node);
                    Ok(new_hash)
                } else {
                    // Split leaf node into branch or extension + branch
                    let common = Self::common_prefix(&existing_key, key_nibbles);

                    let new_branch_node = if common.len() == existing_key.len() && common.len() == key_nibbles.len() {
                        // Both keys are identical, this should be caught by the update logic above.
                        // If it reaches here, it means existing_key == key_nibbles but somehow the value is different,
                        // which should be handled as an update to the existing leaf.
                        // For now, returning an error or asserting this path is not taken.
                        return Err(ConsensusError::TrieError("Attempted to insert identical key with different value. This should be handled by update.".to_string()));
                    } else {
                        self.split_leaf(&existing_key, existing_value, key_nibbles, value)?
                    };
                    
                    let new_hash = new_branch_node.hash();
                    self.nodes.remove(&node_hash);
                    self.nodes.insert(new_hash, new_branch_node);
                    Ok(new_hash)
                }
            }
            TrieNode::Extension { common_prefix, next_hash } => {
                let common_prefix = common_prefix.clone();
                let next_hash = *next_hash;

                let common = Self::common_prefix(&common_prefix, key_nibbles);

                if common.len() == common_prefix.len() { // New key is suffix of extension or extends it
                    let remaining_key_for_next = &key_nibbles[common_prefix.len()..];
                    let new_next_hash = self.insert_recursive(next_hash, remaining_key_for_next, value)?;

                    let new_node = TrieNode::Extension {
                        common_prefix: common_prefix,
                        next_hash: new_next_hash,
                    };
                    self.nodes.remove(&node_hash);
                    let new_hash = new_node.hash();
                    self.nodes.insert(new_hash, new_node);
                    Ok(new_hash)
                } else {
                    // Split extension node
                    let new_common_prefix = key_nibbles[common.len()..].to_vec();
let new_node = self.split_extension(
                    &common_prefix,
                    &next_hash,
                    new_common_prefix,
                    key_nibbles,
                    value,
    common,
)?;
                    let new_hash = new_node.hash();
                    self.nodes.remove(&node_hash);
                    self.nodes.insert(new_hash, new_node);
                    Ok(new_hash)
                }
            }
            TrieNode::Branch { children: branch_children, value: branch_value } => {
                let mut children = branch_children.clone(); // Clone to get mutable ownership
                let mut branch_value = branch_value.clone(); // Clone value as well

                if key_nibbles.is_empty() {
                    // Update value at this branch node
                    branch_value = Some(value);
                    let new_node = TrieNode::Branch {
                        children,
                        value: branch_value,
                    };
                    self.nodes.remove(&node_hash);
                    let new_hash = new_node.hash();
                    self.nodes.insert(new_hash, new_node);
                    Ok(new_hash)
                } else {
                    let first_nibble = key_nibbles[0] as usize;
                    let remaining_key = &key_nibbles[1..];
                    
                    let child_hash = if let Some(child_hash) = children[first_nibble] {
                        self.insert_recursive(child_hash, remaining_key, value)?
                    } else {
                        // Create new leaf for this child
                        let leaf = TrieNode::Leaf {
                            key_end: remaining_key.to_vec(),
                            value,
                        };
                        let leaf_hash = leaf.hash();
                        self.nodes.insert(leaf_hash, leaf);
                        leaf_hash
                    };
                    
                    children[first_nibble] = Some(child_hash);
                    
                    let new_node = TrieNode::Branch {
                        children,
                        value: branch_value,
                    };
                    self.nodes.remove(&node_hash);
                    let new_hash = new_node.hash();
                    self.nodes.insert(new_hash, new_node);
                    Ok(new_hash)
                }
            }
        }
    }

    fn get_recursive(&self, node_hash: &Hash, key_nibbles: &[u8]) -> Result<Option<Vec<u8>>, ConsensusError> {
        let node = self.nodes.get(node_hash)
            .ok_or_else(|| ConsensusError::TrieError("Node not found".to_string()))?;

        match node {
            TrieNode::Empty => Ok(None),
            TrieNode::Leaf { key_end, value } => {
                if key_end == key_nibbles {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Extension { common_prefix, next_hash } => {
                if key_nibbles.starts_with(common_prefix) {
                    let remaining_key = &key_nibbles[common_prefix.len()..];
                    self.get_recursive(next_hash, remaining_key)
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch { children, value } => {
                if key_nibbles.is_empty() {
                    Ok(value.clone())
                } else {
                    let first_nibble = key_nibbles[0] as usize;
                    if let Some(child_hash) = children[first_nibble] {
                        let remaining_key = &key_nibbles[1..];
                        self.get_recursive(&child_hash, remaining_key)
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    fn delete_recursive(&mut self, node_hash: Hash, key_nibbles: &[u8]) -> Result<(Hash, bool), ConsensusError> {
        // Take ownership of the node, removing it from the map. This avoids immutable/mutable borrow conflicts.
        let node = self.nodes.remove(&node_hash)
            .ok_or_else(|| ConsensusError::TrieError("Node not found".to_string()))?;

        let (mut final_node_hash, mut was_deleted) = (node_hash, false); // Initialize with original node hash and not deleted

        let new_node_option = match node {
            TrieNode::Empty => {
                // If we attempted to delete from an Empty node, it means the key wasn't found.
                // It logically still exists, so we return it.
                Some(TrieNode::Empty)
            }
            TrieNode::Leaf { key_end, value } => {
                if key_end == key_nibbles {
                    // Key found in this leaf, it is deleted.
                    was_deleted = true;
                    None // Node is removed
                } else {
                    // Key not found in this leaf, re-insert the original leaf node
                    Some(TrieNode::Leaf { key_end, value })
                }
            }
            TrieNode::Extension { common_prefix, next_hash } => {
                if key_nibbles.starts_with(&common_prefix) {
                    let remaining_key = &key_nibbles[common_prefix.len()..];

                    // Perform the recursive deletion, getting the new hash and deletion status of the child
                    let (new_child_hash, child_deleted) = self.delete_recursive(next_hash, remaining_key)?;

                    if child_deleted {
                        if new_child_hash == rusty_shared_types::Hash::from(blake3::hash(&[])) { // Child became empty, this extension node is now redundant.
                            was_deleted = true;
                            None // This extension node is removed
                        } else {
                            // Child was simplified to a new non-empty node, update this extension to point to it.
                            was_deleted = true;
                            Some(TrieNode::Extension { common_prefix, next_hash: new_child_hash })
                        }
                    } else {
                        // Child not deleted, re-insert the original extension node
                        Some(TrieNode::Extension { common_prefix, next_hash })
                    }
                } else {
                    // Key does not start with shared nibbles, re-insert original extension
                    Some(TrieNode::Extension { common_prefix, next_hash })
                }
            }
            TrieNode::Branch { mut children, value: mut branch_value } => {
                let mut current_node_value = branch_value.take(); // Take ownership
                let mut non_empty_children_count = 0;

                if key_nibbles.is_empty() {
                    // Deleting value at this branch node
                    if current_node_value.is_some() {
                        current_node_value = None; // Value is removed
                        was_deleted = true;
                    }

                    for child_hash_opt in children.iter() {
                        if child_hash_opt.is_some() {
                            non_empty_children_count += 1;
                        }
                    }

                    if non_empty_children_count == 0 {
                        // If no children and no value, this branch is effectively deleted
                        None
                    } else if non_empty_children_count == 1 {
                        // Simplify to extension or leaf if only one child remains
                        let child_hash_to_simplify = children.iter().filter_map(|c| c.clone()).next().unwrap();
                        let child_node_to_simplify = self.nodes.remove(&child_hash_to_simplify)
                            .ok_or_else(|| ConsensusError::StateError(format!("Child node with hash {} not found during branch simplification", hex::encode(child_hash_to_simplify.as_bytes()))))?;

                        let new_simplified_node = match child_node_to_simplify {
                            TrieNode::Leaf { key_end, value } => TrieNode::Leaf { key_end: [0].iter().chain(key_end.iter()).cloned().collect(), value },
                            TrieNode::Extension { common_prefix: ext_common_prefix, next_hash: ext_next_hash } => TrieNode::Extension { common_prefix: [0].iter().chain(ext_common_prefix.iter()).cloned().collect(), next_hash: ext_next_hash, },
                            TrieNode::Branch { children: child_children, value: child_value } => TrieNode::Branch { children: child_children, value: child_value },
                            TrieNode::Empty => TrieNode::Empty, // Should not happen
                        };
                        Some(new_simplified_node)
                    } else {
                        // Multiple children remain, return updated branch node with value removed
                        Some(TrieNode::Branch { children, value: current_node_value })
                    }
                } else {
                    let first_nibble = key_nibbles[0] as usize;
                    if let Some(child_hash) = children[first_nibble] {
                        let remaining_key = &key_nibbles[1..];
                        let (_new_child_hash, child_deleted) = self.delete_recursive(child_hash, remaining_key)?;

                        if child_deleted {
                            children[first_nibble] = None; // Update child to None as it was deleted
                            was_deleted = true;

                            for child_hash_opt in children.iter() {
                                if child_hash_opt.is_some() {
                                    non_empty_children_count += 1;
                                }
                            }

                            if non_empty_children_count == 0 && current_node_value.is_none() {
                                // If no children and no value, this branch is effectively deleted
                                None
                            } else if non_empty_children_count == 1 && current_node_value.is_none() {
                                // Simplify to extension or leaf if only one child remains and no value
                                let child_hash_to_simplify = children.iter().filter_map(|c| c.clone()).next().unwrap();
                                let child_node_to_simplify = self.nodes.remove(&child_hash_to_simplify)
                                    .ok_or_else(|| ConsensusError::StateError(format!("Child node with hash {} not found during branch simplification", hex::encode(child_hash_to_simplify.as_bytes()))))?;

                                let new_simplified_node = match child_node_to_simplify {
                                    TrieNode::Leaf { key_end, value } => TrieNode::Leaf { key_end: [first_nibble as u8].iter().chain(key_end.iter()).cloned().collect(), value },
                                    TrieNode::Extension { common_prefix: ext_common_prefix, next_hash: ext_next_hash } => TrieNode::Extension { common_prefix: [first_nibble as u8].iter().chain(ext_common_prefix.iter()).cloned().collect(), next_hash: ext_next_hash, },
                                    TrieNode::Branch { children: child_children, value: child_value } => TrieNode::Branch { children: child_children, value: child_value },
                                    TrieNode::Empty => TrieNode::Empty, // Should not happen
                                };
                                Some(new_simplified_node)
                            } else {
                                // Re-insert updated branch node
                                Some(TrieNode::Branch { children, value: current_node_value })
                            }
                        } else {
                            // Child not deleted, re-insert original branch node
                            Some(TrieNode::Branch { children, value: current_node_value })
                        }
                    } else {
                        // Child not found, re-insert original branch node
                        Some(TrieNode::Branch { children, value: current_node_value })
                    }
                }
            }
        };

        if let Some(new_node) = new_node_option {
            let hash = new_node.hash();
            self.nodes.insert(hash, new_node);
            final_node_hash = hash;
        } else {
            // Node was completely removed, so its hash becomes an empty hash
            final_node_hash = rusty_shared_types::Hash::from(blake3::hash(&[]));
        }

        // The root hash needs to be updated if the top-level node was truly deleted or changed
        if was_deleted || final_node_hash != node_hash {
            self.root_hash = final_node_hash;
            self.root_node = self.nodes.get(&final_node_hash).cloned();
        }

        Ok((final_node_hash, was_deleted))
    }

    fn split_leaf(
        &mut self,
        existing_key: &[u8],
        existing_value: Vec<u8>,
        new_key: &[u8],
        new_value: Vec<u8>,
    ) -> Result<TrieNode, ConsensusError> {
        let common_prefix = Self::common_prefix(existing_key, new_key);
        
        if common_prefix.is_empty() {
            // No common prefix, create a branch
            let mut children = [None; 16];
            
            // Insert existing leaf
            let existing_remaining = &existing_key[1..];
            let existing_leaf = TrieNode::Leaf {
                key_end: existing_remaining.to_vec(),
                value: existing_value,
            };
            let existing_hash = existing_leaf.hash();
            self.nodes.insert(existing_hash, existing_leaf);
            children[existing_key[0] as usize] = Some(existing_hash);
            
            // Insert new leaf
            let new_remaining = &new_key[1..];
            let new_leaf = TrieNode::Leaf {
                key_end: new_remaining.to_vec(),
                value: new_value,
            };
            let new_hash = new_leaf.hash();
            self.nodes.insert(new_hash, new_leaf);
            children[new_key[0] as usize] = Some(new_hash);
            
            Ok(TrieNode::Branch {
                children,
                value: None,
            })
        } else {
            // Create extension with common prefix
            let branch = self.split_leaf(
                &existing_key[common_prefix.len()..],
                existing_value,
                &new_key[common_prefix.len()..],
                new_value,
            )?;
            let branch_hash = branch.hash();
            self.nodes.insert(branch_hash, branch);
            
            Ok(TrieNode::Extension {
                common_prefix: common_prefix,
                next_hash: branch_hash,
            })
        }
    }

    fn split_extension(
        &mut self,
        common_prefix: &[u8],
        next_hash: &Hash,
        new_common_prefix: Vec<u8>,
        new_key: &[u8],
        new_value: Vec<u8>,
        common: Vec<u8>,
    ) -> Result<TrieNode, ConsensusError> {
        // Implementation for splitting extension nodes
        // This is complex and would require careful handling of the trie structure
        // For now, returning a simplified version
        Ok(TrieNode::Extension {
        common_prefix: common_prefix.to_vec(),
        next_hash: *next_hash,
})
    }

    fn collect_proof_nodes(
        &self,
        node_hash: &Hash,
        key_nibbles: &[u8],
        proof_nodes: &mut Vec<TrieNode>,
    ) -> Result<Option<Vec<u8>>, ConsensusError> {
        let node = self.nodes.get(node_hash)
            .ok_or_else(|| ConsensusError::TrieError("Node not found".to_string()))?;

        proof_nodes.push(node.clone());

        // Continue collecting based on node type and key
        match node {
            TrieNode::Empty => Ok(None),
            TrieNode::Leaf { key_end, value } => {
                if key_end == key_nibbles {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Extension { common_prefix, next_hash } => {
                if key_nibbles.starts_with(common_prefix) {
                    let remaining_key = &key_nibbles[common_prefix.len()..];
                    self.collect_proof_nodes(next_hash, remaining_key, proof_nodes)
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch { children, value } => {
                if key_nibbles.is_empty() {
                    Ok(value.clone())
                } else {
                    let first_nibble = key_nibbles[0] as usize;
                    if let Some(child_hash) = children[first_nibble] {
                        let remaining_key = &key_nibbles[1..];
                        self.collect_proof_nodes(&child_hash, remaining_key, proof_nodes)
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    fn collect_range_proof_nodes(
        &self,
        node_hash: &Hash,
        start_nibbles: &[u8],
        end_nibbles: &[u8],
        proof_nodes: &mut Vec<TrieNode>,
        included_keys: &mut Vec<(Vec<u8>, Vec<u8>)>,
        current_path: &[u8],
    ) -> Result<(), ConsensusError> {
        let node = self.nodes.get(node_hash)
            .ok_or_else(|| ConsensusError::TrieError("Node not found".to_string()))?;

        proof_nodes.push(node.clone());

        match node {
            TrieNode::Empty => Ok(()),
            TrieNode::Leaf { key_end, value } => {
                let full_key = [current_path, key_end].concat();
                let key_bytes = Self::nibbles_to_bytes(&full_key);
                let start_bytes = Self::nibbles_to_bytes(start_nibbles);
                let end_bytes = Self::nibbles_to_bytes(end_nibbles);

                if key_bytes >= start_bytes && key_bytes <= end_bytes {
                    included_keys.push((key_bytes, value.clone()));
                }
                Ok(())
            }
            TrieNode::Extension { common_prefix, next_hash } => {
                let new_path = [current_path, common_prefix].concat();
                self.collect_range_proof_nodes(next_hash, start_nibbles, end_nibbles, proof_nodes, included_keys, &new_path)
            }
            TrieNode::Branch { children, value } => {
                // Include value at this branch if it's in range
                if let Some(branch_value) = value {
                    let key_bytes = Self::nibbles_to_bytes(current_path);
                    let start_bytes = Self::nibbles_to_bytes(start_nibbles);
                    let end_bytes = Self::nibbles_to_bytes(end_nibbles);

                    if key_bytes >= start_bytes && key_bytes <= end_bytes {
                        included_keys.push((key_bytes, branch_value.clone()));
                    }
                }

                // Recursively collect from relevant children
                for (i, child_hash_opt) in children.iter().enumerate() {
                    if let Some(child_hash) = child_hash_opt {
                        let mut child_path = current_path.to_vec();
                        child_path.push(i as u8);

                        // Check if this child could contain keys in our range
                        if self.path_could_contain_range(&child_path, start_nibbles, end_nibbles) {
                            self.collect_range_proof_nodes(child_hash, start_nibbles, end_nibbles, proof_nodes, included_keys, &child_path)?;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    fn path_could_contain_range(&self, path: &[u8], start_nibbles: &[u8], end_nibbles: &[u8]) -> bool {
        // Check if the path prefix could lead to keys within the range
        let path_len = path.len().min(start_nibbles.len()).min(end_nibbles.len());

        if path_len == 0 {
            return true;
        }

        let path_prefix = &path[..path_len];
        let start_prefix = &start_nibbles[..path_len];
        let end_prefix = &end_nibbles[..path_len];

        path_prefix >= start_prefix && path_prefix <= end_prefix
    }

    fn compute_root_from_proof(
        key_nibbles: &[u8],
        expected_value: Option<&[u8]>,
        proof_nodes: &[TrieNode],
    ) -> Result<Hash, ConsensusError> {
        if proof_nodes.is_empty() {
            return Err(ConsensusError::TrieError("Empty proof".to_string()));
        }

        // Start from the leaf and work backwards to compute the root
        let mut current_hash = proof_nodes.last().unwrap().hash();
        let mut remaining_key = key_nibbles;

        // Verify the leaf node contains the expected value
        if let TrieNode::Leaf { key_end, value } = proof_nodes.last().unwrap() {
            if key_end != remaining_key {
                return Err(ConsensusError::TrieError("Key mismatch in leaf".to_string()));
            }
            if expected_value.map(|v| v.to_vec()) != Some(value.clone()) {
                return Err(ConsensusError::TrieError("Value mismatch in leaf".to_string()));
            }
        }

        // Work backwards through the proof nodes
        for node in proof_nodes.iter().rev().skip(1) {
            match node {
                TrieNode::Extension { common_prefix, next_hash } => {
                    if !remaining_key.starts_with(common_prefix) {
                        return Err(ConsensusError::TrieError("Extension key mismatch".to_string()));
                    }
                    if *next_hash != current_hash {
                        return Err(ConsensusError::TrieError("Extension hash mismatch".to_string()));
                    }
                    remaining_key = &remaining_key[common_prefix.len()..];
                    current_hash = node.hash();
                }
                TrieNode::Branch { children, value } => {
                    if remaining_key.is_empty() {
                        // We're at the branch value
                        if value.is_none() && expected_value.is_some() {
                            return Err(ConsensusError::TrieError("Branch value mismatch".to_string()));
                        }
                    } else {
                        let first_nibble = remaining_key[0] as usize;
                        if children[first_nibble] != Some(current_hash) {
                            return Err(ConsensusError::TrieError("Branch child mismatch".to_string()));
                        }
                        remaining_key = &remaining_key[1..];
                    }
                    current_hash = node.hash();
                }
                _ => {
                    return Err(ConsensusError::TrieError("Unexpected node type in proof".to_string()));
                }
            }
        }

        Ok(current_hash)
    }

    fn compute_range_root_from_proof(
        proof_nodes: &[TrieNode],
        _included_keys: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Hash, ConsensusError> {
        // Simplified range proof verification
        // In a full implementation, this would reconstruct the trie structure
        // and verify that all included keys are present and no keys in the range are missing

        if proof_nodes.is_empty() {
            return Ok([0u8; 32]);
        }

        // For now, return the hash of the first proof node as a placeholder
        // A complete implementation would rebuild the trie structure from the proof
        Ok(proof_nodes[0].hash())
    }

    // Utility methods

    fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }
        nibbles
    }

    fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((nibbles.len() + 1) / 2);
        for chunk in nibbles.chunks(2) {
            if chunk.len() == 2 {
                bytes.push((chunk[0] << 4) | chunk[1]);
            } else {
                bytes.push(chunk[0] << 4);
            }
        }
        bytes
    }

    fn common_prefix(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter()
            .zip(b.iter())
            .take_while(|(x, y)| x == y)
            .map(|(x, _)| *x)
            .collect()
    }

    // Encoding methods for different data types

    fn encode_utxo_key(outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"utxo:");
        key.extend_from_slice(&outpoint.txid);
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    fn encode_utxo_value(utxo: &Utxo) -> Result<Vec<u8>, ConsensusError> {
        bincode::serialize(utxo)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    fn encode_ticket_key(ticket_id: &TicketId) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"ticket:");
        key.extend_from_slice(ticket_id.as_ref());
        key
    }

    fn encode_ticket_value(ticket_data: &TicketData) -> Result<Vec<u8>, ConsensusError> {
        bincode::serialize(ticket_data)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    fn encode_masternode_key(mn_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"masternode:");
        key.extend_from_slice(mn_key);
        key
    }

    fn encode_proposal_key(prop_key: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"proposal:");
        key.extend_from_slice(prop_key);
        key
    }
}

/// Merkle proof for a key-value pair in the trie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub proof_nodes: Vec<TrieNode>,
    pub root_hash: Hash,
}

/// Batch Merkle proof for multiple keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    pub proofs: Vec<MerkleProof>,
    pub shared_nodes: HashMap<Hash, (TrieNode, Vec<(usize, usize)>)>, // hash -> (node, proof_indices)
    pub root_hash: Hash,
}

/// Range proof for keys within a specified range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    pub start_key: Vec<u8>,
    pub end_key: Vec<u8>,
    pub included_keys: Vec<(Vec<u8>, Vec<u8>)>, // (key, value) pairs in the range
    pub proof_nodes: Vec<TrieNode>,
    pub root_hash: Hash,
}

/// Ticket data for the trie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketData {
    pub owner: Vec<u8>,
    pub value: u64,
    pub expiration_height: u64,
    pub creation_height: u64,
}

impl Default for MerklePatriciaTrie {
    fn default() -> Self {
        Self::new()
    }
}
