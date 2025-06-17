//! Core data types for Rusty Coin.

use serde::{Serialize, Deserialize};
use crate::crypto::Hash;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use bincode;

/// A transaction input references an output from a previous transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct TxInput {
    /// Reference to the transaction containing the output being spent
    pub txid: Hash,
    /// Index of the output in the referenced transaction
    pub output_index: u32,
    /// Signature that proves ownership of the output being spent
    pub signature: Vec<u8>,
    /// Public key of the output being spent
    pub public_key: Vec<u8>,
}

/// A transaction output specifies an amount and a locking script.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct TxOutput {
    /// Amount in satoshis (1 RUST = 100,000,000 satoshis)
    pub value: u64,
    /// Public key hash of the recipient (20 bytes)
    pub pubkey_hash: [u8; 20],
}

/// A transaction is a transfer of value between wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// List of inputs
    pub inputs: Vec<TxInput>,
    /// List of outputs
    pub outputs: Vec<TxOutput>,
    /// Lock time or block number after which this transaction is valid
    pub lock_time: u32,
}

impl Transaction {
    /// Creates a new coinbase transaction (mining reward)
    pub fn new_coinbase(to: [u8; 20], value: u64, height: u64) -> Self {
        // Coinbase transactions have a single input with special data
        let mut signature = vec![0; 32];
        signature[..8].copy_from_slice(&height.to_le_bytes());

        let input = TxInput {
            txid: Hash::zero(),
            output_index: u32::MAX,
            signature,
            public_key: vec![],
        };

        let output = TxOutput {
            value,
            pubkey_hash: to,
        };

        Transaction {
            version: 1,
            inputs: vec![input],
            outputs: vec![output],
            lock_time: 0,
        }
    }

    /// Computes the transaction hash (used as the transaction ID)
    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let tx_data = bincode::encode_to_vec(&self, config).expect("Failed to serialize transaction");
        Hash::blake3(&tx_data)
    }

    /// Returns true if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 
            && self.inputs[0].txid == Hash::zero() 
            && self.inputs[0].output_index == u32::MAX
    }
}

/// A Merkle tree is a binary tree of hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleTree {
    /// The root hash of the Merkle tree.
    pub root: Hash,
}

impl MerkleTree {
    /// Creates a new Merkle tree from a list of hashes.
    pub fn from_hashes(hashes: Vec<Hash>) -> Self {
        if hashes.is_empty() {
            return Self { root: Hash::zero() };
        }
        
        let mut current_level = hashes;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for pair in current_level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                
                let mut combined = Vec::new();
                combined.extend_from_slice(left.as_bytes());
                combined.extend_from_slice(right.as_bytes());
                next_level.push(blake3::hash(&combined).into());
            }
            
            current_level = next_level;
        }
        
        Self { root: current_level[0] }
    }
}

/// Block header contains metadata about a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    /// Protocol version
    pub version: u32,
    /// Hash of the previous block
    pub prev_block_hash: Hash,
    /// Root hash of the Merkle tree of transactions
    pub merkle_root: Hash,
    /// Block creation timestamp (seconds since Unix epoch)
    pub timestamp: u64,
    /// Current target in compact format
    pub bits: u32,
    /// Nonce value used for mining
    pub nonce: u32,
    /// Hash of the voting tickets used for PoS validation
    pub ticket_hash: Hash,
}

impl BlockHeader {
    /// Creates a new block header
    pub fn new(
        version: u32,
        prev_block_hash: Hash,
        merkle_root: Hash,
        bits: u32,
        ticket_hash: Hash,
    ) -> Self {
        BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            bits,
            nonce: 0,
            ticket_hash,
        }
    }

    /// Computes the block header hash (used for mining)
    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let header_data = bincode::encode_to_vec(&self, config).expect("Failed to serialize block header");
        Hash::blake3(&header_data)
    }
}

/// A block contains a header and a list of transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Creates a new block
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }

    /// Computes the block hash (same as the header hash)
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Computes the Merkle root of the transactions
    pub fn compute_merkle_root(&self) -> Hash {
        let hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        MerkleTree::from_hashes(hashes).root
    }
}
