//! Sidechain type definitions
//!
//! This module contains all the core types used in sidechain operations,
//! including blocks, transactions, fraud proofs, and cross-chain structures.

use serde::{Deserialize, Serialize};
use rusty_shared_types::{Hash, OutPoint, Transaction};

/// Types of fraud that can be proven in sidechain operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FraudType {
    /// Invalid state transition (e.g., incorrect state changes)
    InvalidStateTransition,
    /// Double spending of the same UTXO
    DoubleSpending,
    /// Invalid cross-chain transaction
    InvalidCrossChainTx,
    /// Unauthorized signature from federation member
    UnauthorizedSignature,
    /// Invalid VM execution result
    InvalidVMExecution,
}

/// Evidence provided in a fraud proof
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudEvidence {
    /// Pre-state before the fraudulent operation
    pub pre_state: Vec<u8>,
    /// Post-state after the fraudulent operation
    pub post_state: Vec<u8>,
    /// The fraudulent operation data
    pub fraudulent_operation: Vec<u8>,
    /// Witness data proving the fraud
    pub witness_data: Vec<u8>,
    /// Additional evidence data
    pub additional_evidence: std::collections::HashMap<String, Vec<u8>>,
}

/// A fraud proof submitted to challenge sidechain state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProof {
    /// Type of fraud being proven
    pub fraud_type: FraudType,
    /// Block height where fraud occurred
    pub fraud_block_height: u64,
    /// Index of fraudulent transaction in block (if applicable)
    pub fraud_tx_index: Option<u64>,
    /// Evidence supporting the fraud claim
    pub evidence: FraudEvidence,
    /// Address of the challenger (who submitted the proof)
    pub challenger_address: Vec<u8>,
    /// Bond amount posted by challenger
    pub challenge_bond: u64,
    /// Deadline for responding to the challenge
    pub response_deadline: u64,
}

/// Sidechain block header
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainBlockHeader {
    /// Block version
    pub version: u32,
    /// Block height
    pub height: u64,
    /// Hash of previous block
    pub previous_block_hash: Hash,
    /// Merkle root of transactions
    pub merkle_root: Hash,
    /// Merkle root of cross-chain transactions
    pub cross_chain_merkle_root: Hash,
    /// State root hash
    pub state_root: Hash,
    /// Timestamp
    pub timestamp: u64,
    /// Difficulty target
    pub difficulty_target: u32,
    /// Nonce
    pub nonce: u64,
    /// Sidechain ID
    pub sidechain_id: Hash,
    /// Federation epoch
    pub federation_epoch: u64,
    /// Mainchain anchor height
    pub mainchain_anchor_height: u64,
    /// Mainchain anchor hash
    pub mainchain_anchor_hash: Hash,
}

impl SidechainBlockHeader {
    /// Create a new sidechain block header
    pub fn new(
        previous_block_hash: Hash,
        merkle_root: Hash,
        cross_chain_merkle_root: Hash,
        state_root: Hash,
        height: u64,
        sidechain_id: Hash,
        mainchain_anchor_height: u64,
        mainchain_anchor_hash: Hash,
        federation_epoch: u64,
    ) -> Self {
        Self {
            version: 1,
            height,
            previous_block_hash,
            merkle_root,
            cross_chain_merkle_root,
            state_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            difficulty_target: 0x1d00ffff, // Mainnet difficulty
            nonce: 0,
            sidechain_id,
            federation_epoch,
            mainchain_anchor_height,
            mainchain_anchor_hash,
        }
    }

    /// Calculate the hash of this header
    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&bytes).into()
    }
}

/// Sidechain transaction input
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTxInput {
    /// Reference to previous output
    pub previous_output: SidechainOutPoint,
    /// Script signature
    pub script_sig: Vec<u8>,
    /// Sequence number
    pub sequence: u32,
}

/// Sidechain transaction output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTxOutput {
    /// Value in satoshis
    pub value: u64,
    /// Asset ID
    pub asset_id: Hash,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
    /// Optional memo data
    pub data: Vec<u8>,
}

/// Sidechain outpoint (reference to output)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SidechainOutPoint {
    /// Transaction hash
    pub txid: Hash,
    /// Output index
    pub vout: u32,
}

/// Sidechain transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTransaction {
    /// Version
    pub version: u32,
    /// Inputs
    pub inputs: Vec<SidechainTxInput>,
    /// Outputs
    pub outputs: Vec<SidechainTxOutput>,
    /// Lock time
    pub lock_time: u32,
    /// VM execution data (if applicable)
    pub vm_data: Option<VMExecutionData>,
    /// Transaction fee
    pub fee: u64,
}

/// Cross-chain transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainTransaction {
    /// Transaction ID
    pub id: Hash,
    /// Amount being transferred
    pub amount: u64,
    /// Recipient address on destination chain
    pub recipient_address: Vec<u8>,
    /// Source chain ID
    pub source_chain: Hash,
    /// Destination chain ID
    pub destination_chain: Hash,
    /// Cross-chain proof
    pub proof: CrossChainProof,
    /// Federation signatures
    pub federation_signatures: Vec<FederationSignature>,
    /// Metadata
    pub metadata: Vec<u8>,
}

impl CrossChainTransaction {
    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&bytes).into()
    }
}

/// Cross-chain proof structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainProof {
    /// Merkle proof for transaction inclusion
    pub merkle_proof: Vec<Hash>,
    /// Block header containing the transaction
    pub block_header: Vec<u8>,
    /// Transaction data
    pub transaction_data: Vec<u8>,
    /// Transaction index in block
    pub tx_index: u32,
}

/// Federation signature for threshold signing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationSignature {
    /// BLS signature bytes
    pub signature: Vec<u8>,
    /// Bitmap indicating which federation members signed
    pub signer_bitmap: Vec<u8>,
    /// Threshold required for validity
    pub threshold: u32,
    /// Federation epoch
    pub epoch: u64,
    /// Hash of the message being signed
    pub message_hash: Hash,
}

impl FederationSignature {
    /// Count the number of signers based on bitmap
    pub fn count_signers(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.signer_bitmap {
            count += byte.count_ones();
        }
        count
    }
}

/// VM execution data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VMExecutionData {
    /// VM type
    pub vm_type: VMType,
    /// Bytecode to execute
    pub bytecode: Vec<u8>,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: u64,
    /// Input data
    pub input_data: Vec<u8>,
}

/// Types of virtual machines supported
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VMType {
    /// Ethereum Virtual Machine
    EVM,
    /// WebAssembly
    WASM,
}

/// Sidechain block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainBlock {
    /// Block header
    pub header: SidechainBlockHeader,
    /// Regular transactions
    pub transactions: Vec<SidechainTransaction>,
    /// Cross-chain transactions
    pub cross_chain_transactions: Vec<CrossChainTransaction>,
    /// Fraud proofs included in this block
    pub fraud_proofs: Vec<FraudProof>,
    /// Federation signature
    pub federation_signature: Option<FederationSignature>,
}

impl SidechainBlock {
    /// Create a new sidechain block
    pub fn new(header: SidechainBlockHeader, transactions: Vec<SidechainTransaction>) -> Self {
        Self {
            header,
            transactions,
            cross_chain_transactions: Vec::new(),
            fraud_proofs: Vec::new(),
            federation_signature: None,
        }
    }

    /// Calculate block hash
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get block height
    pub fn height(&self) -> u64 {
        self.header.height
    }
}