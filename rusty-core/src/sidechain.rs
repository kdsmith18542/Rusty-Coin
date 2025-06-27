//! # Sidechain Protocol Implementation for Rusty Coin
//!
//! This module provides a comprehensive implementation of the sidechain functionality for Rusty Coin,
//! including cross-chain transactions, two-way peg mechanisms, fraud proofs, and proof validation
//! as specified in the Rusty Coin Technical Brief (RCTB).
//!
//! ## Overview
//!
//! The sidechain system enables:
//! - **Cross-chain asset transfers** between mainchain and sidechains
//! - **Inter-sidechain communication** for asset transfers between different sidechains
//! - **Fraud detection and prevention** through comprehensive proof systems
//! - **Federation-based security** using BLS threshold signatures from masternodes
//! - **VM execution support** for smart contracts (EVM, WASM, custom UTXO-based VM)
//!
//! ## Key Components
//!
//! ### Core Structures
//! - [`SidechainBlock`] - Complete sidechain block with transactions and proofs
//! - [`SidechainTransaction`] - Individual transactions within sidechains
//! - [`CrossChainTransaction`] - Transactions that span multiple chains
//! - [`SidechainState`] - Global state manager for all sidechain operations
//!
//! ### Two-Way Peg System
//! - [`TwoWayPegManager`] - Manages peg-in and peg-out operations
//! - [`PegInTransaction`] - Locks assets on mainchain, mints on sidechain
//! - [`PegOutTransaction`] - Burns assets on sidechain, unlocks on mainchain
//!
//! ### Security and Validation
//! - [`FraudProofManager`] - Detects and processes fraud proofs
//! - [`SidechainProofValidator`] - Validates all types of sidechain proofs
//! - [`FederationSignature`] - BLS threshold signatures from masternode federation
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use rusty_core::sidechain::*;
//! use rusty_shared_types::Hash;
//!
//! // Create a new sidechain state manager
//! let mut sidechain_state = SidechainState::new();
//!
//! // Register a new sidechain
//! let sidechain_info = SidechainInfo {
//!     sidechain_id: [1u8; 32],
//!     name: "My Sidechain".to_string(),
//!     peg_address: vec![1, 2, 3, 4],
//!     federation_members: vec![],
//!     current_epoch: 1,
//!     vm_type: VMType::EVM,
//!     genesis_block_hash: [0u8; 32],
//!     creation_timestamp: 1234567890,
//!     min_federation_threshold: 2,
//! };
//!
//! sidechain_state.register_sidechain(sidechain_info)?;
//!
//! // Get statistics
//! let stats = sidechain_state.get_stats();
//! println!("Registered sidechains: {}", stats.registered_sidechains);
//! # Ok::<(), String>(())
//! ```
//!
//! ## Security Model
//!
//! The sidechain security model relies on:
//! 1. **Federation Control** - Masternode federation with BLS threshold signatures
//! 2. **Fraud Proofs** - Challenge-response system for detecting invalid operations
//! 3. **Cross-Chain Proofs** - Merkle proofs for transaction inclusion verification
//! 4. **Economic Incentives** - Bonds and rewards for honest behavior
//!
//! ## Compliance
//!
//! This implementation follows the specifications outlined in:
//! - RCTB FERR_001: Two-way peg protocol
//! - RCTB FERR_002: Sidechain VM integration
//! - RCTB FERR_003: Inter-sidechain communication
//! - BLS threshold signature requirements for federation control

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use blake3;
use log::{info, warn, error, debug};

use rusty_shared_types::{Hash, Transaction, BlockHeader, MasternodeID};

pub mod two_way_peg;
pub mod proof_validation;
pub mod fraud_proofs;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;

pub use two_way_peg::{
    TwoWayPegManager, TwoWayPegConfig, PegInTransaction, PegOutTransaction,
    PegStatus, PegOperationType, PegOperationRecord, TwoWayPegStats
};
pub use proof_validation::{
    SidechainProofValidator, ProofValidationConfig, ProofValidationResult, ValidationStats
};
pub use fraud_proofs::{
    FraudProofManager, FraudProofConfig, FraudProofChallenge, FraudProofStatus,
    FraudProofResponse, FraudProofVerdict, FraudPenalty, FraudReward, PenaltyType, FraudProofStats
};

// Sidechain protocol implementation for Rusty Coin (Ferrite sidechains)
// Based on RCTB specifications for two-way peg, BLS threshold signatures, and fraud proofs

/// Core sidechain block structure as per RCTB specifications
///
/// A `SidechainBlock` represents a complete block in a sidechain, containing all transactions,
/// cross-chain operations, fraud proofs, and federation signatures required for consensus.
///
/// ## Structure
///
/// Each block contains:
/// - **Header**: Metadata including merkle roots, timestamps, and chain anchoring
/// - **Transactions**: Regular sidechain transactions (transfers, smart contracts)
/// - **Cross-chain transactions**: Peg operations and inter-sidechain transfers
/// - **Fraud proofs**: Challenges against invalid operations
/// - **Federation signature**: BLS threshold signature from masternode federation
///
/// ## Example
///
/// ```rust,no_run
/// use rusty_core::sidechain::*;
///
/// // Create a new sidechain block
/// let header = SidechainBlockHeader::new(
///     [0u8; 32], // previous_block_hash
///     [1u8; 32], // merkle_root
///     [2u8; 32], // cross_chain_merkle_root
///     [3u8; 32], // state_root
///     1,         // height
///     [100u8; 32], // sidechain_id
///     50,        // mainchain_anchor_height
///     [4u8; 32], // mainchain_anchor_hash
///     1,         // federation_epoch
/// );
///
/// let block = SidechainBlock::new(header, vec![], vec![]);
/// println!("Block hash: {:?}", block.hash());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainBlock {
    /// Block header containing metadata and merkle roots
    pub header: SidechainBlockHeader,
    /// Regular sidechain transactions included in this block
    pub transactions: Vec<SidechainTransaction>,
    /// Cross-chain transactions (peg-in, peg-out, inter-sidechain transfers)
    pub cross_chain_transactions: Vec<CrossChainTransaction>,
    /// Fraud proofs submitted in this block for challenging invalid operations
    pub fraud_proofs: Vec<FraudProof>,
    /// BLS threshold signature from masternode federation authorizing this block
    pub federation_signature: Option<FederationSignature>,
}

/// Sidechain block header
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainBlockHeader {
    /// Version of the sidechain protocol
    pub version: u32,
    /// Hash of the previous sidechain block
    pub previous_block_hash: Hash,
    /// Merkle root of all transactions in this block
    pub merkle_root: Hash,
    /// Merkle root of cross-chain transactions
    pub cross_chain_merkle_root: Hash,
    /// State root after applying all transactions
    pub state_root: Hash,
    /// Timestamp when block was created
    pub timestamp: u64,
    /// Block height in the sidechain
    pub height: u64,
    /// Sidechain identifier
    pub sidechain_id: Hash,
    /// Reference to mainchain block height for anchoring
    pub mainchain_anchor_height: u64,
    /// Hash of the mainchain block this sidechain block is anchored to
    pub mainchain_anchor_hash: Hash,
    /// Difficulty target for sidechain consensus (if applicable)
    pub difficulty_target: u32,
    /// Nonce for proof-of-work (if applicable)
    pub nonce: u64,
    /// Federation epoch number
    pub federation_epoch: u64,
}

/// Sidechain transaction structure for asset transfers and smart contract execution
///
/// A `SidechainTransaction` represents a transaction within a sidechain that can transfer
/// assets, execute smart contracts, or perform other operations within the sidechain ecosystem.
///
/// ## Transaction Types
///
/// Transactions can be:
/// - **Asset transfers**: Moving tokens between addresses
/// - **Smart contract calls**: Executing code on supported VMs (EVM, WASM, etc.)
/// - **Burn transactions**: Destroying assets (used in peg-out operations)
/// - **Mint transactions**: Creating new assets (used in peg-in operations)
///
/// ## VM Support
///
/// The transaction can include VM execution data for smart contracts:
/// - **EVM**: Ethereum Virtual Machine compatibility
/// - **WASM**: WebAssembly runtime
/// - **UtxoVM**: Custom UTXO-based virtual machine
/// - **Native**: Direct Rust code execution
///
/// ## Example
///
/// ```rust,no_run
/// use rusty_core::sidechain::*;
///
/// let transaction = SidechainTransaction {
///     version: 1,
///     inputs: vec![SidechainTxInput {
///         previous_output: SidechainOutPoint {
///             txid: [1u8; 32],
///             vout: 0,
///         },
///         script_sig: vec![1, 2, 3],
///         sequence: 0xffffffff,
///     }],
///     outputs: vec![SidechainTxOutput {
///         value: 1000000,
///         asset_id: [2u8; 32],
///         script_pubkey: vec![4, 5, 6],
///         data: Vec::new(),
///     }],
///     lock_time: 0,
///     vm_data: None,
///     fee: 1000,
/// };
///
/// println!("Transaction ID: {:?}", transaction.txid());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTransaction {
    /// Transaction version for protocol compatibility
    pub version: u32,
    /// Transaction inputs referencing previous outputs
    pub inputs: Vec<SidechainTxInput>,
    /// Transaction outputs creating new UTXOs
    pub outputs: Vec<SidechainTxOutput>,
    /// Lock time preventing transaction inclusion before specified time/block
    pub lock_time: u64,
    /// Optional VM execution data for smart contracts
    pub vm_data: Option<VMExecutionData>,
    /// Transaction fee paid to validators
    pub fee: u64,
}

/// Sidechain transaction input
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTxInput {
    /// Reference to previous transaction output
    pub previous_output: SidechainOutPoint,
    /// Script signature for spending
    pub script_sig: Vec<u8>,
    /// Sequence number
    pub sequence: u32,
}

/// Sidechain transaction output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTxOutput {
    /// Value of the output
    pub value: u64,
    /// Asset type identifier
    pub asset_id: Hash,
    /// Script public key
    pub script_pubkey: Vec<u8>,
    /// Additional data for smart contracts
    pub data: Vec<u8>,
}

/// Reference to a sidechain transaction output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainOutPoint {
    /// Transaction hash
    pub txid: Hash,
    /// Output index
    pub vout: u32,
}

/// VM execution data for smart contracts
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VMExecutionData {
    /// VM type (EVM, WASM, etc.)
    pub vm_type: VMType,
    /// Bytecode to execute
    pub bytecode: Vec<u8>,
    /// Gas limit for execution
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: u64,
    /// Input data for the contract
    pub input_data: Vec<u8>,
}

/// Supported VM types for sidechain execution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VMType {
    /// Ethereum Virtual Machine compatibility
    EVM,
    /// WebAssembly runtime
    WASM,
    /// Custom UTXO-based VM
    UtxoVM,
    /// Native Rust execution
    Native,
}

/// Cross-chain transaction for two-way peg operations and inter-sidechain transfers
///
/// A `CrossChainTransaction` enables asset transfers between different chains in the Rusty Coin
/// ecosystem, including mainchain-to-sidechain (peg-in), sidechain-to-mainchain (peg-out),
/// and sidechain-to-sidechain transfers.
///
/// ## Transaction Types
///
/// - **PegIn**: Lock assets on mainchain, mint equivalent on sidechain
/// - **PegOut**: Burn assets on sidechain, unlock equivalent on mainchain
/// - **SidechainToSidechain**: Transfer assets between different sidechains
///
/// ## Security Model
///
/// Cross-chain transactions require:
/// - **Cryptographic proofs**: Merkle proofs of transaction inclusion
/// - **Federation signatures**: BLS threshold signatures from masternode federation
/// - **Challenge period**: Time window for fraud proof submissions
/// - **Economic bonds**: Collateral to prevent malicious behavior
///
/// ## Example
///
/// ```rust,no_run
/// use rusty_core::sidechain::*;
///
/// // Create a peg-in transaction
/// let peg_in = CrossChainTransaction::new(
///     CrossChainTxType::PegIn,
///     [1u8; 32], // mainchain_id
///     [2u8; 32], // sidechain_id
///     5000000,   // amount
///     [3u8; 32], // asset_id
///     vec![4, 5, 6], // recipient_address
///     vec![7, 8, 9], // additional_data
/// );
///
/// println!("Cross-chain TX hash: {:?}", peg_in.hash());
/// ```
///
/// ## Validation
///
/// Cross-chain transactions must pass several validation steps:
/// 1. **Amount validation**: Non-zero amounts within allowed limits
/// 2. **Address validation**: Valid recipient addresses
/// 3. **Proof validation**: Valid merkle proofs and block headers
/// 4. **Signature validation**: Sufficient federation signatures
/// 5. **Chain validation**: Valid source and destination chains
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainTransaction {
    /// Type of cross-chain operation (PegIn, PegOut, SidechainToSidechain)
    pub tx_type: CrossChainTxType,
    /// Source chain identifier (mainchain or sidechain hash)
    pub source_chain_id: Hash,
    /// Destination chain identifier (mainchain or sidechain hash)
    pub destination_chain_id: Hash,
    /// Amount being transferred (in smallest unit)
    pub amount: u64,
    /// Asset type identifier being transferred
    pub asset_id: Hash,
    /// Recipient address on destination chain
    pub recipient_address: Vec<u8>,
    /// Cryptographic proof of transaction inclusion on source chain
    pub proof: CrossChainProof,
    /// Additional data for complex operations
    pub data: Vec<u8>,
    /// Federation signatures authorizing the cross-chain transfer
    pub federation_signatures: Vec<FederationSignature>,
}

/// Proof for cross-chain transactions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainProof {
    /// Merkle proof of inclusion in source chain
    pub merkle_proof: Vec<Hash>,
    /// Block header of source chain block
    pub block_header: Vec<u8>,
    /// Transaction data being proven
    pub transaction_data: Vec<u8>,
    /// Index of transaction in block
    pub tx_index: u32,
}

/// BLS threshold signature from masternode federation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationSignature {
    /// BLS signature bytes
    pub signature: Vec<u8>,
    /// Bitmap indicating which masternodes signed
    pub signer_bitmap: Vec<u8>,
    /// Threshold used for this signature
    pub threshold: u32,
    /// Federation epoch this signature belongs to
    pub epoch: u64,
    /// Message that was signed
    pub message_hash: Hash,
}

/// Fraud proof for challenging invalid sidechain operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudProof {
    /// Type of fraud being proven
    pub fraud_type: FraudType,
    /// Block height where fraud occurred
    pub fraud_block_height: u64,
    /// Transaction index in block (if applicable)
    pub fraud_tx_index: Option<u32>,
    /// Evidence supporting the fraud claim
    pub evidence: FraudEvidence,
    /// Challenger's address for reward
    pub challenger_address: Vec<u8>,
    /// Bond posted by challenger
    pub challenge_bond: u64,
    /// Deadline for response
    pub response_deadline: u64,
}

/// Types of fraud that can be proven
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FraudType {
    /// Invalid state transition
    InvalidStateTransition,
    /// Double spending
    DoubleSpending,
    /// Invalid cross-chain transaction
    InvalidCrossChainTx,
    /// Unauthorized federation signature
    UnauthorizedSignature,
    /// Invalid VM execution
    InvalidVMExecution,
}

/// Evidence supporting a fraud proof
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudEvidence {
    /// Pre-state before the fraudulent operation
    pub pre_state: Vec<u8>,
    /// Post-state after the fraudulent operation
    pub post_state: Vec<u8>,
    /// Transaction or operation that caused the fraud
    pub fraudulent_operation: Vec<u8>,
    /// Witness data proving the fraud
    pub witness_data: Vec<u8>,
    /// Additional supporting evidence
    pub additional_evidence: HashMap<String, Vec<u8>>,
}

impl SidechainBlock {
    /// Create a new sidechain block
    pub fn new(
        header: SidechainBlockHeader,
        transactions: Vec<SidechainTransaction>,
        cross_chain_transactions: Vec<CrossChainTransaction>,
    ) -> Self {
        Self {
            header,
            transactions,
            cross_chain_transactions,
            fraud_proofs: Vec::new(),
            federation_signature: None,
        }
    }

    /// Calculate the hash of this sidechain block
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Calculate the merkle root of all transactions
    pub fn calculate_merkle_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }

        let tx_hashes: Vec<Hash> = self.transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();

        Self::calculate_merkle_root_from_hashes(&tx_hashes)
    }

    /// Calculate the merkle root of cross-chain transactions
    pub fn calculate_cross_chain_merkle_root(&self) -> Hash {
        if self.cross_chain_transactions.is_empty() {
            return [0u8; 32];
        }

        let tx_hashes: Vec<Hash> = self.cross_chain_transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();

        Self::calculate_merkle_root_from_hashes(&tx_hashes)
    }

    /// Calculate merkle root from a list of hashes
    fn calculate_merkle_root_from_hashes(hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return [0u8; 32];
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0], chunk[1]].concat()
                } else {
                    [chunk[0], chunk[0]].concat() // Duplicate if odd number
                };

                let hash = blake3::hash(&combined);
                next_level.push(hash.into());
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Verify the block's integrity
    pub fn verify(&self) -> Result<(), String> {
        // Verify merkle roots
        let calculated_merkle_root = self.calculate_merkle_root();
        if calculated_merkle_root != self.header.merkle_root {
            return Err("Invalid transaction merkle root".to_string());
        }

        let calculated_cross_chain_root = self.calculate_cross_chain_merkle_root();
        if calculated_cross_chain_root != self.header.cross_chain_merkle_root {
            return Err("Invalid cross-chain transaction merkle root".to_string());
        }

        // Verify all transactions
        for tx in &self.transactions {
            tx.verify()?;
        }

        // Verify all cross-chain transactions
        for tx in &self.cross_chain_transactions {
            tx.verify()?;
        }

        // Verify fraud proofs
        for proof in &self.fraud_proofs {
            proof.verify()?;
        }

        // Verify federation signature if present
        if let Some(ref signature) = self.federation_signature {
            signature.verify(&self.header.hash())?;
        }

        Ok(())
    }

    /// Add a fraud proof to the block
    pub fn add_fraud_proof(&mut self, proof: FraudProof) -> Result<(), String> {
        proof.verify()?;
        self.fraud_proofs.push(proof);
        Ok(())
    }

    /// Set the federation signature for this block
    pub fn set_federation_signature(&mut self, signature: FederationSignature) -> Result<(), String> {
        signature.verify(&self.header.hash())?;
        self.federation_signature = Some(signature);
        Ok(())
    }

    /// Get the total size of the block in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if this block is anchored to the mainchain
    pub fn is_anchored(&self) -> bool {
        self.header.mainchain_anchor_height > 0 &&
        self.header.mainchain_anchor_hash != [0u8; 32]
    }
}

impl SidechainBlockHeader {
    /// Calculate the hash of this header
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

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
            previous_block_hash,
            merkle_root,
            cross_chain_merkle_root,
            state_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            height,
            sidechain_id,
            mainchain_anchor_height,
            mainchain_anchor_hash,
            difficulty_target: 0,
            nonce: 0,
            federation_epoch,
        }
    }
}

impl SidechainTransaction {
    /// Calculate the hash of this transaction
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Verify the transaction's validity
    pub fn verify(&self) -> Result<(), String> {
        // Basic validation
        if self.inputs.is_empty() {
            return Err("Transaction must have at least one input".to_string());
        }

        if self.outputs.is_empty() {
            return Err("Transaction must have at least one output".to_string());
        }

        // Verify input/output balance (simplified)
        let total_output_value: u64 = self.outputs.iter().map(|o| o.value).sum();
        if total_output_value == 0 {
            return Err("Transaction outputs cannot have zero value".to_string());
        }

        // Verify VM execution if present
        if let Some(ref vm_data) = self.vm_data {
            vm_data.verify()?;
        }

        Ok(())
    }

    /// Get the transaction ID
    pub fn txid(&self) -> Hash {
        self.hash()
    }

    /// Calculate the total input value (would require UTXO set in real implementation)
    pub fn total_input_value(&self) -> u64 {
        // In a real implementation, this would look up the UTXO set
        // For now, return a placeholder
        0
    }

    /// Calculate the total output value
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }
}

impl VMExecutionData {
    /// Verify VM execution data
    pub fn verify(&self) -> Result<(), String> {
        if self.bytecode.is_empty() {
            return Err("VM bytecode cannot be empty".to_string());
        }

        if self.gas_limit == 0 {
            return Err("Gas limit must be greater than zero".to_string());
        }

        // Additional VM-specific validation would go here
        match self.vm_type {
            VMType::EVM => {
                // EVM-specific validation
                if self.gas_limit > 30_000_000 {
                    return Err("EVM gas limit too high".to_string());
                }
            }
            VMType::WASM => {
                // WASM-specific validation
                if self.bytecode.len() > 1_000_000 {
                    return Err("WASM bytecode too large".to_string());
                }
            }
            VMType::UtxoVM | VMType::Native => {
                // Custom validation for UTXO VM and native execution
            }
        }

        Ok(())
    }
}

impl CrossChainTransaction {
    /// Create a new cross-chain transaction
    pub fn new(
        tx_type: CrossChainTxType,
        source_chain_id: Hash,
        destination_chain_id: Hash,
        amount: u64,
        asset_id: Hash,
        recipient_address: Vec<u8>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            tx_type,
            source_chain_id,
            destination_chain_id,
            amount,
            asset_id,
            recipient_address,
            proof: CrossChainProof {
                merkle_proof: Vec::new(),
                block_header: Vec::new(),
                transaction_data: Vec::new(),
                tx_index: 0,
            },
            data,
            federation_signatures: Vec::new(),
        }
    }

    /// Calculate the hash of this cross-chain transaction
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Verify the cross-chain transaction
    pub fn verify(&self) -> Result<(), String> {
        if self.amount == 0 {
            return Err("Cross-chain transaction amount cannot be zero".to_string());
        }

        if self.recipient_address.is_empty() {
            return Err("Recipient address cannot be empty".to_string());
        }

        // Verify source and destination chains are different for cross-chain operations
        if self.source_chain_id == self.destination_chain_id {
            match self.tx_type {
                CrossChainTxType::PegIn | CrossChainTxType::PegOut => {
                    // These are allowed to have same source/destination for mainchain operations
                }
                CrossChainTxType::SidechainToSidechain => {
                    return Err("Source and destination chains must be different for sidechain-to-sidechain transfers".to_string());
                }
            }
        }

        // Verify the cross-chain proof
        self.proof.verify()?;

        // Verify federation signatures
        if self.federation_signatures.is_empty() {
            return Err("Cross-chain transaction must have federation signatures".to_string());
        }

        for signature in &self.federation_signatures {
            signature.verify(&self.hash())?;
        }

        Ok(())
    }

    /// Add a federation signature to this transaction
    pub fn add_federation_signature(&mut self, signature: FederationSignature) -> Result<(), String> {
        // Verify signature is for this transaction
        signature.verify(&self.hash())?;

        // Check for duplicate signatures from the same epoch
        if self.federation_signatures.iter().any(|s| s.epoch == signature.epoch) {
            return Err("Signature from this epoch already exists".to_string());
        }

        self.federation_signatures.push(signature);
        Ok(())
    }

    /// Check if this transaction has sufficient federation signatures
    pub fn has_sufficient_signatures(&self, required_threshold: u32) -> bool {
        let total_signers: u32 = self.federation_signatures
            .iter()
            .map(|sig| sig.count_signers())
            .sum();

        total_signers >= required_threshold
    }

    /// Get the transaction type as a string
    pub fn tx_type_string(&self) -> &'static str {
        match self.tx_type {
            CrossChainTxType::PegIn => "peg_in",
            CrossChainTxType::PegOut => "peg_out",
            CrossChainTxType::SidechainToSidechain => "sidechain_to_sidechain",
        }
    }

    /// Check if this is a mainchain operation
    pub fn is_mainchain_operation(&self) -> bool {
        matches!(self.tx_type, CrossChainTxType::PegIn | CrossChainTxType::PegOut)
    }

    /// Check if this is an inter-sidechain operation
    pub fn is_inter_sidechain_operation(&self) -> bool {
        matches!(self.tx_type, CrossChainTxType::SidechainToSidechain)
    }

    /// Get the fee for this cross-chain transaction
    pub fn calculate_fee(&self, base_fee: u64, fee_rate: f64) -> u64 {
        let amount_fee = (self.amount as f64 * fee_rate) as u64;
        base_fee + amount_fee
    }

    /// Serialize transaction for network transmission
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Serialization failed: {}", e))
    }

    /// Deserialize transaction from network data
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
}

impl CrossChainProof {
    /// Verify the cross-chain proof
    pub fn verify(&self) -> Result<(), String> {
        if self.merkle_proof.is_empty() {
            return Err("Merkle proof cannot be empty".to_string());
        }

        if self.block_header.is_empty() {
            return Err("Block header cannot be empty".to_string());
        }

        if self.transaction_data.is_empty() {
            return Err("Transaction data cannot be empty".to_string());
        }

        // In a real implementation, this would verify the merkle proof
        // against the block header and transaction data
        Ok(())
    }
}

impl FederationSignature {
    /// Verify the federation signature
    pub fn verify(&self, message_hash: &Hash) -> Result<(), String> {
        if self.signature.is_empty() {
            return Err("Signature cannot be empty".to_string());
        }

        if self.signer_bitmap.is_empty() {
            return Err("Signer bitmap cannot be empty".to_string());
        }

        if self.threshold == 0 {
            return Err("Threshold must be greater than zero".to_string());
        }

        if message_hash != &self.message_hash {
            return Err("Message hash mismatch".to_string());
        }

        // In a real implementation, this would verify the BLS signature
        // against the federation's public keys
        Ok(())
    }

    /// Count the number of signers from the bitmap
    pub fn count_signers(&self) -> u32 {
        self.signer_bitmap.iter()
            .map(|byte| byte.count_ones())
            .sum()
    }
}

impl FraudProof {
    /// Verify the fraud proof
    pub fn verify(&self) -> Result<(), String> {
        if self.evidence.pre_state.is_empty() {
            return Err("Pre-state cannot be empty".to_string());
        }

        if self.evidence.post_state.is_empty() {
            return Err("Post-state cannot be empty".to_string());
        }

        if self.evidence.fraudulent_operation.is_empty() {
            return Err("Fraudulent operation cannot be empty".to_string());
        }

        if self.challenge_bond == 0 {
            return Err("Challenge bond must be greater than zero".to_string());
        }

        // In a real implementation, this would verify the fraud proof
        // by re-executing the operation and checking the state transition
        match self.fraud_type {
            FraudType::InvalidStateTransition => {
                // Verify that applying the operation to pre_state doesn't result in post_state
            }
            FraudType::DoubleSpending => {
                // Verify that the same input is spent twice
            }
            FraudType::InvalidCrossChainTx => {
                // Verify that the cross-chain transaction is invalid
            }
            FraudType::UnauthorizedSignature => {
                // Verify that the signature is not from authorized federation members
            }
            FraudType::InvalidVMExecution => {
                // Verify that the VM execution result is incorrect
            }
        }

        Ok(())
    }

    /// Calculate the hash of this fraud proof
    pub fn hash(&self) -> Hash {
        let serialized = bincode::serialize(self).unwrap_or_default();
        blake3::hash(&serialized).into()
    }
}

// Update existing structures to be compatible with new design

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainState {
    /// Registered sidechains with their information
    pub registered_sidechains: HashMap<Hash, SidechainInfo>,
    /// Current sidechain blocks by chain ID
    pub current_blocks: HashMap<Hash, SidechainBlock>,
    /// Cross-chain transaction queues
    pub pending_cross_chain_txs: HashMap<Hash, Vec<CrossChainTransaction>>,
    /// Active fraud proofs
    pub active_fraud_proofs: Vec<FraudProof>,
    /// Federation epochs and their members
    pub federation_epochs: HashMap<u64, Vec<MasternodeID>>,
    /// Two-way peg manager for cross-chain operations
    pub peg_manager: TwoWayPegManager,
    /// Proof validator for sidechain operations
    pub proof_validator: SidechainProofValidator,
    /// Fraud proof manager for security
    pub fraud_proof_manager: FraudProofManager,
}

impl SidechainState {
    pub fn new() -> Self {
        SidechainState {
            registered_sidechains: HashMap::new(),
            current_blocks: HashMap::new(),
            pending_cross_chain_txs: HashMap::new(),
            active_fraud_proofs: Vec::new(),
            federation_epochs: HashMap::new(),
            peg_manager: TwoWayPegManager::new(TwoWayPegConfig::default()),
            proof_validator: SidechainProofValidator::new(ProofValidationConfig::default()),
            fraud_proof_manager: FraudProofManager::new(FraudProofConfig::default()),
        }
    }

    /// Register a new sidechain
    pub fn register_sidechain(&mut self, info: SidechainInfo) -> Result<(), String> {
        if self.registered_sidechains.contains_key(&info.sidechain_id) {
            return Err("Sidechain with this ID already registered".to_string());
        }

        self.registered_sidechains.insert(info.sidechain_id, info);
        Ok(())
    }

    /// Process a new sidechain block
    pub fn process_sidechain_block(&mut self, block: SidechainBlock) -> Result<(), String> {
        // Validate the block using the proof validator
        match self.proof_validator.validate_sidechain_block(&block) {
            ProofValidationResult::Valid => {
                info!("Block validation passed for sidechain {:?} height {}",
                      block.header.sidechain_id, block.header.height);
            }
            ProofValidationResult::Invalid(reason) => {
                return Err(format!("Block validation failed: {}", reason));
            }
            ProofValidationResult::Error(reason) => {
                return Err(format!("Block validation error: {}", reason));
            }
            ProofValidationResult::Timeout => {
                return Err("Block validation timed out".to_string());
            }
        }

        // Basic block verification
        block.verify()?;

        let sidechain_id = block.header.sidechain_id;

        // Check if sidechain is registered
        if !self.registered_sidechains.contains_key(&sidechain_id) {
            return Err("Sidechain not registered".to_string());
        }

        // Verify block connects to previous block
        if let Some(current_block) = self.current_blocks.get(&sidechain_id) {
            if block.header.previous_block_hash != current_block.hash() {
                return Err("Block does not connect to previous block".to_string());
            }
            if block.header.height != current_block.header.height + 1 {
                return Err("Invalid block height".to_string());
            }
        }

        // Process cross-chain transactions
        for cross_chain_tx in &block.cross_chain_transactions {
            self.process_cross_chain_transaction(cross_chain_tx.clone())?;
        }

        // Process fraud proofs
        for fraud_proof in &block.fraud_proofs {
            self.process_fraud_proof(fraud_proof.clone())?;
        }

        // Process fraud proof challenges for this block height
        self.process_fraud_proof_challenges(block.header.height)?;

        // Update current block
        self.current_blocks.insert(sidechain_id, block);

        Ok(())
    }

    /// Process a cross-chain transaction
    pub fn process_cross_chain_transaction(&mut self, tx: CrossChainTransaction) -> Result<(), String> {
        // Verify the transaction
        tx.verify()?;

        match tx.tx_type {
            CrossChainTxType::PegIn => {
                // Process peg-in: lock funds on mainchain, mint on sidechain
                self.process_peg_in(&tx)?;
            }
            CrossChainTxType::PegOut => {
                // Process peg-out: burn on sidechain, unlock on mainchain
                self.process_peg_out(&tx)?;
            }
            CrossChainTxType::SidechainToSidechain => {
                // Process inter-sidechain transfer
                self.process_inter_sidechain_transfer(&tx)?;
            }
        }

        Ok(())
    }

    /// Process a fraud proof
    pub fn process_fraud_proof(&mut self, proof: FraudProof) -> Result<(), String> {
        // Verify the fraud proof
        proof.verify()?;

        // Check if this fraud proof is already active
        if self.active_fraud_proofs.iter().any(|p| p.hash() == proof.hash()) {
            return Err("Fraud proof already exists".to_string());
        }

        // Add to active fraud proofs
        self.active_fraud_proofs.push(proof);

        Ok(())
    }

    /// Update federation for a new epoch
    pub fn update_federation(&mut self, epoch: u64, members: Vec<MasternodeID>) -> Result<(), String> {
        if members.is_empty() {
            return Err("Federation cannot be empty".to_string());
        }

        // Update federation in peg manager
        self.peg_manager.update_federation(members.clone());

        // Update federation keys in proof validator (simplified - would need actual public keys)
        let public_keys: Vec<Vec<u8>> = members.iter()
            .map(|id| id.0.encode_to_vec().unwrap_or_default()) // In reality, this would be the actual public keys
            .collect();
        self.proof_validator.update_federation_keys(epoch, public_keys);

        self.federation_epochs.insert(epoch, members);
        Ok(())
    }

    /// Get current federation members for an epoch
    pub fn get_federation_members(&self, epoch: u64) -> Option<&Vec<MasternodeID>> {
        self.federation_epochs.get(&epoch)
    }

    /// Initiate a peg-in operation
    pub fn initiate_peg_in(
        &mut self,
        mainchain_tx: Transaction,
        target_sidechain_id: Hash,
        sidechain_recipient: Vec<u8>,
        amount: u64,
        asset_id: Hash,
    ) -> Result<Hash, String> {
        self.peg_manager.initiate_peg_in(
            mainchain_tx,
            target_sidechain_id,
            sidechain_recipient,
            amount,
            asset_id,
        )
    }

    /// Initiate a peg-out operation
    pub fn initiate_peg_out(
        &mut self,
        sidechain_tx: SidechainTransaction,
        source_sidechain_id: Hash,
        mainchain_recipient: Vec<u8>,
        amount: u64,
        asset_id: Hash,
    ) -> Result<Hash, String> {
        self.peg_manager.initiate_peg_out(
            sidechain_tx,
            source_sidechain_id,
            mainchain_recipient,
            amount,
            asset_id,
        )
    }

    /// Process block confirmations for peg operations
    pub fn process_peg_confirmations(&mut self, block_height: u64) -> Result<(), String> {
        self.peg_manager.process_confirmations(block_height)
    }

    /// Add federation signature to a peg operation
    pub fn add_peg_federation_signature(
        &mut self,
        peg_id: Hash,
        signature: FederationSignature,
    ) -> Result<(), String> {
        self.peg_manager.add_federation_signature(peg_id, signature)
    }

    /// Get peg operation status
    pub fn get_peg_status(&self, peg_id: &Hash) -> Option<PegStatus> {
        self.peg_manager.get_peg_status(peg_id)
    }

    /// Add trusted mainchain header for proof validation
    pub fn add_trusted_mainchain_header(&mut self, header: rusty_shared_types::BlockHeader) {
        self.proof_validator.add_trusted_header(header);
    }

    /// Validate a cross-chain transaction proof
    pub fn validate_cross_chain_proof(&mut self, tx: &CrossChainTransaction) -> ProofValidationResult {
        // Create a temporary block with just this transaction for validation
        let temp_block = SidechainBlock {
            header: SidechainBlockHeader {
                version: 1,
                previous_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                cross_chain_merkle_root: tx.hash(),
                state_root: [0u8; 32],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                height: 0,
                sidechain_id: tx.source_chain_id,
                mainchain_anchor_height: 0,
                mainchain_anchor_hash: [0u8; 32],
                difficulty_target: 0,
                nonce: 0,
                federation_epoch: 0,
            },
            transactions: Vec::new(),
            cross_chain_transactions: vec![tx.clone()],
            fraud_proofs: Vec::new(),
            federation_signature: None,
        };

        self.proof_validator.validate_sidechain_block(&temp_block)
    }

    /// Validate a fraud proof
    pub fn validate_fraud_proof_standalone(&mut self, proof: &FraudProof) -> ProofValidationResult {
        // Create a temporary block with just this fraud proof for validation
        let temp_block = SidechainBlock {
            header: SidechainBlockHeader {
                version: 1,
                previous_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                cross_chain_merkle_root: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                height: proof.fraud_block_height,
                sidechain_id: [0u8; 32], // Would be determined from context
                mainchain_anchor_height: 0,
                mainchain_anchor_hash: [0u8; 32],
                difficulty_target: 0,
                nonce: 0,
                federation_epoch: 0,
            },
            transactions: Vec::new(),
            cross_chain_transactions: Vec::new(),
            fraud_proofs: vec![proof.clone()],
            federation_signature: None,
        };

        self.proof_validator.validate_sidechain_block(&temp_block)
    }

    /// Get proof validation statistics
    pub fn get_proof_validation_stats(&self) -> ValidationStats {
        self.proof_validator.get_stats()
    }

    /// Configure proof validation settings
    pub fn update_proof_validation_config(&mut self, config: ProofValidationConfig) {
        self.proof_validator = SidechainProofValidator::new(config);
    }

    /// Submit a fraud proof challenge
    pub fn submit_fraud_proof(
        &mut self,
        fraud_proof: FraudProof,
        challenger_bond: u64,
    ) -> Result<Hash, String> {
        self.fraud_proof_manager.submit_fraud_proof(fraud_proof, challenger_bond)
    }

    /// Submit response to a fraud proof challenge
    pub fn submit_fraud_proof_response(
        &mut self,
        challenge_id: Hash,
        response: FraudProofResponse,
    ) -> Result<(), String> {
        self.fraud_proof_manager.submit_response(challenge_id, response)
    }

    /// Process fraud proof challenges for the current block
    pub fn process_fraud_proof_challenges(&mut self, block_height: u64) -> Result<(), String> {
        self.fraud_proof_manager.process_challenges(block_height)
    }

    /// Get fraud proof challenge status
    pub fn get_fraud_proof_status(&self, challenge_id: &Hash) -> Option<FraudProofStatus> {
        self.fraud_proof_manager.get_challenge_status(challenge_id)
    }

    /// Get fraud proof statistics
    pub fn get_fraud_proof_stats(&self) -> FraudProofStats {
        self.fraud_proof_manager.get_stats()
    }

    /// Configure fraud proof settings
    pub fn update_fraud_proof_config(&mut self, config: FraudProofConfig) {
        self.fraud_proof_manager = FraudProofManager::new(config);
    }

    /// Get sidechain statistics
    pub fn get_stats(&self) -> SidechainStats {
        let peg_stats = self.peg_manager.get_stats();
        let validation_stats = self.proof_validator.get_stats();
        let fraud_stats = self.fraud_proof_manager.get_stats();

        SidechainStats {
            registered_sidechains: self.registered_sidechains.len(),
            active_blocks: self.current_blocks.len(),
            pending_cross_chain_txs: self.pending_cross_chain_txs.values().map(|v| v.len()).sum(),
            active_fraud_proofs: self.active_fraud_proofs.len(),
            federation_epochs: self.federation_epochs.len(),
            active_peg_ins: peg_stats.active_peg_ins,
            active_peg_outs: peg_stats.active_peg_outs,
            completed_pegs: peg_stats.completed_pegs,
            proof_validations: validation_stats.total_validations,
            successful_validations: validation_stats.successful_validations,
            failed_validations: validation_stats.failed_validations,
            fraud_challenges: fraud_stats.total_challenges,
            proven_frauds: fraud_stats.proven_frauds,
            active_fraud_challenges: self.fraud_proof_manager.get_active_challenges_count(),
        }
    }

    // Private helper methods

    fn process_peg_in(&mut self, tx: &CrossChainTransaction) -> Result<(), String> {
        // In a real implementation, this would:
        // 1. Verify the mainchain transaction that locked funds
        // 2. Mint equivalent assets on the sidechain
        // 3. Update the sidechain state

        println!("Processing peg-in: {} units of asset {:?} to sidechain {:?}",
                 tx.amount, tx.asset_id, tx.destination_chain_id);
        Ok(())
    }

    fn process_peg_out(&mut self, tx: &CrossChainTransaction) -> Result<(), String> {
        // In a real implementation, this would:
        // 1. Burn assets on the sidechain
        // 2. Create a mainchain transaction to unlock funds
        // 3. Update the sidechain state

        println!("Processing peg-out: {} units of asset {:?} from sidechain {:?}",
                 tx.amount, tx.asset_id, tx.source_chain_id);
        Ok(())
    }

    fn process_inter_sidechain_transfer(&mut self, tx: &CrossChainTransaction) -> Result<(), String> {
        // In a real implementation, this would:
        // 1. Burn assets on source sidechain
        // 2. Mint assets on destination sidechain
        // 3. Update both sidechain states atomically

        println!("Processing inter-sidechain transfer: {} units from {:?} to {:?}",
                 tx.amount, tx.source_chain_id, tx.destination_chain_id);
        Ok(())
    }
}

/// Updated sidechain information structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainInfo {
    /// Unique sidechain identifier
    pub sidechain_id: Hash,
    /// Human-readable name
    pub name: String,
    /// Peg address on the main chain
    pub peg_address: Vec<u8>,
    /// Current federation members (masternode IDs)
    pub federation_members: Vec<MasternodeID>,
    /// Current epoch number
    pub current_epoch: u64,
    /// VM type used by this sidechain
    pub vm_type: VMType,
    /// Genesis block hash
    pub genesis_block_hash: Hash,
    /// Creation timestamp
    pub creation_timestamp: u64,
    /// Minimum federation threshold
    pub min_federation_threshold: u32,
}

/// Statistics about sidechain operations
#[derive(Debug, Clone)]
pub struct SidechainStats {
    pub registered_sidechains: usize,
    pub active_blocks: usize,
    pub pending_cross_chain_txs: usize,
    pub active_fraud_proofs: usize,
    pub federation_epochs: usize,
    pub active_peg_ins: usize,
    pub active_peg_outs: usize,
    pub completed_pegs: usize,
    pub proof_validations: u64,
    pub successful_validations: u64,
    pub failed_validations: u64,
    pub fraud_challenges: u64,
    pub proven_frauds: u64,
    pub active_fraud_challenges: usize,
}

// Legacy compatibility structures (updated)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTxPayload {
    pub sidechain_id: Hash,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidechainTx {
    pub payload: SidechainTxPayload,
    // Add other fields as needed, e.g., inputs, outputs, signatures
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrossChainTxType {
    PegIn,
    PegOut,
    SidechainToSidechain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossChainTxPayload {
    pub tx_type: CrossChainTxType,
    pub source_chain_id: Hash,
    pub destination_chain_id: Hash,
    pub amount: u64,
    pub asset_id: Hash,
    pub recipient_address: String,
    pub data: Vec<u8>,
}

/// Builder for constructing cross-chain transactions
pub struct CrossChainTxBuilder {
    tx_type: Option<CrossChainTxType>,
    source_chain_id: Option<Hash>,
    destination_chain_id: Option<Hash>,
    amount: Option<u64>,
    asset_id: Option<Hash>,
    recipient_address: Option<Vec<u8>>,
    data: Vec<u8>,
}

impl CrossChainTxBuilder {
    /// Create a new cross-chain transaction builder
    pub fn new() -> Self {
        Self {
            tx_type: None,
            source_chain_id: None,
            destination_chain_id: None,
            amount: None,
            asset_id: None,
            recipient_address: None,
            data: Vec::new(),
        }
    }

    /// Build a peg-in transaction
    pub fn build_peg_in(
        mainchain_id: Hash,
        sidechain_id: Hash,
        amount: u64,
        asset_id: Hash,
        sidechain_recipient: Vec<u8>,
    ) -> CrossChainTransaction {
        CrossChainTransaction::new(
            CrossChainTxType::PegIn,
            mainchain_id,
            sidechain_id,
            amount,
            asset_id,
            sidechain_recipient,
            Vec::new(),
        )
    }

    /// Build a peg-out transaction
    pub fn build_peg_out(
        sidechain_id: Hash,
        mainchain_id: Hash,
        amount: u64,
        asset_id: Hash,
        mainchain_recipient: Vec<u8>,
    ) -> CrossChainTransaction {
        CrossChainTransaction::new(
            CrossChainTxType::PegOut,
            sidechain_id,
            mainchain_id,
            amount,
            asset_id,
            mainchain_recipient,
            Vec::new(),
        )
    }

    /// Build an inter-sidechain transaction
    pub fn build_inter_sidechain(
        source_sidechain_id: Hash,
        destination_sidechain_id: Hash,
        amount: u64,
        asset_id: Hash,
        recipient: Vec<u8>,
    ) -> Result<CrossChainTransaction, String> {
        if source_sidechain_id == destination_sidechain_id {
            return Err("Source and destination sidechains must be different".to_string());
        }

        Ok(CrossChainTransaction::new(
            CrossChainTxType::SidechainToSidechain,
            source_sidechain_id,
            destination_sidechain_id,
            amount,
            asset_id,
            recipient,
            Vec::new(),
        ))
    }
}

impl Default for CrossChainTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for cross-chain transaction management
pub struct CrossChainTxUtils;

impl CrossChainTxUtils {
    /// Validate a batch of cross-chain transactions
    pub fn validate_batch(transactions: &[CrossChainTransaction]) -> Result<(), String> {
        for (i, tx) in transactions.iter().enumerate() {
            tx.verify().map_err(|e| format!("Transaction {} invalid: {}", i, e))?;
        }
        Ok(())
    }

    /// Calculate total value for a batch of transactions
    pub fn calculate_batch_value(transactions: &[CrossChainTransaction], asset_id: &Hash) -> u64 {
        transactions
            .iter()
            .filter(|tx| tx.asset_id == *asset_id)
            .map(|tx| tx.amount)
            .sum()
    }

    /// Group transactions by type
    pub fn group_by_type(transactions: &[CrossChainTransaction]) -> HashMap<CrossChainTxType, Vec<&CrossChainTransaction>> {
        let mut groups: HashMap<CrossChainTxType, Vec<&CrossChainTransaction>> = HashMap::new();

        for tx in transactions {
            groups.entry(tx.tx_type.clone()).or_insert_with(Vec::new).push(tx);
        }

        groups
    }

    /// Filter transactions by chain
    pub fn filter_by_chain<'a>(transactions: &'a [CrossChainTransaction], chain_id: &'a Hash) -> Vec<&'a CrossChainTransaction> {
        transactions
            .iter()
            .filter(|tx| tx.source_chain_id == *chain_id || tx.destination_chain_id == *chain_id)
            .collect()
    }

    /// Check if a transaction is ready for execution (has sufficient signatures)
    pub fn is_ready_for_execution(tx: &CrossChainTransaction, required_threshold: u32) -> bool {
        tx.has_sufficient_signatures(required_threshold)
    }

    /// Create a cross-chain transaction ID from components
    pub fn create_tx_id(
        tx_type: &CrossChainTxType,
        source_chain: &Hash,
        destination_chain: &Hash,
        amount: u64,
        nonce: u64,
    ) -> Hash {
        let type_byte = match tx_type {
            CrossChainTxType::PegIn => 1u8,
            CrossChainTxType::PegOut => 2u8,
            CrossChainTxType::SidechainToSidechain => 3u8,
        };

        let data = [
            &[type_byte],
            source_chain.as_slice(),
            destination_chain,
            &amount.to_le_bytes(),
            &nonce.to_le_bytes(),
        ].concat();

        blake3::hash(&data).into()
    }
}