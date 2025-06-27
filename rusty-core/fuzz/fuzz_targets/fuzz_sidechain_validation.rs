//! Fuzz testing for sidechain validation and operations
//! 
//! This fuzz target tests sidechain block validation, cross-chain transactions,
//! and other sidechain-specific operations for robustness and security.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use rusty_core::sidechain::*;
use rusty_shared_types::*;
use std::collections::HashMap;

/// Fuzzable sidechain block for testing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSidechainBlock {
    header: FuzzSidechainBlockHeader,
    transactions: Vec<FuzzSidechainTransaction>,
    cross_chain_transactions: Vec<FuzzCrossChainTransaction>,
    fraud_proofs: Vec<FuzzFraudProof>,
}

/// Fuzzable sidechain block header
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSidechainBlockHeader {
    version: u32,
    previous_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    cross_chain_merkle_root: [u8; 32],
    state_root: [u8; 32],
    timestamp: u64,
    height: u64,
    sidechain_id: [u8; 32],
    mainchain_anchor_height: u64,
    mainchain_anchor_hash: [u8; 32],
    difficulty_target: u64,
    nonce: u64,
    federation_epoch: u64,
}

/// Fuzzable sidechain transaction
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSidechainTransaction {
    version: u32,
    inputs: Vec<FuzzSidechainTxInput>,
    outputs: Vec<FuzzSidechainTxOutput>,
    lock_time: u64,
    vm_data: Option<FuzzVMExecutionData>,
    fee: u64,
}

/// Fuzzable sidechain transaction input
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSidechainTxInput {
    previous_output_txid: [u8; 32],
    previous_output_vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

/// Fuzzable sidechain transaction output
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSidechainTxOutput {
    value: u64,
    asset_id: [u8; 32],
    script_pubkey: Vec<u8>,
    data: Vec<u8>,
}

/// Fuzzable VM execution data
#[derive(Debug, Clone, Arbitrary)]
struct FuzzVMExecutionData {
    vm_type: u8, // Will be converted to VMType
    bytecode: Vec<u8>,
    gas_limit: u64,
    gas_price: u64,
    input_data: Vec<u8>,
}

/// Fuzzable cross-chain transaction
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCrossChainTransaction {
    tx_type: u8, // Will be converted to CrossChainTxType
    source_chain_id: [u8; 32],
    destination_chain_id: [u8; 32],
    amount: u64,
    asset_id: [u8; 32],
    recipient_address: Vec<u8>,
    proof: FuzzCrossChainProof,
    data: Vec<u8>,
}

/// Fuzzable cross-chain proof
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCrossChainProof {
    merkle_proof: Vec<[u8; 32]>,
    block_header: Vec<u8>,
    transaction_data: Vec<u8>,
    tx_index: u32,
}

/// Fuzzable fraud proof
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFraudProof {
    fraud_type: u8, // Will be converted to FraudType
    fraud_block_height: u64,
    fraud_tx_index: Option<u32>,
    evidence: FuzzFraudEvidence,
    challenger_address: Vec<u8>,
    challenge_bond: u64,
    response_deadline: u64,
}

/// Fuzzable fraud evidence
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFraudEvidence {
    pre_state: Vec<u8>,
    post_state: Vec<u8>,
    fraudulent_operation: Vec<u8>,
    witness_data: Vec<u8>,
    additional_evidence: Vec<(String, Vec<u8>)>,
}

// Conversion implementations
impl From<FuzzSidechainBlock> for SidechainBlock {
    fn from(fuzz_block: FuzzSidechainBlock) -> Self {
        SidechainBlock {
            header: fuzz_block.header.into(),
            transactions: fuzz_block.transactions.into_iter().map(Into::into).collect(),
            cross_chain_transactions: fuzz_block.cross_chain_transactions.into_iter().map(Into::into).collect(),
            fraud_proofs: fuzz_block.fraud_proofs.into_iter().map(Into::into).collect(),
            federation_signature: None,
        }
    }
}

impl From<FuzzSidechainBlockHeader> for SidechainBlockHeader {
    fn from(fuzz_header: FuzzSidechainBlockHeader) -> Self {
        SidechainBlockHeader::new(
            fuzz_header.previous_block_hash,
            fuzz_header.merkle_root,
            fuzz_header.cross_chain_merkle_root,
            fuzz_header.state_root,
            fuzz_header.height,
            fuzz_header.sidechain_id,
            fuzz_header.mainchain_anchor_height,
            fuzz_header.mainchain_anchor_hash,
            fuzz_header.federation_epoch,
        )
    }
}

impl From<FuzzSidechainTransaction> for SidechainTransaction {
    fn from(fuzz_tx: FuzzSidechainTransaction) -> Self {
        SidechainTransaction {
            version: fuzz_tx.version,
            inputs: fuzz_tx.inputs.into_iter().map(Into::into).collect(),
            outputs: fuzz_tx.outputs.into_iter().map(Into::into).collect(),
            lock_time: fuzz_tx.lock_time,
            vm_data: fuzz_tx.vm_data.map(Into::into),
            fee: fuzz_tx.fee,
        }
    }
}

impl From<FuzzSidechainTxInput> for SidechainTxInput {
    fn from(fuzz_input: FuzzSidechainTxInput) -> Self {
        SidechainTxInput {
            previous_output: SidechainOutPoint {
                txid: fuzz_input.previous_output_txid,
                vout: fuzz_input.previous_output_vout,
            },
            script_sig: fuzz_input.script_sig,
            sequence: fuzz_input.sequence,
        }
    }
}

impl From<FuzzSidechainTxOutput> for SidechainTxOutput {
    fn from(fuzz_output: FuzzSidechainTxOutput) -> Self {
        SidechainTxOutput {
            value: fuzz_output.value,
            asset_id: fuzz_output.asset_id,
            script_pubkey: fuzz_output.script_pubkey,
            data: fuzz_output.data,
        }
    }
}

impl From<FuzzVMExecutionData> for VMExecutionData {
    fn from(fuzz_vm: FuzzVMExecutionData) -> Self {
        let vm_type = match fuzz_vm.vm_type % 4 {
            0 => VMType::EVM,
            1 => VMType::WASM,
            2 => VMType::UtxoVM,
            _ => VMType::Native,
        };
        
        VMExecutionData {
            vm_type,
            bytecode: fuzz_vm.bytecode,
            gas_limit: fuzz_vm.gas_limit,
            gas_price: fuzz_vm.gas_price,
            input_data: fuzz_vm.input_data,
        }
    }
}

impl From<FuzzCrossChainTransaction> for CrossChainTransaction {
    fn from(fuzz_tx: FuzzCrossChainTransaction) -> Self {
        let tx_type = match fuzz_tx.tx_type % 3 {
            0 => CrossChainTxType::PegIn,
            1 => CrossChainTxType::PegOut,
            _ => CrossChainTxType::SidechainToSidechain,
        };
        
        CrossChainTransaction {
            tx_type,
            source_chain_id: fuzz_tx.source_chain_id,
            destination_chain_id: fuzz_tx.destination_chain_id,
            amount: fuzz_tx.amount,
            asset_id: fuzz_tx.asset_id,
            recipient_address: fuzz_tx.recipient_address,
            proof: fuzz_tx.proof.into(),
            data: fuzz_tx.data,
            federation_signatures: vec![],
        }
    }
}

impl From<FuzzCrossChainProof> for CrossChainProof {
    fn from(fuzz_proof: FuzzCrossChainProof) -> Self {
        CrossChainProof {
            merkle_proof: fuzz_proof.merkle_proof,
            block_header: fuzz_proof.block_header,
            transaction_data: fuzz_proof.transaction_data,
            tx_index: fuzz_proof.tx_index,
        }
    }
}

impl From<FuzzFraudProof> for FraudProof {
    fn from(fuzz_proof: FuzzFraudProof) -> Self {
        let fraud_type = match fuzz_proof.fraud_type % 5 {
            0 => FraudType::InvalidStateTransition,
            1 => FraudType::DoubleSpending,
            2 => FraudType::InvalidCrossChainTx,
            3 => FraudType::UnauthorizedSignature,
            _ => FraudType::InvalidVMExecution,
        };
        
        FraudProof {
            fraud_type,
            fraud_block_height: fuzz_proof.fraud_block_height,
            fraud_tx_index: fuzz_proof.fraud_tx_index,
            evidence: fuzz_proof.evidence.into(),
            challenger_address: fuzz_proof.challenger_address,
            challenge_bond: fuzz_proof.challenge_bond,
            response_deadline: fuzz_proof.response_deadline,
        }
    }
}

impl From<FuzzFraudEvidence> for FraudEvidence {
    fn from(fuzz_evidence: FuzzFraudEvidence) -> Self {
        let mut additional_evidence = HashMap::new();
        for (key, value) in fuzz_evidence.additional_evidence {
            additional_evidence.insert(key, value);
        }
        
        FraudEvidence {
            pre_state: fuzz_evidence.pre_state,
            post_state: fuzz_evidence.post_state,
            fraudulent_operation: fuzz_evidence.fraudulent_operation,
            witness_data: fuzz_evidence.witness_data,
            additional_evidence,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Test 1: Raw sidechain data parsing
    test_raw_sidechain_parsing(data);
    
    // Test 2: Structured sidechain block fuzzing
    if let Ok(fuzz_block) = FuzzSidechainBlock::arbitrary(&mut Unstructured::new(data)) {
        test_structured_sidechain_fuzzing(fuzz_block);
    }
    
    // Test 3: Cross-chain transaction validation
    test_cross_chain_validation(data);
    
    // Test 4: Fraud proof validation
    test_fraud_proof_validation(data);
    
    // Test 5: VM execution fuzzing
    test_vm_execution_fuzzing(data);
});

/// Test parsing of raw binary data as sidechain components
fn test_raw_sidechain_parsing(data: &[u8]) {
    // Test sidechain block parsing
    if let Ok(block) = bincode::deserialize::<SidechainBlock>(data) {
        let _ = block.hash();
        let _ = block.verify();
        let _ = block.calculate_merkle_root();
        let _ = block.is_anchored();
    }
    
    // Test sidechain transaction parsing
    if let Ok(tx) = bincode::deserialize::<SidechainTransaction>(data) {
        let _ = tx.hash();
        let _ = tx.verify();
        let _ = tx.total_output_value();
    }
    
    // Test cross-chain transaction parsing
    if let Ok(cross_tx) = bincode::deserialize::<CrossChainTransaction>(data) {
        let _ = cross_tx.hash();
        let _ = cross_tx.verify();
    }
    
    // Test fraud proof parsing
    if let Ok(fraud_proof) = bincode::deserialize::<FraudProof>(data) {
        let _ = fraud_proof.hash();
        let _ = fraud_proof.verify();
    }
}

/// Test structured sidechain block fuzzing
fn test_structured_sidechain_fuzzing(fuzz_block: FuzzSidechainBlock) {
    let block: SidechainBlock = fuzz_block.into();
    
    // Test basic block operations
    let block_hash = block.hash();
    assert_eq!(block_hash.len(), 32);
    
    // Test block validation
    let _ = block.verify();
    
    // Test merkle root calculation
    let merkle_root = block.calculate_merkle_root();
    assert_eq!(merkle_root.len(), 32);
    
    let cross_chain_merkle_root = block.calculate_cross_chain_merkle_root();
    assert_eq!(cross_chain_merkle_root.len(), 32);
    
    // Test anchoring
    let _ = block.is_anchored();
    
    // Test sidechain state operations
    let mut sidechain_state = SidechainState::new();
    
    // Register a test sidechain
    let sidechain_info = SidechainInfo {
        sidechain_id: block.header.sidechain_id,
        name: "Fuzz Test Sidechain".to_string(),
        peg_address: vec![1, 2, 3, 4],
        federation_members: vec![],
        current_epoch: 1,
        vm_type: VMType::EVM,
        genesis_block_hash: [0u8; 32],
        creation_timestamp: 1234567890,
        min_federation_threshold: 1,
    };
    
    let _ = sidechain_state.register_sidechain(sidechain_info);
    
    // Test block processing
    let _ = sidechain_state.process_sidechain_block(block);
}

/// Test cross-chain transaction validation
fn test_cross_chain_validation(data: &[u8]) {
    if let Ok(fuzz_tx) = FuzzCrossChainTransaction::arbitrary(&mut Unstructured::new(data)) {
        let cross_tx: CrossChainTransaction = fuzz_tx.into();
        
        // Test basic operations
        let _ = cross_tx.hash();
        let _ = cross_tx.verify();
        let _ = cross_tx.tx_type_string();
        let _ = cross_tx.is_mainchain_operation();
        let _ = cross_tx.is_inter_sidechain_operation();
        let _ = cross_tx.calculate_fee(1000, 0.001);
        
        // Test serialization
        if let Ok(serialized) = cross_tx.serialize() {
            let _ = CrossChainTransaction::deserialize(&serialized);
        }
        
        // Test with sidechain state
        let mut sidechain_state = SidechainState::new();
        let _ = sidechain_state.validate_cross_chain_proof(&cross_tx);
    }
}

/// Test fraud proof validation
fn test_fraud_proof_validation(data: &[u8]) {
    if let Ok(fuzz_proof) = FuzzFraudProof::arbitrary(&mut Unstructured::new(data)) {
        let fraud_proof: FraudProof = fuzz_proof.into();
        
        // Test basic operations
        let _ = fraud_proof.hash();
        let _ = fraud_proof.verify();
        
        // Test with sidechain state
        let mut sidechain_state = SidechainState::new();
        let _ = sidechain_state.validate_fraud_proof_standalone(&fraud_proof);
        
        // Test fraud proof submission
        let _ = sidechain_state.submit_fraud_proof(fraud_proof, 1000000);
    }
}

/// Test VM execution fuzzing
fn test_vm_execution_fuzzing(data: &[u8]) {
    if let Ok(fuzz_vm) = FuzzVMExecutionData::arbitrary(&mut Unstructured::new(data)) {
        let vm_data: VMExecutionData = fuzz_vm.into();
        
        // Test VM data validation
        let _ = vm_data.verify();
        
        // Test with different VM types
        for vm_type in [VMType::EVM, VMType::WASM, VMType::UtxoVM, VMType::Native] {
            let mut test_vm_data = vm_data.clone();
            test_vm_data.vm_type = vm_type;
            let _ = test_vm_data.verify();
        }
        
        // Test in transaction context
        let tx = SidechainTransaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            vm_data: Some(vm_data),
            fee: 1000,
        };
        
        let _ = tx.verify();
        let _ = tx.hash();
    }
}
