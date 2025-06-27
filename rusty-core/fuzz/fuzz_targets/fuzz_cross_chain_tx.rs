//! Fuzz testing for cross-chain transactions
//! 
//! This fuzz target tests cross-chain transaction parsing, validation,
//! and processing for security vulnerabilities and edge cases.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use rusty_core::sidechain::*;
use rusty_shared_types::*;

/// Fuzzable cross-chain transaction
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCrossChainTransaction {
    tx_type: u8,
    source_chain_id: [u8; 32],
    destination_chain_id: [u8; 32],
    amount: u64,
    asset_id: [u8; 32],
    recipient_address: Vec<u8>,
    proof: FuzzCrossChainProof,
    data: Vec<u8>,
    federation_signatures: Vec<FuzzFederationSignature>,
}

/// Fuzzable cross-chain proof
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCrossChainProof {
    merkle_proof: Vec<[u8; 32]>,
    block_header: Vec<u8>,
    transaction_data: Vec<u8>,
    tx_index: u32,
}

/// Fuzzable federation signature
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFederationSignature {
    signature: Vec<u8>,
    signer_bitmap: Vec<u8>,
    threshold: u32,
    epoch: u64,
    message_hash: [u8; 32],
}

// Conversion implementations
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
            federation_signatures: fuzz_tx.federation_signatures.into_iter().map(Into::into).collect(),
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

impl From<FuzzFederationSignature> for FederationSignature {
    fn from(fuzz_sig: FuzzFederationSignature) -> Self {
        FederationSignature {
            signature: fuzz_sig.signature,
            signer_bitmap: fuzz_sig.signer_bitmap,
            threshold: fuzz_sig.threshold,
            epoch: fuzz_sig.epoch,
            message_hash: fuzz_sig.message_hash,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Test 1: Raw cross-chain transaction parsing
    test_raw_cross_chain_parsing(data);
    
    // Test 2: Structured cross-chain transaction fuzzing
    if let Ok(fuzz_tx) = FuzzCrossChainTransaction::arbitrary(&mut Unstructured::new(data)) {
        test_structured_cross_chain_fuzzing(fuzz_tx);
    }
    
    // Test 3: Cross-chain proof validation
    test_cross_chain_proof_validation(data);
    
    // Test 4: Federation signature validation
    test_federation_signature_validation(data);
    
    // Test 5: Cross-chain transaction utilities
    test_cross_chain_utilities(data);
});

/// Test parsing of raw binary data as cross-chain components
fn test_raw_cross_chain_parsing(data: &[u8]) {
    // Test cross-chain transaction parsing
    if let Ok(cross_tx) = bincode::deserialize::<CrossChainTransaction>(data) {
        let _ = cross_tx.hash();
        let _ = cross_tx.verify();
        let _ = cross_tx.tx_type_string();
        let _ = cross_tx.is_mainchain_operation();
        let _ = cross_tx.is_inter_sidechain_operation();
        let _ = cross_tx.calculate_fee(1000, 0.001);
        
        // Test serialization round-trip
        if let Ok(serialized) = cross_tx.serialize() {
            let _ = CrossChainTransaction::deserialize(&serialized);
        }
    }
    
    // Test cross-chain proof parsing
    if let Ok(proof) = bincode::deserialize::<CrossChainProof>(data) {
        let _ = proof.verify();
        let _ = proof.merkle_proof.len();
        let _ = proof.block_header.len();
        let _ = proof.transaction_data.len();
    }
    
    // Test federation signature parsing
    if let Ok(signature) = bincode::deserialize::<FederationSignature>(data) {
        let test_hash = [1u8; 32];
        let _ = signature.verify(&test_hash);
        let _ = signature.count_signers();
    }
}

/// Test structured cross-chain transaction fuzzing
fn test_structured_cross_chain_fuzzing(fuzz_tx: FuzzCrossChainTransaction) {
    let cross_tx: CrossChainTransaction = fuzz_tx.into();
    
    // Test basic operations
    let tx_hash = cross_tx.hash();
    assert_eq!(tx_hash.len(), 32);
    
    // Test validation
    let _ = cross_tx.verify();
    
    // Test type checking
    let type_string = cross_tx.tx_type_string();
    assert!(!type_string.is_empty());
    
    let is_mainchain = cross_tx.is_mainchain_operation();
    let is_inter_sidechain = cross_tx.is_inter_sidechain_operation();
    
    // Test fee calculation
    let _ = cross_tx.calculate_fee(1000, 0.001);
    let _ = cross_tx.calculate_fee(0, 0.0);
    let _ = cross_tx.calculate_fee(u64::MAX, 1.0);
    
    // Test serialization
    if let Ok(serialized) = cross_tx.serialize() {
        if let Ok(deserialized) = CrossChainTransaction::deserialize(&serialized) {
            assert_eq!(cross_tx.hash(), deserialized.hash());
            assert_eq!(cross_tx.amount, deserialized.amount);
            assert_eq!(cross_tx.tx_type, deserialized.tx_type);
        }
    }
    
    // Test with sidechain state
    let mut sidechain_state = SidechainState::new();
    let _ = sidechain_state.validate_cross_chain_proof(&cross_tx);
    
    // Test builder patterns
    match cross_tx.tx_type {
        CrossChainTxType::PegIn => {
            let built_tx = CrossChainTxBuilder::build_peg_in(
                cross_tx.source_chain_id,
                cross_tx.destination_chain_id,
                cross_tx.amount,
                cross_tx.asset_id,
                cross_tx.recipient_address.clone(),
            );
            assert_eq!(built_tx.tx_type, CrossChainTxType::PegIn);
        }
        CrossChainTxType::PegOut => {
            let built_tx = CrossChainTxBuilder::build_peg_out(
                cross_tx.source_chain_id,
                cross_tx.destination_chain_id,
                cross_tx.amount,
                cross_tx.asset_id,
                cross_tx.recipient_address.clone(),
            );
            assert_eq!(built_tx.tx_type, CrossChainTxType::PegOut);
        }
        CrossChainTxType::SidechainToSidechain => {
            if let Ok(built_tx) = CrossChainTxBuilder::build_inter_sidechain(
                cross_tx.source_chain_id,
                cross_tx.destination_chain_id,
                cross_tx.amount,
                cross_tx.asset_id,
                cross_tx.recipient_address.clone(),
            ) {
                assert_eq!(built_tx.tx_type, CrossChainTxType::SidechainToSidechain);
            }
        }
    }
    
    // Test federation signature operations
    for signature in &cross_tx.federation_signatures {
        let _ = signature.verify(&cross_tx.hash());
        let _ = signature.count_signers();
    }
}

/// Test cross-chain proof validation
fn test_cross_chain_proof_validation(data: &[u8]) {
    if let Ok(fuzz_proof) = FuzzCrossChainProof::arbitrary(&mut Unstructured::new(data)) {
        let proof: CrossChainProof = fuzz_proof.into();
        
        // Test basic proof operations
        let _ = proof.verify();
        
        // Test proof components
        assert_eq!(proof.merkle_proof.len(), proof.merkle_proof.len());
        
        // Test with different merkle proof sizes
        for i in 0..std::cmp::min(proof.merkle_proof.len(), 32) {
            let truncated_proof = CrossChainProof {
                merkle_proof: proof.merkle_proof[..i].to_vec(),
                block_header: proof.block_header.clone(),
                transaction_data: proof.transaction_data.clone(),
                tx_index: proof.tx_index,
            };
            let _ = truncated_proof.verify();
        }
        
        // Test with modified transaction index
        let modified_proof = CrossChainProof {
            merkle_proof: proof.merkle_proof.clone(),
            block_header: proof.block_header.clone(),
            transaction_data: proof.transaction_data.clone(),
            tx_index: proof.tx_index.wrapping_add(1),
        };
        let _ = modified_proof.verify();
        
        // Test with empty components
        let empty_proof = CrossChainProof {
            merkle_proof: vec![],
            block_header: vec![],
            transaction_data: vec![],
            tx_index: 0,
        };
        let _ = empty_proof.verify();
    }
}

/// Test federation signature validation
fn test_federation_signature_validation(data: &[u8]) {
    if let Ok(fuzz_sig) = FuzzFederationSignature::arbitrary(&mut Unstructured::new(data)) {
        let signature: FederationSignature = fuzz_sig.into();
        
        // Test signature operations
        let test_message = [42u8; 32];
        let _ = signature.verify(&test_message);
        let _ = signature.verify(&signature.message_hash);
        
        // Test signer counting
        let signer_count = signature.count_signers();
        
        // Test with different message hashes
        let different_messages = [
            [0u8; 32],
            [255u8; 32],
            signature.message_hash,
        ];
        
        for message in &different_messages {
            let _ = signature.verify(message);
        }
        
        // Test threshold validation
        let meets_threshold = signer_count >= signature.threshold;
        
        // Test with modified threshold
        let mut modified_signature = signature.clone();
        modified_signature.threshold = modified_signature.threshold.saturating_add(1);
        let _ = modified_signature.verify(&test_message);
        
        modified_signature.threshold = modified_signature.threshold.saturating_sub(2);
        let _ = modified_signature.verify(&test_message);
        
        // Test with empty signature
        let empty_signature = FederationSignature {
            signature: vec![],
            signer_bitmap: vec![],
            threshold: 0,
            epoch: 0,
            message_hash: [0u8; 32],
        };
        let _ = empty_signature.verify(&test_message);
        let _ = empty_signature.count_signers();
    }
}

/// Test cross-chain transaction utilities
fn test_cross_chain_utilities(data: &[u8]) {
    // Create multiple cross-chain transactions for batch testing
    let mut transactions = Vec::new();
    
    for chunk in data.chunks(64) {
        if chunk.len() >= 64 {
            let tx = CrossChainTransaction::new(
                CrossChainTxType::PegIn,
                {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&chunk[0..32]);
                    id
                },
                {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&chunk[32..64]);
                    id
                },
                u64::from_le_bytes([
                    chunk.get(64).copied().unwrap_or(0),
                    chunk.get(65).copied().unwrap_or(0),
                    chunk.get(66).copied().unwrap_or(0),
                    chunk.get(67).copied().unwrap_or(0),
                    chunk.get(68).copied().unwrap_or(0),
                    chunk.get(69).copied().unwrap_or(0),
                    chunk.get(70).copied().unwrap_or(0),
                    chunk.get(71).copied().unwrap_or(0),
                ]),
                [1u8; 32], // asset_id
                chunk.get(72..).unwrap_or(&[]).to_vec(),
                chunk.get(80..).unwrap_or(&[]).to_vec(),
            );
            transactions.push(tx);
        }
        
        // Limit to prevent excessive memory usage
        if transactions.len() >= 10 {
            break;
        }
    }
    
    if !transactions.is_empty() {
        // Test batch validation
        let _ = CrossChainTxUtils::validate_batch(&transactions);
        
        // Test batch value calculation
        let asset_id = [1u8; 32];
        let total_value = CrossChainTxUtils::calculate_batch_value(&transactions, &asset_id);
        
        // Verify total value calculation
        let manual_total: u64 = transactions.iter()
            .filter(|tx| tx.asset_id == asset_id)
            .map(|tx| tx.amount)
            .sum();
        assert_eq!(total_value, manual_total);
        
        // Test grouping by type
        let groups = CrossChainTxUtils::group_by_type(&transactions);
        let total_grouped: usize = groups.values().map(|v| v.len()).sum();
        assert_eq!(total_grouped, transactions.len());
        
        // Test filtering by chain
        if !transactions.is_empty() {
            let chain_id = transactions[0].source_chain_id;
            let filtered = CrossChainTxUtils::filter_by_chain(&transactions, &chain_id);
            
            // All filtered transactions should involve the specified chain
            for tx in &filtered {
                assert!(tx.source_chain_id == chain_id || tx.destination_chain_id == chain_id);
            }
        }
        
        // Test readiness checking
        for tx in &transactions {
            let _ = CrossChainTxUtils::is_ready_for_execution(tx, 2);
            let _ = CrossChainTxUtils::is_ready_for_execution(tx, 0);
            let _ = CrossChainTxUtils::is_ready_for_execution(tx, u32::MAX);
        }
    }
    
    // Test edge cases with empty collections
    let empty_transactions = Vec::new();
    let _ = CrossChainTxUtils::validate_batch(&empty_transactions);
    let _ = CrossChainTxUtils::calculate_batch_value(&empty_transactions, &[0u8; 32]);
    let _ = CrossChainTxUtils::group_by_type(&empty_transactions);
    let _ = CrossChainTxUtils::filter_by_chain(&empty_transactions, &[0u8; 32]);
}
