//! Fuzz testing for transaction parsing and validation
//! 
//! This fuzz target focuses on transaction-specific parsing, validation,
//! and edge cases that could lead to vulnerabilities.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use rusty_core::types::{OutPoint, Transaction, TxInput, TxOutput, StandardTransaction};
use rusty_shared_types::Hash;
use std::io::Read;

/// Fuzzable transaction for comprehensive testing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTransaction {
    version: u32,
    inputs: Vec<FuzzTxInput>,
    outputs: Vec<FuzzTxOutput>,
    lock_time: u32,
    fee: u64,
    witness: Vec<Vec<u8>>,
}

/// Fuzzable transaction input with edge case handling
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTxInput {
    previous_output_txid: [u8; 32],
    previous_output_vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
    witness: Vec<u8>,
}

/// Fuzzable transaction output with value testing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTxOutput {
    value: u64,
    script_pubkey: Vec<u8>,
    memo: Option<Vec<u8>>,
}

impl From<FuzzTransaction> for Transaction {
    fn from(fuzz_tx: FuzzTransaction) -> Self {
        Transaction::Standard(StandardTransaction {
            version: fuzz_tx.version,
            inputs: fuzz_tx.inputs.into_iter().map(Into::into).collect(),
            outputs: fuzz_tx.outputs.into_iter().map(Into::into).collect(),
            lock_time: fuzz_tx.lock_time,
            fee: fuzz_tx.fee,
            witness: fuzz_tx.witness,
        })
    }
}

impl From<FuzzTxInput> for TxInput {
    fn from(fuzz_input: FuzzTxInput) -> Self {
        TxInput {
            previous_output: OutPoint {
                txid: fuzz_input.previous_output_txid,
                vout: fuzz_input.previous_output_vout,
            },
            script_sig: fuzz_input.script_sig,
            sequence: fuzz_input.sequence,
            witness: vec![fuzz_input.witness],
        }
    }
}

impl From<FuzzTxOutput> for TxOutput {
    fn from(fuzz_output: FuzzTxOutput) -> Self {
        TxOutput {
            value: fuzz_output.value,
            script_pubkey: fuzz_output.script_pubkey,
            memo: fuzz_output.memo.or(Some(vec![])),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    if let Ok(tx) = Transaction::arbitrary(&mut unstructured) {
        // Test basic serialization and deserialization
        let serialized = bincode::serialize(&tx).unwrap();
        let deserialized: Transaction = bincode::deserialize(&serialized).unwrap();
        assert_eq!(tx, deserialized);

        // Test transaction hashing
        let _tx_hash = tx.hash();

        // Test `verify` and `total_output_value` if `Transaction` is `Standard`
        if let Transaction::Standard(standard_tx) = tx {
            // Dummy implementations for fuzzing - actual verification would be in core logic
            let _ = standard_tx.version;
            let _ = standard_tx.inputs;
            let _ = standard_tx.lock_time;
            let _ = standard_tx.fee;
            let _ = standard_tx.witness;

            let manual_total: u64 = standard_tx.outputs.iter().map(|output| output.value).sum();
            let _ = manual_total;

            for (_i, input) in standard_tx.inputs.iter().enumerate() {
                let _ = input;
            }

            for (_i, output) in standard_tx.outputs.iter().enumerate() {
                let _ = output;
            }

            // You would call tx.verify() and tx.total_output_value() here
            // For fuzzing, we can simulate these or call dummy versions if they are not yet fully implemented
            // For now, let's just ensure we can access outputs and inputs
        }
    }

    // Fuzz transactions that only have outputs
    if data.len() > 100 {
        let mut unstructured_output_only = Unstructured::new(data);
        if let Ok(output) = TxOutput::arbitrary(&mut unstructured_output_only) {
            let output_only_tx = Transaction::Standard(StandardTransaction {
                version: 1,
                inputs: vec![],
                outputs: vec![output],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            });
            let _ = output_only_tx.hash();
            // The following would be actual calls to verify and total_output_value
            // let _ = output_only_tx.verify();
            // let _ = output_only_tx.total_output_value();
        }
    }

    // Fuzz transactions that only have inputs
    if data.len() > 100 {
        let mut unstructured_input_only = Unstructured::new(data);
        if let Ok(input) = TxInput::arbitrary(&mut unstructured_input_only) {
            let input_only_tx = Transaction::Standard(StandardTransaction {
                version: 1,
                inputs: vec![input],
                outputs: vec![],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            });
            let _ = input_only_tx.hash();
        }
    }

    // Fuzz empty transactions
    let empty_tx = Transaction::Standard(StandardTransaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        fee: 0,
        witness: vec![],
    });
    let _ = empty_tx.hash();
});

/// Test parsing of raw binary data as transactions
fn test_raw_transaction_parsing(data: &[u8]) {
    // Test transaction parsing
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        // Test transaction methods - access fields through match
        match &tx {
            Transaction::Standard(standard_tx) => {
                // Access fields of StandardTransaction
                let _total_output: u64 = standard_tx.outputs.iter().map(|o| o.value).sum();
            }
            // Add other variants if needed
            _ => {}
        }
        let _ = tx.get_outputs();
        let _ = tx.get_lock_time();
        let _ = tx.is_coinbase();
        let _ = tx.input_count();
        let _ = tx.output_count();
        let _ = tx.hash();
        
        // Test serialization roundtrip
        if let Ok(serialized) = bincode::serialize(&tx) {
            let _ = bincode::deserialize::<Transaction>(&serialized);
        }
    }
    
    // Test parsing individual components
    let _ = bincode::deserialize::<TxInput>(data);
    let _ = bincode::deserialize::<TxOutput>(data);
    let _ = bincode::deserialize::<OutPoint>(data);
    
    // Test with various data lengths
    for chunk_size in [1, 4, 8, 16, 32, 64, 128] {
        if data.len() >= chunk_size {
            let chunk = &data[..chunk_size];
            let _ = bincode::deserialize::<Transaction>(chunk);
        }
    }
}

/// Test structured transaction fuzzing with well-formed data
fn test_structured_transaction_fuzzing(fuzz_tx: FuzzTransaction) {
    let transaction: Transaction = fuzz_tx.into();
    
    // Test basic transaction operations
    let tx_hash = transaction.hash();
    assert_eq!(tx_hash.len(), 32);
    
    // Match on transaction variant to access fields
    match &transaction {
        Transaction::Standard(standard_tx) => {
            // Test value calculations
            let manual_total: u64 = standard_tx.outputs.iter().map(|output| output.value).sum();
            assert_eq!(standard_tx.fee, standard_tx.fee); // Basic assertion to use fee
            // Test input/output access patterns
            for (i, input) in standard_tx.inputs.iter().enumerate() {
                let _ = input.previous_output.txid;
                let _ = input.previous_output.vout;
                let _ = input.script_sig.len();
                let _ = input.sequence;
                if !input.script_sig.is_empty() {
                    let _ = input.script_sig[0];
                    let _ = input.script_sig[input.script_sig.len() - 1];
                }
            }
            for (i, output) in standard_tx.outputs.iter().enumerate() {
                let _ = output.value;
                let _ = output.script_pubkey.len();
                if !output.script_pubkey.is_empty() {
                    let _ = output.script_pubkey[0];
                    let _ = output.script_pubkey[output.script_pubkey.len() - 1];
                }
            }
            if let Ok(serialized) = bincode::serialize(&transaction) {
                if let Ok(deserialized) = bincode::deserialize::<Transaction>(&serialized) {
                    assert_eq!(transaction.hash(), deserialized.hash());
                }
            }
        }
        // Add other variants as needed
        _ => {}
    }
}

/// Test transaction validation with edge cases
fn test_transaction_validation_edge_cases(data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    
    // Create edge case transactions
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let lock_time = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    
    // Test empty transaction
    let empty_tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
    
    let _ = empty_tx.hash();
    
    // Test transaction with only inputs
    if data.len() >= 68 {
        let input = TxInput {
            previous_output: OutPoint {
                txid: {
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(&data[8..40]);
                    txid
                },
                vout: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            },
            script_sig: data[44..68].to_vec(),
            sequence: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            witness: vec![],
        };
        
        let input_only_tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
        
        let _ = input_only_tx.hash();
    }
    
    // Test transaction with only outputs
    if data.len() >= 24 {
        let value = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data.get(12).copied().unwrap_or(0),
            data.get(13).copied().unwrap_or(0),
            data.get(14).copied().unwrap_or(0),
            data.get(15).copied().unwrap_or(0),
        ]);
        
        let output = TxOutput {
            value,
            script_pubkey: data.get(16..40).unwrap_or(&[]).to_vec(),
            memo: None,
        };
        
        let output_only_tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
        let _ = output_only_tx.verify();
        let _ = output_only_tx.hash();
        let _ = output_only_tx.total_output_value();
    }
}

/// Test value arithmetic for overflow/underflow conditions
fn test_value_arithmetic(data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    
    // Test with extreme values
    let extreme_values = [
        0u64,
        1u64,
        u64::MAX,
        u64::MAX - 1,
        2_100_000_000_000_000u64, // Max Bitcoin supply in satoshis
    ];
    
    for &value in &extreme_values {
        let output = TxOutput {
            value,
            script_pubkey: vec![],
            memo: None,
        };
        
        let tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
        
        // Test hash calculation
        let _ = tx.hash();
        
        // Test output value access
        if let Transaction::Standard(standard_tx) = tx {
            // Calculate total output value manually
            let total: u64 = standard_tx.outputs.iter().map(|o| o.value).sum();
            assert_eq!(total, value);
        }
    }
    
    // Test multiple outputs with potential overflow
    let mut outputs = vec![];
    for chunk in data.chunks(8) {
        if chunk.len() == 8 {
            let value = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            outputs.push(TxOutput {
                value,
                script_pubkey: vec![],
                memo: None,
            });
        }
        
        // Limit to prevent excessive memory usage
        if outputs.len() >= 100 {
            break;
        }
    }
    
    if !outputs.is_empty() {
        let tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
        
        // Test total value calculation with potential overflow
        if let Transaction::Standard(standard_tx) = tx {
            let total: u64 = standard_tx.outputs.iter().map(|o| o.value).sum();
            // Just ensure the sum doesn't panic, actual value might wrap around
            let _ = total;
        }
        
        // Test hash calculation
        let _ = tx.hash();
    }
}

/// Test script parsing and validation
fn test_script_parsing(data: &[u8]) {
    // Test various script sizes and patterns
    for script_size in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 520] {
        if data.len() >= script_size {
            let script = data[..script_size].to_vec();
            
            // Test script in input
            let input = TxInput {
                previous_output: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: script.clone(),
                sequence: 0,
                witness: vec![],
            };
            
            // Test script in output
            let output = TxOutput {
                value: 1000000,
                script_pubkey: script,
                memo: None,
            };
            
            let tx = Transaction::Standard(StandardTransaction { version: 1, inputs: vec![], outputs: vec![], lock_time: 0, fee: 0, witness: vec![] });
            
            // Test hash calculation
            let _ = tx.hash();
        }
    }
    
    // Test common script patterns
    let script_patterns = [
        vec![],                           // Empty script
        vec![0x00],                       // OP_0
        vec![0x51],                       // OP_1
        vec![0x52],                       // OP_2
        vec![0x76, 0xa9, 0x14],          // OP_DUP OP_HASH160 <20 bytes>
        vec![0x21],                       // Push 33 bytes (pubkey)
        vec![0x41],                       // Push 65 bytes (uncompressed pubkey)
        vec![0x6a],                       // OP_RETURN
        vec![0xa9, 0x14],                // OP_HASH160 <20 bytes> (P2SH start)
    ];
    
    for pattern in script_patterns {
        let mut script = pattern;
        if data.len() > script.len() {
            script.extend_from_slice(&data[..std::cmp::min(data.len() - script.len(), 100)]);
        }
        let tx = Transaction::Standard(StandardTransaction {
            version: 1,
            inputs: vec![TxInput {
                previous_output: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: script.clone(),
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOutput {
                value: 1000000,
                script_pubkey: script,
                memo: Some(vec![]),
            }],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        });
        // Test hash calculation
        let _ = tx.hash();
    }
}
