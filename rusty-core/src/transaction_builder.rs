use rusty_shared_types::{TxInput, TxOutput, Transaction, UtxoId, Utxo, StandardTransaction, OutPoint};
use std::collections::HashMap;
use std::fmt;

pub enum TransactionBuilderError {
    InsufficientFunds,
    NoUtxosAvailable,
    UtxoNotFound(UtxoId),
    GenericError(String),
    InvalidInput,
}

impl From<String> for TransactionBuilderError {
    fn from(msg: String) -> Self {
        TransactionBuilderError::GenericError(msg)
    }
}

impl fmt::Display for TransactionBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionBuilderError::InsufficientFunds => write!(f, "Insufficient funds"),
            TransactionBuilderError::InvalidInput => write!(f, "Invalid input"),
            TransactionBuilderError::NoUtxosAvailable => write!(f, "No UTXOs available"),
            TransactionBuilderError::UtxoNotFound(utxo) => write!(f, "UTXO not found: {:?}", utxo),
            TransactionBuilderError::GenericError(msg) => write!(f, "{}", msg),
        }
    }
}

// A simple UTXO selector for demonstration purposes.
// In a real wallet, this would be more sophisticated, considering factors like
// coin age, privacy, and fee optimization.
pub fn select_utxos(
    available_utxos: &HashMap<UtxoId, Utxo>,
    amount_needed: u64,
    fee_per_byte: u64,
) -> Result<(Vec<TxInput>, u64), TransactionBuilderError> {
    let mut selected_inputs = Vec::new();
    let mut current_value = 0;

    // Sort UTXOs by value to try and pick smaller ones first to minimize change outputs
    let mut sorted_utxos: Vec<(&UtxoId, &Utxo)> = available_utxos.iter().collect();
    sorted_utxos.sort_by_key(|(_, utxo)| utxo.output.value);

    for (utxo_id, utxo) in sorted_utxos {
        selected_inputs.push(TxInput {
            previous_output: utxo_id.0.clone(),
            script_sig: Vec::new(), // To be filled by signing
            sequence: 0xFFFFFFFF,
            witness: vec![],
        });
        current_value += utxo.output.value;

        // Rough fee estimation: base fee + inputs * 100 + outputs * 100 bytes
        let estimated_fee = (selected_inputs.len() as u64 * 100 + 2 * 100) * fee_per_byte; // rough estimate

        if current_value >= amount_needed + estimated_fee {
            return Ok((selected_inputs, current_value));
        }
    }

    Err(TransactionBuilderError::InsufficientFunds)
}

pub fn calculate_transaction_fee(tx: &Transaction, fee_per_byte: u64) -> u64 {
    // This is a very simplistic fee calculation. In a real system,
    // you'd serialize the transaction and get its byte size.
    // For now, we'll just use a rough estimate based on inputs and outputs.
    let base_size = 100; // Base size for transaction overhead
    let input_size = 100; // Average size per input
    let output_size = 100; // Average size per output

    let num_inputs = tx.input_count();
    let num_outputs = tx.output_count();

    let total_size = base_size + (num_inputs * input_size) + (num_outputs * output_size);
    (total_size as u64) * fee_per_byte
}

pub struct TransactionBuilder;

impl TransactionBuilder {
    pub fn input_count(&self, tx: &Transaction) -> usize {
        match tx {
            Transaction::Standard { inputs, .. } => inputs.len(),
            Transaction::TicketPurchase { inputs, .. } => inputs.len(),
            Transaction::TicketRedemption { inputs, .. } => inputs.len(),
            _ => 0
        }
    }

    pub fn output_count(&self, tx: &Transaction) -> usize {
        match tx {
            Transaction::Standard { outputs, .. } => outputs.len(),
            Transaction::TicketPurchase { outputs, .. } => outputs.len(),
            Transaction::TicketRedemption { outputs, .. } => outputs.len(),
            _ => 0
        }
    }

    pub fn build_standard_transaction(
        &self,
        selected_inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        fee: u64
    ) -> Result<Transaction, TransactionBuilderError> {
        Ok(Transaction::Standard {
            version: 1,
            inputs: selected_inputs,
            outputs,
            fee,
            lock_time: 0,
            witness: vec![],
        })
    }

    pub fn build_ticket_purchase_transaction(
        &self,
        tx: StandardTransaction,
        ticket_id: [u8; 32],
        locked_amount: u64,
        ticket_address: Vec<u8>
    ) -> Transaction {
        Transaction::TicketPurchase {
            version: tx.version,
            inputs: tx.inputs,
            outputs: tx.outputs,
            ticket_id,
            locked_amount,
            lock_time: tx.lock_time,
            fee: tx.fee,
            ticket_address,
            witness: vec![],
        }
    }

    pub fn build_ticket_redemption_transaction(
        &self,
        tx: StandardTransaction,
        ticket_id: [u8; 32]
    ) -> Transaction {
        Transaction::TicketRedemption {
            version: tx.version,
            inputs: tx.inputs,
            outputs: tx.outputs,
            ticket_id,
            lock_time: tx.lock_time,
            fee: tx.fee,
            witness: vec![],
        }
    }
}

/// Creates a coinbase transaction for a block
pub fn create_coinbase_transaction(
    miner_address: Vec<u8>,
    block_height: u64,
    block_reward: u64,
) -> Transaction {
    let coinbase_input = TxInput {
        previous_output: OutPoint { txid: [0u8; 32], vout: 0xFFFFFFFF }, // Null hash for coinbase
        script_sig: block_height.to_le_bytes().to_vec(), // Block height in script_sig
        sequence: 0xFFFFFFFF,
        witness: vec![],
    };

    let coinbase_output = TxOutput {
        value: block_reward,
        script_pubkey: miner_address,
        memo: None,
    };

    Transaction::Coinbase {
        version: 1,
        inputs: vec![coinbase_input],
        outputs: vec![coinbase_output],
        lock_time: 0,
        // Coinbase transactions don't pay fees - remove this field
        witness: vec![],
    }
}