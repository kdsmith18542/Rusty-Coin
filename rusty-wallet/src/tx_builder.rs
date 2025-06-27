// rusty-wallet/src/tx_builder.rs

use anyhow::{anyhow, Result};
use rusty_shared_types::{OutPoint, StandardTransaction, Transaction, TxInput, TxOutput};
use crate::keys::HDWallet;
use std::convert::TryInto;

pub struct TransactionBuilder {
    // Placeholder for UTXO set management
    // In a real wallet, this would be a more sophisticated UTXO database
    available_utxos: Vec<([u8; 32], u64, u64)>, // (txid, vout, amount)
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder { available_utxos: Vec::new() }
    }

    // Placeholder for adding UTXOs to the builder
    pub fn add_utxo(&mut self, txid_hex: String, vout: u64, amount: u64) -> Result<()> {
        // Convert hex string to [u8; 32]
        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| anyhow!("Invalid txid hex: {}", e))?;
        let txid: [u8; 32] = txid_bytes.try_into()
            .map_err(|_| anyhow!("Invalid txid length, expected 32 bytes"))?;
            
        self.available_utxos.push((txid, vout, amount));
        Ok(())
    }

    /// Builds a new transaction
    pub fn build_transaction(
        &mut self,
        recipient_address: &str,
        amount: u64,
        _fee_per_byte: u64,  // Will be used in future implementation
        wallet: &HDWallet,
    ) -> Result<Transaction> {
        let _sender_pubkey = wallet.public_key_bytes()?;  // Will be used in future implementation
        let recipient_pubkey = hex::decode(recipient_address)
            .map_err(|e| anyhow!("Invalid recipient address: {}", e))?;

        // Simple transaction with one input and one output
        // In a real implementation, you would select appropriate UTXOs and calculate fees
        let (txid, vout) = if let Some((txid, vout, _)) = self.available_utxos.first() {
            // Use the first available UTXO
            (*txid, *vout)
        } else {
            // Fallback to a zero txid if no UTXOs are available
            ([0u8; 32], 0)
        };

        // Convert vout from u64 to u32, panicking if it doesn't fit
        // In a production environment, you'd want to handle this more gracefully
        let vout_u32 = vout.try_into().expect("vout value too large for u32");

        let input = TxInput {
            previous_output: OutPoint {
                txid,
                vout: vout_u32,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
            witness: vec![], // Add missing witness field
        };

        let output = TxOutput {
            value: amount,
            script_pubkey: recipient_pubkey,
            memo: None, // Add missing memo field
        };

        // Create the outputs
        let outputs = vec![output];
        
        // In a real implementation, you would calculate the actual fee based on tx size
        let estimated_fee = 1000; // Placeholder fee

        // Create a standard transaction
        let standard_tx = StandardTransaction {
            version: 1,
            inputs: vec![input],
            outputs,
            lock_time: 0,
            fee: estimated_fee,
            witness: vec![], // Add missing witness field
        };

        // Wrap it in the Transaction enum
        let tx = Transaction::Standard {
            version: standard_tx.version,
            inputs: standard_tx.inputs,
            outputs: standard_tx.outputs,
            lock_time: standard_tx.lock_time,
            fee: standard_tx.fee,
            witness: standard_tx.witness,
        };

        Ok(tx)
    }

    /// Signs a transaction with the wallet's private key
    pub fn sign_transaction(
        &self,
        transaction: &mut Transaction,
        wallet: &HDWallet,
    ) -> Result<()> {
        match transaction {
            Transaction::Standard { ref mut inputs, .. } => {
                // In a real implementation, you would:
                // 1. Create a sighash of the transaction
                // 2. Sign the hash with the wallet's private key
                // 3. Add the signature to the appropriate input(s)
                
                // For now, we'll just add a placeholder signature
                if let Some(input) = inputs.first_mut() {
                    // Sign the transaction hash (in reality, you'd sign the sighash)
                    let tx_hash = b"TX_HASH_PLACEHOLDER";
                    let signature = wallet.sign(tx_hash)?;
                    
                    // In a real implementation, you'd use a proper script
                    input.script_sig = signature;
                    
                    Ok(())
                } else {
                    Err(anyhow!("No inputs to sign"))
                }
            }
            _ => Err(anyhow!("Unsupported transaction type")),
        }
    }
}