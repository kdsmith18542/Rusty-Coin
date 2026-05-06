// rusty-wallet/src/tx_builder.rs

use crate::keys::HDWallet;
use anyhow::{anyhow, Result};
use bincode;
use blake3;
use rusty_core::constants::MIN_RELAY_FEE_PER_BYTE;
use rusty_shared_types::{OutPoint, StandardTransaction, Transaction, TxInput, TxOutput};
use std::collections::HashMap;
use std::convert::TryInto;

/// Script types supported by the wallet per docs/specs/05_utxo_model_spec.md
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (P2PKH) - 20-byte pubkey hash
    P2PKH(Vec<u8>),
    /// Pay-to-Script-Hash (P2SH) - 20-byte script hash
    P2SH(Vec<u8>),
    /// Pay-to-Public-Key (P2PK) - 33-byte compressed pubkey
    P2PK(Vec<u8>),
    /// M-of-N Multisig
    Multisig { m: u8, pubkeys: Vec<Vec<u8>> },
    /// OP_RETURN data output (provably unspendable)
    OpReturn(Vec<u8>),
    /// Custom raw script bytes
    Custom(Vec<u8>),
}

impl ScriptType {
    /// Create script_pubkey bytes for this script type
    pub fn to_script_pubkey(&self) -> Result<Vec<u8>> {
        match self {
            ScriptType::P2PKH(pubkey_hash) => {
                if pubkey_hash.len() != 20 {
                    return Err(anyhow!("P2PKH requires 20-byte pubkey hash"));
                }
                Ok(create_p2pkh_script(&pubkey_hash[..20].try_into().unwrap()))
            }
            ScriptType::P2SH(script_hash) => {
                if script_hash.len() != 20 {
                    return Err(anyhow!("P2SH requires 20-byte script hash"));
                }
                Ok(create_p2sh_script(&script_hash[..20].try_into().unwrap()))
            }
            ScriptType::P2PK(pubkey) => {
                if pubkey.len() != 33 {
                    return Err(anyhow!("P2PK requires 33-byte compressed pubkey"));
                }
                Ok(create_p2pk_script(&pubkey[..33].try_into().unwrap()))
            }
            ScriptType::Multisig { m, pubkeys } => {
                if *m == 0 || *m > pubkeys.len() as u8 || pubkeys.len() > 20 {
                    return Err(anyhow!("Invalid multisig parameters"));
                }
                for pubkey in pubkeys {
                    if pubkey.len() != 33 {
                        return Err(anyhow!("Multisig requires 33-byte compressed pubkeys"));
                    }
                }
                Ok(create_multisig_script(*m, pubkeys))
            }
            ScriptType::OpReturn(data) => {
                if data.len() > 80 {
                    return Err(anyhow!("OP_RETURN data too large (max 80 bytes)"));
                }
                Ok(create_op_return_script(data))
            }
            ScriptType::Custom(script) => {
                if script.len() > 10000 {
                    return Err(anyhow!("Script too large (max 10,000 bytes)"));
                }
                Ok(script.clone())
            }
        }
    }
}

/// Enhanced UTXO information for better wallet management
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoInfo {
    pub outpoint: OutPoint,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub block_height: u64,
    pub is_coinbase: bool,
    pub confirmations: u64,
    pub spent: bool,
}

impl UtxoInfo {
    /// Check if this UTXO is mature and spendable
    pub fn is_spendable(&self, _current_height: u64) -> bool {
        !self.spent && {
            if self.is_coinbase {
                // Coinbase outputs require 100 confirmations
                self.confirmations >= 100
            } else {
                // Regular outputs just need to be confirmed
                self.confirmations > 0
            }
        }
    }

    /// Calculate current confirmations
    pub fn current_confirmations(&self, current_height: u64) -> u64 {
        if current_height >= self.block_height {
            current_height - self.block_height + 1
        } else {
            0
        }
    }
}

/// Create P2PKH script_pubkey per docs/specs/05_utxo_model_spec.md
/// Format: OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
fn create_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create P2SH script_pubkey per docs/specs/05_utxo_model_spec.md
/// Format: OP_HASH160 <20-byte-script-hash> OP_EQUAL
fn create_p2sh_script(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(script_hash);
    script.push(0x87); // OP_EQUAL
    script
}

/// Create P2PK script_pubkey per docs/specs/05_utxo_model_spec.md
/// Format: <33-byte-pubkey> OP_CHECKSIG
fn create_p2pk_script(pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(35);
    script.push(0x21); // Push 33 bytes
    script.extend_from_slice(pubkey);
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create multisig script_pubkey per docs/specs/05_utxo_model_spec.md
/// Format: <m> <pubkey1> <pubkey2> ... <pubkeyn> <n> OP_CHECKMULTISIG
fn create_multisig_script(m: u8, pubkeys: &[Vec<u8>]) -> Vec<u8> {
    let mut script = Vec::with_capacity(1 + pubkeys.len() * 34 + 2);

    // Push m (required signatures)
    script.push(0x50 + m); // OP_1 through OP_16 (0x51-0x60), OP_0 is 0x00

    // Push each public key
    for pubkey in pubkeys {
        script.push(0x21); // Push 33 bytes
        script.extend_from_slice(pubkey);
    }

    // Push n (total public keys)
    script.push(0x50 + pubkeys.len() as u8);
    script.push(0xae); // OP_CHECKMULTISIG

    script
}

/// Create OP_RETURN script_pubkey per docs/specs/05_utxo_model_spec.md
/// Format: OP_RETURN <data>
fn create_op_return_script(data: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(1 + data.len() + 1);
    script.push(0x6a); // OP_RETURN

    if !data.is_empty() {
        if data.len() <= 75 {
            script.push(data.len() as u8); // Push data length
        } else {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(data.len() as u8);
        }
        script.extend_from_slice(data);
    }

    script
}

/// Generate a P2PKH script_pubkey for a given outpoint (legacy function for compatibility)
/// This follows the FerrisScript specification for P2PKH outputs
fn generate_p2pkh_script_pubkey(outpoint: &OutPoint) -> Vec<u8> {
    // Generate a deterministic public key hash from the outpoint
    // In a real implementation, this would be derived from the actual public key
    let outpoint_bytes = bincode::serialize(outpoint).unwrap_or_default();
    let hash = blake3::hash(&outpoint_bytes);
    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&hash.as_bytes()[..20]);

    create_p2pkh_script(&pubkey_hash)
}

pub struct TransactionBuilder {
    /// Enhanced UTXO set management with full UTXO information
    available_utxos: HashMap<OutPoint, UtxoInfo>,
    /// Current blockchain height for maturity calculations
    current_height: u64,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            available_utxos: HashMap::new(),
            current_height: 0,
        }
    }

    /// Set the current blockchain height for maturity calculations
    pub fn set_current_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Enhanced UTXO management with full information
    pub fn add_utxo(&mut self, txid_hex: String, vout: u64, amount: u64) -> Result<()> {
        // Convert hex string to [u8; 32]
        let txid_bytes = hex::decode(txid_hex).map_err(|e| anyhow!("Invalid txid hex: {}", e))?;
        let txid: [u8; 32] = txid_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid txid length, expected 32 bytes"))?;

        let outpoint = OutPoint {
            txid,
            vout: vout as u32,
        };

        let utxo_info = UtxoInfo {
            outpoint: outpoint.clone(),
            amount,
            script_pubkey: generate_p2pkh_script_pubkey(&outpoint), // Generate proper script_pubkey
            block_height: self.current_height,
            is_coinbase: false, // Default to false, can be set separately
            confirmations: 1,   // Default to 1 confirmation
            spent: false,
        };

        self.available_utxos.insert(outpoint, utxo_info);
        Ok(())
    }

    /// Add a UTXO with full information
    pub fn add_utxo_full(&mut self, utxo_info: UtxoInfo) -> Result<()> {
        self.available_utxos
            .insert(utxo_info.outpoint.clone(), utxo_info);
        Ok(())
    }

    /// Get all spendable UTXOs
    pub fn get_spendable_utxos(&self) -> Vec<&UtxoInfo> {
        self.available_utxos
            .values()
            .filter(|utxo| utxo.is_spendable(self.current_height))
            .collect()
    }

    /// Calculate total spendable balance
    pub fn get_spendable_balance(&self) -> u64 {
        self.get_spendable_utxos()
            .iter()
            .map(|utxo| utxo.amount)
            .sum()
    }

    /// Select UTXOs for a transaction using a simple strategy
    pub fn select_utxos_for_amount(&self, target_amount: u64) -> Result<Vec<&UtxoInfo>> {
        let mut selected = Vec::new();
        let mut total = 0;

        // Simple selection strategy: largest first
        let mut spendable: Vec<_> = self.get_spendable_utxos();
        spendable.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in spendable {
            selected.push(utxo);
            total += utxo.amount;

            if total >= target_amount {
                break;
            }
        }

        if total < target_amount {
            return Err(anyhow!(
                "Insufficient funds: need {} satoshis, have {} spendable",
                target_amount,
                total
            ));
        }

        Ok(selected)
    }

    /// Mark a UTXO as spent
    pub fn mark_utxo_spent(&mut self, outpoint: &OutPoint) -> Result<()> {
        if let Some(utxo) = self.available_utxos.get_mut(outpoint) {
            utxo.spent = true;
            Ok(())
        } else {
            Err(anyhow!("UTXO not found: {:?}", outpoint))
        }
    }

    /// Select UTXOs using greedy algorithm to cover target amount
    pub fn select_utxos_greedy(&self, target_amount: u64) -> Result<Vec<&UtxoInfo>> {
        let mut available_utxos: Vec<&UtxoInfo> = self.get_spendable_utxos();

        // Sort by amount in descending order for greedy selection
        available_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected_utxos = Vec::new();
        let mut total_selected = 0u64;

        for utxo in available_utxos {
            if total_selected >= target_amount {
                break;
            }
            selected_utxos.push(utxo);
            total_selected = total_selected
                .checked_add(utxo.amount)
                .ok_or_else(|| anyhow!("UTXO amount overflow"))?;
        }

        if total_selected < target_amount {
            return Err(anyhow!(
                "Insufficient funds: need {} satoshis, have {} satoshis",
                target_amount,
                total_selected
            ));
        }

        Ok(selected_utxos)
    }

    /// Builds a new transaction with protocol-compliant fee validation
    /// Following UTXO spec: Fee = V_in - V_out, Fee ≥ MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes
    pub fn build_transaction(
        &mut self,
        recipient_address: &str,
        amount: u64,
        fee_per_byte: u64, // User-specified fee rate
        wallet: &HDWallet,
    ) -> Result<Transaction> {
        let _sender_pubkey = wallet.public_key_bytes()?; // Will be used in future implementation
        let recipient_pubkey = hex::decode(recipient_address)
            .map_err(|e| anyhow!("Invalid recipient address: {}", e))?;

        // Estimate transaction size for fee calculation
        let estimated_tx_size = self.estimate_transaction_size(1, 2); // 1 input, 2 outputs (recipient + change)
        let estimated_fee = fee_per_byte * estimated_tx_size as u64;
        let total_needed = amount + estimated_fee;

        // Select UTXOs using enhanced selection
        let selected_utxos = self.select_utxos_for_amount(total_needed)?;
        let total_input_value: u64 = selected_utxos.iter().map(|utxo| utxo.amount).sum();

        // Calculate change amount if any
        let change_amount = if total_input_value > total_needed {
            total_input_value - total_needed
        } else {
            0
        };

        // Use the first selected UTXO for input (can be extended to multiple inputs later)
        let selected_utxo = selected_utxos
            .first()
            .ok_or_else(|| anyhow!("No UTXOs selected"))?;

        let txid = selected_utxo.outpoint.txid;
        let vout = selected_utxo.outpoint.vout;
        let input_value = selected_utxo.amount;

        let previous_output = OutPoint { txid, vout };
        let input = TxInput::from_outpoint(previous_output, vec![], 0xFFFFFFFF, vec![]);

        let output = TxOutput {
            value: amount,
            script_pubkey: recipient_pubkey,
            memo: None,
        };

        let mut outputs = vec![output];

        // Add change output if there's significant change (avoid dust)
        if change_amount > 1000 {
            // Only create change output if more than 1000 satoshis
            let change_output = TxOutput {
                value: change_amount,
                script_pubkey: wallet.public_key_bytes()?, // Send change back to wallet
                memo: Some("change".as_bytes().to_vec()),
            };
            outputs.push(change_output);
        }

        // Calculate protocol-compliant fee: Fee = V_in - V_out
        let v_in = input_value;
        let v_out: u64 = outputs.iter().map(|out| out.value).sum();

        // Protocol requirement: V_in ≥ V_out (Fee MUST NOT be negative)
        if v_in < v_out {
            return Err(anyhow!(
                "Insufficient funds: input value {} < output value {}",
                v_in,
                v_out
            ));
        }

        // Calculate actual fee: Fee = V_in - V_out
        let actual_fee = v_in - v_out;

        // Validate fee meets minimum relay requirements
        self.validate_fee_compliance(&[input.clone()], &outputs, actual_fee, fee_per_byte)?;

        // Create a standard transaction
        let standard_tx = StandardTransaction {
            version: 1,
            inputs: vec![input],
            outputs,
            lock_time: 0,
            fee: actual_fee,
            witness: vec![],
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

    /// Validates fee meets protocol compliance requirements
    /// Fee ≥ MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes
    fn validate_fee_compliance(
        &self,
        inputs: &[TxInput],
        outputs: &[TxOutput],
        actual_fee: u64,
        user_fee_per_byte: u64,
    ) -> Result<()> {
        // Estimate transaction size for fee calculation
        let estimated_tx_size = self.estimate_transaction_size(inputs.len(), outputs.len());

        // Calculate minimum relay fee per protocol spec
        let min_relay_fee = MIN_RELAY_FEE_PER_BYTE * estimated_tx_size as u64;

        // Check if actual fee meets minimum relay requirements
        if actual_fee < min_relay_fee {
            return Err(anyhow!(
                "Fee {} is below minimum relay fee {}. Reduce output amount or use a higher input value.",
                actual_fee, min_relay_fee
            ));
        }

        // Calculate expected fee based on user's fee rate preference
        let expected_fee = user_fee_per_byte * estimated_tx_size as u64;

        // Warn if actual fee is significantly different from user's expectation
        if actual_fee < expected_fee {
            println!(
                "Warning: Actual fee {} is lower than expected fee {} based on requested rate",
                actual_fee, expected_fee
            );
        }

        Ok(())
    }

    /// Estimate transaction size in bytes for fee calculation
    fn estimate_transaction_size(&self, input_count: usize, output_count: usize) -> usize {
        // Conservative estimation based on typical transaction structure:
        // - Base transaction: ~10 bytes (version, input count, output count, lock_time)
        // - Per input: ~148 bytes (prev_out: 36, script_sig: ~107, sequence: 4, witness: 1)
        // - Per output: ~34 bytes (value: 8, script_pubkey: ~25, memo: 1)

        const BASE_TX_SIZE: usize = 10;
        const INPUT_SIZE: usize = 148;
        const OUTPUT_SIZE: usize = 34;

        BASE_TX_SIZE + (input_count * INPUT_SIZE) + (output_count * OUTPUT_SIZE)
    }

    /// Estimate fee for a given amount
    fn estimate_fee_for_amount(&self, _amount: u64) -> Result<u64, Box<dyn std::error::Error>> {
        // Simple fee estimation: assume 1 input and 2 outputs (recipient + change)
        let estimated_size = self.estimate_transaction_size(1, 2);
        let fee_per_byte = 10; // Default fee rate
        Ok(estimated_size as u64 * fee_per_byte)
    }

    /// Signs a transaction with the wallet's private key per docs/specs/01_block_structure.md
    /// Implements proper sighash calculation and scriptSig generation for each input
    pub fn sign_transaction(&self, transaction: &mut Transaction, wallet: &HDWallet) -> Result<()> {
        match transaction {
            Transaction::Standard {
                ref mut inputs,
                ref outputs,
                version,
                lock_time,
                ..
            } => {
                // Create immutable copy of inputs for sighash calculation
                let inputs_for_sighash = inputs.clone();

                // Sign each input individually with the script_pubkey of the UTXO being spent
                for (input_index, input) in inputs.iter_mut().enumerate() {
                    // Get the UTXO being spent to access its script_pubkey
                    let utxo_info = self
                        .available_utxos
                        .get(&input.previous_output)
                        .ok_or_else(|| {
                            anyhow!(
                                "Cannot find UTXO for input {}: {:?}",
                                input_index,
                                input.previous_output
                            )
                        })?;

                    // Calculate sighash for this specific input per FerrisScript specification
                    let sighash = self.calculate_sighash_for_input(
                        *version,
                        &inputs_for_sighash,
                        outputs,
                        *lock_time,
                        input_index,
                        &utxo_info.script_pubkey,
                    )?;

                    // Sign the sighash with wallet's private key
                    let signature = wallet.sign(&sighash)?;

                    // Create proper scriptSig based on the script_pubkey type
                    let script_sig = self.create_script_sig_for_utxo(
                        &signature,
                        &wallet.public_key_bytes()?,
                        &utxo_info.script_pubkey,
                    )?;

                    // Set the scriptSig for this input
                    input.script_sig = script_sig;
                }

                Ok(())
            }
            _ => Err(anyhow!("Unsupported transaction type for signing")),
        }
    }

    /// Calculate sighash for a specific input per docs/specs/04_ferrisscript_spec.md
    /// This implements the Bitcoin-style sighash with BLAKE3 hashing
    fn calculate_sighash_for_input(
        &self,
        version: u32,
        inputs: &[TxInput],
        outputs: &[TxOutput],
        lock_time: u32,
        input_index: usize,
        script_pubkey: &[u8],
    ) -> Result<[u8; 32]> {
        if input_index >= inputs.len() {
            return Err(anyhow!("Input index {} out of bounds", input_index));
        }

        // Create a copy of inputs for sighash calculation
        let mut sighash_inputs = Vec::new();
        for (i, input) in inputs.iter().enumerate() {
            if i == input_index {
                // For the input being signed, use the script_pubkey of the UTXO being spent
                sighash_inputs.push(TxInput::from_outpoint(
                    input.previous_output.clone(),
                    script_pubkey.to_vec(), // Use the script_pubkey, not script_sig
                    input.sequence,
                    input.witness.clone(),
                ));
            } else {
                // For other inputs, use empty script_sig
                sighash_inputs.push(TxInput::from_outpoint(
                    input.previous_output.clone(),
                    Vec::new(),
                    input.sequence,
                    input.witness.clone(),
                ));
            }
        }

        // Create temporary transaction for sighash calculation
        let sighash_tx = Transaction::Standard {
            version,
            inputs: sighash_inputs,
            outputs: outputs.to_vec(),
            lock_time,
            fee: 0, // Fee not included in sighash
            witness: Vec::new(),
        };

        // Serialize and hash with BLAKE3
        let serialized = bincode::serialize(&sighash_tx)
            .map_err(|e| anyhow!("Failed to serialize transaction for sighash: {}", e))?;

        Ok(blake3::hash(&serialized).into())
    }

    /// Create scriptSig for different UTXO script types per docs/specs/04_ferrisscript_spec.md
    fn create_script_sig_for_utxo(
        &self,
        signature: &[u8],
        public_key: &[u8],
        script_pubkey: &[u8],
    ) -> Result<Vec<u8>> {
        // Detect script type by analyzing the script_pubkey
        if self.is_p2pkh_script(script_pubkey) {
            // P2PKH scriptSig: <Signature> <PublicKey>
            self.create_p2pkh_script_sig(signature, public_key)
        } else if self.is_p2pk_script(script_pubkey) {
            // P2PK scriptSig: <Signature>
            Ok(signature.to_vec())
        } else if self.is_p2sh_script(script_pubkey) {
            // P2SH is more complex - for now, return error
            Err(anyhow!("P2SH scriptSig creation not yet implemented"))
        } else if self.is_multisig_script(script_pubkey) {
            // Multisig is complex - for now, return error
            Err(anyhow!("Multisig scriptSig creation not yet implemented"))
        } else {
            // Unknown script type
            Err(anyhow!(
                "Unknown script_pubkey type, cannot create scriptSig"
            ))
        }
    }

    /// Create P2PKH scriptSig: <Signature> <PublicKey>
    fn create_p2pkh_script_sig(&self, signature: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
        let mut script_sig = Vec::new();

        // Push signature
        if signature.len() > 75 {
            return Err(anyhow!("Signature too large: {} bytes", signature.len()));
        }
        script_sig.push(signature.len() as u8);
        script_sig.extend_from_slice(signature);

        // Push public key
        if public_key.len() > 75 {
            return Err(anyhow!("Public key too large: {} bytes", public_key.len()));
        }
        script_sig.push(public_key.len() as u8);
        script_sig.extend_from_slice(public_key);

        Ok(script_sig)
    }

    /// Detect if script_pubkey is P2PKH format
    fn is_p2pkh_script(&self, script: &[u8]) -> bool {
        script.len() == 25 &&
        script[0] == 0x76 && // OP_DUP
        script[1] == 0xa9 && // OP_HASH160
        script[2] == 0x14 && // Push 20 bytes
        script[23] == 0x88 && // OP_EQUALVERIFY
        script[24] == 0xac // OP_CHECKSIG
    }

    /// Detect if script_pubkey is P2PK format
    fn is_p2pk_script(&self, script: &[u8]) -> bool {
        script.len() == 35 &&
        script[0] == 0x21 && // Push 33 bytes
        script[34] == 0xac // OP_CHECKSIG
    }

    /// Detect if script_pubkey is P2SH format
    fn is_p2sh_script(&self, script: &[u8]) -> bool {
        script.len() == 23 &&
        script[0] == 0xa9 && // OP_HASH160
        script[1] == 0x14 && // Push 20 bytes
        script[22] == 0x87 // OP_EQUAL
    }

    /// Detect if script_pubkey is multisig format
    fn is_multisig_script(&self, script: &[u8]) -> bool {
        script.len() > 3 &&
        script[0] >= 0x51 && script[0] <= 0x60 && // OP_1 through OP_16
        script[script.len() - 1] == 0xae // OP_CHECKMULTISIG
    }

    /// Calculate the maximum amount that can be sent from this wallet
    /// This takes into account the minimum fee required for the transaction
    pub fn calculate_max_sendable_amount(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let spendable_balance = self.get_spendable_balance();
        let estimated_fee = self.estimate_fee_for_amount(spendable_balance)?;

        if spendable_balance <= estimated_fee {
            return Ok(0);
        }

        Ok(spendable_balance - estimated_fee)
    }

    /// Refresh the wallet's UTXO set from the node using the RPC client.
    /// This ensures the wallet's UTXO set is always in sync with the canonical UTXO_SET (see UTXO model spec 5.4).
    ///
    /// # Arguments
    /// * `rpc_client` - An instance of RpcClient connected to the node
    /// * `address` - The wallet's address to fetch UTXOs for
    ///
    /// # Returns
    /// * `Result<usize>` - The number of UTXOs loaded
    pub async fn refresh_utxos_from_node(
        &mut self,
        rpc_client: &mut crate::rpc_integration::RpcClient,
        address: &str,
    ) -> anyhow::Result<usize> {
        // Fetch UTXOs from the node for this address
        let utxos = rpc_client
            .get_utxos_by_address(address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get UTXOs: {}", e))?;
        self.available_utxos.clear();
        for utxo in utxos {
            // Convert RPC UtxoInfo to wallet UtxoInfo
            let txid_bytes = hex::decode(&utxo.txid)
                .map_err(|e| anyhow::anyhow!("Failed to decode txid: {}", e))?;
            let txid: [u8; 32] = txid_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid txid length"))?;
            let outpoint = OutPoint {
                txid,
                vout: utxo.vout,
            };
            let utxo_info = UtxoInfo {
                outpoint,
                amount: utxo.value,
                script_pubkey: utxo.script_pubkey,
                block_height: 0, // Block height is not provided by RPC, can be set if available
                is_coinbase: false, // Not provided by RPC, can be set if available
                confirmations: utxo.confirmations as u64,
                spent: false,
            };
            self.available_utxos
                .insert(utxo_info.outpoint.clone(), utxo_info);
        }
        Ok(self.available_utxos.len())
    }

    /// Build transaction with specific script types per docs/specs/05_utxo_model_spec.md
    /// Supports P2PKH, P2SH, P2PK, Multisig, and OP_RETURN outputs
    pub fn build_transaction_with_script_types(
        &mut self,
        outputs: Vec<(ScriptType, u64)>, // (script_type, amount) pairs
        fee_per_byte: u64,
        wallet: &HDWallet,
    ) -> Result<Transaction> {
        // Calculate total output amount and validate scripts
        let mut total_output_value = 0u64;
        let mut tx_outputs = Vec::new();

        for (script_type, amount) in outputs {
            // Validate dust limits (OP_RETURN can be below dust limit)
            let is_op_return = matches!(script_type, ScriptType::OpReturn(_));
            if !is_op_return && amount < 1000 {
                // DUST_LIMIT = 1000 satoshis
                return Err(anyhow!("Output below dust limit: {} satoshis", amount));
            }

            // Create script_pubkey from ScriptType
            let script_pubkey = script_type.to_script_pubkey()?;

            tx_outputs.push(TxOutput {
                value: amount,
                script_pubkey,
                memo: None,
            });

            total_output_value = total_output_value
                .checked_add(amount)
                .ok_or_else(|| anyhow!("Output value overflow"))?;
        }

        // Estimate transaction size for fee calculation
        let estimated_tx_size = self.estimate_transaction_size(1, tx_outputs.len()); // Start with 1 input estimate
        let mut target_fee = estimated_tx_size as u64 * fee_per_byte;
        let total_needed = total_output_value + target_fee;

        // Select UTXOs to cover the needed amount
        let selected_utxos = self.select_utxos_greedy(total_needed)?;
        let input_value: u64 = selected_utxos.iter().map(|utxo| utxo.amount).sum();

        if input_value < total_needed {
            return Err(anyhow!(
                "Insufficient funds: need {} satoshis, have {} satoshis",
                total_needed,
                input_value
            ));
        }

        // Recalculate fee with actual input count
        let actual_tx_size = self.estimate_transaction_size(selected_utxos.len(), tx_outputs.len());
        target_fee = actual_tx_size as u64 * fee_per_byte;
        let change_amount = input_value.saturating_sub(total_output_value + target_fee);

        // Add change output if significant
        if change_amount > 1000 {
            let wallet_pubkey_hash = blake3::hash(&wallet.public_key_bytes()?);
            let mut pubkey_hash = [0u8; 20];
            pubkey_hash.copy_from_slice(&wallet_pubkey_hash.as_bytes()[..20]);

            let change_script = create_p2pkh_script(&pubkey_hash);
            tx_outputs.push(TxOutput {
                value: change_amount,
                script_pubkey: change_script,
                memo: Some("change".as_bytes().to_vec()),
            });
        }

        // Create transaction inputs
        let mut inputs = Vec::new();
        for utxo in &selected_utxos {
            inputs.push(TxInput::from_outpoint(
                utxo.outpoint.clone(),
                Vec::new(), // Will be filled by signing
                0xFFFFFFFF,
                Vec::new(),
            ));
        }

        // Create unsigned transaction
        let tx = Transaction::Standard {
            version: 1,
            inputs,
            outputs: tx_outputs,
            lock_time: 0,
            fee: target_fee,
            witness: Vec::new(),
        };

        // Mark selected UTXOs as spent (after creating transaction to avoid borrowing conflicts)
        let outpoints_to_mark: Vec<_> = selected_utxos
            .iter()
            .map(|utxo| utxo.outpoint.clone())
            .collect();
        for outpoint in outpoints_to_mark {
            if let Some(tracked_utxo) = self.available_utxos.get_mut(&outpoint) {
                tracked_utxo.spent = true;
            }
        }

        Ok(tx)
    }

    /// Create a P2PKH output for an address
    pub fn create_p2pkh_output(address_hash: [u8; 20], amount: u64) -> (ScriptType, u64) {
        (ScriptType::P2PKH(address_hash.to_vec()), amount)
    }

    /// Create a P2SH output for a script hash
    pub fn create_p2sh_output(script_hash: [u8; 20], amount: u64) -> (ScriptType, u64) {
        (ScriptType::P2SH(script_hash.to_vec()), amount)
    }

    /// Create a multisig output
    pub fn create_multisig_output(
        m: u8,
        pubkeys: Vec<Vec<u8>>,
        amount: u64,
    ) -> Result<(ScriptType, u64)> {
        if m == 0 || m > pubkeys.len() as u8 || pubkeys.len() > 20 {
            return Err(anyhow!(
                "Invalid multisig parameters: m={}, n={}",
                m,
                pubkeys.len()
            ));
        }
        Ok((ScriptType::Multisig { m, pubkeys }, amount))
    }

    /// Create an OP_RETURN data output
    pub fn create_op_return_output(data: Vec<u8>) -> Result<(ScriptType, u64)> {
        if data.len() > 80 {
            return Err(anyhow!(
                "OP_RETURN data too large: {} bytes (max 80)",
                data.len()
            ));
        }
        Ok((ScriptType::OpReturn(data), 0)) // OP_RETURN outputs have 0 value
    }

    /// Validate a script_pubkey against protocol limits
    pub fn validate_script_pubkey(script: &[u8]) -> Result<()> {
        if script.len() > 10000 {
            return Err(anyhow!(
                "Script too large: {} bytes (max 10,000)",
                script.len()
            ));
        }

        // Count opcodes (simplified check)
        let opcode_count = script.iter().filter(|&&byte| byte > 75).count();
        if opcode_count > 200 {
            return Err(anyhow!("Too many opcodes: {} (max 200)", opcode_count));
        }

        Ok(())
    }
}
