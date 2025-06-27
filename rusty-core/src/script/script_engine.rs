// rusty-core/src/script/script_engine.rs

use crate::script::opcode::Opcode;
use crate::consensus::utxo_set::UtxoSet;
use ed25519_dalek::{Signature, Verifier, PublicKey as DalekPublicKey};
use ripemd::Ripemd160;
use rusty_shared_types::{Transaction, TxOutput};
// Simple Script wrapper for now
#[derive(Debug, Clone)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Script { bytes }
    }
}

impl From<&[u8]> for Script {
    fn from(bytes: &[u8]) -> Self {
        Script { bytes: bytes.to_vec() }
    }
}

impl Script {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
use crate::constants::{MAX_SCRIPT_BYTES, MAX_OPCODE_COUNT, MAX_STACK_DEPTH, MAX_SIG_OPS};
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha256Digest};

mod standard_scripts;

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ScriptError {
    InvalidOpcode,
    StackUnderflow,
    StackOverflow,
    InvalidStackState,
    ScriptTooLarge,
    TooManyOpcodes,
    TooManySigOps,
    TooManyOperations,
    VerificationFailed,
    OpReturn,
    NotImplemented,
    // Add more specific errors as needed
}

pub struct ScriptEngine {
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    opcode_count: usize,
    sig_op_count: usize,
    control_stack: Vec<bool>, // Tracks whether we're in a true/false branch
    skip_depth: usize, // Tracks nested skip levels
}

impl ScriptEngine {
    pub fn new() -> Self {
        ScriptEngine {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            opcode_count: 0,
            sig_op_count: 0,
            control_stack: Vec::new(),
            skip_depth: 0,
        }
    }

    // Push data onto the stack
    fn push_data(&mut self, data: Vec<u8>) {
        self.stack.push(data);
    }

    // Pop data from the stack
    fn pop_data(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    // Read N bytes for pushdata opcodes
    fn read_bytes(&self, script: &[u8], ip: &mut usize, num_bytes: usize) -> Result<Vec<u8>, ScriptError> {
        if *ip + num_bytes > script.len() {
            return Err(ScriptError::ScriptTooLarge);
        }
        let data = script[*ip..*ip + num_bytes].to_vec();
        *ip += num_bytes;
        Ok(data)
    }

    // Push data based on the next N bytes
    fn push_data_n(&mut self, script: &[u8], ip: &mut usize, len_bytes: usize) -> Result<(), ScriptError> {
        let len_data = self.read_bytes(script, ip, len_bytes)?;
        let len = ScriptEngine::as_usize(&len_data)?;
        let data = self.read_bytes(script, ip, len)?;
        self.push_data(data);
        Ok(())
    }

    // Helper to check if a stack item is "false" (empty or single zero byte)
    fn is_false(v: &[u8]) -> bool {
        v.is_empty() || (v.len() == 1 && v[0] == 0)
    }

    // Helper to convert a stack item to usize
    fn as_usize(v: &[u8]) -> Result<usize, ScriptError> {
        if v.is_empty() {
            Ok(0)
        } else if v.len() <= 8 {
            let mut buf = [0u8; 8];
            buf[..v.len()].copy_from_slice(v);
            Ok(u64::from_le_bytes(buf) as usize)
        } else {
            Err(ScriptError::InvalidStackState)
        }
    }

    // Main verification function for a transaction
    pub fn validate_transaction(&mut self, tx: &Transaction, utxo_set: &UtxoSet, current_block_height: u64) -> bool {
        self.sig_op_count = 0; // Initialize sig_op_count once per transaction
        for (input_index, input) in tx.get_inputs().iter().enumerate() {
            // Skip coinbase transaction inputs
            if tx.is_coinbase() {
                continue;
            }

            let prev_output = match utxo_set.get_utxo(&input.previous_output) {
                Some(output) => output,
                None => return false, // Referenced UTXO not found
            };

            // Combine scriptSig and scriptPubKey
            let mut script = input.script_sig.clone();
            script.extend_from_slice(&prev_output.output.script_pubkey);

            // Execute the combined script
            self.stack.clear(); // Clear stack for each script execution
            self.alt_stack.clear();
            self.opcode_count = 0;
            self.control_stack.clear();
            self.skip_depth = 0;

            let tx_hash = tx.txid();
            if self.execute(&script, tx_hash.as_slice(), tx, current_block_height, input_index).is_err() {
                return false;
            }

            // The script must result in a true value on top of the stack
            match self.pop_data() {
                Ok(result) => {
                    if ScriptEngine::is_false(&result) {
                        return false;
                    }
                    // Ensure only one element remains on the stack after validation
                    if !self.stack.is_empty() {
                        return false;
                    }
                }
                Err(_) => return false, // Stack underflow, script failed
            }
        }
        true
    }

    pub fn execute(&mut self, script: &[u8], message: &[u8], tx: &Transaction, current_block_height: u64, input_index: usize) -> Result<(), ScriptError> {
        // Validate script size
        if script.len() > MAX_SCRIPT_BYTES {
            return Err(ScriptError::ScriptTooLarge);
        }
        
        let mut ip = 0;
        while ip < script.len() {
            // Check opcode count
            if self.opcode_count >= MAX_OPCODE_COUNT {
                return Err(ScriptError::TooManyOpcodes);
            }
            
            let opcode_byte = script[ip];
            ip += 1;
            self.opcode_count += 1;

            let opcode = Opcode::from(opcode_byte);

            if self.should_skip() {
                match opcode {
                    Opcode::OpIf | Opcode::OpNotIf => {
                        self.skip_depth += 1;
                    }
                    Opcode::OpElse => {
                        if self.skip_depth == 1 {
                            self.skip_depth = 0;
                        }
                    }
                    Opcode::OpEndIf => {
                        self.skip_depth -= 1;
                    }
                    _ => {}
                }
                continue;
            }

            match opcode {
                Opcode::Op0 => self.push_data(vec![]),
                Opcode::OpPushdata1 => self.push_data_n(script, &mut ip, 1)?,
                Opcode::OpPushdata2 => self.push_data_n(script, &mut ip, 2)?,
                Opcode::OpPushdata4 => self.push_data_n(script, &mut ip, 4)?,
                Opcode::Op1 => self.push_data(vec![0x01]),
                Opcode::Op2 => self.push_data(vec![0x02]),
                Opcode::Op3 => self.push_data(vec![0x03]),
                Opcode::Op4 => self.push_data(vec![0x04]),
                Opcode::Op5 => self.push_data(vec![0x05]),
                Opcode::Op6 => self.push_data(vec![0x06]),
                Opcode::Op7 => self.push_data(vec![0x07]),
                Opcode::Op8 => self.push_data(vec![0x08]),
                Opcode::Op9 => self.push_data(vec![0x09]),
                Opcode::Op10 => self.push_data(vec![0x0A]),
                Opcode::Op11 => self.push_data(vec![0x0B]),
                Opcode::Op12 => self.push_data(vec![0x0C]),
                Opcode::Op13 => self.push_data(vec![0x0D]),
                Opcode::Op14 => self.push_data(vec![0x0E]),
                Opcode::Op15 => self.push_data(vec![0x0F]),
                Opcode::Op16 => self.push_data(vec![0x10]),
                Opcode::OpDup => self.op_dup()?,
                Opcode::OpHash160 => self.op_hash160()?,
                Opcode::OpEqual => self.op_equal()?,
                Opcode::OpEqualverify => self.op_equal_verify()?,
                Opcode::OpVerify => self.op_verify()?,
                Opcode::OpCheckSig => self.op_checksig(message)?,
                Opcode::OpCheckMultiSig => self.op_checkmultisig(tx)?,
                Opcode::OpCheckLockTimeVerify => self.op_checklocktimeverify(tx, current_block_height)?,
                Opcode::OpCheckSequenceVerify => self.op_checksequenceverify(tx, current_block_height, input_index)?,
                Opcode::OpReturn => return Err(ScriptError::OpReturn), // OP_RETURN makes the script invalid for spending
                Opcode::OpNop => { /* Do nothing */ }, // OP_NOP is a no-operation
                Opcode::OpInvalidOpcode => return Err(ScriptError::InvalidOpcode),
                Opcode::OpRipemd160 => self.op_ripemd160()?,
                Opcode::OpSha1 => self.op_sha1()?,
                Opcode::OpSha256 => self.op_sha256()?,
                Opcode::OpHash256 => self.op_hash256()?,
                Opcode::OpCodeSeparator => self.op_codeseparator()?,
                Opcode::OpCheckSigVerify => self.op_checksigverify(message)?,
                Opcode::OpCheckMultiSigVerify => self.op_checkmultisigverify(tx)?,
                Opcode::OpIf => self.op_if()?,
                Opcode::OpNotIf => self.op_notif()?,
                Opcode::OpElse => self.op_else()?,
                Opcode::OpEndIf => self.op_endif()?,
                Opcode::OpToAltStack => self.op_toaltstack()?,
                Opcode::OpFromAltStack => self.op_fromaltstack()?,
                Opcode::OpDrop => self.op_drop()?,
                Opcode::OpNip => self.op_nip()?,
                Opcode::OpOver => self.op_over()?,
                Opcode::OpPick => self.op_pick()?,
                Opcode::OpRoll => self.op_roll()?,
                Opcode::OpRot => self.op_rot()?,
                Opcode::OpSwap => self.op_swap()?,
                Opcode::OpTuck => self.op_tuck()?,
                Opcode::Op2Drop => self.op_2drop()?,
                Opcode::Op2Dup => self.op_2dup()?,
                Opcode::Op3Dup => self.op_3dup()?,
                Opcode::Op2Over => self.op_2over()?,
                Opcode::Op2Rot => self.op_2rot()?,
                Opcode::Op2Swap => self.op_2swap()?,
                Opcode::OpCat => self.op_cat()?,
                Opcode::OpSubStr => self.op_substr()?,
                Opcode::OpLeft => self.op_left()?,
                Opcode::OpRight => self.op_right()?,
                Opcode::OpSize => self.op_size()?,
                Opcode::OpInvert => self.op_invert()?,
                Opcode::OpAnd => self.op_and()?,
                Opcode::OpOr => self.op_or()?,
                Opcode::OpXor => self.op_xor()?,
                _ => return Err(ScriptError::InvalidOpcode),
            }

            if self.stack.len() > MAX_STACK_DEPTH {
                return Err(ScriptError::StackOverflow);
            }
        }

        Ok(())
    }

    pub fn execute_standard_script(
        &mut self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        tx: &Transaction,
        input_index: usize,
    ) -> Result<(), ScriptError> {
        if let Ok(()) = standard_scripts::verify_p2pkh_script(
            &Script::from(script_sig),
            &Script::from(script_pubkey),
            tx,
            input_index,
        ) {
            return Ok(());
        }

        // Try P2SH
        if let Ok(()) = standard_scripts::verify_p2sh_script(
            &Script::from(script_sig),
            &Script::from(script_pubkey),
            tx,
            input_index,
            self, // Pass self to allow recursive script execution
        ) {
            return Ok(());
        }
        
        // Fall back to custom script execution
        self.execute(script_sig, script_pubkey, tx, 0, input_index)
    }

    // OP_DUP
    fn op_dup(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_data()?;
        self.push_data(a.clone());
        self.push_data(a);
        Ok(())
    }

    // OP_HASH160
    fn op_hash160(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let sha256_hash = blake3::hash(&data);
        let mut hasher = Ripemd160::new();
        hasher.update(sha256_hash.as_bytes());
        let ripemd160_hash = hasher.finalize();
        self.push_data(ripemd160_hash.to_vec());
        Ok(())
    }

    // OP_EQUAL
    fn op_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_data()?;
        let a = self.pop_data()?;
        self.push_data(if a == b { vec![0x01] } else { vec![] });
        Ok(())
    }

    // OP_EQUALVERIFY
    fn op_equal_verify(&mut self) -> Result<(), ScriptError> {
        self.op_equal()?;
        self.op_verify()
    }

    // OP_VERIFY
    fn op_verify(&mut self) -> Result<(), ScriptError> {
        let top = self.pop_data()?;
        if ScriptEngine::is_false(&top) {
            return Err(ScriptError::VerificationFailed);
        }
        Ok(())
    }

    // OP_CHECKSIG
    fn op_checksig(&mut self, message: &[u8]) -> Result<(), ScriptError> {
        self.sig_op_count += 1;
        if self.sig_op_count > MAX_SIG_OPS {
            return Err(ScriptError::TooManySigOps);
        }
        let public_key_bytes = self.pop_data()?;
        let signature_bytes = self.pop_data()?;

        let public_key = DalekPublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| ScriptError::VerificationFailed)?;
        let signature = Signature::from_bytes(&signature_bytes)
            .map_err(|_| ScriptError::VerificationFailed)?;

        if public_key.verify(message, &signature).is_ok() {
            self.push_data(vec![0x01]);
        } else {
            self.push_data(vec![]);
        }
        Ok(())
    }

    // OP_CHECKMULTISIG
    fn op_checkmultisig(&mut self, tx: &Transaction) -> Result<(), ScriptError> {
        self.sig_op_count += 1;
        if self.sig_op_count > MAX_SIG_OPS {
            return Err(ScriptError::TooManySigOps);
        }
        let num_signatures = self.pop_data()?[0] as usize;
        if num_signatures > self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        let mut signatures = Vec::with_capacity(num_signatures);
        for _ in 0..num_signatures {
            signatures.push(self.pop_data()?);
        }

        let num_public_keys = self.pop_data()?[0] as usize;
        if num_public_keys > self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        let mut public_keys = Vec::with_capacity(num_public_keys);
        for _ in 0..num_public_keys {
            public_keys.push(self.pop_data()?);
        }

        // The message to be signed is the transaction hash.
        let message = tx.txid();

        let mut verified_signatures = 0;
        for signature_bytes in signatures.iter() {
            for public_key_bytes in public_keys.iter() {
                let signature = Signature::from_bytes(signature_bytes.as_slice()).map_err(|_| ScriptError::VerificationFailed)?;
                let public_key = DalekPublicKey::from_bytes(public_key_bytes.as_slice()).map_err(|_| ScriptError::VerificationFailed)?;

                if Verifier::verify(&public_key, message.as_slice(), &signature).is_ok() {
                    verified_signatures += 1;
                    break; // Move to the next signature
                }
            }
        }

        if verified_signatures >= num_signatures {
            self.push_data(vec![0x01]);
        } else {
            self.push_data(vec![]);
        }
        Ok(())
    }

    // OP_CHECKLOCKTIMEVERIFY
    fn op_checklocktimeverify(&mut self, tx: &Transaction, current_block_height: u64) -> Result<(), ScriptError> {
        // Pop the locktime value from the stack
        let lock_time_bytes = self.pop_data()?;
        let lock_time = ScriptEngine::as_u32(&lock_time_bytes)?;

        // The transaction's lock_time must be less than or equal to the block's lock_time
        // If the transaction's lock_time is greater than the block's lock_time, validation fails.
        // If the lock_time value is interpreted as a block height, compare with current_block_height.
        // If interpreted as a timestamp, compare with current block's timestamp (not available here directly, using height as proxy).
        // Also, check if all input sequence numbers are MAX_SEQUENCE.

        let tx_lock_time = tx.get_lock_time();

        if tx_lock_time < lock_time {
            return Err(ScriptError::VerificationFailed); // Locktime not met
        }
        
        // If locktime is interpreted as block height, check against current block height
        if lock_time < crate::constants::LOCKTIME_THRESHOLD && current_block_height < lock_time as u64 {
            return Err(ScriptError::VerificationFailed);
        }

        // If locktime is interpreted as timestamp, check against current block timestamp
        // (Simplified to height for now)
        if lock_time >= crate::constants::LOCKTIME_THRESHOLD && current_block_height < lock_time as u64 {
            return Err(ScriptError::VerificationFailed);
        }

        // Rule: all TxInput.sequence values in the transaction MUST NOT be equal to MAX_SEQUENCE if lock_time is set
        // This is already checked in blockchain.rs. This is a redundant check for CLTV, but good for robustness.
        for input in tx.get_inputs() {
            if input.sequence == crate::constants::MAX_SEQUENCE {
                return Err(ScriptError::VerificationFailed);
            }
        }

        self.push_data(vec![0x01]); // True if locktime conditions met
        Ok(())
    }

    // OP_CHECKSEQUENCEVERIFY
    fn op_checksequenceverify(&mut self, tx: &Transaction, _current_block_height: u64, input_index: usize) -> Result<(), ScriptError> {
        // Pop the relative sequence value from the stack
        let relative_sequence_bytes = self.pop_data()?;
        let relative_sequence = ScriptEngine::as_u32(&relative_sequence_bytes)?;

        // Get the current transaction's input sequence.
        let tx_input_sequence = tx.get_inputs().get(input_index).ok_or(ScriptError::InvalidStackState)?.sequence;

        // Check flags in relative_sequence
        let locktime_is_seconds = (relative_sequence & (1 << 22)) != 0;
        let sequence_is_relative = (relative_sequence & (1 << 31)) != 0;

        if !sequence_is_relative {
            // Relative sequence must have the relative flag set
            return Err(ScriptError::VerificationFailed);
        }

        let masked_sequence = relative_sequence & 0x0000FFFF; // Only lower 16 bits are used for relative locktime

        if locktime_is_seconds {
            // Relative locktime in seconds
            // Compare with block.header.timestamp, not current_block_height
            // For now, we use block.header.height as a proxy for time
            if tx_input_sequence < masked_sequence {
                self.push_data(vec![]); // False
            } else {
                self.push_data(vec![0x01]); // True
            }
        } else {
            // Relative locktime in blocks
            if tx_input_sequence < masked_sequence {
                self.push_data(vec![]); // False
            } else {
                self.push_data(vec![0x01]); // True
            }
        }

        Ok(())
    }

    // Helper to convert a stack item to u32
    fn as_u32(v: &[u8]) -> Result<u32, ScriptError> {
        if v.len() > 4 {
            return Err(ScriptError::InvalidStackState);
        }
        let mut buf = [0u8; 4];
        buf[..v.len()].copy_from_slice(v);
        Ok(u32::from_le_bytes(buf))
    }

    // OP_RIPEMD160
    fn op_ripemd160(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let mut hasher = Ripemd160::new();
        hasher.update(data);
        let result = hasher.finalize();
        self.push_data(result.to_vec());
        Ok(())
    }

    // OP_SHA1
    fn op_sha1(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        self.push_data(result.to_vec());
        Ok(())
    }

    // OP_SHA256
    fn op_sha256(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        self.push_data(result.to_vec());
        Ok(())
    }

    // OP_HASH256
    fn op_hash256(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let first_hash = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(first_hash);
        let result = hasher.finalize();
        self.push_data(result.to_vec());
        Ok(())
    }

    // OP_CODESEPARATOR
    fn op_codeseparator(&mut self) -> Result<(), ScriptError> {
        // Currently a no-op as we don't track code separation positions
        Ok(())
    }

    // OP_CHECKSIGVERIFY
    fn op_checksigverify(&mut self, message: &[u8]) -> Result<(), ScriptError> {
        self.op_checksig(message)?;
        self.op_verify()
    }

    // OP_CHECKMULTISIGVERIFY
    fn op_checkmultisigverify(&mut self, tx: &Transaction) -> Result<(), ScriptError> {
        self.op_checkmultisig(tx)?;
        self.op_verify()
    }

    // Main validation function for a TxInput
    pub fn verify_script(
        script_sig: &[u8],
        script_pubkey: &[u8],
        tx: &Transaction,
        input_index: usize,
        _utxo_output: &TxOutput,  // Currently unused, but kept for future use
    ) -> Result<(), ScriptError> {
        let mut script_engine = ScriptEngine::new();

        // Create a dummy message (in a real scenario, this would be the sighash)
        let message = vec![0; 32]; // Example dummy message

        // Execute scriptSig
        script_engine.execute(script_sig, &message, tx, 0, input_index)?;

        // Execute scriptPubKey
        script_engine.execute(script_pubkey, &message, tx, 0, input_index)?;

        // Final stack check (result should be true and stack should be empty)
        let result = script_engine.pop_data()?;
        if ScriptEngine::is_false(&result) || !script_engine.stack.is_empty() {
            return Err(ScriptError::VerificationFailed);
        }

        Ok(())
    }

    // OP_IF
    fn op_if(&mut self) -> Result<(), ScriptError> {
        if self.skip_depth > 0 {
            self.skip_depth += 1;
            return Ok(());
        }

        let condition = if let Ok(val) = self.pop_data() {
            !ScriptEngine::is_false(&val)
        } else {
            false
        };

        self.control_stack.push(condition);
        if !condition {
            self.skip_depth = 1;
        }
        Ok(())
    }

    // OP_NOTIF
    fn op_notif(&mut self) -> Result<(), ScriptError> {
        if self.skip_depth > 0 {
            self.skip_depth += 1;
            return Ok(());
        }

        let condition = if let Ok(val) = self.pop_data() {
            ScriptEngine::is_false(&val)
        } else {
            false
        };

        self.control_stack.push(condition);
        if !condition {
            self.skip_depth = 1;
        }
        Ok(())
    }

    // OP_ELSE
    fn op_else(&mut self) -> Result<(), ScriptError> {
        if self.skip_depth > 0 {
            if self.skip_depth == 1 {
                self.skip_depth = 0;
            }
            return Ok(());
        }

        if let Some(condition) = self.control_stack.last_mut() {
            *condition = !*condition;
            if !*condition {
                self.skip_depth = 1;
            }
        } else {
            return Err(ScriptError::InvalidStackState);
        }
        Ok(())
    }

    // OP_ENDIF
    fn op_endif(&mut self) -> Result<(), ScriptError> {
        if self.skip_depth > 0 {
            self.skip_depth -= 1;
            return Ok(());
        }

        self.control_stack.pop().ok_or(ScriptError::InvalidStackState)?;
        Ok(())
    }

    // Helper to determine if we should skip execution
    fn should_skip(&self) -> bool {
        self.skip_depth > 0
    }

    // OP_TOALTSTACK
    fn op_toaltstack(&mut self) -> Result<(), ScriptError> {
        let val = self.pop_data()?;
        self.alt_stack.push(val);
        Ok(())
    }

    // OP_FROMALTSTACK
    fn op_fromaltstack(&mut self) -> Result<(), ScriptError> {
        let val = self.alt_stack.pop().ok_or(ScriptError::StackUnderflow)?;
        self.push_data(val);
        Ok(())
    }

    // OP_DROP
    fn op_drop(&mut self) -> Result<(), ScriptError> {
        self.pop_data()?;
        Ok(())
    }

    // OP_NIP
    fn op_nip(&mut self) -> Result<(), ScriptError> {
        let x2 = self.pop_data()?;
        let _x1 = self.pop_data()?;
        self.push_data(x2);
        Ok(())
    }

    // OP_OVER
    fn op_over(&mut self) -> Result<(), ScriptError> {
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x1.clone());
        self.push_data(x2);
        self.push_data(x1);
        Ok(())
    }

    // OP_PICK
    fn op_pick(&mut self) -> Result<(), ScriptError> {
        let n = ScriptEngine::as_usize(&self.pop_data()?)?;
        if n >= self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        let val = self.stack[self.stack.len() - n - 1].clone();
        self.push_data(val);
        Ok(())
    }

    // OP_ROLL
    fn op_roll(&mut self) -> Result<(), ScriptError> {
        let n = ScriptEngine::as_usize(&self.pop_data()?)?;
        if n >= self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        let val = self.stack.remove(self.stack.len() - n - 1);
        self.push_data(val);
        Ok(())
    }

    // OP_ROT
    fn op_rot(&mut self) -> Result<(), ScriptError> {
        let x3 = self.pop_data()?;
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x2);
        self.push_data(x3);
        self.push_data(x1);
        Ok(())
    }

    // OP_SWAP
    fn op_swap(&mut self) -> Result<(), ScriptError> {
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x2);
        self.push_data(x1);
        Ok(())
    }

    // OP_TUCK
    fn op_tuck(&mut self) -> Result<(), ScriptError> {
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x2.clone());
        self.push_data(x1);
        self.push_data(x2);
        Ok(())
    }

    // OP_2DROP
    fn op_2drop(&mut self) -> Result<(), ScriptError> {
        self.pop_data()?;
        self.pop_data()?;
        Ok(())
    }

    // OP_2DUP
    fn op_2dup(&mut self) -> Result<(), ScriptError> {
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x1.clone());
        self.push_data(x2.clone());
        self.push_data(x1);
        self.push_data(x2);
        Ok(())
    }

    // OP_3DUP
    fn op_3dup(&mut self) -> Result<(), ScriptError> {
        let x3 = self.pop_data()?;
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x1.clone());
        self.push_data(x2.clone());
        self.push_data(x3.clone());
        self.push_data(x1);
        self.push_data(x2);
        self.push_data(x3);
        Ok(())
    }

    // OP_2OVER
    fn op_2over(&mut self) -> Result<(), ScriptError> {
        let x4 = self.pop_data()?;
        let x3 = self.pop_data()?;
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x1.clone());
        self.push_data(x2.clone());
        self.push_data(x3);
        self.push_data(x4);
        self.push_data(x1);
        self.push_data(x2);
        Ok(())
    }

    // OP_2ROT
    fn op_2rot(&mut self) -> Result<(), ScriptError> {
        let x6 = self.pop_data()?;
        let x5 = self.pop_data()?;
        let x4 = self.pop_data()?;
        let x3 = self.pop_data()?;
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x3);
        self.push_data(x4);
        self.push_data(x5);
        self.push_data(x6);
        self.push_data(x1);
        self.push_data(x2);
        Ok(())
    }

    // OP_2SWAP
    fn op_2swap(&mut self) -> Result<(), ScriptError> {
        let x4 = self.pop_data()?;
        let x3 = self.pop_data()?;
        let x2 = self.pop_data()?;
        let x1 = self.pop_data()?;
        self.push_data(x3);
        self.push_data(x4);
        self.push_data(x1);
        self.push_data(x2);
        Ok(())
    }

    // OP_CAT
    fn op_cat(&mut self) -> Result<(), ScriptError> {
        let mut b = self.pop_data()?;
        let mut a = self.pop_data()?;
        a.append(&mut b);
        self.push_data(a);
        Ok(())
    }

    // OP_SUBSTR
    fn op_substr(&mut self) -> Result<(), ScriptError> {
        let size = ScriptEngine::as_usize(&self.pop_data()?)?;
        let offset = ScriptEngine::as_usize(&self.pop_data()?)?;
        let data = self.pop_data()?;
        
        if offset + size > data.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        self.push_data(data[offset..offset+size].to_vec());
        Ok(())
    }

    // OP_LEFT
    fn op_left(&mut self) -> Result<(), ScriptError> {
        let size = ScriptEngine::as_usize(&self.pop_data()?)?;
        let data = self.pop_data()?;
        
        if size > data.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        self.push_data(data[..size].to_vec());
        Ok(())
    }

    // OP_RIGHT
    fn op_right(&mut self) -> Result<(), ScriptError> {
        let size = ScriptEngine::as_usize(&self.pop_data()?)?;
        let data = self.pop_data()?;
        
        if size > data.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        self.push_data(data[data.len()-size..].to_vec());
        Ok(())
    }

    // OP_SIZE
    fn op_size(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let len = data.len() as u64;
        self.push_data(data);
        self.push_data(len.to_le_bytes().to_vec());
        Ok(())
    }

    // OP_INVERT
    fn op_invert(&mut self) -> Result<(), ScriptError> {
        let data = self.pop_data()?;
        let inverted = data.iter().map(|b| !b).collect();
        self.push_data(inverted);
        Ok(())
    }

    // OP_AND
    fn op_and(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_data()?;
        let a = self.pop_data()?;
        
        if a.len() != b.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        let result = a.iter().zip(b.iter()).map(|(x, y)| x & y).collect();
        self.push_data(result);
        Ok(())
    }

    // OP_OR
    fn op_or(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_data()?;
        let a = self.pop_data()?;
        
        if a.len() != b.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        let result = a.iter().zip(b.iter()).map(|(x, y)| x | y).collect();
        self.push_data(result);
        Ok(())
    }

    // OP_XOR
    fn op_xor(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_data()?;
        let a = self.pop_data()?;
        
        if a.len() != b.len() {
            return Err(ScriptError::InvalidStackState);
        }
        
        let result = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        self.push_data(result);
        Ok(())
    }
}
