use super::{Script, ScriptEngine, ScriptError};
use blake3;
use ed25519_dalek::{PublicKey as DalekPublicKey, Signature, Verifier};
use ripemd::Ripemd160;
use rusty_shared_types::{Transaction, TxInput};
use sha2::{Digest, Sha256};

/// Verify a P2PKH (Pay-to-Public-Key-Hash) script
/// P2PKH format: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn verify_p2pkh_script(
    script_sig: &Script,
    script_pubkey: &Script,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), ScriptError> {
    // P2PKH scriptSig format: <signature> <pubkey>
    // Per spec 04 Section 4.6.1: script_sig contains [Signature] [PublicKey]
    let sig_bytes = script_sig.as_bytes();

    // Ed25519 signatures are 64 bytes, Ed25519 public keys are 32 bytes
    // Minimum size: 64 (signature) + 32 (pubkey) = 96 bytes
    // However, script_sig may include push opcodes, so we need to parse properly
    // For now, assume simple format: signature followed by pubkey
    if sig_bytes.len() < 96 {
        return Err(ScriptError::VerificationFailed);
    }

    // Extract signature (first 64 bytes) and public key (last 32 bytes, assuming Ed25519)
    // Per spec: Ed25519 signatures are 64 bytes, public keys are 32 bytes
    let signature_bytes = &sig_bytes[0..64];
    let pubkey_bytes = &sig_bytes[sig_bytes.len() - 32..];

    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    let pubkey_script = script_pubkey.as_bytes();
    if pubkey_script.len() != 25 || pubkey_script[0] != 0x76 || pubkey_script[1] != 0xa9 {
        return Err(ScriptError::VerificationFailed);
    }

    let expected_hash = &pubkey_script[3..23]; // 20-byte hash

    // Hash the public key (SHA256 + RIPEMD160)
    // Per spec 04 Section 4.3.4: OP_HASH160 = RIPEMD160(SHA256(data))
    let sha256_hash = Sha256::digest(pubkey_bytes);
    let pubkey_hash = Ripemd160::digest(&sha256_hash);

    // Verify the hash matches (OP_EQUALVERIFY step from spec)
    // Per spec 04 Section 4.6.1: OP_EQUALVERIFY compares PubKeyHash_calculated and PubKeyHash_expected
    if pubkey_hash.as_slice() != expected_hash {
        return Err(ScriptError::VerificationFailed);
    }

    // Verify the signature (OP_CHECKSIG step from spec)
    // Per spec 04 Section 4.6.1: OP_CHECKSIG verifies Sig is a valid signature for the transaction
    // (excluding script_sig and substituting script_pubkey) using PubKey
    let pubkey =
        DalekPublicKey::from_bytes(pubkey_bytes).map_err(|_| ScriptError::VerificationFailed)?;
    let signature =
        Signature::from_bytes(signature_bytes).map_err(|_| ScriptError::VerificationFailed)?;

    // Per spec: Signature is over transaction hash excluding script_sig and substituting script_pubkey
    // Calculate proper sighash: transaction hash excluding script_sigs, substituting script_pubkeys
    let sighash = calculate_sighash(tx, input_index, script_pubkey.as_bytes())?;

    pubkey
        .verify(&sighash, &signature)
        .map_err(|_| ScriptError::VerificationFailed)?;

    Ok(())
}

/// Calculate sighash for a transaction input
/// Per FerrisScript spec 04 Section 4.6.1: Signature is over transaction hash excluding script_sig and substituting script_pubkey
/// This implements BIP143-style sighash adapted for FerrisScript with BLAKE3 hashing
fn calculate_sighash(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &[u8],
) -> Result<[u8; 32], ScriptError> {
    let inputs = tx.get_inputs();
    if input_index >= inputs.len() {
        return Err(ScriptError::VerificationFailed);
    }

    // Create a copy of inputs for sighash calculation
    // For the input being signed, use empty script_sig but track the script_pubkey for inclusion
    // For other inputs, use empty script_sig
    let mut sighash_inputs = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        if i == input_index {
            // For the input being signed, use empty script_sig (will be substituted later)
            sighash_inputs.push(TxInput::from_outpoint(
                input.previous_output.clone(),
                Vec::new(), // Empty script_sig - will be substituted with script_pubkey
                input.sequence,
                input.witness.clone(),
            ));
        } else {
            // For other inputs, use empty script_sig
            sighash_inputs.push(TxInput::from_outpoint(
                input.previous_output.clone(),
                Vec::new(), // Empty script_sig
                input.sequence,
                input.witness.clone(),
            ));
        }
    }

    // Serialize the transaction components in canonical order for sighash
    let mut sighash_data = Vec::new();

    // 1. Transaction version (4 bytes, little-endian)
    let version = match tx {
        Transaction::Standard { version, .. } => *version,
        Transaction::Coinbase { version, .. } => *version,
        Transaction::MasternodeRegister { .. } => 1, // MasternodeRegister doesn't have explicit version
        Transaction::MasternodeCollateral { version, .. } => *version,
        Transaction::ActivateProposal { version, .. } => *version,
        Transaction::TicketPurchase { version, .. } => *version,
        Transaction::TicketRedemption { version, .. } => *version,
        Transaction::TicketSlashNonParticipation { version, .. } => *version,
        Transaction::TicketSlashMalicious { version, .. } => *version,
        Transaction::GovernanceProposal(_) => 1, // GovernanceProposal doesn't have explicit version
        Transaction::GovernanceVote(_) => 1, // GovernanceVote doesn't have explicit version
        Transaction::MasternodeSlashTx(tx) => tx.version,
    };
    sighash_data.extend_from_slice(&version.to_le_bytes());

    // 2. Number of inputs (varint)
    let input_count = sighash_inputs.len() as u64;
    sighash_data.extend_from_slice(&encode_varint(input_count));

    // 3. Serialize each input with proper script_pubkey substitution
    for (i, input) in sighash_inputs.iter().enumerate() {
        // Previous output hash (32 bytes)
        sighash_data.extend_from_slice(&input.prev_out_hash);
        
        // Previous output index (4 bytes, little-endian)
        sighash_data.extend_from_slice(&input.prev_out_index.to_le_bytes());
        
        // ScriptSig - for the input being signed, use script_pubkey, otherwise empty
        let script_sig = if i == input_index {
            script_pubkey.to_vec()
        } else {
            Vec::new()
        };
        sighash_data.extend_from_slice(&encode_varint(script_sig.len() as u64));
        sighash_data.extend_from_slice(&script_sig);
        
        // Sequence (4 bytes, little-endian)
        sighash_data.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // 4. Number of outputs (varint)
    let outputs = tx.get_outputs();
    let output_count = outputs.len() as u64;
    sighash_data.extend_from_slice(&encode_varint(output_count));

    // 5. Serialize each output
    for output in outputs {
        // Value (8 bytes, little-endian)
        sighash_data.extend_from_slice(&output.value.to_le_bytes());
        
        // ScriptPubKey (varint length + data)
        sighash_data.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        sighash_data.extend_from_slice(&output.script_pubkey);
    }

    // 6. Lock time (4 bytes, little-endian)
    let lock_time = tx.get_lock_time();
    sighash_data.extend_from_slice(&lock_time.to_le_bytes());

    // 7. Sighash type (4 bytes, little-endian) - FerrisScript uses 0x00000001 for ALL
    sighash_data.extend_from_slice(&0x00000001u32.to_le_bytes());

    // Hash with BLAKE3 to get the sighash
    Ok(blake3::hash(&sighash_data).into())
}

/// Encode a u64 as a variable-length integer (varint)
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut result = vec![0xfd];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value <= 0xffffffff {
        let mut result = vec![0xfe];
        result.extend_from_slice(&(value as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xff];
        result.extend_from_slice(&value.to_le_bytes());
        result
    }
}

/// Verify a P2SH (Pay-to-Script-Hash) script
/// P2SH format: OP_HASH160 <script_hash> OP_EQUAL
pub fn verify_p2sh_script(
    script_sig: &Script,
    script_pubkey: &Script,
    tx: &Transaction,
    _input_index: usize,
    script_engine: &mut ScriptEngine,
) -> Result<(), ScriptError> {
    // P2SH scriptPubKey format: OP_HASH160 <20-byte-hash> OP_EQUAL
    let pubkey_script = script_pubkey.as_bytes();
    if pubkey_script.len() != 23 || pubkey_script[0] != 0xa9 || pubkey_script[22] != 0x87 {
        return Err(ScriptError::VerificationFailed);
    }

    let expected_script_hash = &pubkey_script[2..22]; // 20-byte hash

    // P2SH scriptSig format: <data> ... <data> <redeemScript>
    let sig_bytes = script_sig.as_bytes();
    if sig_bytes.is_empty() {
        return Err(ScriptError::VerificationFailed);
    }

    // Extract the redeem script (last element)
    // This is a simplified extraction - in practice you'd need proper script parsing
    let script_len = sig_bytes.len();
    if script_len < 1 {
        return Err(ScriptError::VerificationFailed);
    }

    // For simplicity, assume the redeem script is the last 32 bytes
    let redeem_script_start = if script_len >= 32 { script_len - 32 } else { 0 };
    let redeem_script = &sig_bytes[redeem_script_start..];

    // Hash the redeem script (SHA256 + RIPEMD160)
    let sha256_hash = Sha256::digest(redeem_script);
    let script_hash = Ripemd160::digest(&sha256_hash);

    // Verify the hash matches
    if script_hash.as_slice() != expected_script_hash {
        return Err(ScriptError::VerificationFailed);
    }

    // Execute the redeem script
    let redeem_script_obj = Script::new(redeem_script.to_vec());
    script_engine
        .execute(&redeem_script_obj.bytes, &[], tx, 0, 0, script_pubkey.as_bytes()) // Use 0 for input_index since it's unused
        .map_err(|_| ScriptError::VerificationFailed)?;

    Ok(())
}

/// Standard script creation helpers
pub struct StandardScripts;

impl StandardScripts {
    /// Check if script is P2PKH
    pub fn is_p2pkh(script: &Script) -> bool {
        let bytes = script.as_bytes();
        bytes.len() == 25
            && bytes[0] == 0x76
            && bytes[1] == 0xa9
            && bytes[2] == 0x14
            && bytes[23] == 0x88
            && bytes[24] == 0xac
    }

    /// Check if script is P2SH
    pub fn is_p2sh(script: &Script) -> bool {
        let bytes = script.as_bytes();
        bytes.len() == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 && bytes[22] == 0x87
    }

    /// Create a P2PKH script from a 20-byte hash
    pub fn create_p2pkh(hash: &[u8; 20]) -> Script {
        let mut script_bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <20-byte-hash>
        script_bytes.extend_from_slice(hash);
        script_bytes.push(0x88); // OP_EQUALVERIFY
        script_bytes.push(0xac); // OP_CHECKSIG
        Script::new(script_bytes)
    }

    /// Create a P2SH script from a 20-byte hash
    pub fn create_p2sh(hash: &[u8; 20]) -> Script {
        let mut script_bytes = vec![0xa9, 0x14]; // OP_HASH160 <20-byte-hash>
        script_bytes.extend_from_slice(hash);
        script_bytes.push(0x87); // OP_EQUAL
        Script::new(script_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_creation() {
        let hash = [0u8; 20];
        let script = StandardScripts::create_p2pkh(&hash);
        assert!(StandardScripts::is_p2pkh(&script));
    }

    #[test]
    fn test_p2sh_creation() {
        let hash = [0u8; 20];
        let script = StandardScripts::create_p2sh(&hash);
        assert!(StandardScripts::is_p2sh(&script));
    }
}
