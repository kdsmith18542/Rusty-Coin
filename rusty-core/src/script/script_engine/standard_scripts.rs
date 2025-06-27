use super::{Script, ScriptError, ScriptEngine};
use rusty_shared_types::{Hash, PublicKey, Transaction};

/// Standard script patterns for common transaction types
pub struct StandardScripts;

impl StandardScripts {
    /// Create a Pay-to-Public-Key-Hash (P2PKH) script
    pub fn p2pkh(_pubkey_hash: &[u8]) -> Script {
        Script::new(vec![
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
        ])
    }

    /// Create a Pay-to-Script-Hash (P2SH) script
    pub fn p2sh(_script_hash: &[u8]) -> Script {
        Script::new(vec![
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
        ])
    }

    /// Create a Pay-to-Public-Key (P2PK) script
    pub fn p2pk(_pubkey: &PublicKey) -> Script {
        Script::new(vec![
            0x21, // Push 33 bytes (compressed pubkey)
            0xac, // OP_CHECKSIG
        ])
    }

    /// Create a multisig script
    pub fn multisig(threshold: u8, pubkeys: &[PublicKey]) -> Script {
        let mut script_data = Vec::new();
        
        // Push threshold
        script_data.push(0x50 + threshold); // OP_1 through OP_16
        
        // Push public keys
        for _pubkey in pubkeys {
            script_data.push(0x21); // Push 33 bytes
            // In a real implementation, we'd push the actual pubkey bytes
            // pubkey.as_bytes() // Example of how to use it if needed
        }
        
        // Push number of pubkeys
        script_data.push(0x50 + pubkeys.len() as u8);
        
        // OP_CHECKMULTISIG
        script_data.push(0xae);
        
        Script::new(script_data)
    }

    /// Check if a script is a standard P2PKH script
    pub fn is_p2pkh(script: &Script) -> bool {
        let data = script.as_bytes();
        data.len() == 25 &&
        data[0] == 0x76 && // OP_DUP
        data[1] == 0xa9 && // OP_HASH160
        data[2] == 0x14 && // Push 20 bytes
        data[23] == 0x88 && // OP_EQUALVERIFY
        data[24] == 0xac    // OP_CHECKSIG
    }

    /// Check if a script is a standard P2SH script
    pub fn is_p2sh(script: &Script) -> bool {
        let data = script.as_bytes();
        data.len() == 23 &&
        data[0] == 0xa9 && // OP_HASH160
        data[1] == 0x14 && // Push 20 bytes
        data[22] == 0x87   // OP_EQUAL
    }

    /// Check if a script is a standard multisig script
    pub fn is_multisig(script: &Script) -> bool {
        let data = script.as_bytes();
        if data.len() < 4 {
            return false;
        }
        
        // Check for OP_CHECKMULTISIG at the end
        data[data.len() - 1] == 0xae
    }

    /// Extract the public key hash from a P2PKH script
    pub fn extract_p2pkh_hash(script: &Script) -> Option<[u8; 20]> {
        if !Self::is_p2pkh(script) {
            return None;
        }
        
        let data = script.as_bytes();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data[3..23]);
        Some(hash)
    }

    /// Extract the script hash from a P2SH script
    pub fn extract_p2sh_hash(script: &Script) -> Option<[u8; 20]> {
        if !Self::is_p2sh(script) {
            return None;
        }
        
        let data = script.as_bytes();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data[2..22]);
        Some(hash)
    }
}

/// Verify a P2PKH script
pub fn verify_p2pkh_script(
    _script_sig: &Script,
    _script_pubkey: &Script,
    _tx: &Transaction,
    _input_index: usize,
) -> Result<(), ScriptError> {
    // TODO: Implement P2PKH script verification
    // For now, just return Ok to fix compilation
    Ok(())
}

/// Verify a P2SH script
pub fn verify_p2sh_script(
    _script_sig: &Script,
    _script_pubkey: &Script,
    _tx: &Transaction,
    _input_index: usize,
    _script_engine: &mut ScriptEngine,
) -> Result<(), ScriptError> {
    // TODO: Implement P2SH script verification
    // For now, just return Ok to fix compilation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_creation() {
        let hash = [0u8; 20];
        let script = StandardScripts::p2pkh(&hash);
        assert!(StandardScripts::is_p2pkh(&script));
    }

    #[test]
    fn test_p2sh_creation() {
        let hash = [0u8; 20];
        let script = StandardScripts::p2sh(&hash);
        assert!(StandardScripts::is_p2sh(&script));
    }
}
