// rusty-crypto/src/signature.rs

use ed25519_dalek::{Signature, Verifier, PublicKey};
use ed25519_dalek::SignatureError;

pub fn sign_message(keypair: &crate::keypair::RustyKeyPair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), ed25519_dalek::SignatureError> {
    public_key.verify(message, signature)
}

// Placeholder for multi-signature verification
pub fn verify_multi_signature(public_keys: &[PublicKey], _message: &[u8], signatures: &[Signature]) -> Result<bool, SignatureError> {
    // TODO: Implement actual multi-signature verification logic.
    // This is a simplified placeholder and does not provide real multi-signature functionality.
    // For demonstration, we'll just return true if there's at least one signature and public key.
    if public_keys.is_empty() || signatures.is_empty() {
        return Ok(false);
    }
    Ok(true)
}