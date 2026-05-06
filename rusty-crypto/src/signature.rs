// rusty-crypto/src/signature.rs

use ed25519_dalek::SignatureError;
use ed25519_dalek::{PublicKey, Signature, Verifier};

pub fn sign_message(keypair: &crate::keypair::RustyKeyPair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), ed25519_dalek::SignatureError> {
    public_key.verify(message, signature)
}

/// Verify multi-signature scheme using M-of-N threshold
///
/// This implements a simple M-of-N multi-signature verification where at least M signatures
/// from N possible signers must be valid for the verification to pass.
///
/// # Arguments
/// * `public_keys` - Vector of public keys from authorized signers
/// * `message` - The message that was signed
/// * `signatures` - Vector of signatures to verify
/// * `threshold` - Minimum number of valid signatures required (M in M-of-N)
///
/// # Returns
/// * `Ok(true)` if at least `threshold` signatures are valid
/// * `Ok(false)` if fewer than `threshold` signatures are valid
/// * `Err` if there's a cryptographic error during verification
pub fn verify_multi_signature(
    public_keys: &[PublicKey],
    message: &[u8],
    signatures: &[Signature],
    threshold: usize,
) -> Result<bool, SignatureError> {
    if public_keys.is_empty() || signatures.is_empty() {
        return Ok(false);
    }

    if threshold == 0 {
        return Ok(true); // Trivial case
    }

    if threshold > public_keys.len() {
        return Ok(false); // Cannot meet threshold with available keys
    }

    let mut valid_signatures = 0;

    // For each signature, try to verify it against all public keys
    // This allows for partial signature sets where not all signers participated
    for signature in signatures {
        for public_key in public_keys {
            if public_key.verify(message, signature).is_ok() {
                valid_signatures += 1;
                break; // Found matching public key for this signature
            }
        }
    }

    Ok(valid_signatures >= threshold)
}

/// Verify multi-signature with specific signer indices
///
/// This variant requires signatures to be paired with specific public key indices,
/// providing more control over which keys signed the message.
///
/// # Arguments
/// * `public_keys` - Vector of public keys from authorized signers
/// * `message` - The message that was signed
/// * `signature_data` - Vector of (signature, key_index) pairs
/// * `threshold` - Minimum number of valid signatures required
///
/// # Returns
/// * `Ok(true)` if at least `threshold` signatures are valid
/// * `Ok(false)` if fewer than `threshold` signatures are valid or indices are invalid
/// * `Err` if there's a cryptographic error during verification
pub fn verify_indexed_multi_signature(
    public_keys: &[PublicKey],
    message: &[u8],
    signature_data: &[(Signature, usize)], // (signature, public_key_index)
    threshold: usize,
) -> Result<bool, SignatureError> {
    if public_keys.is_empty() || signature_data.is_empty() {
        return Ok(false);
    }

    if threshold == 0 {
        return Ok(true);
    }

    if threshold > public_keys.len() {
        return Ok(false);
    }

    let mut valid_signatures = 0;
    let mut used_indices = std::collections::HashSet::new();

    for (signature, key_index) in signature_data {
        // Check if index is valid and not already used (prevent signature reuse)
        if *key_index >= public_keys.len() || used_indices.contains(key_index) {
            continue;
        }

        // Verify signature against the specific public key
        if public_keys[*key_index].verify(message, signature).is_ok() {
            valid_signatures += 1;
            used_indices.insert(*key_index);

            // Early exit if threshold is met
            if valid_signatures >= threshold {
                break;
            }
        }
    }

    Ok(valid_signatures >= threshold)
}

/// Verify multi-signature for masternode operations
///
/// This is a specialized version for masternode quorum operations that includes
/// additional validation for masternode-specific requirements.
///
/// # Arguments
/// * `masternode_public_keys` - Public keys of masternodes in the quorum
/// * `message` - The message (typically transaction hash) that was signed
/// * `signatures` - Signatures from participating masternodes
/// * `quorum_threshold` - Minimum number of masternode signatures required
///
/// # Returns
/// * `Ok(true)` if the quorum threshold is met with valid signatures
/// * `Ok(false)` if the threshold is not met
/// * `Err` if there's a verification error
pub fn verify_masternode_multi_signature(
    masternode_public_keys: &[PublicKey],
    message: &[u8],
    signatures: &[Signature],
    quorum_threshold: usize,
) -> Result<bool, SignatureError> {
    // Masternodes must meet a minimum threshold (e.g., 51% for most operations)
    let min_threshold = (masternode_public_keys.len() / 2) + 1;
    let effective_threshold = std::cmp::max(quorum_threshold, min_threshold);

    verify_multi_signature(
        masternode_public_keys,
        message,
        signatures,
        effective_threshold,
    )
}
