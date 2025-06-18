//! Cryptographic primitives for Rusty Coin.
//!
//! This module provides all cryptographic operations required by the Rusty Coin network,
//! including:
//! - Key generation and management
//! - Digital signatures
//! - Cryptographic hashing
//! - Proof-of-work components
//!
//! The default implementation uses Ed25519 for signatures and a custom multi-layer
//! hash function (OxideHash) for ASIC-resistant hashing.

use anyhow::Result;
use bincode::{Encode, Decode};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as Ed25519Signature};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, Deserialize};
use sha2::Digest;
use libp2p_identity::{self as libp2p_identity, ed25519, PublicKey as Libp2pPublicKey};

pub mod oxide_hash;

/// A 32-byte hash output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Encode, Decode)]
pub struct Hash(pub [u8; 32]);

impl From<blake3::Hash> for Hash {
    fn from(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }
}

impl Hash {
    /// Creates a new zero-initialized hash.
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }

    /// Creates a hash from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            Some(Self(hash))
        } else {
            None
        }
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the BLAKE3 hash of the given data.
    pub fn blake3(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Hash(*hash.as_bytes())
    }

    /// Computes the SHA-256 hash of the given data.
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash(hash)
    }
    
    /// Converts a hash value to a compact bits representation.
    /// This is the reverse of `from_bits`.
    pub fn to_bits(&self) -> u32 {
        // Find the first non-zero byte to determine the exponent
        let mut first_byte_idx = 0;
        for (i, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                first_byte_idx = i;
                break;
            }
        }

        // The exponent is typically calculated based on the position of the most significant byte.
        // If the hash is zero, return a default easy difficulty (e.g., 0x1d00FFFF).
        if self.0 == [0u8; 32] {
            return 0x1d00FFFF; // Default easy difficulty
        }

        // Calculate the exponent: (number of bytes after first non-zero byte) + 3
        let exponent = (32 - first_byte_idx) as u8;

        // Extract the mantissa (first 3 bytes after leading zeros, or padded with zeros if less than 3 significant bytes)
        let mut mantissa_bytes = [0u8; 4]; // Use 4 bytes to allow for 3 bytes of mantissa + leading zero for u32 conversion
        
        // Copy up to 3 significant bytes into the mantissa
        let bytes_to_copy = (32 - first_byte_idx).min(3);
        mantissa_bytes[1..1 + bytes_to_copy].copy_from_slice(&self.0[first_byte_idx..first_byte_idx + bytes_to_copy]);

        let mantissa = u32::from_be_bytes(mantissa_bytes);

        // Combine exponent and mantissa into the bits format
        ((exponent as u32) << 24) | (mantissa & 0x00FF_FFFF)
    }

    /// Converts a compact bits representation to a hash value.
    /// The compact format is used in block headers to represent the target difficulty.
    /// Format: [exponent (1 byte)][mantissa (3 bytes)]
    pub fn from_bits(bits: u32) -> Self {
        // Extract exponent (first byte) and mantissa (last 3 bytes)
        let exponent = (bits >> 24) as u8;
        let mantissa = bits & 0x00FF_FFFF;
        
        // Handle zero case
        if mantissa == 0 {
            return Hash([0u8; 32]);
        }
        
        // Calculate the shift amount (number of bits to shift left)
        // The formula is: target = mantissa * 2^(8*(exponent-3))
        let shift_bits = 8 * ((exponent as i32).saturating_sub(3));
        
        // Initialize the target as a 32-byte array
        let mut target = [0u8; 32];
        
        if shift_bits >= 0 {
            // Left shift case (exponent >= 3)
            let shift_bytes = (shift_bits / 8) as usize;
            let shift_remainder = (shift_bits % 8) as u32;
            
            // Calculate the value with the shift applied
            let value = (mantissa as u128) << shift_remainder;
            
            // Convert to big-endian bytes
            let bytes = value.to_be_bytes();
            
            // Copy bytes to the target, starting from the end
            let start_byte = 32 - shift_bytes - 1;
            let bytes_to_copy = bytes.len().min(32 - start_byte);
            
            if start_byte < 32 && bytes_to_copy > 0 {
                let src_start = bytes.len() - bytes_to_copy;
                target[start_byte..start_byte + bytes_to_copy].copy_from_slice(&bytes[src_start..]);
            }
        } else {
            // Right shift case (exponent < 3)
            // This is a very large target (very easy difficulty)
            let shift = shift_bits.unsigned_abs() as u32;
            let value = (mantissa >> shift.min(24)) as u8; // Limit shift to 24 bits (3 bytes)
            
            // Set the highest byte
            target[31] = value;
        }
        
        Hash(target)
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::zero()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Represents a public key in the Rusty Coin cryptographic system.
///
/// This is used for verifying signatures and identifying participants in the network.
/// The underlying implementation uses Ed25519 elliptic curve cryptography.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Creates a PublicKey from a 32-byte array.
    ///
    /// # Arguments
    /// * `bytes` - A 32-byte array representing the public key
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Creates a new zero-initialized public key.
    pub fn zero() -> Self {
        PublicKey([0u8; 32])
    }

    /// Returns the public key as a 32-byte array reference.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts this public key to a `libp2p_identity::PublicKey`.
    #[cfg(feature = "std")]
    pub fn to_lib_p2p_public_key(&self) -> Libp2pPublicKey {
        Libp2pPublicKey::from(ed25519::PublicKey::try_from_bytes(&self.0).expect("Valid Ed25519 public key"))
    }
}

/// Represents a private key in the Rusty Coin cryptographic system.
///
/// This is used for signing transactions and must be kept secret.
/// The underlying implementation uses Ed25519 elliptic curve cryptography.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    /// Creates a PrivateKey from a 32-byte array.
    ///
    /// # Arguments
    /// * `bytes` - A 32-byte array representing the private key
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Returns the private key as a 32-byte array reference.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generates a new random private key using cryptographically secure random number generation.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl From<SigningKey> for PrivateKey {
    fn from(signing_key: SigningKey) -> Self {
        PrivateKey(signing_key.to_bytes())
    }
}

impl From<PrivateKey> for SigningKey {
    fn from(private_key: PrivateKey) -> Self {
        SigningKey::from_bytes(&private_key.0)
    }
}

/// Represents a digital signature in the Rusty Coin cryptographic system.
///
/// This is used to prove ownership of transactions and other messages.
/// The underlying implementation uses Ed25519 elliptic curve cryptography.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Signature(pub [u8; 64]);

impl From<Ed25519Signature> for Signature {
    fn from(signature: Ed25519Signature) -> Self {
        Signature(signature.to_bytes())
    }
}

impl TryFrom<Signature> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        match ed25519_dalek::Signature::from_slice(&signature.0) {
            Ok(sig) => Ok(sig),
            Err(e) => Err(anyhow::anyhow!("Invalid signature bytes: {:?}", e)),
        }
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() == 64 {
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&bytes);
            Ok(Signature(sig_bytes))
        } else {
            Err(anyhow::anyhow!("Invalid signature length"))
        }
    }
}

/// A cryptographic key pair consisting of a private and public key.
///
/// This struct simplifies key management by bundling both components.
pub struct KeyPair {
    /// The private key component used for creating digital signatures
    pub secret_key: [u8; 32],
    
    /// The public key component used for verifying signatures
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = PublicKey(*signing_key.verifying_key().as_bytes());
        KeyPair {
            secret_key: signing_key.to_bytes(),
            public_key,
        }
    }

    /// Creates a `KeyPair` from raw key bytes.
    ///
    /// # Arguments
    /// * `secret_key` - The private key bytes
    /// * `public_key` - The corresponding public key
    pub fn new(secret_key: [u8; 32], public_key: PublicKey) -> Self {
        Self { secret_key, public_key }
    }
}

/// Signs a message with a key pair's secret key.
///
/// # Arguments
/// * `keypair` - The key pair containing the secret key
/// * `message` - The message to be signed
///
/// # Returns
/// A Signature object or an error if signing fails
pub fn sign(keypair: &KeyPair, message: &[u8]) -> Result<Signature, anyhow::Error> {
    let signing_key = SigningKey::from_bytes(&keypair.secret_key);
    let signature = signing_key.sign(message);
    Ok(signature.into())
}

/// Verifies a signature against a public key and message.
///
/// # Arguments
/// * `pubkey` - The public key to verify against
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` if invalid, or an error if verification fails
pub fn verify_signature(pubkey: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error> {
    let verifying_key = VerifyingKey::from_bytes(pubkey.as_bytes())?;
    let ed25519_signature: Ed25519Signature = signature.clone().try_into()?;
    Ok(verifying_key.verify(message, &ed25519_signature).is_ok())
}

/// Defines the cryptographic operations required by Rusty Coin.
///
/// This trait provides an abstraction layer for cryptographic operations,
/// allowing different implementations to be used while maintaining
/// a consistent interface.
pub trait Crypto: Send + Sync {
    /// Generates a new cryptographic key pair.
    ///
    /// # Returns
    /// A tuple containing (PrivateKey, PublicKey) or an error
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey), anyhow::Error>;

    /// Signs a message with a private key.
    ///
    /// # Arguments
    /// * `private_key` - The private key to sign with
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// A Signature or an error if signing fails
    fn sign(&self, private_key: &PrivateKey, message: &[u8]) -> Result<Signature, anyhow::Error>;

    /// Verifies a signature against a public key and message.
    ///
    /// # Arguments
    /// * `public_key` - The public key to verify against
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `true` if valid, `false` if invalid, or an error if verification fails
    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error>;
}

/// Default implementation of cryptographic operations using Ed25519.
///
/// Provides methods for key generation, signing, and verification.
#[derive(Debug)]
pub struct Ed25519Crypto;

impl Crypto for Ed25519Crypto {
    /// Generates a new key pair for signing and verification.
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey), anyhow::Error> {
        let keypair = SigningKey::generate(&mut OsRng);
        let public_key = PublicKey(*keypair.verifying_key().as_bytes());
        Ok((PrivateKey(keypair.to_bytes()), public_key))
    }

    /// Signs a message with the given private key.
    fn sign(&self, private_key: &PrivateKey, message: &[u8]) -> Result<Signature, anyhow::Error> {
        let signing_key = SigningKey::from_bytes(&private_key.0);
        let signature = signing_key.sign(message);
        Ok(signature.into())
    }

    /// Verifies a signature against a public key and message.
    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error> {
        let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())?;
        let ed_signature = Ed25519Signature::try_from(signature.clone())?;
        Ok(verifying_key.verify(message, &ed_signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_crypto() -> Result<(), anyhow::Error> {
        let crypto = Ed25519Crypto;
        
        // Test keypair generation and signing
        let (private_key, public_key) = crypto.generate_keypair()?;
        let message = b"test message";
        let signature = crypto.sign(&private_key, message)?;
        
        // Verify valid signature
        assert!(crypto.verify(&public_key, message, &signature)?);
        
        // Test invalid message
        let wrong_message = b"wrong message";
        assert!(!crypto.verify(&public_key, wrong_message, &signature)?);
        
        // Test wrong key
        let (private_key_2, public_key_2) = crypto.generate_keypair()?;
        let signature_2 = crypto.sign(&private_key_2, message)?;
        assert!(!crypto.verify(&public_key, message, &signature_2)?);
        
        Ok(())
    }

    #[test]
    fn test_keypair_generation() -> Result<()> {
        let crypto = Ed25519Crypto;
        let (private_key_1, public_key_1) = crypto.generate_keypair()?;
        let (_private_key_2, _public_key_2) = crypto.generate_keypair()?;
        
        assert_ne!(private_key_1.0, _private_key_2.0);
        assert_ne!(public_key_1.as_bytes(), _public_key_2.as_bytes());
        Ok(())
    }

    #[test]
    fn test_sign_verify() -> Result<()> {
        let crypto = Ed25519Crypto;
        let (private_key_1, public_key_1) = crypto.generate_keypair()?;
        let (private_key_2, _public_key_2) = crypto.generate_keypair()?;
        
        let message = b"test message";
        let signature = crypto.sign(&private_key_1, message)?;
        
        assert!(crypto.verify(&public_key_1, message, &signature)?);
        assert!(!crypto.verify(&public_key_1, b"wrong message", &signature)?);
        assert!(!crypto.verify(&public_key_1, message, &crypto.sign(&private_key_2, message)?)?);
        
        Ok(())
    }
}

pub use self::oxide_hash::oxide_hash_impl;