//! Cryptographic primitives and utilities for Rusty Coin.

use blake3;
use sha2::{Sha256, Digest};
use std::fmt;
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature as Ed25519Signature};
use rand_core::OsRng;
use anyhow::Result;
use serde::{Serialize, Deserialize};

pub mod oxide_hash;

/// A 32-byte hash output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, bincode::Encode, bincode::Decode)]
pub struct Hash(#[bincode(with_serde)] pub [u8; 32]);

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
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash(hash)
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

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Public key wrapper for ed25519
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A private key used in the Rusty Coin network.
#[derive(Debug, Clone)]
pub struct PrivateKey(pub [u8; 32]);

impl From<SigningKey> for PrivateKey {
    fn from(signing_key: SigningKey) -> Self {
        PrivateKey(signing_key.to_bytes()[..32].try_into().unwrap())
    }
}

impl From<PrivateKey> for SigningKey {
    fn from(private_key: PrivateKey) -> Self {
        SigningKey::from_bytes(&private_key.0)
    }
}

/// A digital signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl From<Ed25519Signature> for Signature {
    fn from(signature: Ed25519Signature) -> Self {
        Signature(signature.to_bytes())
    }
}

impl TryFrom<Signature> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        Ed25519Signature::try_from(&signature.0[..])
            .map_err(|e| anyhow::anyhow!("Invalid signature bytes: {:?}", e))
    }
}

/// Key pair for signing and verification
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub secret_key: [u8; 32],
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generates a new key pair.
    pub fn generate() -> Result<Self, anyhow::Error> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = PublicKey(signing_key.verifying_key().to_bytes());
        Ok(Self {
            secret_key: signing_key.to_bytes(),
            public_key,
        })
    }
    
    /// Signs a message with the key pair's secret key.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, anyhow::Error> {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        Ok(Signature(signing_key.sign(message).to_bytes()))
    }
}

pub fn verify_signature(pubkey: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error> {
    let verifying_key = match VerifyingKey::from_bytes(pubkey.as_bytes()) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    
    let ed25519_signature = Ed25519Signature::from_bytes(&signature.0);
    
    Ok(verifying_key.verify(message, &ed25519_signature).is_ok())
}

/// Cryptographic operations for Rusty Coin.
pub trait Crypto {
    /// Generates a new key pair.
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey), anyhow::Error>;
    
    /// Signs a message with the given private key.
    fn sign(&self, private_key: &PrivateKey, message: &[u8]) -> Result<Signature, anyhow::Error>;
    
    /// Verifies a signature with the given public key and message.
    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error>;
}

pub struct Ed25519Crypto;

impl Crypto for Ed25519Crypto {
    fn generate_keypair(&self) -> Result<(PrivateKey, PublicKey), anyhow::Error> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = PublicKey(signing_key.verifying_key().to_bytes());
        Ok((PrivateKey(signing_key.to_bytes()), public_key))
    }

    fn sign(&self, private_key: &PrivateKey, message: &[u8]) -> Result<Signature, anyhow::Error> {
        let signing_key = SigningKey::from_bytes(&private_key.0);
        Ok(Signature(signing_key.sign(message).to_bytes()))
    }

    fn verify(&self, public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool, anyhow::Error> {
        let verifying_key = match VerifyingKey::from_bytes(public_key.as_bytes()) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        
        let ed25519_signature = Ed25519Signature::from_bytes(&signature.0);
        Ok(verifying_key.verify(message, &ed25519_signature).is_ok())
    }
}

/// Implementation of the OxideHash algorithm as specified in the Rusty Coin blueprint.
pub fn oxide_hash(header: &[u8]) -> Hash {
    oxide_hash::oxide_hash_impl(header)
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
}
