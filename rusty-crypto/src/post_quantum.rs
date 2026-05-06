//! Post-Quantum Cryptography Migration Module
//!
//! This module provides structures and mechanisms for migrating Rusty Coin
//! to post-quantum cryptography, specifically CRYSTALS-Dilithium signatures.
//! Per spec 11 (Post-Quantum Migration) and RCTB QuantumGuard tasks.

use bs58;
use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature, Signer, Verifier};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_falcon::{falcon512, falcon1024};
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumDetachedSignatureTrait, PublicKey as DilithiumPublicKeyTrait,
    SecretKey as DilithiumSecretKeyTrait,
};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Post-quantum signature scheme identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostQuantumScheme {
    /// CRYSTALS-Dilithium2 (recommended for blockchain)
    Dilithium2,
    /// CRYSTALS-Dilithium3 (higher security, larger signatures)
    Dilithium3,
    /// CRYSTALS-Dilithium5 (maximum security)
    Dilithium5,
    /// Falcon-512 (compact signatures)
    Falcon512,
    /// Falcon-1024 (higher security)
    Falcon1024,
}

impl Default for PostQuantumScheme {
    fn default() -> Self {
        PostQuantumScheme::Dilithium2
    }
}

impl PostQuantumScheme {
    /// Return the address version byte associated with this scheme.
    pub const fn address_version_byte(&self) -> u8 {
        match self {
            PostQuantumScheme::Dilithium2 => 0x51, // 'Q1' style versioning
            PostQuantumScheme::Dilithium3 => 0x52,
            PostQuantumScheme::Dilithium5 => 0x53,
            PostQuantumScheme::Falcon512 => 0x54,
            PostQuantumScheme::Falcon1024 => 0x55,
        }
    }
}

/// Errors that can occur when working with post-quantum primitives.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PostQuantumError {
    #[error("invalid post-quantum public key")]
    InvalidPublicKey,
    #[error("invalid post-quantum private key")]
    InvalidPrivateKey,
    #[error("invalid post-quantum signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}

/// Hybrid signature combining classical and post-quantum signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical signature (Ed25519)
    pub classical_sig: Vec<u8>,
    /// Post-quantum signature (Dilithium)
    pub pq_sig: Vec<u8>,
    /// Signature scheme identifier
    pub scheme: PostQuantumScheme,
}

impl HybridSignature {
    /// Create a new hybrid signature
    pub fn new(classical_sig: Vec<u8>, pq_sig: Vec<u8>, scheme: PostQuantumScheme) -> Self {
        Self {
            classical_sig,
            pq_sig,
            scheme,
        }
    }

    /// Verify both signatures (classical Ed25519 + Dilithium)
    pub fn verify(&self, message: &[u8], classical_pubkey: &[u8], pq_pubkey: &[u8]) -> bool {
        let classical_valid = (|| -> Result<(), PostQuantumError> {
            let pk = DalekPublicKey::from_bytes(classical_pubkey)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig = DalekSignature::from_bytes(&self.classical_sig)
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            pk.verify(message, &sig)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        })()
        .is_ok();

        if !classical_valid {
            return false;
        }

        verify_pq_signature(self.scheme, message, &self.pq_sig, pq_pubkey).is_ok()
    }
}

/// Post-quantum public key (hybrid Ed25519 + Dilithium)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumPublicKey {
    /// Ed25519 public key bytes
    pub ed25519_public_key: Vec<u8>,
    /// Dilithium public key bytes
    pub dilithium_key_bytes: Vec<u8>,
    /// Signature scheme
    pub scheme: PostQuantumScheme,
}

impl PostQuantumPublicKey {
    /// Create a new post-quantum public key
    pub fn new(ed25519_public_key: Vec<u8>, dilithium_key_bytes: Vec<u8>, scheme: PostQuantumScheme) -> Self {
        Self { ed25519_public_key, dilithium_key_bytes, scheme }
    }

    /// Get the address format for this public key
    /// Per spec: new address prefixes/formats for Dilithium public keys
    pub fn to_address(&self) -> String {
        let mut combined = self.ed25519_public_key.clone();
        combined.extend_from_slice(&self.dilithium_key_bytes);
        let key_hash = hash160(&combined);
        let mut payload = Vec::with_capacity(1 + key_hash.len() + 4);
        payload.push(self.scheme.address_version_byte());
        payload.extend_from_slice(&key_hash);

        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);

        format!("pq{}", bs58::encode(payload).into_string())
    }
}

/// Post-quantum private key (hybrid Ed25519 + Dilithium)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumPrivateKey {
    /// Ed25519 private key bytes
    pub ed25519_secret_key: Vec<u8>,
    /// Dilithium private key bytes
    pub dilithium_key_bytes: Vec<u8>,
    /// Cached Ed25519 public key bytes
    pub ed25519_public_key_bytes: Vec<u8>,
    /// Cached Dilithium public key bytes
    pub dilithium_public_key_bytes: Vec<u8>,
    /// Signature scheme
    pub scheme: PostQuantumScheme,
}

impl PostQuantumPrivateKey {
    /// Create a new post-quantum private key
    pub fn new(ed25519_secret_key: Vec<u8>, dilithium_key_bytes: Vec<u8>, ed25519_public_key_bytes: Vec<u8>, dilithium_public_key_bytes: Vec<u8>, scheme: PostQuantumScheme) -> Self {
        Self {
            ed25519_secret_key,
            dilithium_key_bytes,
            ed25519_public_key_bytes,
            dilithium_public_key_bytes,
            scheme,
        }
    }

    /// Generate a fresh post-quantum keypair for the given scheme
    pub fn generate(
        scheme: PostQuantumScheme,
    ) -> Result<(PostQuantumPublicKey, PostQuantumPrivateKey), PostQuantumError> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let ed25519_keypair = ed25519_dalek::Keypair::generate(&mut rng);
        let ed25519_secret_key = ed25519_keypair.secret.to_bytes().to_vec();
        let ed25519_public_key = ed25519_keypair.public.to_bytes().to_vec();

        let (dilithium_public_key_bytes, dilithium_private_key_bytes) = generate_keypair_bytes(scheme)?;
        Ok((
            PostQuantumPublicKey::new(ed25519_public_key.clone(), dilithium_public_key_bytes.clone(), scheme),
            PostQuantumPrivateKey::new(ed25519_secret_key, dilithium_private_key_bytes, ed25519_public_key, dilithium_public_key_bytes, scheme),
        ))
    }

    /// Sign a message with the hybrid private key (Ed25519 + Dilithium)
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature, PostQuantumError> {
        let ed25519_secret = ed25519_dalek::SecretKey::from_bytes(&self.ed25519_secret_key)
            .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
        let ed25519_public = ed25519_dalek::PublicKey::from_bytes(&self.ed25519_public_key_bytes)
            .map_err(|_| PostQuantumError::InvalidPublicKey)?;
        let ed25519_keypair = ed25519_dalek::Keypair { secret: ed25519_secret, public: ed25519_public };
        let classical_sig = ed25519_keypair.sign(message).to_bytes().to_vec();

        let pq_sig = sign_with_scheme(self.scheme, message, &self.dilithium_key_bytes)?;

        Ok(HybridSignature::new(classical_sig, pq_sig, self.scheme))
    }

    /// Derive the corresponding public key
    pub fn public_key(&self) -> Result<PostQuantumPublicKey, PostQuantumError> {
        Ok(PostQuantumPublicKey::new(
            self.ed25519_public_key_bytes.clone(),
            self.dilithium_public_key_bytes.clone(),
            self.scheme,
        ))
    }
}

/// Migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Enable hybrid signatures (both Ed25519 and Dilithium)
    pub enable_hybrid: bool,
    /// Block height at which migration starts
    pub migration_start_height: u64,
    /// Block height at which classical-only signatures are deprecated
    pub deprecation_height: Option<u64>,
    /// Block height at which classical-only signatures are rejected
    pub rejection_height: Option<u64>,
    /// Post-quantum scheme to use
    pub scheme: PostQuantumScheme,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            enable_hybrid: true,
            migration_start_height: 0,
            deprecation_height: None,
            rejection_height: None,
            scheme: PostQuantumScheme::Dilithium2,
        }
    }
}

/// Migration status for a transaction or block
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    /// Classical-only signatures (pre-migration)
    ClassicalOnly,
    /// Hybrid signatures (migration period)
    Hybrid,
    /// Post-quantum-only signatures (post-migration)
    PostQuantumOnly,
}

/// Migration manager
pub struct MigrationManager {
    config: MigrationConfig,
    current_height: u64,
}

impl MigrationManager {
    /// Create a new migration manager
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            config,
            current_height: 0,
        }
    }

    /// Update current block height
    pub fn update_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Get current migration status
    pub fn get_status(&self) -> MigrationStatus {
        if let Some(rejection_height) = self.config.rejection_height {
            if self.current_height >= rejection_height {
                return MigrationStatus::PostQuantumOnly;
            }
        }
        if let Some(deprecation_height) = self.config.deprecation_height {
            if self.current_height >= deprecation_height {
                return MigrationStatus::Hybrid;
            }
        }
        if self.current_height >= self.config.migration_start_height {
            if self.config.enable_hybrid {
                return MigrationStatus::Hybrid;
            }
        }
        MigrationStatus::ClassicalOnly
    }

    /// Check if hybrid signatures are required at current height
    pub fn requires_hybrid(&self) -> bool {
        matches!(self.get_status(), MigrationStatus::Hybrid)
    }

    /// Check if post-quantum signatures are required at current height
    pub fn requires_post_quantum(&self) -> bool {
        matches!(self.get_status(), MigrationStatus::PostQuantumOnly)
    }

    /// Check if classical-only signatures are still allowed
    pub fn allows_classical_only(&self) -> bool {
        !matches!(self.get_status(), MigrationStatus::PostQuantumOnly)
    }
}

fn verify_pq_signature(
    scheme: PostQuantumScheme,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), PostQuantumError> {
    match scheme {
        PostQuantumScheme::Dilithium2 => {
            let pk = <dilithium2::PublicKey as DilithiumPublicKeyTrait>::from_bytes(public_key)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig =
                <dilithium2::DetachedSignature as DilithiumDetachedSignatureTrait>::from_bytes(
                    signature,
                )
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            dilithium2::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        }
        PostQuantumScheme::Dilithium3 => {
            let pk = <dilithium3::PublicKey as DilithiumPublicKeyTrait>::from_bytes(public_key)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig =
                <dilithium3::DetachedSignature as DilithiumDetachedSignatureTrait>::from_bytes(
                    signature,
                )
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            dilithium3::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        }
        PostQuantumScheme::Dilithium5 => {
            let pk = <dilithium5::PublicKey as DilithiumPublicKeyTrait>::from_bytes(public_key)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig =
                <dilithium5::DetachedSignature as DilithiumDetachedSignatureTrait>::from_bytes(
                    signature,
                )
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            dilithium5::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        }
        PostQuantumScheme::Falcon512 => {
            let pk = <falcon512::PublicKey as DilithiumPublicKeyTrait>::from_bytes(public_key)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig =
                <falcon512::DetachedSignature as DilithiumDetachedSignatureTrait>::from_bytes(
                    signature,
                )
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            falcon512::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        }
        PostQuantumScheme::Falcon1024 => {
            let pk = <falcon1024::PublicKey as DilithiumPublicKeyTrait>::from_bytes(public_key)
                .map_err(|_| PostQuantumError::InvalidPublicKey)?;
            let sig =
                <falcon1024::DetachedSignature as DilithiumDetachedSignatureTrait>::from_bytes(
                    signature,
                )
                .map_err(|_| PostQuantumError::InvalidSignature)?;
            falcon1024::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| PostQuantumError::SignatureVerificationFailed)
        }
    }
}

fn sign_with_scheme(
    scheme: PostQuantumScheme,
    message: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, PostQuantumError> {
    match scheme {
        PostQuantumScheme::Dilithium2 => {
            let sk = <dilithium2::SecretKey as DilithiumSecretKeyTrait>::from_bytes(secret_key)
                .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
            let sig = dilithium2::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        PostQuantumScheme::Dilithium3 => {
            let sk = <dilithium3::SecretKey as DilithiumSecretKeyTrait>::from_bytes(secret_key)
                .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
            let sig = dilithium3::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        PostQuantumScheme::Dilithium5 => {
            let sk = <dilithium5::SecretKey as DilithiumSecretKeyTrait>::from_bytes(secret_key)
                .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
            let sig = dilithium5::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        PostQuantumScheme::Falcon512 => {
            let sk = <falcon512::SecretKey as DilithiumSecretKeyTrait>::from_bytes(secret_key)
                .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
            let sig = falcon512::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
        PostQuantumScheme::Falcon1024 => {
            let sk = <falcon1024::SecretKey as DilithiumSecretKeyTrait>::from_bytes(secret_key)
                .map_err(|_| PostQuantumError::InvalidPrivateKey)?;
            let sig = falcon1024::detached_sign(message, &sk);
            Ok(sig.as_bytes().to_vec())
        }
    }
}

fn generate_keypair_bytes(
    scheme: PostQuantumScheme,
) -> Result<(Vec<u8>, Vec<u8>), PostQuantumError> {
    match scheme {
        PostQuantumScheme::Dilithium2 => {
            let (pk, sk) = dilithium2::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
        PostQuantumScheme::Dilithium3 => {
            let (pk, sk) = dilithium3::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
        PostQuantumScheme::Dilithium5 => {
            let (pk, sk) = dilithium5::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
        PostQuantumScheme::Falcon512 => {
            let (pk, sk) = falcon512::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
        PostQuantumScheme::Falcon1024 => {
            let (pk, sk) = falcon1024::keypair();
            Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
        }
    }
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha);
    let result = ripemd_hasher.finalize();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&result);
    hash
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;

    #[test]
    fn test_migration_status_transitions() {
        let mut manager = MigrationManager::new(MigrationConfig {
            enable_hybrid: true,
            migration_start_height: 1000,
            deprecation_height: Some(2000),
            rejection_height: Some(3000),
            scheme: PostQuantumScheme::Dilithium2,
        });

        // Before migration
        manager.update_height(500);
        assert_eq!(manager.get_status(), MigrationStatus::ClassicalOnly);
        assert!(manager.allows_classical_only());

        // During migration (hybrid period)
        manager.update_height(1500);
        assert_eq!(manager.get_status(), MigrationStatus::Hybrid);
        assert!(manager.requires_hybrid());

        // After deprecation but before rejection
        manager.update_height(2500);
        assert_eq!(manager.get_status(), MigrationStatus::Hybrid);
        assert!(manager.requires_hybrid());

        // After rejection (post-quantum only)
        manager.update_height(3500);
        assert_eq!(manager.get_status(), MigrationStatus::PostQuantumOnly);
        assert!(manager.requires_post_quantum());
        assert!(!manager.allows_classical_only());
    }

    #[test]
    fn test_post_quantum_keypair_and_sign() {
        let (public_key, private_key) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();

        let message = b"quantum-safe message";
        let signature = private_key.sign(message).unwrap();

        assert!(signature.verify(
            message,
            &public_key.ed25519_public_key,
            &public_key.dilithium_key_bytes
        ));

        let derived_public_key = private_key.public_key().unwrap();
        assert_eq!(derived_public_key.ed25519_public_key, public_key.ed25519_public_key);
        assert_eq!(derived_public_key.dilithium_key_bytes, public_key.dilithium_key_bytes);
    }

    #[test]
    fn test_falcon_keypair_and_sign() {
        let (public_key, private_key) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Falcon512).unwrap();

        let message = b"falcon quantum-safe message";
        let signature = private_key.sign(message).unwrap();

        assert!(signature.verify(
            message,
            &public_key.ed25519_public_key,
            &public_key.dilithium_key_bytes
        ));

        let derived_public_key = private_key.public_key().unwrap();
        assert_eq!(derived_public_key.ed25519_public_key, public_key.ed25519_public_key);
        assert_eq!(derived_public_key.dilithium_key_bytes, public_key.dilithium_key_bytes);
    }

    #[test]
    fn test_pq_address_encoding() {
        let (public_key, _) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium3).unwrap();
        let address = public_key.to_address();
        assert!(address.starts_with("pq"));
        // Ensure the payload encodes both hash and checksum (should be longer than prefix + hash).
        assert!(address.len() > 20);

        let (falcon_public_key, _) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Falcon512).unwrap();
        let falcon_address = falcon_public_key.to_address();
        assert!(falcon_address.starts_with("pq"));
        assert!(falcon_address.len() > 20);
    }

    #[test]
    fn test_hybrid_signature_verification() {
        let (pq_public, pq_private) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Dilithium2).unwrap();

        let message = b"hybrid signature message";
        let hybrid_signature = pq_private.sign(message).unwrap();

        // Verify using the correct Ed25519 public key from the PQ keypair
        assert!(hybrid_signature.verify(
            message,
            &pq_public.ed25519_public_key,
            &pq_public.dilithium_key_bytes
        ));

        // Test with Falcon
        let (falcon_public, falcon_private) =
            PostQuantumPrivateKey::generate(PostQuantumScheme::Falcon512).unwrap();

        let falcon_hybrid_signature = falcon_private.sign(message).unwrap();

        // Verify using the correct Ed25519 public key from the PQ keypair
        assert!(falcon_hybrid_signature.verify(
            message,
            &falcon_public.ed25519_public_key,
            &falcon_public.dilithium_key_bytes
        ));
    }
}
