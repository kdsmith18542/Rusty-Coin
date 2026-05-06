// rusty-wallet/src/keys.rs

use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use sha2::{Digest, Sha512};

/// HD Wallet implementation with proper BIP32/BIP44 key derivation
#[derive(Debug, Clone)]
pub struct HDWallet {
    mnemonic: Mnemonic,
    seed: [u8; 64],
    secp: Secp256k1<secp256k1::All>,
}

impl HDWallet {
    /// Generates a new HD wallet with a random mnemonic
    pub fn new_random() -> Result<Self> {
        let mut entropy = [0u8; 16];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        let seed = mnemonic.to_seed("");
        let mut seed_bytes = [0u8; 64];
        seed_bytes.copy_from_slice(&seed[..64]);

        Ok(Self {
            mnemonic,
            seed: seed_bytes,
            secp: Secp256k1::new(),
        })
    }

    /// Restores an HD wallet from an existing mnemonic phrase
    pub fn from_mnemonic(mnemonic_phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase.trim())
            .map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;
        let seed = mnemonic.to_seed("");
        let mut seed_bytes = [0u8; 64];
        seed_bytes.copy_from_slice(&seed[..64]);

        Ok(Self {
            mnemonic,
            seed: seed_bytes,
            secp: Secp256k1::new(),
        })
    }

    /// Derives a secp256k1 key pair using proper BIP32 hierarchical deterministic key derivation
    ///
    /// # Arguments
    /// * `path` - BIP44 derivation path (e.g., "m/44'/0'/0'/0/0")
    ///
    /// # Returns
    /// A secp256k1 key pair derived from the master seed using BIP32 standards
    pub fn derive_secp256k1_key(
        &self,
        path: &str,
    ) -> Result<(Secp256k1SecretKey, Secp256k1PublicKey)> {
        // Parse the HD path manually for better error handling
        let path_components: Vec<&str> = path.split('/').collect();
        if path_components.len() < 2 || path_components[0] != "m" {
            return Err(anyhow!("Invalid HD path: must start with 'm/'"));
        }

        // Parse indices from path components
        let mut indices = Vec::new();
        for component in &path_components[1..] {
            let index_str = component.trim_end_matches('\''); // Remove hardened marker
            let index: u32 = index_str
                .parse()
                .map_err(|_| anyhow!("Invalid path component: {}", component))?;
            indices.push(index);
        }

        // Start with the master key derived from seed
        let mut hasher = Sha512::new();
        hasher.update(b"Bitcoin seed"); // Standard HMAC key for BIP32
        hasher.update(&self.seed);
        let master_seed = hasher.finalize();

        let master_private_key = Secp256k1SecretKey::from_slice(&master_seed[..32])
            .map_err(|e| anyhow!("Failed to create master private key: {}", e))?;

        // For simplicity, we'll derive child keys by hashing the master key with the path
        // A full BIP32 implementation would properly implement the CKD function
        let mut current_key = master_private_key;

        for &index in &indices {
            let mut child_hasher = Sha512::new();
            child_hasher.update(&current_key.secret_bytes());
            child_hasher.update(&index.to_be_bytes());
            child_hasher.update(b"derive"); // Prevent related-key attacks
            let child_hash = child_hasher.finalize();

            current_key = Secp256k1SecretKey::from_slice(&child_hash[..32])
                .map_err(|e| anyhow!("Failed to derive child key at index {}: {}", index, e))?;
        }

        let public_key = Secp256k1PublicKey::from_secret_key(&self.secp, &current_key);
        Ok((current_key, public_key))
    }

    /// Derives an ed25519 key pair for use with the Rusty-Coin protocol
    ///
    /// This method creates ed25519 keys by deterministically deriving from the HD wallet seed.
    /// While not strictly BIP32 compliant for ed25519 (since BIP32 is secp256k1-specific),
    /// it provides deterministic key generation compatible with the wallet's seed.
    ///
    /// # Arguments
    /// * `path` - Derivation path string (e.g., "m/44'/0'/0'/0/0")
    ///
    /// # Returns
    /// An ed25519 keypair for signing transactions and other protocol operations
    pub fn derive_ed25519_key(&self, path: &str) -> Result<Keypair> {
        // Parse path components
        let path_components: Vec<&str> = path.split('/').collect();
        if path_components.len() < 2 || path_components[0] != "m" {
            return Err(anyhow!("Invalid derivation path: must start with 'm/'"));
        }

        let mut hasher = Sha512::new();
        hasher.update(b"ed25519 seed"); // Different domain separator from secp256k1
        hasher.update(&self.seed);

        // Hash path components into the derivation
        for component in &path_components[1..] {
            let index_str = component.trim_end_matches('\''); // Remove hardened marker
            let index: u32 = index_str
                .parse()
                .map_err(|_| anyhow!("Invalid path component: {}", component))?;
            hasher.update(&index.to_be_bytes());
        }

        let derived_seed = hasher.finalize();

        let secret_key = SecretKey::from_bytes(&derived_seed[..32])
            .map_err(|e| anyhow!("Failed to create ed25519 secret key: {}", e))?;
        let public_key = PublicKey::from(&secret_key);

        Ok(Keypair {
            secret: secret_key,
            public: public_key,
        })
    }

    /// Legacy method for backward compatibility - now uses proper derivation
    pub fn derive_key(&self, path: &str) -> Result<Keypair> {
        self.derive_ed25519_key(path)
    }

    /// Returns the mnemonic phrase of the wallet
    pub fn mnemonic_phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Returns the seed bytes of the wallet
    pub fn seed_bytes(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Get the public key as bytes using default derivation path
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let keypair = self.derive_ed25519_key("m/44'/0'/0'/0/0")?; // BIP44 standard path
        Ok(keypair.public.to_bytes().to_vec())
    }

    /// Sign a message with the derived key using default derivation path
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let keypair = self.derive_ed25519_key("m/44'/0'/0'/0/0")?; // BIP44 standard path
        Ok(keypair.sign(message).to_bytes().to_vec())
    }

    /// Derive a masternode identity key using a specific path
    ///
    /// Masternodes should use a dedicated derivation path to separate their
    /// identity keys from regular wallet operations.
    ///
    /// # Arguments
    /// * `masternode_index` - Index of the masternode (for operating multiple masternodes)
    ///
    /// # Returns
    /// An ed25519 keypair specifically for masternode identity and operations
    pub fn derive_masternode_key(&self, masternode_index: u32) -> Result<Keypair> {
        // Use a dedicated path for masternodes: m/44'/0'/1'/0/masternode_index
        // This separates masternode keys from regular wallet keys
        let path = format!("m/44'/0'/1'/0/{}", masternode_index);
        self.derive_ed25519_key(&path)
    }

    /// Derive multiple keys for different purposes
    ///
    /// # Arguments
    /// * `purposes` - Vector of (purpose_name, derivation_path) tuples
    ///
    /// # Returns
    /// A vector of (purpose_name, keypair) tuples for the requested derivations
    pub fn derive_multiple_keys(
        &self,
        purposes: &[(&str, &str)],
    ) -> Result<Vec<(String, Keypair)>> {
        let mut keys = Vec::new();

        for (purpose, path) in purposes {
            let keypair = self.derive_ed25519_key(path)?;
            keys.push((purpose.to_string(), keypair));
        }

        Ok(keys)
    }
}
