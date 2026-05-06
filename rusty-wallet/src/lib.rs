// rusty-wallet/src/lib.rs
//! `rusty-wallet` provides functionalities for managing Rusty Coin wallets,
//! including key derivation, secure key storage, transaction building, and signing.

use anyhow::Result;
use rusty_shared_types::Transaction;
use thiserror::Error;

mod keys;
mod rpc_integration;
mod storage;
mod tx_builder;

pub use keys::*;
pub use rpc_integration::{RpcClient, RpcError};
pub use storage::*;
pub use tx_builder::*;

/// Custom error type for wallet operations
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Securely saves wallet data using OS keyring and encrypted file storage
fn save_wallet_data_securely(
    wallet_data: &storage::SecureWalletData,
    password: &str,
    wallet_id: Option<String>,
) -> Result<()> {
    Ok(
        storage::save_wallet_data_securely(wallet_data, password, wallet_id)
            .map_err(|e| WalletError::StorageError(e.to_string()))?,
    )
}

/// Loads wallet data from secure storage (OS keyring and encrypted files)
fn load_wallet_data_securely(password: &str) -> Result<storage::SecureWalletData> {
    Ok(storage::load_wallet_data_securely(password)
        .map_err(|e| WalletError::StorageError(e.to_string()))?)
}

/// Main wallet structure that holds the HD wallet and related functionality
pub struct Wallet {
    hd_wallet: HDWallet,
}

impl Wallet {
    /// Creates a new wallet with a randomly generated mnemonic
    pub fn new() -> Result<Self> {
        let hd_wallet =
            HDWallet::new_random().map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        // Save the wallet seed securely using OS keyring and encrypted file storage
        let mnemonic = hd_wallet.mnemonic_phrase();
        let seed_data = mnemonic.as_bytes();
        let wallet_data = storage::SecureWalletData::new(seed_data.to_vec());
        save_wallet_data_securely(&wallet_data, "default_password", None)?;

        Ok(Self { hd_wallet })
    }

    /// Restores a wallet from an existing mnemonic phrase
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let hd_wallet = HDWallet::from_mnemonic(mnemonic)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        Ok(Self { hd_wallet })
    }

    /// Restores a wallet from secure storage (OS keyring)
    pub fn restore_from_secure_storage() -> Result<Self> {
        let wallet_data = load_wallet_data_securely("default_password")?;
        let mnemonic = String::from_utf8(wallet_data.seed.clone()).map_err(|e| {
            WalletError::StorageError(format!("Invalid UTF-8 in stored seed: {}", e))
        })?;

        Self::from_mnemonic(&mnemonic)
    }

    /// Converts a public key to an address string per docs/specs/05_utxo_model_spec.md
    pub fn public_key_to_address(public_key: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        // 1. Hash the public key using double SHA-256 (simplified approach)
        // In production, would use SHA-256 + RIPEMD-160 for better address format
        let first_hash = Sha256::digest(public_key);
        let address_hash = Sha256::digest(&first_hash);

        // 2. Take first 20 bytes of the hash for address (similar to Bitcoin's RIPEMD-160)
        let address_bytes = &address_hash[..20];

        // 3. Add version byte for Rusty Coin mainnet (0x3C for 'R')
        let mut versioned_hash = Vec::with_capacity(21);
        versioned_hash.push(0x3C); // Version byte for Rusty Coin
        versioned_hash.extend_from_slice(address_bytes);

        // 4. Calculate checksum (first 4 bytes of double SHA-256)
        let checksum_full = Sha256::digest(&Sha256::digest(&versioned_hash));
        let checksum = &checksum_full[..4];

        // 5. Append checksum
        versioned_hash.extend_from_slice(checksum);

        // 6. Encode using Base58
        Self::base58_encode(&versioned_hash)
    }

    /// Simplified Base58-like encoding for addresses (without external dependencies)
    fn base58_encode(input: &[u8]) -> String {
        if input.is_empty() {
            return String::new();
        }

        // Count leading zeros for leading '1's
        let leading_zeros = input.iter().take_while(|&&x| x == 0).count();

        // Simple implementation: use hex encoding with a 'R' prefix for Rusty Coin
        // In production, this would use proper Base58 encoding
        let mut result = String::with_capacity(1 + leading_zeros + input.len() * 2);
        result.push('R'); // Rusty Coin address prefix
        result.extend(std::iter::repeat('1').take(leading_zeros)); // Leading zeros as '1's
        result.push_str(&hex::encode(input));

        result
    }

    /// Generates a new address from the HD wallet
    pub fn generate_address(&self) -> Result<String> {
        let pubkey = self.hd_wallet.public_key_bytes()?;
        Ok(Self::public_key_to_address(&pubkey))
    }

    /// Returns the public key as bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        self.hd_wallet.public_key_bytes()
    }

    /// Signs a message with the wallet's private key
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.hd_wallet.sign(message)
    }

    /// Returns the mnemonic phrase of the wallet
    pub fn mnemonic_phrase(&self) -> String {
        self.hd_wallet.mnemonic_phrase()
    }

    /// Signs a transaction with the wallet's private key
    pub fn sign_transaction(&self, transaction: &mut Transaction) -> Result<()> {
        let tx_builder = tx_builder::TransactionBuilder::new();
        tx_builder.sign_transaction(transaction, &self.hd_wallet)
    }

    /// Builds and signs a new transaction with specified fee rate, automatically refreshing UTXOs from the node (see UTXO model spec 5.4).
    pub async fn create_transaction_with_refresh(
        &self,
        recipient: &str,
        amount: u64,
        fee_per_byte: u64,
        rpc_client: &mut RpcClient,
        address: &str,
    ) -> anyhow::Result<Transaction> {
        let mut tx_builder = tx_builder::TransactionBuilder::new();
        tx_builder
            .refresh_utxos_from_node(rpc_client, address)
            .await?;
        let mut tx =
            tx_builder.build_transaction(recipient, amount, fee_per_byte, &self.hd_wallet)?;
        self.sign_transaction(&mut tx)?;
        Ok(tx)
    }

    /// Builds and signs a new transaction with default fee rate (10 sats/byte), automatically refreshing UTXOs from the node.
    pub async fn create_transaction_default_fee_with_refresh(
        &self,
        recipient: &str,
        amount: u64,
        rpc_client: &mut RpcClient,
        address: &str,
    ) -> anyhow::Result<Transaction> {
        self.create_transaction_with_refresh(recipient, amount, 10, rpc_client, address)
            .await
    }
}

pub async fn create_wallet_async(name: &str, password: &str) -> Result<Wallet> {
    // Implementation for async wallet creation
    create_wallet(name, password)
}

pub async fn restore_wallet_async(name: &str, mnemonic: &str, password: &str) -> Result<Wallet> {
    // Implementation for async wallet restoration
    restore_wallet(name, mnemonic, password)
}

/// Creates a new wallet with the given name and password
fn create_wallet(name: &str, _password: &str) -> Result<Wallet> {
    // Create a new wallet
    let wallet = Wallet::new()?;

    // Store name and password in secure storage (not implemented yet)
    // This would typically involve encrypting the wallet with the password
    // and storing it with the given name
    println!("Created new wallet with name: {}", name);

    Ok(wallet)
}

/// Restores a wallet from a mnemonic phrase
fn restore_wallet(name: &str, mnemonic: &str, _password: &str) -> Result<Wallet> {
    // Restore wallet from mnemonic
    let wallet = Wallet::from_mnemonic(mnemonic)?;

    // Store name and password in secure storage (not implemented yet)
    // This would typically involve encrypting the wallet with the password
    // and storing it with the given name
    println!("Restored wallet with name: {}", name);

    Ok(wallet)
}
