// rusty-wallet/src/lib.rs
//! `rusty-wallet` provides functionalities for managing Rusty Coin wallets,
//! including key derivation, secure key storage, transaction building, and signing.

pub mod keys;
pub mod tx_builder;

use anyhow::{anyhow, Result};
use keys::HDWallet;
use rusty_shared_types::Transaction;

use thiserror::Error;

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

/// Securely saves wallet data (placeholder implementation)
fn save_wallet_data_securely(_data: &[u8]) -> Result<()> {
    // In a real application, you would encrypt and save the data securely
    // For now, this is just a placeholder
    Ok(())
}

// Placeholder for loading wallet data from secure storage
// This will be implemented when secure storage is added
#[allow(dead_code)]
fn load_wallet_data_securely() -> Result<Vec<u8>> {
    // Implementation will be added when secure storage is implemented
    Err(anyhow!("Secure storage not implemented yet"))
}

/// Main wallet structure that holds the HD wallet and related functionality
pub struct Wallet {
    hd_wallet: HDWallet,
}

impl Wallet {
    /// Creates a new wallet with a randomly generated mnemonic
    pub fn new() -> Result<Self> {
        let hd_wallet = HDWallet::new_random()
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
            
        // In a real implementation, you would save the wallet data securely
        // For now, we'll just ignore the result since it's a placeholder
        let _ignored = save_wallet_data_securely(&[]);
        
        Ok(Self { hd_wallet })
    }
    
    /// Restores a wallet from an existing mnemonic phrase
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let hd_wallet = HDWallet::from_mnemonic(mnemonic)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
            
        Ok(Self { hd_wallet })
    }
    
    /// Converts a public key to an address string
    pub fn public_key_to_address(public_key: &[u8]) -> String {
        // Simple implementation: use the hex-encoded public key as the address
        // In a real implementation, you would:
        // 1. Hash the public key (e.g., using SHA-256 + RIPEMD-160)
        // 2. Add version byte and checksum
        // 3. Encode using Base58 or Bech32
        hex::encode(public_key)
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
    
    /// Builds and signs a new transaction
    pub fn create_transaction(&self, recipient: &str, amount: u64) -> Result<Transaction> {
        let mut tx_builder = tx_builder::TransactionBuilder::new();
        let mut tx = tx_builder.build_transaction(recipient, amount, 1, &self.hd_wallet)?;
        self.sign_transaction(&mut tx)?;
        Ok(tx)
    }
}