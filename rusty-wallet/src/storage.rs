//! `rusty-wallet/src/storage.rs` provides secure storage functionalities for wallet data.
//! Implements encryption at rest, password-based key derivation, and secure memory handling
//! per industry best practices and UTXO model security requirements.

use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use argon2::{
    password_hash::{PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use base64::engine::{general_purpose::STANDARD as Base64Engine, Engine as _};
use confy;
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

const APP_NAME: &str = "rusty-coin-wallet";
const WALLET_KEY: &str = "encrypted_wallet_data";

// Security parameters per industry best practices
const ARGON2_MEMORY: u32 = 65536; // 64MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const NONCE_SIZE: usize = 12; // AES-GCM nonce size
const SALT_SIZE: usize = 32;

/// Secure wallet configuration stored in plaintext
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct WalletConfig {
    /// Unique wallet identifier
    pub wallet_id: String,
    /// Creation timestamp for audit purposes
    pub created_at: u64,
    /// Last access timestamp for security monitoring
    pub last_accessed: u64,
    /// Number of failed unlock attempts (for rate limiting)
    pub failed_attempts: u32,
    /// Whether the wallet is currently locked
    pub is_locked: bool,
    /// Backup verification hash (non-sensitive)
    pub backup_hash: Option<String>,
}

/// Encrypted wallet data structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedWalletData {
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Nonce for AES-GCM encryption
    pub nonce: Vec<u8>,
    /// Encrypted wallet seed/private data
    pub encrypted_data: Vec<u8>,
    /// Argon2 password hash for verification
    pub password_hash: String,
    /// Data integrity checksum
    pub checksum: Vec<u8>,
}

/// Secure memory container for sensitive data
#[derive(ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecureWalletData {
    /// Master seed or mnemonic
    pub seed: Vec<u8>,
    /// Additional private keys if any
    pub private_keys: Vec<Vec<u8>>,
    /// Wallet metadata
    pub metadata: Vec<u8>,
}

impl SecureWalletData {
    /// Create new secure wallet data container
    pub fn new(seed: Vec<u8>) -> Self {
        Self {
            seed,
            private_keys: Vec::new(),
            metadata: Vec::new(),
        }
    }

    /// Add a private key to secure storage
    pub fn add_private_key(&mut self, key: Vec<u8>) {
        self.private_keys.push(key);
    }

    /// Serialize for encryption (will be zeroized after use)
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize secure wallet data: {}", e))
    }

    /// Deserialize from decrypted data
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize secure wallet data: {}", e))
    }
}

/// Save wallet data securely with encryption and password-based key derivation
/// Implements AES-256-GCM encryption with Argon2 key derivation per industry best practices
pub fn save_wallet_data_securely(
    wallet_data: &SecureWalletData,
    password: &str,
    wallet_id: Option<String>,
) -> Result<(), String> {
    // Create wallet configuration
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cfg = WalletConfig {
        wallet_id: wallet_id.unwrap_or_else(|| "default".to_string()),
        created_at: current_time,
        last_accessed: current_time,
        failed_attempts: 0,
        is_locked: false,
        backup_hash: None,
    };

    // Save non-sensitive configuration
    confy::store(APP_NAME, &cfg).map_err(|e| format!("Failed to save wallet config: {}", e))?;

    // Serialize wallet data for encryption
    let mut serialized_data = wallet_data.serialize()?;

    // Generate cryptographic salt and nonce
    let mut salt = vec![0u8; SALT_SIZE];
    let mut nonce = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Derive encryption key using Argon2
    let argon2 = Argon2::default();
    let salt_string =
        SaltString::encode_b64(&salt).map_err(|e| format!("Failed to encode salt: {}", e))?;

    // Create password hash for verification
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| format!("Failed to hash password: {}", e))?
        .to_string();

    // Derive AES key from password
    let mut key_bytes = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| format!("Failed to create Argon2 params: {}", e))?,
    )
    .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
    .map_err(|e| format!("Failed to derive encryption key: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Encrypt the wallet data
    let nonce_array = GenericArray::from_slice(&nonce);
    let encrypted_data = cipher
        .encrypt(nonce_array, serialized_data.as_ref())
        .map_err(|e| format!("Failed to encrypt wallet data: {}", e))?;

    // Calculate checksum for integrity verification
    let checksum = blake3::hash(&encrypted_data).as_bytes().to_vec();

    // Create encrypted wallet data structure
    let encrypted_wallet = EncryptedWalletData {
        salt,
        nonce,
        encrypted_data,
        password_hash,
        checksum,
    };

    // Serialize and encode encrypted wallet data
    let encrypted_serialized = bincode::serialize(&encrypted_wallet)
        .map_err(|e| format!("Failed to serialize encrypted wallet: {}", e))?;
    let encoded_data = Base64Engine.encode(&encrypted_serialized);

    // Store encrypted data in OS keyring
    let entry = Entry::new(APP_NAME, WALLET_KEY)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;
    entry
        .set_password(&encoded_data)
        .map_err(|e| format!("Failed to store encrypted wallet data: {}", e))?;

    // Zeroize sensitive data
    key_bytes.zeroize();
    serialized_data.zeroize();

    Ok(())
}

/// Load and decrypt wallet data securely with password verification
/// Implements rate limiting and security monitoring per best practices
pub fn load_wallet_data_securely(password: &str) -> Result<SecureWalletData, String> {
    // Load and validate wallet configuration
    let mut cfg: WalletConfig =
        confy::load(APP_NAME).map_err(|e| format!("Failed to load wallet config: {}", e))?;

    // Check if wallet is locked due to failed attempts
    if cfg.is_locked {
        return Err("Wallet is locked due to too many failed attempts".to_string());
    }

    // Rate limiting: if too many failed attempts, lock the wallet
    if cfg.failed_attempts >= 5 {
        cfg.is_locked = true;
        let _ = confy::store(APP_NAME, &cfg); // Best effort save
        return Err("Too many failed attempts. Wallet locked for security.".to_string());
    }

    // Load encrypted data from keyring
    let entry = Entry::new(APP_NAME, WALLET_KEY)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;
    let encoded_data = entry
        .get_password()
        .map_err(|e| format!("Failed to retrieve encrypted wallet data: {}", e))?;

    // Decode and deserialize encrypted wallet data
    let encrypted_serialized = Base64Engine
        .decode(&encoded_data)
        .map_err(|e| format!("Failed to decode wallet data: {}", e))?;
    let encrypted_wallet: EncryptedWalletData = bincode::deserialize(&encrypted_serialized)
        .map_err(|e| format!("Failed to deserialize encrypted wallet: {}", e))?;

    // Verify password using stored hash
    let parsed_hash = PasswordHash::new(&encrypted_wallet.password_hash)
        .map_err(|e| format!("Failed to parse password hash: {}", e))?;

    let argon2 = Argon2::default();
    if argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_err()
    {
        // Increment failed attempts
        cfg.failed_attempts += 1;
        let _ = confy::store(APP_NAME, &cfg); // Best effort save
        return Err("Invalid password".to_string());
    }

    // Derive decryption key
    let mut key_bytes = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| format!("Failed to create Argon2 params: {}", e))?,
    )
    .hash_password_into(password.as_bytes(), &encrypted_wallet.salt, &mut key_bytes)
    .map_err(|e| format!("Failed to derive decryption key: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Verify data integrity
    let calculated_checksum = blake3::hash(&encrypted_wallet.encrypted_data)
        .as_bytes()
        .to_vec();
    if calculated_checksum != encrypted_wallet.checksum {
        key_bytes.zeroize();
        return Err("Data integrity check failed. Wallet data may be corrupted.".to_string());
    }

    // Decrypt wallet data
    let nonce_array = GenericArray::from_slice(&encrypted_wallet.nonce);
    let mut decrypted_data = cipher
        .decrypt(nonce_array, encrypted_wallet.encrypted_data.as_ref())
        .map_err(|e| {
            key_bytes.zeroize();
            format!("Failed to decrypt wallet data: {}", e)
        })?;

    // Deserialize wallet data
    let wallet_data = SecureWalletData::deserialize(&decrypted_data)?;

    // Update configuration on successful access
    cfg.last_accessed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    cfg.failed_attempts = 0; // Reset failed attempts on successful access
    let _ = confy::store(APP_NAME, &cfg); // Best effort save

    // Zeroize sensitive data
    key_bytes.zeroize();
    decrypted_data.zeroize();

    Ok(wallet_data)
}

/// Legacy function for backward compatibility - uses new secure implementation
pub fn save_wallet_data_securely_legacy(data: &[u8]) -> Result<(), String> {
    let wallet_data = SecureWalletData::new(data.to_vec());
    save_wallet_data_securely(&wallet_data, "default_password", None)
}

/// Legacy function for backward compatibility - uses new secure implementation  
pub fn load_wallet_data_securely_legacy() -> Result<Vec<u8>, String> {
    let wallet_data = load_wallet_data_securely("default_password")?;
    Ok(wallet_data.seed.clone())
}

/// Create a secure backup of wallet data
pub fn create_wallet_backup(
    wallet_data: &SecureWalletData,
    backup_password: &str,
    backup_path: &str,
) -> Result<String, String> {
    // Generate backup verification hash
    let backup_hash = blake3::hash(&wallet_data.seed).to_hex().to_string();

    // Encrypt backup with different password
    let mut backup_serialized = wallet_data.serialize()?;
    let mut backup_salt = vec![0u8; SALT_SIZE];
    let mut backup_nonce = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut backup_salt);
    OsRng.fill_bytes(&mut backup_nonce);

    // Use stronger parameters for backup encryption
    let mut backup_key = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(131072, 4, 2, Some(32)) // Stronger params for backup
            .map_err(|e| format!("Failed to create backup Argon2 params: {}", e))?,
    )
    .hash_password_into(backup_password.as_bytes(), &backup_salt, &mut backup_key)
    .map_err(|e| format!("Failed to derive backup key: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&backup_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_array = GenericArray::from_slice(&backup_nonce);

    let encrypted_backup = cipher
        .encrypt(nonce_array, backup_serialized.as_ref())
        .map_err(|e| format!("Failed to encrypt backup: {}", e))?;

    // Create backup structure
    let backup_data = EncryptedWalletData {
        salt: backup_salt,
        nonce: backup_nonce,
        encrypted_data: encrypted_backup.clone(),
        password_hash: String::new(), // Not needed for backup
        checksum: blake3::hash(&encrypted_backup).as_bytes().to_vec(),
    };

    // Write backup to file
    let backup_json = serde_json::to_string_pretty(&backup_data)
        .map_err(|e| format!("Failed to serialize backup: {}", e))?;

    std::fs::write(backup_path, backup_json)
        .map_err(|e| format!("Failed to write backup file: {}", e))?;

    // Zeroize sensitive data
    backup_key.zeroize();
    backup_serialized.zeroize();

    Ok(backup_hash)
}

/// Verify wallet backup integrity
pub fn verify_wallet_backup(backup_path: &str, backup_password: &str) -> Result<bool, String> {
    let backup_json = std::fs::read_to_string(backup_path)
        .map_err(|e| format!("Failed to read backup file: {}", e))?;

    let backup_data: EncryptedWalletData = serde_json::from_str(&backup_json)
        .map_err(|e| format!("Failed to parse backup file: {}", e))?;

    // Verify checksum
    let calculated_checksum = blake3::hash(&backup_data.encrypted_data)
        .as_bytes()
        .to_vec();
    if calculated_checksum != backup_data.checksum {
        return Ok(false);
    }

    // Try to decrypt (without storing the result)
    let mut backup_key = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(131072, 4, 2, Some(32))
            .map_err(|e| format!("Failed to create backup Argon2 params: {}", e))?,
    )
    .hash_password_into(
        backup_password.as_bytes(),
        &backup_data.salt,
        &mut backup_key,
    )
    .map_err(|e| format!("Failed to derive backup key: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&backup_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_array = GenericArray::from_slice(&backup_data.nonce);

    let result = cipher
        .decrypt(nonce_array, backup_data.encrypted_data.as_ref())
        .is_ok();

    // Zeroize sensitive data
    backup_key.zeroize();

    Ok(result)
}
