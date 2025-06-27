//! `rusty-wallet/src/storage.rs` provides secure storage functionalities for wallet data.

use confy;
use keyring::Entry;
use serde::{Serialize, Deserialize};

const APP_NAME: &str = "rusty-coin-wallet";
const WALLET_KEY: &str = "master_seed";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct WalletConfig {
    // For now, we'll store a placeholder. In a real app, this might be paths to encrypted files
    // or other configuration data, with the sensitive master seed in the OS keyring.
    pub wallet_id: String,
}

pub fn save_wallet_data_securely(data: &[u8]) -> Result<(), String> {
    // Save non-sensitive configuration using confy
    let cfg = WalletConfig { wallet_id: "default".to_string() };
    confy::store(APP_NAME, None, cfg)
        .map_err(|e| format!("Failed to save wallet config: {}", e))?;

    // Save sensitive master seed using keyring
    let entry = Entry::new(APP_NAME, WALLET_KEY)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;
    entry.set_password(base64::encode(data).as_str())
        .map_err(|e| format!("Failed to set keyring password: {}", e))?;

    Ok(())
}

pub fn load_wallet_data_securely() -> Result<Vec<u8>, String> {
    // Load non-sensitive configuration using confy
    let cfg: WalletConfig = confy::load(APP_NAME, None)
        .map_err(|e| format!("Failed to load wallet config: {}", e))?;

    // Load sensitive master seed using keyring
    let entry = Entry::new(APP_NAME, WALLET_KEY)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;
    let password = entry.get_password()
        .map_err(|e| format!("Failed to get keyring password: {}", e))?;

    base64::decode(password)
        .map_err(|e| format!("Failed to decode wallet data from base64: {}", e))
}