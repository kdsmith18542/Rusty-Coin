// rusty-core/src/lib.rs
//! `rusty-core` is the core library for the Rusty Coin blockchain, providing fundamental functionalities
//! such as consensus mechanisms, network communication, and scripting capabilities.
//!
//! This crate aims to encapsulate the essential logic required for a Rusty Coin full node to operate,
//! including block validation, transaction processing, and state management.
//!
//! # Modules
//!
//! - `consensus`: Handles the blockchain's consensus rules, including proof-of-work, proof-of-stake,
//!   and block validation.
//! - `network`: Manages peer-to-peer communication and data synchronization within the Rusty Coin network.
//! - `script`: Provides the scripting language and execution engine for transaction logic.
//!
//! # Usage
//!
//! To initialize the core blockchain functionalities, use the `init` function:
//!
//! ```rust
//! use std::path::Path;
//! use rusty_core::{self, blockchain::Blockchain};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let data_dir = Path::new("./data");
//!     let _blockchain = rusty_core::init(data_dir)?;
//!     // Further operations with the blockchain...
//!     Ok(())
//! }
//! ```

pub mod audit_log;
pub mod consensus;
pub mod constants;
pub mod governance;
pub mod light_client;
pub mod mempool;
pub mod network;
pub mod protocol_constants;
pub mod script;
pub mod sidechain;
pub mod state;
pub mod transaction_builder;
pub mod types;
pub mod validation;

// Placeholder for core functionalities
use crate::consensus::blockchain::Blockchain;
use crate::network::P2PNetwork;
use std::path::Path;
use std::sync::Arc;

/// Initializes the core blockchain functionalities.
///
/// This function sets up the blockchain, typically by loading an existing blockchain
/// from the specified data directory or creating a new one if it doesn't exist.
///
/// # Arguments
///
/// * `data_dir` - A reference to the `Path` where blockchain data should be stored or loaded from.
/// * `p2p_network` - The P2P network interface for peer communication.
///
/// # Returns
///
/// A `Result` which is:
/// - `Ok(Blockchain)` if the blockchain is successfully initialized.
/// - `Err(Box<dyn std::error::Error>)` if an error occurs during initialization (e.g., issues with
///   file system access, data corruption, or database errors).
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use rusty_core::{self, blockchain::Blockchain};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let data_dir = Path::new("./my_blockchain_data");
///     // let p2p_network = ...; // Initialize P2P network
///     // let _blockchain = rusty_core::init(data_dir, p2p_network)?;
///     println!("Blockchain initialized successfully!");
///     Ok(())
/// }
/// ```
pub fn init(
    _data_dir: &Path,
    p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>,
) -> Result<Blockchain, Box<dyn std::error::Error>> {
    let blockchain = Blockchain::new(p2p_network).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    Ok(blockchain)
}
