//! Rusty Coin P2P Network Implementation
//! 
//! This crate provides the peer-to-peer networking functionality for the Rusty Coin
//! blockchain, including block and transaction propagation, peer discovery, and more.

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]
// #![feature(trivial_bounds)]

/// Network module for Rusty Coin P2P
pub mod network;
/// Protocols module for Rusty Coin P2P
pub mod protocols;
/// Types used in Rusty Coin P2P
pub mod types;
/// Main P2P network implementation
pub mod p2p_network;
/// Behaviour and event types for Rusty Coin P2P
pub mod behaviour;

// Re-export commonly used types

/// Multiaddr and PeerId types from libp2p
pub use libp2p::{Multiaddr, PeerId};
/// P2P network, error, and result types
pub use p2p_network::{P2PNetwork, P2PError, P2PResult};
/// Protocol constants for block sync and transaction propagation
pub use protocols::{BLOCK_SYNC_PROTOCOL, TX_PROPAGATION_PROTOCOL};
/// Block sync codec
pub use protocols::block_sync::BlockSyncCodec;
/// Transaction propagation codec
pub use protocols::tx_prop::TxPropCodec;
/// Network configuration for Rusty Coin P2P
pub use crate::behaviour::RustyCoinNetworkConfig;
/// Network events for Rusty Coin P2P
pub use crate::behaviour::RustyCoinEvent;
/// Combined network behaviour for Rusty Coin P2P
pub use crate::behaviour::CombinedBehaviour as RustyCoinBehaviour;

// Suppress unused crate dependency warnings for required crates
#[allow(unused_imports)]
use async_std as _;
#[allow(unused_imports)]
use async_trait as _;
#[allow(unused_imports)]
use bytes as _;
#[allow(unused_imports)]
use env_logger as _;
#[allow(unused_imports)]
use lazy_static as _;
#[allow(unused_imports)]
use rand as _;
#[allow(unused_imports)]
use rand_chacha as _;
#[allow(unused_imports)]
use rusty_core as _;
#[allow(unused_imports)]
use serde_json as _;
#[allow(unused_imports)]
use tracing as _;
#[allow(unused_imports)]
use tracing_subscriber as _;