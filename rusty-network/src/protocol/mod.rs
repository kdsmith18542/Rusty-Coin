//! Network protocol implementation for Rusty Coin

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

pub mod message;
pub mod types;

/// Network magic value for mainnet
pub const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Network magic value for testnet
pub const TESTNET_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

/// Network magic value for regtest
pub const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Hash, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    /// Get the magic bytes for this network
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => MAINNET_MAGIC,
            Network::Testnet => TESTNET_MAGIC,
            Network::Regtest => REGTEST_MAGIC,
        }
    }
    
    /// Get the default port for this network
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet => 18333,
            Network::Regtest => 18444,
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Network::Mainnet
    }
}

/// Network address
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAddress {
    /// Services supported by this node
    pub services: u64,
    /// Network address (IPv4 or IPv6)
    pub address: SocketAddr,
}

impl Default for NetworkAddress {
    fn default() -> Self {
        Self {
            services: 0,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

impl NetworkAddress {
    /// Create a new network address
    pub fn new(services: u64, ip: String, port: u16) -> Self {
        let address = format!("{}:{}", ip, port).parse().unwrap_or_else(|_| {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        });
        Self { services, address }
    }
    
    /// Check if the address is valid
    pub fn is_valid(&self) -> bool {
        !matches!(self.address.ip(), IpAddr::V4(ip) if ip.is_unspecified() || ip.is_broadcast())
    }
}

/// Inventory type
#[derive(Debug, Clone, Copy, PartialEq, Hash, Serialize, Deserialize)]
pub enum InventoryType {
    Error = 0,
    MsgTx = 1,
    MsgBlock = 2,
    MsgFilteredBlock = 3,
    MsgCmpctBlock = 4,
}

impl TryFrom<u32> for InventoryType {
    type Error = NetworkError;
    
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(InventoryType::Error),
            1 => Ok(InventoryType::MsgTx),
            2 => Ok(InventoryType::MsgBlock),
            3 => Ok(InventoryType::MsgFilteredBlock),
            4 => Ok(InventoryType::MsgCmpctBlock),
            _ => Err(NetworkError::Protocol(format!("Invalid inventory type: {}", value))),
        }
    }
}

/// Inventory vector
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    /// The type of inventory
    pub inv_type: InventoryType,
    /// The hash of the inventory item
    pub hash: [u8; 32],
}

impl Inventory {
    /// Create a new inventory item
    pub fn new(inv_type: InventoryType, hash: [u8; 32]) -> Self {
        Self { inv_type, hash }
    }
    
    /// Create a new transaction inventory item
    pub fn new_tx(hash: [u8; 32]) -> Self {
        Self::new(InventoryType::MsgTx, hash)
    }
    
    /// Create a new block inventory item
    pub fn new_block(hash: [u8; 32]) -> Self {
        Self::new(InventoryType::MsgBlock, hash)
    }
}

/// Current timestamp in seconds since epoch
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_magic() {
        assert_eq!(Network::Mainnet.magic(), MAINNET_MAGIC);
        assert_eq!(Network::Testnet.magic(), TESTNET_MAGIC);
        assert_eq!(Network::Regtest.magic(), REGTEST_MAGIC);
    }
    
    #[test]
    fn test_network_address() {
        let ip = "127.0.0.1".to_string();
        let port = 8333;
        let net_addr = NetworkAddress::new(1, ip.clone(), port);
        
        assert_eq!(net_addr.services, 1);
        assert_eq!(net_addr.address, format!("{}:{}", ip, port).parse().unwrap());
        assert!(net_addr.is_valid());
    }
    
    #[test]
    fn test_inventory() {
        let hash = [0u8; 32];
        let inv = Inventory::new_tx(hash);
        
        assert_eq!(inv.inv_type, InventoryType::MsgTx);
        assert_eq!(inv.hash, hash);
    }
}
