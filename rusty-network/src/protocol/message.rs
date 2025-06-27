//! Network message types and serialization

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::protocol::{Inventory, InventoryType, Network, NetworkAddress};

/// Maximum size of a message in bytes (32MB)
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Network message header (24 bytes)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Network magic value
    pub magic: [u8; 4],
    /// Command name (null-padded)
    pub command: [u8; 12],
    /// Payload length (little-endian)
    pub length: u32,
    /// Checksum (first 4 bytes of sha256(sha256(payload)))
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Create a new message header
    pub fn new(network: Network, command: &str, payload: &[u8]) -> Result<Self, NetworkError> {
        if command.len() > 12 {
            return Err(NetworkError::Protocol("Command name too long".to_string()));
        }

        let mut command_bytes = [0u8; 12];
        command_bytes[..command.len()].copy_from_slice(command.as_bytes());

        let checksum = Self::checksum(payload);

        Ok(Self {
            magic: network.magic(),
            command: command_bytes,
            length: payload.len() as u32,
            checksum,
        })
    }

    /// Calculate the checksum of a payload
    pub fn checksum(payload: &[u8]) -> [u8; 4] {
        use blake3::hash;
        let hash = hash(payload);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash.as_bytes()[..4]);
        checksum
    }

    /// Get the command as a string
    pub fn command_str(&self) -> Result<&str, NetworkError> {
        let end = self
            .command
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.command.len());
        std::str::from_utf8(&self.command[..end])
            .map_err(|e| NetworkError::InvalidMessage(format!("Invalid command: {}", e)))
    }

    /// Verify the checksum of a payload
    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        self.checksum == Self::checksum(payload)
    }
}

/// Network message types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// Version message (sent when a connection is established)
    Version(VersionMessage),
    /// Version acknowledgment (sent in response to version)
    Verack,
    /// Address message (contains network addresses)
    Addr(Vec<NetworkAddress>),
    /// Inventory message (contains hashes of objects available)
    Inv(Vec<Inventory>),
    /// Request for specific inventory
    GetData(Vec<Inventory>),
    /// Request for block headers
    GetHeaders(GetHeadersMessage),
    /// Block headers message
    Headers(Vec<BlockHeader>),
    /// Block message (contains a block)
    Block(Block),
    /// Transaction message (contains a transaction)
    Tx(Transaction),
    /// Reject message (indicates a rejected message)
    Reject(RejectMessage),
    /// Ping message (used to check if a connection is alive)
    Ping(u64),
    /// Pong message (response to ping)
    Pong(u64),
    /// Alert message (deprecated, but included for compatibility)
    Alert(Vec<u8>),
    /// Send compact blocks message
    SendCmpct(SendCmpctMessage),
    /// Compact block message
    CmpctBlock(CmpctBlock),
}

impl Message {
    /// Get the command string for this message type
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::Addr(_) => "addr",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::GetHeaders(_) => "getheaders",
            Message::Headers(_) => "headers",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::Reject(_) => "reject",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::Alert(_) => "alert",
            Message::SendCmpct(_) => "sendcmpct",
            Message::CmpctBlock(_) => "cmpctblock",
        }
    }
}

/// Version message (sent when a connection is established)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionMessage {
    /// Protocol version
    pub version: i32,
    /// Services supported by this node
    pub services: u64,
    /// Timestamp of this message
    pub timestamp: i64,
    /// Address of the remote node
    pub receiver_addr: NetworkAddress,
    /// Address of the local node
    pub sender_addr: NetworkAddress,
    /// Random nonce to detect connections to self
    pub nonce: u64,
    /// User agent string
    pub user_agent: String,
    /// Height of the blockchain
    pub start_height: i32,
    /// Whether to relay transactions
    pub relay: bool,
}

/// GetHeaders message (requests block headers)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetHeadersMessage {
    /// Protocol version
    pub version: u32,
    /// Block locator hashes
    pub hashes: Vec<[u8; 32]>,
    /// Hash of the last desired block
    pub hash_stop: [u8; 32],
}

/// Reject message (indicates a rejected message)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectMessage {
    /// Message that was rejected
    pub message: String,
    /// Rejection code
    pub code: RejectCode,
    /// Reason for rejection
    pub reason: String,
    /// Additional data (e.g., block hash)
    pub data: Vec<u8>,
}

/// Reject code
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RejectCode {
    /// Malformed message
    Malformed = 0x01,
    /// Invalid message
    Invalid = 0x10,
    /// Obsolete message
    Obsolete = 0x11,
    /// Duplicate message
    Duplicate = 0x12,
    /// Non-standard transaction
    NonStandard = 0x40,
    /// Transaction fee too low
    Dust = 0x41,
    /// Requested data not found
    NotFound = 0x44,
}

/// SendCmpct message (enables compact block relay)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SendCmpctMessage {
    /// Whether to enable compact block relay
    pub enable: bool,
    /// Protocol version
    pub version: u64,
}

/// Compact block message (efficient block relay)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CmpctBlock {
    // Implementation depends on your compact block structure
    // Add fields as needed
    pub header: BlockHeader,
    // ... other fields
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_header() {
        let payload = b"test payload";
        let header = MessageHeader::new(Network::Mainnet, "test", payload).unwrap();
        
        assert_eq!(header.magic, Network::Mainnet.magic());
        assert_eq!(header.command[0..4], *b"test");
        assert_eq!(header.length as usize, payload.len());
        assert!(header.verify_checksum(payload));
    }
    
    #[test]
    fn test_version_message() {
        let receiver_addr = NetworkAddress::new(1, "127.0.0.1".to_string(), 8333);
        let sender_addr = NetworkAddress::new(1, "127.0.0.1".to_string(), 8333);
        let version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            receiver_addr,
            sender_addr,
            nonce: 12345,
            user_agent: "/rusty-coin:0.1.0/".to_string(),
            start_height: 0,
            relay: true,
        };
        
        let message = Message::Version(version);
        assert_eq!(message.command(), "version");
    }
}
