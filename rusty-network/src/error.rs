//! Error types for the Rusty Network module.

use std::{io, net::AddrParseError, string::FromUtf8Error};
use thiserror::Error;

/// Main error type for the network module
#[derive(Error, Debug)]
pub enum NetworkError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    /// Error parsing network address
    #[error("Failed to parse network address: {0}")]
    AddrParse(#[from] AddrParseError),
    
    /// UTF-8 conversion error
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] FromUtf8Error),
    
    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    /// Protocol violation
    #[error("Protocol violation: {0}")]
    Protocol(String),
    
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
    
    /// Peer disconnected
    #[error("Peer disconnected: {0}")]
    Disconnected(String),
    
    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,
    
    /// Peer rejected the connection
    #[error("Connection rejected: {0}")]
    ConnectionRejected(String),
    
    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    /// Invalid network magic value
    #[error("Invalid network magic: expected {expected:?}, got {actual:?}")]
    InvalidMagic { expected: [u8; 4], actual: [u8; 4] },
    
    /// Message too large
    #[error("Message too large: {size} bytes (max: {max} bytes)")]
    MessageTooLarge { size: usize, max: usize },
    
    /// Peer sent too many messages too quickly
    #[error("Peer is sending messages too quickly")]
    RateLimitExceeded,
    
    /// Peer is misbehaving
    #[error("Peer misbehaving: {0}")]
    MisbehavingPeer(String),
}

impl From<bincode::Error> for NetworkError {
    fn from(err: bincode::Error) -> Self {
        NetworkError::Serialization(err.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for NetworkError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        match err {
            tokio_tungstenite::tungstenite::Error::Io(io_err) => NetworkError::Io(io_err),
            _ => NetworkError::Protocol(err.to_string()),
        }
    }
}

/// A specialized `Result` type for network operations
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;
