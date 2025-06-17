//! Error types for the Rusty Coin implementation.

use thiserror::Error;

/// Main error type for the Rusty Coin crate.
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid data format or value
    #[error("Invalid data: {0}")]
    InvalidData(String),


    /// Block validation failed
    #[error("Block validation failed: {0}")]
    BlockValidation(String),


    /// Transaction validation failed
    #[error("Transaction validation failed: {0}")]
    TxValidation(String),


    /// Consensus error
    #[error("Consensus error: {0}")]
    ConsensusError(String),


    /// Input/output error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// A specialized `Result` type for Rusty Coin operations.
pub type Result<T> = std::result::Result<T, Error>;

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}
