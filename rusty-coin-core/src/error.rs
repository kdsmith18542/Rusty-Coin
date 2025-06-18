//! Error types for Rusty Coin

pub mod prelude {
    pub use super::ConsensusError;
}

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

    /// Transaction related error
    #[error("Transaction error: {0}")]
    TxError(String),

    /// Block validation failed
    #[error("Block validation failed: {0}")]
    BlockValidation(String),


    /// Transaction validation failed
    #[error("Transaction validation failed: {0}")]
    TxValidation(String),


    /// Consensus error
    #[error("Consensus error: {0}")]
    ConsensusError(ConsensusError),


    /// Input/output error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Consensus-specific error type
#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Block validation failed: {0}")]
    BlockValidation(String),
    
    #[error("Invalid consensus proof: {0}")]
    InvalidProof(String),
    
    #[error("Staking validation failed: {0}")]
    StakingError(String),
    
    #[error("Difficulty adjustment error: {0}")]
    DifficultyError(String),

    #[error("Transaction validation failed: {0}")]
    TxValidation(String),

    #[error("Duplicate transaction in block: {0}")]
    DuplicateTransactionInBlock(crate::crypto::Hash),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Staking ticket expired")]
    TicketExpired,

    #[error("Insufficient stake amount")]
    InsufficientStake,

    #[error("Duplicate staking ticket")]
    DuplicateTicket,

    #[error("Insufficient eligible tickets for quorum selection")]
    InsufficientEligibleTickets,

    #[error("Invalid quorum size")]
    InvalidQuorumSize,

    #[error("Invalid ticket hash")]
    InvalidTicketHash,

    #[error("Ticket did not approve block")]
    TicketDidntApproveBlock,

    #[error("Failed to verify ticket signature")]
    FailedToVerifyTicketSignature,

    #[error("Insufficient stake amount")]
    InsufficientStakeAmount,

    #[error("Duplicate ticket in quorum")]
    DuplicateTicketInQuorum,
}

/// A specialized `Result` type for Rusty Coin operations.
pub type Result<T> = std::result::Result<T, Error>;

impl From<ConsensusError> for Error {
    fn from(err: ConsensusError) -> Self {
        Error::ConsensusError(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}
