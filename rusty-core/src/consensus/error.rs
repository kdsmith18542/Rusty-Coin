// rusty-core/src/consensus/error.rs

use hex;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum ConsensusError {
    #[error("Block validation failed: {0}")]
    BlockValidation(String),
    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),
    #[error("UTXO set error: {0}")]
    UtxoSetError(String),
    #[error("State error: {0}")]
    StateError(String),
    #[error("Proof of Work verification failed: {0}")]
    ProofOfWorkError(String),
    #[error("Script verification failed: {0}")]
    ScriptError(String),
    #[error("Coinbase transaction error: {0}")]
    CoinbaseError(String),
    #[error("Masternode error: {0}")]
    MasternodeError(String),
    #[error("Coinbase UTXO not mature: {0}")]
    CoinbaseMaturity(String),
    #[error("Output value below dust limit: {0}")]
    DustLimit(String),
    #[error("Negative fee: {0}")]
    NegativeFee(String),
    #[error("Merkle Patricia Trie error: {0}")]
    TrieError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Missing previous output: {}", format_outpoint(.0))]
    MissingPreviousOutput(rusty_shared_types::OutPoint),
    #[error("Empty block")]
    EmptyBlock,
    #[error("Threshold signature error: {0}")]
    ThresholdSignatureError(String),
    #[error("DKG error: {0}")]
    DKGError(String),
    #[error("Other consensus error: {0}")]
    Other(String),

    // Additional error variants needed by the codebase
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("State root not found for block height: {0}")]
    StateRootNotFound(u64),
    #[error("Invalid proof of work")]
    InvalidProofOfWork,
    
    // Governance errors
    #[error("Proposal with ID {} already exists", format_hash(.0))]
    ProposalAlreadyExists(rusty_shared_types::Hash),
    #[error("Proposal with ID {} not found", format_hash(.0))]
    ProposalNotFound(rusty_shared_types::Hash),
    #[error("Vote not found for proposal {} and voter {}", format_hash(.0), format_hash(.1))]
    VoteNotFound(rusty_shared_types::Hash, rusty_shared_types::Hash),
    #[error("Rule violation: {0}")]
    RuleViolation(String),
    #[error("Invalid script: {0}")]
    InvalidScript(String),
    #[error("Invalid coinbase: {0}")]
    InvalidCoinbase(String),
    #[error("Insufficient fee: got {0}, expected at least {1}")]
    InsufficientFee(u64, u64),
    #[error("Invalid lock time: {0}")]
    InvalidLockTime(String),
    #[error("Invalid ticket: {0}")]
    InvalidTicket(String),
    #[error("Duplicate ticket vote: {0}")]
    DuplicateTicketVote(String),
    #[error("Immature ticket: {0}")]
    ImmatureTicket(String),
    #[error("Expired ticket: {0}")]
    ExpiredTicket(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Failed to find historical UTXO: {}", format_outpoint(.0))]
    FailedToFindHistoricalUTXO(rusty_shared_types::OutPoint),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid ticket vote: {0}")]
    InvalidTicketVote(String),
    #[error("Invalid PoSe response: {0}")]
    InvalidPoSeResponse(String),
    #[error("PoSe challenge expired: {0}")]
    PoSeChallengeExpired(String),
}

// Implement conversions from other error types
impl From<Box<bincode::ErrorKind>> for ConsensusError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        ConsensusError::SerializationError(err.to_string())
    }
}

impl From<String> for ConsensusError {
    fn from(err: String) -> Self {
        ConsensusError::Internal(err)
    }
}

// Format Hash for error messages
fn format_hash(hash: &rusty_shared_types::Hash) -> String {
    format!("0x{}", hex::encode(hash))
}

// Format OutPoint for error messages
fn format_outpoint(outpoint: &rusty_shared_types::OutPoint) -> String {
    format!("{}:{}", hex::encode(outpoint.txid), outpoint.vout)
}