use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Block size too large: {0} bytes, max allowed: {1} bytes")]
    BlockTooLarge(usize, usize),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Invalid proof of work")]
    InvalidProofOfWork,

    #[error("Empty block")]
    EmptyBlock,

    #[error("Transaction is locked by locktime")]
    TransactionLocked,

    #[error("Transaction locktime not met")]
    TransactionLocktimeNotMet,

    #[error("Invalid sequence number")]
    InvalidSequence,

    #[error("Negative fee")]
    NegativeFee,

    #[error("Dust output: {0} satoshis")]
    DustOutput(u64),

    #[error("Invalid script: {0}")]
    InvalidScript(String),

    #[error("Masternode error: {0}")]
    MasternodeError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    // PoS Ticket Validation Errors
    #[error("No ticket votes found")]
    NoTicketVotes,

    #[error("Duplicate ticket vote")]
    DuplicateTicketVote,

    #[error("Invalid ticket ID")]
    InvalidTicketID,

    #[error("Invalid ticket status")]
    InvalidTicketStatus,

    #[error("Expired ticket")]
    ExpiredTicket,

    #[error("Invalid vote type")]
    InvalidVoteType,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Insufficient ticket votes")]
    InsufficientTicketVotes,

    #[error("Invalid block hash")]
    InvalidBlockHash,

    #[error("Governance error: {0}")]
    GovernanceError(String),

    #[error("Invalid ticket vote")]
    InvalidTicketVote,

    #[error("UTXO set inconsistent: {0} inconsistencies found")]
    UtxoSetInconsistent(usize),

    // --- Added missing variants below ---
    #[error("Empty transaction")]
    EmptyTransaction,

    #[error("Coinbase transaction has inputs")]
    CoinbaseHasInputs,

    #[error("Non-coinbase transaction has no inputs")]
    NonCoinbaseHasNoInputs,

    #[error("Duplicate input")]
    DuplicateInput,

    #[error("Missing transaction input")]
    MissingTxInput,

    #[error("Coinbase input not mature")]
    CoinbaseNotMature,

    #[error("Invalid script signature")]
    InvalidScriptSig,

    #[error("Invalid transaction type: {0}")]
    InvalidTransactionType(String),

    #[error("Invalid masternode deregistration: {0}")]
    InvalidMasternodeDeregistration(String),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Invalid previous block hash")]
    InvalidPreviousBlockHash,

    #[error("Invalid Merkle root")]
    InvalidMerkleRoot,

    #[error("Timestamp too far in future")]
    TimestampTooFarInFuture,

    #[error("Timestamp too old")]
    TimestampTooOld,

    #[error("Missing previous block")]
    MissingPreviousBlock,

    #[error("Masternode not found")]
    MasternodeNotFound,

    #[error("Masternode is inactive")]
    MasternodeInactive,

    #[error("Invalid proof of service")]
    InvalidProofOfService,

    #[error("Duplicate transaction")]
    DuplicateTransaction,

    #[error("No outputs in transaction")]
    NoOutputs,

    #[error("Output value is zero at index {0}")]
    OutputValueZero(usize),

    #[error("Invalid coinbase transaction: {0}")]
    InvalidCoinbase(String),

    #[error("Spending more than inputs")]
    SpendingMoreThanInputs,

    #[error("Invalid lock time: {0}")]
    InvalidLockTime(String),

    #[error("Transaction too large: {0} bytes, max allowed: {1} bytes")]
    TransactionTooLarge(usize, usize),

    #[error("Insufficient fee: {0} satoshis, minimum required: {1} satoshis")]
    InsufficientFee(u64, u64),

    #[error("Merkle root mismatch: expected {expected:?}, found {found:?}")]
    MerkleRootMismatch { expected: [u8; 32], found: [u8; 32] },

    #[error("No coinbase transaction in block")]
    NoCoinbaseTransaction,

    #[error("Invalid coinbase input")]
    InvalidCoinbaseInput,

    #[error("Invalid slashing transaction: {0}")]
    InvalidSlashingTransaction(String),

    #[error("Invalid state root: expected {expected:?}, found {found:?}")]
    InvalidStateRoot { expected: [u8; 32], found: [u8; 32] },
}

impl From<rocksdb::Error> for ConsensusError {
    fn from(e: rocksdb::Error) -> Self {
        ConsensusError::DatabaseError(e.to_string())
    }
}

impl From<Box<bincode::ErrorKind>> for ConsensusError {
    fn from(e: Box<bincode::ErrorKind>) -> Self {
        ConsensusError::SerializationError(e.to_string())
    }
}
