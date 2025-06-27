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
}
