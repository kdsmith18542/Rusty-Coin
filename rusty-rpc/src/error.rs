use jsonrpsee::core::Error as RpcError;
use rusty_core::error::ConsensusError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcServerError {
    #[error("Internal server error: {0}")]
    InternalError(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Blockchain error: {0}")]
    BlockchainError(#[from] ConsensusError),
    #[error("Not implemented")]
    NotImplemented,
}

impl From<RpcServerError> for RpcError {
    fn from(err: RpcServerError) -> Self {
        RpcError::Call(jsonrpsee::types::error::CallError::Custom(
            jsonrpsee::types::error::ErrorObject::owned(
                match err {
                    RpcServerError::InternalError(_) => -32000,
                    RpcServerError::InvalidRequest(_) => -32600,
                    RpcServerError::BlockchainError(_) => -32001,
                    RpcServerError::NotImplemented => -32601,
                },
                err.to_string(),
                None::<()>,
            ),
        ))
    }
} 