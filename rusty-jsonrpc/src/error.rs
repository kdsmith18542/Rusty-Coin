use jsonrpc_core::Error as JsonRpcError;
use jsonrpc_core::ErrorCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Block not found")]
    BlockNotFound,
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Method not implemented")]
    MethodNotImplemented,
}

impl From<RpcError> for JsonRpcError {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::BlockNotFound => JsonRpcError::new(ErrorCode::ServerError(1000)),
            RpcError::TransactionNotFound => JsonRpcError::new(ErrorCode::ServerError(1001)),
            RpcError::InvalidParameter(msg) => JsonRpcError::invalid_params(msg),
            RpcError::Validation(msg) => JsonRpcError::new(ErrorCode::ServerError(1002)).add_data(json!({ "details": msg })),
            RpcError::Internal(msg) => JsonRpcError::internal_error().add_data(json!({ "details": msg })),
            RpcError::MethodNotImplemented => JsonRpcError::method_not_found(),
        }
    }
}

impl From<bincode::Error> for RpcError {
    fn from(err: bincode::Error) -> Self {
        RpcError::InvalidParameter(format!("Bincode deserialization error: {}", err))
    }
}

impl From<hex::FromHexError> for RpcError {
    fn from(err: hex::FromHexError) -> Self {
        RpcError::InvalidParameter(format!("Hex decoding error: {}", err))
    }
}

impl From<rusty_core::BlockchainError> for RpcError {
    fn from(err: rusty_core::BlockchainError) -> Self {
        match err {
            rusty_core::BlockchainError::BlockNotFound => RpcError::BlockNotFound,
            rusty_core::BlockchainError::TransactionNotFound => RpcError::TransactionNotFound,
            rusty_core::BlockchainError::ValidationError(msg) => RpcError::Validation(msg),
            _ => RpcError::Internal(format!("Blockchain error: {}", err)),
        }
    }
}