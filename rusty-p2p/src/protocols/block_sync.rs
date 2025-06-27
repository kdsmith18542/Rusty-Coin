//! Block Synchronization Protocol Implementation
//! 
//! Implements the `/rusty/block-sync/1.0` protocol for efficient block retrieval
//! during Initial Block Download (IBD) and when catching up to the chain tip.

use bytes::Bytes;
use libp2p::request_response::{RequestResponseCodec, RequestResponseMessage};
use serde::{Deserialize, Serialize};
use std::io;
use std::marker::PhantomData;
use thiserror::Error;

/// Maximum number of blocks to include in a single BlockResponse message
const MAX_BLOCKS_PER_RESPONSE: usize = 500;

/// Block synchronization protocol request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSyncRequest {
    /// Request a range of blocks by height
    BlockRange { 
        /// Starting block height (inclusive)
        start_height: u64, 
        /// Ending block height (inclusive, must be <= start_height + MAX_BLOCKS_PER_RESPONSE)
        end_height: u64 
    },
    
    /// Request block headers for efficient chain synchronization
    GetHeaders { 
        /// Locator hashes (in reverse order from chain tip)
        locator_hashes: Vec<[u8; 32]>, 
        /// Stop at this block hash (or all headers if None)
        stop_hash: Option<[u8; 32]>,
    },
}

/// Block synchronization protocol response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSyncResponse {
    /// Response containing a range of blocks
    BlockRange(Vec<BlockData>),
    
    /// Response containing block headers
    Headers(Vec<BlockHeaderData>),
    
    /// Error response with a message
    Error(String),
}

/// Serialized block data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    /// Block height
    pub height: u64,
    /// Serialized block data
    pub data: Vec<u8>,
    /// Block hash (for verification)
    pub hash: [u8; 32],
}

/// Serialized block header data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderData {
    /// Block height
    pub height: u64,
    /// Serialized block header
    pub header: Vec<u8>,
    /// Block hash (for verification)
    pub hash: [u8; 32],
}

/// Errors that can occur during block synchronization
#[derive(Debug, Error)]
pub enum BlockSyncError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Invalid block range: {0}")]
    InvalidRange(String),
}

/// Codec for the block synchronization protocol
#[derive(Debug, Clone)]
pub struct BlockSyncCodec {
    _marker: PhantomData<()>,
}

impl Default for BlockSyncCodec {
    fn default() -> Self {
        Self { _marker: PhantomData }
    }
}

#[async_trait::async_trait]
impl RequestResponseCodec for BlockSyncCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> futures::future::BoxFuture<io::Result<()>>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Box::pin(async move {
            let buf = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            futures::AsyncWriteExt::write_all(io, &buf).await?;
            Ok(())
        })
    }

    fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> futures::future::BoxFuture<io::Result<()>>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Box::pin(async move {
            let buf = bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            futures::AsyncWriteExt::write_all(io, &buf).await?;
            Ok(())
        })
    }
}

/// Handler for block synchronization protocol messages
pub struct BlockSyncHandler {
    // Chain store for retrieving blocks and headers
    // chain_store: Arc<dyn ChainStore>,
}

impl BlockSyncHandler {
    /// Create a new BlockSyncHandler
    pub fn new(/* chain_store: Arc<dyn ChainStore> */) -> Self {
        Self { 
            // chain_store 
        }
    }

    /// Handle an incoming block sync request
    pub async fn handle_request(&self, request: BlockSyncRequest) -> Result<BlockSyncResponse, BlockSyncError> {
        match request {
            BlockSyncRequest::BlockRange { start_height, end_height } => {
                self.handle_block_range_request(start_height, end_height).await
            }
            BlockSyncRequest::GetHeaders { locator_hashes, stop_hash } => {
                self.handle_get_headers_request(locator_hashes, stop_hash).await
            }
        }
    }

    async fn handle_block_range_request(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<BlockSyncResponse, BlockSyncError> {
        // Validate the requested range
        if start_height > end_height {
            return Err(BlockSyncError::InvalidRange(
                "start_height must be less than or equal to end_height".to_string(),
            ));
        }

        if end_height - start_height >= MAX_BLOCKS_PER_RESPONSE as u64 {
            return Err(BlockSyncError::InvalidRange(format!(
                "Requested range too large. Max {} blocks per request",
                MAX_BLOCKS_PER_RESPONSE
            )));
        }

        // TODO: Implement actual block retrieval from chain store
        // let blocks = self.chain_store.get_block_range(start_height, end_height).await?;
        let blocks = Vec::new(); // Placeholder
        
        Ok(BlockSyncResponse::BlockRange(blocks))
    }

    async fn handle_get_headers_request(
        &self,
        _locator_hashes: Vec<[u8; 32]>,
        _stop_hash: Option<[u8; 32]>,
    ) -> Result<BlockSyncResponse, BlockSyncError> {
        // TODO: Implement actual header retrieval from chain store
        // 1. Find the first hash in locator_hashes that exists in our chain
        // 2. Return headers from that point until stop_hash or max_headers
        // 3. Handle the case where no hash is found
        
        // Placeholder implementation
        Ok(BlockSyncResponse::Headers(Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec;
    use futures::io::Cursor;

    #[tokio::test]
    async fn test_block_sync_codec() {
        let mut codec = BlockSyncCodec::default();
        let protocol = libp2p::StreamProtocol::new("/test");
        
        // Test request serialization/deserialization
        let request = BlockSyncRequest::BlockRange {
            start_height: 100,
            end_height: 150,
        };
        
        let mut buf = Vec::new();
        codec.write_request(&protocol, &mut buf, request.clone()).await.unwrap();
        let deserialized = codec.read_request(&protocol, &mut Cursor::new(&buf)).await.unwrap();
        
        if let (
            BlockSyncRequest::BlockRange { start_height: s1, end_height: e1 },
            BlockSyncRequest::BlockRange { start_height: s2, end_height: e2 },
        ) = (request, deserialized) {
            assert_eq!(s1, s2);
            assert_eq!(e1, e2);
        } else {
            panic!("Request deserialization failed");
        }
        
        // Test response serialization/deserialization
        let response = BlockSyncResponse::BlockRange(vec![
            BlockData {
                height: 100,
                data: vec![1, 2, 3],
                hash: [0; 32],
            }
        ]);
        
        let mut buf = Vec::new();
        codec.write_response(&protocol, &mut buf, response.clone()).await.unwrap();
        let deserialized = codec.read_response(&protocol, &mut Cursor::new(&buf)).await.unwrap();
        
        match (response, deserialized) {
            (
                BlockSyncResponse::BlockRange(a),
                BlockSyncResponse::BlockRange(b),
            ) => {
                assert_eq!(a.len(), b.len());
                assert_eq!(a[0].height, b[0].height);
                assert_eq!(a[0].data, b[0].data);
                assert_eq!(a[0].hash, b[0].hash);
            }
            _ => panic!("Response deserialization failed"),
        }
    }
    
    #[tokio::test]
    async fn test_block_sync_handler() {
        let handler = BlockSyncHandler::new();
        
        // Test block range request
        let request = BlockSyncRequest::BlockRange {
            start_height: 100,
            end_height: 150,
        };
        
        let response = handler.handle_request(request).await;
        assert!(matches!(response, Ok(_)));
        
        // Test invalid range
        let request = BlockSyncRequest::BlockRange {
            start_height: 200,
            end_height: 100, // Invalid: start > end
        };
        
        let response = handler.handle_request(request).await;
        assert!(matches!(response, Err(BlockSyncError::InvalidRange(_))));
        
        // Test get headers request
        let request = BlockSyncRequest::GetHeaders {
            locator_hashes: vec![[0; 32]],
            stop_hash: None,
        };
        
        let response = handler.handle_request(request).await;
        assert!(matches!(response, Ok(BlockSyncResponse::Headers(_))));
    }
}
