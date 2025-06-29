//! Block Synchronization Protocol for Rusty Coin
//! See docs/specs/07_p2p_protocol_spec.md for details.

use libp2p::request_response::Codec;
use std::pin::Pin;
use std::future::Future;
use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use rusty_shared_types::p2p::{BlockRequest, BlockResponse};
use std::io;

/// Block synchronization protocol marker type for Rusty Coin.
#[derive(Debug, Clone)]
pub struct BlockSyncProtocol;

impl AsRef<str> for BlockSyncProtocol {
    fn as_ref(&self) -> &str {
        "/rusty/block-sync/1.0"
    }
}

/// Codec for block synchronization requests and responses.
#[derive(Default, Clone)]
pub struct BlockSyncCodec;

/// Block synchronization request type (see `rusty_shared_types::p2p::BlockRequest`).
pub type BlockSyncRequest = BlockRequest;
/// Block synchronization response type (see `rusty_shared_types::p2p::BlockResponse`).
pub type BlockSyncResponse = BlockResponse;

impl Codec for BlockSyncCodec {
    type Protocol = BlockSyncProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Request>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;
            bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;
            bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let data = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let len = data.len() as u32;
            io.write_all(&len.to_le_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        res: Self::Response,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let data = bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let len = data.len() as u32;
            io.write_all(&len.to_le_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await
        })
    }
}
