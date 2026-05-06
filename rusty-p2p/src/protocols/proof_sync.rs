//! State Proof Synchronization Protocol for Rusty Coin
//! See docs/specs/07_p2p_protocol_spec.md for details.

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use rusty_shared_types::p2p::{ProofRequest, ProofResponse};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::{Duration, Instant};

/// Marker type for the Rusty Coin state proof protocol.
/// Used to identify the protocol in libp2p request/response handlers.
#[derive(Debug, Clone)]
pub struct ProofSyncProtocol;

impl AsRef<str> for ProofSyncProtocol {
    /// Returns the protocol string identifier.
    fn as_ref(&self) -> &str {
        "/rusty/proof-sync/1.0"
    }
}

/// Codec for state proof synchronization requests and responses.
/// Handles serialization and deserialization of proof sync messages.
#[derive(Default, Clone)]
pub struct ProofSyncCodec;

/// State proof synchronization request type.
pub type ProofSyncRequest = ProofRequest;
/// State proof synchronization response type.
pub type ProofSyncResponse = ProofResponse;

impl Codec for ProofSyncCodec {
    type Protocol = ProofSyncProtocol;
    type Request = ProofSyncRequest;
    type Response = ProofSyncResponse;

    /// Reads a proof sync request from the given async reader.
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

    /// Reads a proof sync response from the given async reader.
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

    /// Writes a proof sync request to the given async writer.
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
            let data = bincode::serialize(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let len = data.len() as u32;
            io.write_all(&len.to_le_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await
        })
    }

    /// Writes a proof sync response to the given async writer.
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
            let data = bincode::serialize(&res)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let len = data.len() as u32;
            io.write_all(&len.to_le_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await
        })
    }
}

/// Rate limiter for tracking peer message/bandwidth limits for proof requests
#[derive(Debug)]
pub struct ProofRateLimiter {
    /// Per-peer message counts in current window
    peer_message_counts: HashMap<libp2p::PeerId, u32>,
    /// Per-peer byte counts in current window
    peer_byte_counts: HashMap<libp2p::PeerId, u64>,
    /// Last window reset time
    last_reset: Instant,
    /// Configuration
    max_messages_per_second: u32,
    max_bytes_per_second: u64,
    window_duration: Duration,
}

impl ProofRateLimiter {
    /// Create a new proof rate limiter with the given limits
    pub fn new(
        max_messages_per_second: u32,
        max_bytes_per_second: u64,
        window_duration: Duration,
    ) -> Self {
        Self {
            peer_message_counts: HashMap::new(),
            peer_byte_counts: HashMap::new(),
            last_reset: Instant::now(),
            max_messages_per_second,
            max_bytes_per_second,
            window_duration,
        }
    }

    /// Check if a peer is allowed to send a proof request of given size
    pub fn check_rate_limit(&mut self, peer_id: &libp2p::PeerId, message_size: u64) -> bool {
        self.maybe_reset_window();

        let message_count = self.peer_message_counts.get(peer_id).unwrap_or(&0);
        let byte_count = self.peer_byte_counts.get(peer_id).unwrap_or(&0);

        // Check if this message would exceed limits
        if *message_count >= self.max_messages_per_second {
            return false;
        }

        if *byte_count + message_size > self.max_bytes_per_second {
            return false;
        }

        // Update counters
        self.peer_message_counts.insert(*peer_id, message_count + 1);
        self.peer_byte_counts
            .insert(*peer_id, byte_count + message_size);

        true
    }

    /// Reset tracking window if needed
    fn maybe_reset_window(&mut self) {
        if self.last_reset.elapsed() >= self.window_duration {
            self.peer_message_counts.clear();
            self.peer_byte_counts.clear();
            self.last_reset = Instant::now();
        }
    }

    /// Clean up disconnected peers
    pub fn cleanup_peer(&mut self, peer_id: &libp2p::PeerId) {
        self.peer_message_counts.remove(peer_id);
        self.peer_byte_counts.remove(peer_id);
    }
}