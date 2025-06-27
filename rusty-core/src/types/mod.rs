//! Core types for the Rusty Coin blockchain

use serde::{Deserialize, Serialize};
use rusty_shared_types::{Block, BlockHeader, Transaction, Hash};

// Re-export submodules
pub mod block;
pub mod utxo;

/// P2P message types for network communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Request for block headers
    GetHeaders { locator_hashes: Vec<Hash> },
    /// Response with block headers
    Headers(Vec<BlockHeader>),
    /// Request for a specific block
    GetBlock { block_hash: Hash },
    /// Response with a block
    Block(Block),
    /// Inventory message with hashes
    Inv { hashes: Vec<Hash> },
    /// Request for data by hash
    GetData { hashes: Vec<Hash> },
    /// Transaction data
    Transaction(Transaction),
    /// Compact block for efficient transmission
    CompactBlock(CompactBlock),
    /// Request for block transactions
    GetBlockTxs(GetBlockTxs),
    /// Response with block transactions
    BlockTransactions { block_hash: Hash, transactions: Vec<Transaction> },
}

/// Request for block data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub start_height: u32,
    pub end_height: u32,
}

/// Response with block data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<Block>,
}

/// Request for headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeaders {
    pub locator_hashes: Vec<Hash>,
    pub stop_hash: Hash,
}

/// Response with headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}

/// Inventory message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inv {
    pub hashes: Vec<Hash>,
}

/// Transaction data message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub transactions: Vec<Transaction>,
}

/// Request for block transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockTxs {
    pub block_hash: Hash,
    pub indexes: Vec<u32>,
}

/// Compact block for efficient transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub short_txids: Vec<[u8; 6]>,
    pub prefilled_transactions: Vec<(u32, Transaction)>,
    pub ticket_votes: Vec<rusty_shared_types::TicketVote>,
}

/// Peer identifier
pub type PeerId = String;

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub address: String,
    pub last_seen: u64,
    pub blocks_in_flight: u32,
    pub transactions_in_flight: u32,
}

/// Event types for the Rusty Coin system
#[derive(Debug, Clone)]
pub enum RustyCoinEvent {
    /// A new block was added to the blockchain
    BlockAdded { block_hash: Hash, height: u64 },
    /// A new transaction was added to the mempool
    TransactionAdded { tx_hash: Hash },
    /// A peer connected to the network
    PeerConnected { peer_id: PeerId },
    /// A peer disconnected from the network
    PeerDisconnected { peer_id: PeerId },
    /// Sync progress update
    SyncProgress { current_height: u64, target_height: u64 },
}
