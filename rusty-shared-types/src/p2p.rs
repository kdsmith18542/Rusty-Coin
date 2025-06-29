use serde::{Deserialize, Serialize};
use crate::{Block, BlockHeader, Transaction, Hash, Txid, TxOutput, TxInput};
use crate::masternode::MasternodeID;

/// P2P message types for network communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Ping,
    Pong,
    GetBlocks(BlockRequest),
    Blocks(BlockResponse),
    GetHeaders(GetHeaders),
    Headers(Headers),
    Inv(Inv),
    GetData(Vec<Inv>),
    Transaction(Transaction),
    TransactionResponse(Txid),
    Block(Block),
}

/// Block request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub start_hash: Hash,
    pub end_hash: Option<Hash>,
    pub max_blocks: u32,
}

/// Block response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<BlockData>,
}

/// Block data for P2P transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    pub header: BlockHeaderData,
    pub transactions: Vec<Transaction>,
}

/// Block header data for P2P transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderData {
    pub hash: Hash,
    pub previous_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub height: u64,
    pub nonce: u64,
    pub target: u32,
}

/// Get headers request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeaders {
    pub start_hash: Hash,
    pub end_hash: Option<Hash>,
    pub max_headers: u32,
}

/// Headers response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Headers {
    pub headers: Vec<BlockHeaderData>,
}

/// Inventory message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inv {
    pub inv_type: InvType,
    pub hash: Hash,
}

/// Inventory types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvType {
    Transaction,
    Block,
    FilteredBlock,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub version: u32,
    pub services: u64,
    pub last_seen: u64,
    pub user_agent: String,
}