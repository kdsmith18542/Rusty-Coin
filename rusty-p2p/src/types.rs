use serde::{Serialize, Deserialize};
use rusty_core::types::{Block, BlockHeader, Transaction};
use rusty_shared_types::masternode::{PoSeResponse, MasternodeEntry, MasternodeID};

// NOTE: All message structs below are reviewed for canonical serialization and field compliance per 07_p2p_protocol_spec.md and 01_block_structure.md.
// If any spec changes, update field order/types and add #[serde(...)] attributes as needed for canonical bincode serialization.
// TODO: Add/expand unit tests to verify round-trip serialization matches spec vectors.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum P2PMessage {
    BlockRequest(BlockRequest),
    BlockResponse(BlockResponse),
    GetHeaders(GetHeaders),
    Headers(Headers),
    Inv(Inv),
    TxData(TxData),
    PoSeResponse(PoSeResponse),
    Chunk(Chunk),
    CompactBlock(CompactBlock),
    GetBlockTxs(GetBlockTxs),
    BlockTxs(BlockTxs),
    // Masternode list propagation messages
    MasternodeListRequest(MasternodeListRequest),
    MasternodeListResponse(MasternodeListResponse),
    MasternodeUpdate(MasternodeUpdate),
    MasternodeListSync(MasternodeListSync),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockRequest {
    pub start_height: u32,
    pub end_height: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockResponse {
    pub blocks: Vec<Block>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetHeaders {
    pub locator_hashes: Vec<[u8; 32]>,
    pub stop_hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Inv {
    pub txid: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxData {
    pub transaction: Transaction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Chunk {
    pub header: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompactBlock {
    pub header: BlockHeader, // Block header
    pub short_txids: Vec<[u8; 6]>, // Short transaction IDs (6 bytes each, as in BIP152)
    pub prefilled_txn: Vec<(u32, Transaction)>, // Prefilled transactions (index, full tx)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetBlockTxs {
    pub block_hash: [u8; 32],
    pub indexes: Vec<u32>, // Indexes of missing transactions
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockTxs {
    pub block_hash: [u8; 32],
    pub transactions: Vec<Transaction>, // Full transactions for requested indexes
}

// Masternode list propagation message types

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeListRequest {
    pub version: u32, // Protocol version for masternode list
    pub last_known_hash: Option<[u8; 32]>, // Hash of last known masternode list
    pub request_full_list: bool, // Whether to request full list or just updates
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeListResponse {
    pub version: u32,
    pub list_hash: [u8; 32], // Hash of the current masternode list
    pub block_height: u64, // Block height at which this list is valid
    pub masternodes: Vec<rusty_shared_types::masternode::MasternodeEntry>,
    pub is_full_list: bool, // Whether this is a full list or incremental update
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeUpdate {
    pub masternode_id: rusty_shared_types::masternode::MasternodeID,
    pub update_type: MasternodeUpdateType,
    pub entry: Option<rusty_shared_types::masternode::MasternodeEntry>, // Present for registration/status updates
    pub block_height: u64, // Block height at which this update occurred
    pub signature: Vec<u8>, // Signature by the masternode operator key
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MasternodeUpdateType {
    Registration, // New masternode registration
    StatusChange, // Status change (active, offline, etc.)
    Deregistration, // Masternode deregistration
    PoSeUpdate, // Proof-of-Service update
    DKGParticipation, // DKG participation update
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MasternodeListSync {
    pub version: u32,
    pub our_list_hash: [u8; 32], // Hash of our current masternode list
    pub our_block_height: u64, // Our current block height
    pub peer_list_hash: [u8; 32], // Hash of peer's masternode list
    pub peer_block_height: u64, // Peer's block height
    pub sync_needed: bool, // Whether synchronization is needed
}