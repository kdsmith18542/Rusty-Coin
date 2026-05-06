use crate::{
    dkg_messages::DKGMessage,
    masternode::{PoSeChallenge, PoSeResponse},
    Block, Hash, Transaction, Txid,
};
pub use crate::proof::{ProofRequest, ProofResponse};
use serde::{Deserialize, Serialize};

/// P2P message types for network communication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    MasternodeListRequest(MasternodeListRequest),
    MasternodeListResponse(MasternodeListResponse),
    MasternodeUpdate(MasternodeUpdate),
    MasternodeListSync(MasternodeListSync),
    /// PoSe (Proof of Service) challenge message
    PoSeChallenge(PoSeChallenge),
    /// PoSe (Proof of Service) response message
    PoSeResponse(PoSeResponse),
    /// DKG (Distributed Key Generation) message
    DKG(DKGMessage),
    /// State proof request message
    GetProof(ProofRequest),
    /// State proof response message
    Proof(ProofResponse),
}

/// Block request message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRequest {
    pub start_hash: Hash,
    pub end_hash: Option<Hash>,
    pub max_blocks: u32,
}

/// Block response message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockResponse {
    pub blocks: Vec<BlockData>,
}

/// Block data for P2P transmission
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockData {
    pub header: BlockHeaderData,
    pub transactions: Vec<Transaction>,
}

/// Block header data for P2P transmission
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetHeaders {
    pub start_hash: Hash,
    pub end_hash: Option<Hash>,
    pub max_headers: u32,
}

/// Headers response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Headers {
    pub headers: Vec<BlockHeaderData>,
}

/// Inventory message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inv {
    pub inv_type: InvType,
    pub hash: Hash,
}

/// Inventory types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvType {
    Transaction,
    Block,
    FilteredBlock,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub version: u32,
    pub services: u64,
    pub last_seen: u64,
    pub user_agent: String,
}

/// Masternode list request message (for masternode sync)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasternodeListRequest {
    pub request_id: u64,
}

/// Masternode list response message (for masternode sync)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasternodeListResponse {
    pub request_id: u64,
    pub masternodes: Vec<crate::masternode::MasternodeEntry>,
}

/// Masternode update message (for masternode sync)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasternodeUpdate {
    pub masternode_id: crate::masternode::MasternodeID,
    pub update_type: MasternodeUpdateType,
    pub entry: Option<crate::masternode::MasternodeEntry>, // Present for registration/status updates
    pub block_height: u64,  // Block height at which this update occurred
    pub signature: Vec<u8>, // Signature by the masternode operator key
}

/// Masternode update type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MasternodeUpdateType {
    Registration,
    StatusChange,
    Deregistration,
    PoSeUpdate,
    DKGParticipation,
}

/// Masternode list sync message (for full list sync)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasternodeListSync {
    pub masternodes: Vec<crate::masternode::MasternodeEntry>,
}

