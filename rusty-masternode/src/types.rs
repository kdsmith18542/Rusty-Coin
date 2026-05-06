use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

// Re-export commonly used types from core
pub use rusty_core::masternode::{
    MasternodeID, MasternodeIdentity, MasternodeRegistration, MasternodeStatus,
    MasternodeEntry, MasternodeList, MnRegisterTxPayload, PoSeChallenge,
    PoSeResponse, TxInputLock, FerrousShieldMixRequest, FerrousShieldMixOutput,
    MasternodeSlashTx, MasternodeUpdate, MasternodeUpdateType, MasternodeListSync,
    MasternodeListRequest, MasternodeListResponse, SlashingReason as SharedSlashingReason,
};

use rusty_shared_types::{
    Hash, OutPoint, Amount, PublicKey, Signature,
    transaction::{Transaction, StandardTransaction, TxInput, TxOutput},
};

use rusty_core::dkg::{
    DKGSession, DKGSessionID, DKGParticipant, DKGParams, DKGMessage,
    DKGCommitment, DKGSecretShare, DKGComplaint, DKGJustification, DKGError,
};

use rusty_core::pose::{
    PoSeManager, PoSeConfig, PoSeStats,
};

use ed25519_dalek::{Keypair, SigningKey, VerifyingKey};

/// Common result type for masternode operations
pub type Result<T> = std::result::Result<T, MasternodeError>;

/// Error type for masternode operations
#[derive(Debug, thiserror::Error)]
pub enum MasternodeError {
    #[error("Masternode not found: {0}")]
    NotFound(String),
    
    #[error("Invalid masternode state: {0}")]
    InvalidState(String),
    
    #[error("Insufficient collateral: expected {expected}, got {actual}")]
    InsufficientCollateral { expected: Amount, actual: Amount },
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("DKG error: {0}")]
    DKGError(#[from] DKGError),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Consensus error: {0}")]
    ConsensusError(String),
}

/// Masternode configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeConfig {
    /// Minimum collateral amount required to register a masternode
    pub min_collateral: Amount,
    
    /// Block confirmation requirement for collateral
    pub collateral_confirmations: u32,
    
    /// Port for masternode P2P communication
    pub p2p_port: u16,
    
    /// Enable/disable masternode features
    pub enabled: bool,
    
    /// Masternode private key (if this node is a masternode)
    pub private_key: Option<Vec<u8>>,
}

impl Default for MasternodeConfig {
    fn default() -> Self {
        Self {
            min_collateral: 10_000_000_000, // 10,000 coins (assuming 8 decimals)
            collateral_confirmations: 15,
            p2p_port: 19999,
            enabled: true,
            private_key: None,
        }
    }
}

/// Masternode state shared across threads
#[derive(Clone)]
pub struct MasternodeState {
    /// Current masternode list
    pub masternode_list: Arc<Mutex<MasternodeList>>,
    
    /// Active DKG sessions
    pub dkg_sessions: Arc<Mutex<HashMap<DKGSessionID, DKGSession>>>,
    
    /// Pending masternode updates
    pub pending_updates: Arc<Mutex<Vec<MasternodeUpdate>>>,
    
    /// Current block height
    pub current_height: Arc<Mutex<u64>>,
}

impl Default for MasternodeState {
    fn default() -> Self {
        Self {
            masternode_list: Arc::new(Mutex::new(MasternodeList::new())),
            dkg_sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_updates: Arc::new(Mutex::new(Vec::new())),
            current_height: Arc::new(Mutex::new(0)),
        }
    }
}

/// Masternode network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasternodeMessage {
    /// Request masternode list from peers
    ListRequest(MasternodeListRequest),
    
    /// Response with masternode list
    ListResponse(MasternodeListResponse),
    
    /// Masternode update notification
    Update(MasternodeUpdate),
    
    /// PoSe challenge
    PoSeChallenge(PoSeChallenge),
    
    /// PoSe response
    PoSeResponse(PoSeResponse),
    
    /// DKG message
    DKG(DKGMessage),
}

/// Helper trait for masternode operations
pub trait MasternodeOperations {
    /// Register a new masternode
    fn register(&self, registration: MasternodeRegistration) -> Result<()>;
    
    /// Update masternode status
    fn update_status(&self, masternode_id: &MasternodeID, status: MasternodeStatus) -> Result<()>;
    
    /// Get masternode by ID
    fn get_masternode(&self, masternode_id: &MasternodeID) -> Result<MasternodeEntry>;
    
    /// Get all masternodes
    fn get_masternodes(&self) -> Result<Vec<(MasternodeID, MasternodeEntry)>>;
}

/// Helper trait for DKG operations
pub trait DKGOperations {
    /// Start a new DKG session
    fn start_dkg_session(&self, participants: Vec<MasternodeID>, threshold: u32) -> Result<DKGSessionID>;
    
    /// Process a DKG message
    fn process_dkg_message(&self, message: DKGMessage) -> Result<()>;
    
    /// Get the public key share for a DKG session
    fn get_public_key_share(&self, session_id: &DKGSessionID) -> Result<PublicKey>;
}

/// Helper trait for PoSe operations
pub trait PoSEOperations {
    /// Create a new PoSe challenge
    fn create_challenge(&self, target: MasternodeID) -> Result<PoSeChallenge>;
    
    /// Process a PoSe challenge
    fn process_challenge(&self, challenge: PoSeChallenge) -> Result<PoSeResponse>;
    
    /// Verify a PoSe response
    fn verify_response(&self, response: PoSeResponse) -> Result<bool>;
}

// Implement standard conversions
impl From<DKGError> for MasternodeError {
    fn from(err: DKGError) -> Self {
        MasternodeError::DKGError(err)
    }
}

// Implement serialization for common types
impl MasternodeMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| MasternodeError::SerializationError(e.to_string()))
    }
    
    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| MasternodeError::SerializationError(e.to_string()))
    }
}

// Implement common utility functions
impl MasternodeState {
    /// Get the current block height
    pub fn get_height(&self) -> u64 {
        *self.current_height.lock().unwrap()
    }
    
    /// Update the current block height
    pub fn update_height(&self, height: u64) {
        *self.current_height.lock().unwrap() = height;
    }
    
    /// Get a copy of the current masternode list
    pub fn get_masternode_list(&self) -> MasternodeList {
        self.masternode_list.lock().unwrap().clone()
    }
    
    /// Update the masternode list
    pub fn update_masternode_list<F>(&self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut MasternodeList) -> Result<()>,
    {
        let mut list = self.masternode_list.lock().unwrap();
        updater(&mut list)
    }
}