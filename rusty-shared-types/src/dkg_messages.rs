//! DKG network message types for Rusty Coin masternode coordination

use serde::{Serialize, Deserialize};
use crate::{Hash, MasternodeID};
use crate::dkg::{
    DKGSessionID, DKGCommitment, DKGSecretShare, DKGComplaint, DKGJustification,
    SignatureShare, ThresholdSignatureRequest
};


/// Network message types for DKG protocol coordination
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DKGMessage {
    /// Request to initiate a new DKG session
    InitiateDKG(DKGInitiateRequest),
    /// Response to DKG initiation request
    DKGInitiateResponse(DKGInitiateResponse),
    /// Commitment phase message
    CommitmentBroadcast(DKGCommitmentMessage),
    /// Secret share distribution message
    ShareDistribution(DKGShareMessage),
    /// Complaint against invalid shares
    ComplaintBroadcast(DKGComplaintMessage),
    /// Justification response to complaints
    JustificationBroadcast(DKGJustificationMessage),
    /// DKG session completion announcement
    DKGComplete(DKGCompleteMessage),
    /// Request for threshold signature
    ThresholdSignRequest(ThresholdSignRequestMessage),
    /// Signature share contribution
    SignatureShareBroadcast(SignatureShareMessage),
    /// Final aggregated threshold signature
    ThresholdSignatureComplete(ThresholdSignatureCompleteMessage),
}

/// Request to initiate a new DKG session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGInitiateRequest {
    pub session_id: DKGSessionID,
    pub initiator: MasternodeID,
    pub participants: Vec<MasternodeID>,
    pub threshold: u32,
    pub purpose: DKGPurpose,
    pub block_height: u64,
    pub signature: Vec<u8>, // Ed25519 signature by initiator
}

/// Response to DKG initiation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGInitiateResponse {
    pub session_id: DKGSessionID,
    pub responder: MasternodeID,
    pub accepted: bool,
    pub reason: Option<String>, // Reason for rejection if not accepted
    pub signature: Vec<u8>, // Ed25519 signature by responder
}

/// Purpose of the DKG session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DKGPurpose {
    OxideSendQuorum,
    FerrousShieldCoordination,
    GovernanceVoting,
    SidechainBridge,
    Custom(String),
}

/// Commitment phase message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGCommitmentMessage {
    pub session_id: DKGSessionID,
    pub commitment: DKGCommitment,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Secret share distribution message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGShareMessage {
    pub session_id: DKGSessionID,
    pub shares: Vec<DKGSecretShare>, // Encrypted shares for multiple recipients
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Complaint message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGComplaintMessage {
    pub session_id: DKGSessionID,
    pub complaint: DKGComplaint,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Justification message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGJustificationMessage {
    pub session_id: DKGSessionID,
    pub justification: DKGJustification,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// DKG completion announcement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGCompleteMessage {
    pub session_id: DKGSessionID,
    pub group_public_key: Vec<u8>, // Serialized threshold public key
    pub participants: Vec<MasternodeID>,
    pub threshold: u32,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Request for threshold signature
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdSignRequestMessage {
    pub session_id: DKGSessionID,
    pub request: ThresholdSignatureRequest,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Signature share contribution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureShareMessage {
    pub session_id: DKGSessionID,
    pub signature_share: SignatureShare,
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Final aggregated threshold signature
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdSignatureCompleteMessage {
    pub session_id: DKGSessionID,
    pub message_hash: Hash,
    pub aggregated_signature: Vec<u8>, // Final BLS threshold signature
    pub signers: Vec<u32>, // Participant indices who contributed
    pub sender: MasternodeID,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// DKG message validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DKGMessageValidation {
    Valid,
    InvalidSignature,
    InvalidSender,
    InvalidSession,
    InvalidTimestamp,
    InvalidContent(String),
}

impl DKGMessage {
    /// Get the session ID associated with this message
    pub fn session_id(&self) -> &DKGSessionID {
        match self {
            DKGMessage::InitiateDKG(msg) => &msg.session_id,
            DKGMessage::DKGInitiateResponse(msg) => &msg.session_id,
            DKGMessage::CommitmentBroadcast(msg) => &msg.session_id,
            DKGMessage::ShareDistribution(msg) => &msg.session_id,
            DKGMessage::ComplaintBroadcast(msg) => &msg.session_id,
            DKGMessage::JustificationBroadcast(msg) => &msg.session_id,
            DKGMessage::DKGComplete(msg) => &msg.session_id,
            DKGMessage::ThresholdSignRequest(msg) => &msg.session_id,
            DKGMessage::SignatureShareBroadcast(msg) => &msg.session_id,
            DKGMessage::ThresholdSignatureComplete(msg) => &msg.session_id,
        }
    }

    /// Get the sender of this message
    pub fn sender(&self) -> &MasternodeID {
        match self {
            DKGMessage::InitiateDKG(msg) => &msg.initiator,
            DKGMessage::DKGInitiateResponse(msg) => &msg.responder,
            DKGMessage::CommitmentBroadcast(msg) => &msg.sender,
            DKGMessage::ShareDistribution(msg) => &msg.sender,
            DKGMessage::ComplaintBroadcast(msg) => &msg.sender,
            DKGMessage::JustificationBroadcast(msg) => &msg.sender,
            DKGMessage::DKGComplete(msg) => &msg.sender,
            DKGMessage::ThresholdSignRequest(msg) => &msg.sender,
            DKGMessage::SignatureShareBroadcast(msg) => &msg.sender,
            DKGMessage::ThresholdSignatureComplete(msg) => &msg.sender,
        }
    }

    /// Get the timestamp of this message
    pub fn timestamp(&self) -> u64 {
        match self {
            DKGMessage::InitiateDKG(_) => 0, // No timestamp in initiate request
            DKGMessage::DKGInitiateResponse(_) => 0, // No timestamp in response
            DKGMessage::CommitmentBroadcast(msg) => msg.timestamp,
            DKGMessage::ShareDistribution(msg) => msg.timestamp,
            DKGMessage::ComplaintBroadcast(msg) => msg.timestamp,
            DKGMessage::JustificationBroadcast(msg) => msg.timestamp,
            DKGMessage::DKGComplete(msg) => msg.timestamp,
            DKGMessage::ThresholdSignRequest(msg) => msg.timestamp,
            DKGMessage::SignatureShareBroadcast(msg) => msg.timestamp,
            DKGMessage::ThresholdSignatureComplete(msg) => msg.timestamp,
        }
    }

    /// Get the signature of this message
    pub fn signature(&self) -> &[u8] {
        match self {
            DKGMessage::InitiateDKG(msg) => &msg.signature,
            DKGMessage::DKGInitiateResponse(msg) => &msg.signature,
            DKGMessage::CommitmentBroadcast(msg) => &msg.signature,
            DKGMessage::ShareDistribution(msg) => &msg.signature,
            DKGMessage::ComplaintBroadcast(msg) => &msg.signature,
            DKGMessage::JustificationBroadcast(msg) => &msg.signature,
            DKGMessage::DKGComplete(msg) => &msg.signature,
            DKGMessage::ThresholdSignRequest(msg) => &msg.signature,
            DKGMessage::SignatureShareBroadcast(msg) => &msg.signature,
            DKGMessage::ThresholdSignatureComplete(msg) => &msg.signature,
        }
    }

    /// Serialize the message for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(self)
    }

    /// Deserialize a message from network data
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(data)
    }
}

/// DKG session status for network synchronization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGSessionStatus {
    pub session_id: DKGSessionID,
    pub state: crate::dkg::DKGSessionState,
    pub participants: Vec<MasternodeID>,
    pub threshold: u32,
    pub commitments_received: u32,
    pub shares_received: u32,
    pub complaints_count: u32,
    pub justifications_count: u32,
    pub completion_percentage: f32,
}

/// Network synchronization message for DKG sessions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGSyncMessage {
    pub requester: MasternodeID,
    pub session_statuses: Vec<DKGSessionStatus>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}
