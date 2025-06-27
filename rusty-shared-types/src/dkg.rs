//! Distributed Key Generation (DKG) types for Rusty Coin masternode threshold signatures

use serde::{Serialize, Deserialize};
use crate::{Hash, MasternodeID};
use std::collections::HashMap;
use std::hash::Hash as StdHash;

/// Unique identifier for a DKG session
#[derive(Debug, Clone, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub struct DKGSessionID(pub Hash);

impl AsRef<[u8]> for DKGSessionID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Hash> for DKGSessionID {
    fn from(hash: Hash) -> Self {
        DKGSessionID(hash)
    }
}

impl From<DKGSessionID> for Hash {
    fn from(dkg_session_id: DKGSessionID) -> Self {
        dkg_session_id.0
    }
}

/// Represents a participant in a DKG session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGParticipant {
    pub masternode_id: MasternodeID,
    pub participant_index: u32,
    pub public_key: Vec<u8>, // Ed25519 public key for authentication
}

/// DKG commitment data for Feldman's VSS (Verifiable Secret Sharing)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGCommitment {
    pub participant_index: u32,
    pub commitments: Vec<Vec<u8>>, // G1 points serialized as bytes
    pub signature: Vec<u8>, // Ed25519 signature over commitments by participant
}

/// Secret share for a specific participant in DKG
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGSecretShare {
    pub from_participant: u32,
    pub to_participant: u32,
    pub encrypted_share: Vec<u8>, // Encrypted with recipient's public key
    pub signature: Vec<u8>, // Ed25519 signature by sender
}

/// Complaint against a participant for invalid shares
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGComplaint {
    pub complainant: u32,
    pub accused: u32,
    pub session_id: DKGSessionID,
    pub evidence: Vec<u8>, // Cryptographic proof of invalid share
    pub signature: Vec<u8>, // Ed25519 signature by complainant
}

/// Response to a complaint with justification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGJustification {
    pub accused: u32,
    pub complainant: u32,
    pub session_id: DKGSessionID,
    pub revealed_share: Vec<u8>, // The actual share to prove validity
    pub signature: Vec<u8>, // Ed25519 signature by accused
}

/// Current state of a DKG session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DKGSessionState {
    /// Initial state, waiting for participants to join
    WaitingForParticipants,
    /// Commitment phase - participants submit commitments
    CommitmentPhase,
    /// Share distribution phase
    ShareDistribution,
    /// Complaint phase - participants can file complaints
    ComplaintPhase,
    /// Justification phase - accused participants provide justifications
    JustificationPhase,
    /// DKG completed successfully
    Completed,
    /// DKG failed due to too many complaints or timeouts
    Failed,
}

/// Complete DKG session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGSession {
    pub session_id: DKGSessionID,
    pub participants: Vec<DKGParticipant>,
    pub threshold: u32, // Minimum number of participants needed for signing
    pub state: DKGSessionState,
    pub commitments: HashMap<u32, DKGCommitment>,
    pub complaints: Vec<DKGComplaint>,
    pub justifications: Vec<DKGJustification>,
    pub secret_shares: HashMap<u32, DKGSecretShare>, // New field for secret shares
    pub creation_block_height: u64,
    pub timeout_block_height: u64,
    pub group_public_key: Option<Vec<u8>>, // BLS12-381 G2 point when completed
}

/// Threshold signature created by DKG participants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub session_id: DKGSessionID,
    pub message_hash: Hash,
    pub signature_shares: HashMap<u32, Vec<u8>>, // Participant index -> BLS signature share
    pub aggregated_signature: Option<Vec<u8>>, // Final aggregated BLS signature
    pub signers: Vec<u32>, // Indices of participants who contributed shares
}

/// Request to create a threshold signature
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdSignatureRequest {
    pub session_id: DKGSessionID,
    pub message: Vec<u8>,
    pub message_hash: Hash,
    pub requester: MasternodeID,
    pub signature: Vec<u8>, // Ed25519 signature by requester
}

/// Individual signature share for threshold signing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureShare {
    pub session_id: DKGSessionID,
    pub participant_index: u32,
    pub message_hash: Hash,
    pub signature_share: Vec<u8>, // BLS signature share
    pub signature: Vec<u8>, // Ed25519 signature by participant for authenticity
}

/// DKG protocol parameters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DKGParams {
    pub min_participants: u32,
    pub max_participants: u32,
    pub threshold_percentage: u32, // Percentage (e.g., 67 for 2/3 threshold)
    pub commitment_timeout_blocks: u64,
    pub share_timeout_blocks: u64,
    pub complaint_timeout_blocks: u64,
    pub justification_timeout_blocks: u64,
}

impl Default for DKGParams {
    fn default() -> Self {
        Self {
            min_participants: 3,
            max_participants: 100,
            threshold_percentage: 67, // 2/3 threshold
            commitment_timeout_blocks: 10,
            share_timeout_blocks: 10,
            complaint_timeout_blocks: 5,
            justification_timeout_blocks: 5,
        }
    }
}

impl DKGSession {
    /// Create a new DKG session
    pub fn new(
        session_id: DKGSessionID,
        participants: Vec<DKGParticipant>,
        threshold: u32,
        creation_block_height: u64,
        params: &DKGParams,
    ) -> Self {
        let timeout_block_height = creation_block_height + 
            params.commitment_timeout_blocks + 
            params.share_timeout_blocks + 
            params.complaint_timeout_blocks + 
            params.justification_timeout_blocks;

        Self {
            session_id,
            participants,
            threshold,
            state: DKGSessionState::WaitingForParticipants,
            commitments: HashMap::new(),
            complaints: Vec::new(),
            justifications: Vec::new(),
            secret_shares: HashMap::new(), // Initialize new field
            creation_block_height,
            timeout_block_height,
            group_public_key: None,
        }
    }

    /// Check if the session has enough participants
    pub fn has_minimum_participants(&self, min_participants: u32) -> bool {
        self.participants.len() as u32 >= min_participants
    }

    /// Check if all participants have submitted commitments
    pub fn all_commitments_received(&self) -> bool {
        self.commitments.len() == self.participants.len()
    }

    /// Get participant by index
    pub fn get_participant(&self, index: u32) -> Option<&DKGParticipant> {
        self.participants.iter().find(|p| p.participant_index == index)
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, current_block_height: u64) -> bool {
        current_block_height > self.timeout_block_height
    }

    /// Calculate the threshold from percentage
    pub fn calculate_threshold(num_participants: u32, threshold_percentage: u32) -> u32 {
        ((num_participants * threshold_percentage + 99) / 100).max(1) // Ceiling division
    }

    /// Add a commitment to the session
    pub fn add_commitment(&mut self, commitment: DKGCommitment) -> Result<(), DKGError> {
        if self.state != DKGSessionState::CommitmentPhase {
            return Err(DKGError::InvalidSessionState);
        }

        // Verify the participant is part of this session
        if !self.participants.iter().any(|p| p.participant_index == commitment.participant_index) {
            return Err(DKGError::InvalidParticipant);
        }

        // Check for duplicate commitments
        if self.commitments.contains_key(&commitment.participant_index) {
            return Err(DKGError::DuplicateCommitment);
        }

        self.commitments.insert(commitment.participant_index, commitment);
        Ok(())
    }

    /// Add a secret share to the session
    pub fn add_secret_share(&mut self, share: DKGSecretShare) -> Result<(), DKGError> {
        if self.state != DKGSessionState::ShareDistribution {
            return Err(DKGError::InvalidSessionState);
        }

        // Verify the participant is part of this session
        if !self.participants.iter().any(|p| p.participant_index == share.from_participant) {
            return Err(DKGError::InvalidParticipant);
        }

        // Check for duplicate shares
        if self.secret_shares.contains_key(&share.from_participant) {
            return Err(DKGError::DuplicateShare);
        }

        self.secret_shares.insert(share.from_participant, share);
        Ok(())
    }

    /// Check if all participants have submitted secret shares
    pub fn all_shares_received(&self) -> bool {
        self.secret_shares.len() == self.participants.len()
    }

    // Removed get_our_participant_state: This should be managed by DKGProtocol or DKGManager, not DKGSession.

    /// Advance to the next phase of the DKG protocol
    pub fn advance_phase(&mut self) -> Result<(), DKGError> {
        match self.state {
            DKGSessionState::WaitingForParticipants => {
                if self.participants.len() >= 3 { // Minimum participants
                    self.state = DKGSessionState::CommitmentPhase;
                } else {
                    return Err(DKGError::InsufficientParticipants);
                }
            }
            DKGSessionState::CommitmentPhase => {
                if self.all_commitments_received() {
                    self.state = DKGSessionState::ShareDistribution;
                } else {
                    return Err(DKGError::InsufficientCommitments);
                }
            }
            DKGSessionState::ShareDistribution => {
                if self.all_shares_received() {
                    self.state = DKGSessionState::ComplaintPhase;
                } else {
                    return Err(DKGError::InsufficientShares);
                }
            }
            DKGSessionState::ComplaintPhase => {
                // Logic for complaint processing
                self.state = DKGSessionState::JustificationPhase;
            }
            DKGSessionState::JustificationPhase => {
                // Logic for justification processing
                self.state = DKGSessionState::Completed;
            }
            DKGSessionState::Completed => {
                return Err(DKGError::InvalidSessionState);
            }
            DKGSessionState::Failed => {
                return Err(DKGError::InvalidSessionState);
            }
        }
        Ok(())
    }
}

/// DKG-related error types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DKGError {
    InvalidParticipant,
    InvalidCommitment,
    InvalidShare,
    InsufficientParticipants,
    SessionNotFound,
    InvalidSessionState,
    ThresholdNotMet,
    InvalidSignature,
    Timeout,
    DuplicateCommitment,
    DuplicateShare,
    NetworkError(String),
    SerializationError(String),
    CryptographicError(String),
    InsufficientCommitments, // New error variant
    InsufficientShares, // New error variant
    InternalError(String), // New error variant
}

impl std::fmt::Display for DKGError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DKGError::InvalidParticipant => write!(f, "Invalid participant"),
            DKGError::InvalidCommitment => write!(f, "Invalid commitment"),
            DKGError::InvalidShare => write!(f, "Invalid share"),
            DKGError::InsufficientParticipants => write!(f, "Insufficient participants"),
            DKGError::SessionNotFound => write!(f, "DKG session not found"),
            DKGError::InvalidSessionState => write!(f, "Invalid session state"),
            DKGError::ThresholdNotMet => write!(f, "Threshold not met"),
            DKGError::InvalidSignature => write!(f, "Invalid signature"),
            DKGError::Timeout => write!(f, "DKG session timeout"),
            DKGError::DuplicateCommitment => write!(f, "Duplicate commitment received"),
            DKGError::DuplicateShare => write!(f, "Duplicate share received"),
            DKGError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            DKGError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            DKGError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            DKGError::InsufficientCommitments => write!(f, "Insufficient commitments"),
            DKGError::InsufficientShares => write!(f, "Insufficient shares"),
            DKGError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for DKGError {}
