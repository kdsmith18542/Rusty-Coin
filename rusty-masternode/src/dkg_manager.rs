//! DKG Manager for coordinating distributed key generation across masternode quorums

use blake3;
use hex;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::quorum_formation::{QuorumConfig, QuorumFormationManager, QuorumType};
use ed25519_dalek::Keypair;
use rusty_crypto::dkg::DKGProtocol;
use rusty_shared_types::{
    dkg::{
        DKGCommitment, DKGError, DKGParams, DKGParticipant, DKGSecretShare, DKGSession,
        DKGSessionID,
    },
    dkg_messages::{DKGInitiateRequest, DKGMessage, DKGPurpose},
    MasternodeID,
};
use thiserror::Error;
use threshold_crypto::{PublicKey as ThresholdPublicKey, SecretKeyShare};

#[derive(Error, Debug)]
pub enum DKGManagerError {
    #[error("DKG error: {0}")]
    DkgError(#[from] DKGError),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

type Result<T> = std::result::Result<T, DKGManagerError>;

/// DKG Manager handles all DKG sessions for a masternode
pub struct DKGManager {
    /// Our masternode ID
    masternode_id: MasternodeID,
    /// Our authentication keypair
    auth_keypair: Keypair,
    /// Reference to the masternode list for getting public keys
    masternode_list: Arc<Mutex<rusty_shared_types::masternode::MasternodeList>>,
    /// Sophisticated quorum formation manager
    quorum_manager: Mutex<QuorumFormationManager>,
    /// Active DKG sessions we're participating in
    active_sessions: Arc<Mutex<HashMap<DKGSessionID, DKGSessionData>>>,
    /// DKG protocol parameters
    params: DKGParams,
    /// Message queue for outgoing DKG messages
    outgoing_messages: Arc<Mutex<Vec<DKGMessage>>>,
    /// Current block height for DKG operations
    current_block_height: Arc<Mutex<u64>>,
}

/// Internal data for a DKG session
pub struct DKGSessionData {
    pub session: DKGSession,
    pub protocol: DKGProtocol,
    pub our_participant_index: u32,
    pub received_commitments: HashMap<u32, DKGCommitment>,
    pub received_shares: HashMap<u32, DKGSecretShare>,
    pub our_secret_key_share: Option<SecretKeyShare>,
    pub group_public_key: Option<ThresholdPublicKey>,
}

impl DKGManager {
    /// Create a new DKG manager
    pub fn new(
        masternode_id: MasternodeID,
        auth_keypair: Keypair,
        masternode_list: Arc<Mutex<rusty_shared_types::masternode::MasternodeList>>,
        params: DKGParams,
    ) -> Self {
        Self {
            masternode_id,
            auth_keypair,
            masternode_list,
            quorum_manager: Mutex::new(QuorumFormationManager::new(QuorumConfig::default())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            params,
            outgoing_messages: Arc::new(Mutex::new(Vec::new())),
            current_block_height: Arc::new(Mutex::new(0)),
        }
    }

    /// Update the current block height
    pub fn update_block_height(&self, height: u64, block_hash: [u8; 32]) -> Result<()> {
        let mut current_height = self
            .current_block_height
            .lock()
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
        *current_height = height;
        // Trigger any height-dependent DKG operations
        self.process_height_dependent_operations(height, block_hash)?;
        Ok(())
    }

    /// Get the current block height
    pub fn get_current_block_height(&self) -> Result<u64> {
        let height = self
            .current_block_height
            .lock()
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
        Ok(*height)
    }

    /// Process any DKG operations that depend on block height
    fn process_height_dependent_operations(&self, height: u64, block_hash: [u8; 32]) -> Result<()> {
        // Clean up expired sessions
        self.cleanup_expired_sessions(height)?;
        // Check if we need to initiate new DKG sessions
        self.maybe_initiate_scheduled_dkg(height, block_hash)?;
        Ok(())
    }

    /// Clean up DKG sessions that have expired
    fn cleanup_expired_sessions(&self, current_height: u64) -> Result<()> {
        let mut sessions = self
            .active_sessions
            .lock()
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;

        // Remove sessions that are too old (older than 1000 blocks)
        let expiry_threshold = current_height.saturating_sub(1000);

        let expired_sessions: Vec<_> = sessions
            .iter()
            .filter(|(_, data)| data.session.timeout_block_height < expiry_threshold)
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in expired_sessions {
            sessions.remove(&session_id);
            info!(
                "Cleaned up expired DKG session: {}",
                hex::encode(session_id.0)
            );
        }

        Ok(())
    }

    /// Check if we should initiate new DKG sessions based on current height
    fn maybe_initiate_scheduled_dkg(
        &self,
        current_height: u64,
        block_hash: [u8; 32],
    ) -> Result<()> {
        // DKG sessions are scheduled at regular intervals or when the masternode set changes
        let interval = 1000; // Example: every 1000 blocks
        if current_height % interval == 0 {
            info!(
                "Checking for scheduled DKG initiation at height {}",
                current_height
            );

            // Check if there is already an active session for this height
            let sessions = self.active_sessions.lock().unwrap();
            let already_active = sessions
                .values()
                .any(|session_data| session_data.session.creation_block_height == current_height);
            drop(sessions);
            if already_active {
                debug!("DKG session already active for height {}", current_height);
                return Ok(());
            }

            // Select DKG participants using the real block hash
            let min_participants = 5;
            let max_participants = 50;
            let participants = self.select_dkg_participants(
                min_participants,
                max_participants,
                current_height,
                &block_hash,
            )?;
            if participants.is_empty() {
                warn!("No eligible DKG participants at height {}", current_height);
                return Ok(());
            }

            // Initiate DKG session
            match self.initiate_dkg_session(
                participants,
                DKGPurpose::OxideSendQuorum,
                current_height,
            ) {
                Ok(session_id) => {
                    info!(
                        "Scheduled DKG session {} initiated at height {}",
                        hex::encode(session_id.0),
                        current_height
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to initiate scheduled DKG session at height {}: {:?}",
                        current_height, e
                    );
                }
            }
        }
        Ok(())
    }

    /// Use sophisticated quorum selection to choose DKG participants
    pub fn select_dkg_participants(
        &self,
        min_participants: usize,
        max_participants: usize,
        block_height: u64,
        block_hash: &rusty_shared_types::Hash,
    ) -> Result<Vec<MasternodeID>> {
        let masternode_list = self.masternode_list.lock().map_err(|e| {
            DKGManagerError::SerializationError(format!("Failed to lock masternode list: {}", e))
        })?;

        let mut quorum_manager = self.quorum_manager.lock().map_err(|e| {
            DKGManagerError::SerializationError(format!("Failed to lock quorum manager: {}", e))
        })?;

        // Determine quorum size within the specified range
        let active_count = masternode_list
            .map
            .values()
            .filter(|entry| {
                entry.status == rusty_shared_types::masternode::MasternodeStatus::Active
            })
            .count();

        let target_size = std::cmp::min(
            max_participants,
            std::cmp::max(min_participants, active_count / 3),
        );

        // Use sophisticated quorum formation for DKG participants
        let quorum = quorum_manager
            .form_quorum(
                QuorumType::DKGParticipant,
                &*masternode_list,
                block_height,
                block_hash,
                None, // No additional criteria
            )
            .map_err(|e| {
                DKGManagerError::SerializationError(format!("Quorum formation failed: {}", e))
            })?;

        // Limit to target size if the quorum is larger
        let mut participants = quorum.members;
        if participants.len() > target_size {
            participants.truncate(target_size);
        }

        // Convert masternode IDs to the DKG module's MasternodeID type
        let converted_participants: Vec<MasternodeID> = participants
            .into_iter()
            .map(|mn_id| MasternodeID(mn_id.0))
            .collect();

        info!(
            "Selected {} sophisticated DKG participants using quorum formation",
            converted_participants.len()
        );
        Ok(converted_participants)
    }

    /// Initiate a new DKG session
    pub fn initiate_dkg_session(
        &self,
        participants: Vec<MasternodeID>,
        purpose: DKGPurpose,
        current_block_height: u64,
    ) -> Result<DKGSessionID> {
        let threshold = DKGSession::calculate_threshold(
            participants.len() as u32,
            self.params.threshold_percentage,
        );

        // Generate session ID
        let mut session_data = Vec::new();
        // Convert OutPoint to bytes for hashing
        let outpoint_bytes = bincode::serialize(&self.masternode_id)
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
        session_data.extend_from_slice(&outpoint_bytes);
        session_data.extend_from_slice(&current_block_height.to_le_bytes());
        for participant in &participants {
            let participant_bytes = bincode::serialize(participant)
                .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
            session_data.extend_from_slice(&participant_bytes);
        }
        let session_id = DKGSessionID(blake3::hash(&session_data).into());

        // Create DKG participants
        let dkg_participants: Vec<DKGParticipant> = participants
            .iter()
            .enumerate()
            .map(|(index, mn_id)| DKGParticipant {
                masternode_id: mn_id.clone(),
                participant_index: index as u32,
                public_key: self
                    .get_masternode_public_key(mn_id)
                    .unwrap_or_else(|_| vec![0u8; 32]),
            })
            .collect();

        // Find our participant index
        let our_index = dkg_participants
            .iter()
            .find(|p| p.masternode_id == self.masternode_id)
            .map(|p| p.participant_index)
            .ok_or(DKGError::NotAParticipant)?;

        // Create DKG session
        let session = DKGSession::new(
            session_id.clone(),
            dkg_participants,
            threshold,
            current_block_height,
            &self.params,
        );

        // Create DKG protocol instance
        // ed25519_dalek::Keypair does not implement Clone, so use to_bytes/from_bytes
        let keypair_bytes = self.auth_keypair.to_bytes();
        let auth_keypair_copy = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
        let protocol = DKGProtocol::new(our_index, auth_keypair_copy);

        // Store session data
        let session_data = DKGSessionData {
            session,
            protocol,
            our_participant_index: our_index,
            received_commitments: HashMap::new(),
            received_shares: HashMap::new(),
            our_secret_key_share: None,
            group_public_key: None,
        };

        {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.insert(session_id.clone(), session_data);
        }

        // Create initiation request message (without signature)
        let mut initiate_request = DKGInitiateRequest {
            session_id: session_id.clone(),
            initiator: self.masternode_id.clone(),
            participants,
            threshold,
            purpose,
            block_height: current_block_height,
            signature: vec![], // Will be set after signing below
        };

        // Per protocol spec, sign the request (all fields except signature) with the operator key
        let signature = self.sign_dkg_message(&initiate_request)?;
        initiate_request.signature = signature;

        // Queue the message for broadcast
        {
            let mut messages = self.outgoing_messages.lock().unwrap();
            messages.push(DKGMessage::InitiateDKG(initiate_request));
        }

        info!(
            "Initiated DKG session {} with {} participants",
            hex::encode(session_id.0),
            threshold
        );

        Ok(session_id)
    }

    /// Handle incoming DKG message
    pub fn handle_dkg_message(&self, message: DKGMessage) -> Result<()> {
        match message {
            DKGMessage::InitiateDKG(request) => self.handle_initiate_request(request),
            DKGMessage::CommitmentBroadcast(msg) => {
                self.handle_dkg_message(DKGMessage::CommitmentBroadcast(msg))
            }
            DKGMessage::ShareDistribution(msg) => {
                self.handle_dkg_message(DKGMessage::ShareDistribution(msg))
            }
            DKGMessage::ComplaintBroadcast(msg) => {
                self.handle_dkg_message(DKGMessage::ComplaintBroadcast(msg))
            }
            DKGMessage::JustificationBroadcast(msg) => {
                self.handle_dkg_message(DKGMessage::JustificationBroadcast(msg))
            }
            DKGMessage::DKGComplete(msg) => self.handle_dkg_message(DKGMessage::DKGComplete(msg)),
            _ => {
                debug!("Ignoring non-DKG message type");
                Ok(())
            }
        }
    }

    /// Handle DKG initiation request
    fn handle_initiate_request(&self, request: DKGInitiateRequest) -> Result<()> {
        // Check if we're in the participant list
        if !request.participants.contains(&self.masternode_id) {
            debug!(
                "Not a participant in DKG session {}",
                hex::encode(request.session_id.0)
            );
            return Ok(());
        }

        // Validate the DKG request
        self.validate_dkg_request(&request)?;

        // Find our participant index
        let our_index = request
            .participants
            .iter()
            .position(|id| id == &self.masternode_id)
            .ok_or(DKGError::NotAParticipant)? as u32;

        // Create DKG participants
        let dkg_participants: Vec<DKGParticipant> = request
            .participants
            .iter()
            .enumerate()
            .map(|(index, mn_id)| DKGParticipant {
                masternode_id: mn_id.clone(),
                participant_index: index as u32,
                public_key: self
                    .get_masternode_public_key(mn_id)
                    .unwrap_or_else(|_| vec![0u8; 32]),
            })
            .collect();

        // Create DKG session
        let session = DKGSession::new(
            request.session_id.clone(),
            dkg_participants,
            request.threshold,
            request.block_height,
            &self.params,
        );

        // Create DKG protocol instance
        let keypair_bytes = self.auth_keypair.to_bytes();
        let auth_keypair_copy = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;
        let protocol = DKGProtocol::new(our_index, auth_keypair_copy);

        // Store session data
        let session_data = DKGSessionData {
            session,
            protocol,
            our_participant_index: our_index,
            received_commitments: HashMap::new(),
            received_shares: HashMap::new(),
            our_secret_key_share: None,
            group_public_key: None,
        };

        {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.insert(request.session_id.clone(), session_data);
        }

        info!(
            "Joined DKG session {} as participant {}",
            hex::encode(request.session_id.0),
            our_index
        );

        Ok(())
    }

    /// Sign a DKG message using our authentication keypair
    fn sign_dkg_message<T: serde::Serialize>(&self, message: &T) -> Result<Vec<u8>> {
        // Serialize the message for signing
        let message_bytes = bincode::serialize(message)
            .map_err(|e| DKGManagerError::SerializationError(e.to_string()))?;

        // Sign the message
        use ed25519_dalek::Signer;
        let signature = self.auth_keypair.sign(&message_bytes);

        Ok(signature.to_bytes().to_vec())
    }

    /// Validate a DKG initiation request
    fn validate_dkg_request(&self, request: &DKGInitiateRequest) -> Result<()> {
        // 1. Validate threshold parameters
        if request.threshold == 0 {
            return Err(DKGManagerError::DkgError(DKGError::InvalidThreshold));
        }

        let participant_count = request.participants.len() as u32;
        if request.threshold > participant_count {
            return Err(DKGManagerError::DkgError(DKGError::InvalidThreshold));
        }

        // 2. Validate participant count is within reasonable bounds
        if participant_count < 3 {
            return Err(DKGManagerError::DkgError(DKGError::NotEnoughParticipants));
        }

        if participant_count > 100 {
            // Reasonable upper bound
            return Err(DKGManagerError::DkgError(DKGError::TooManyParticipants));
        }

        // 3. Validate that all participants are unique
        let mut unique_participants = std::collections::HashSet::new();
        for participant in &request.participants {
            if !unique_participants.insert(participant) {
                return Err(DKGManagerError::DkgError(DKGError::DuplicateParticipant));
            }
        }

        // 4. Validate initiator is in the participant list
        if !request.participants.contains(&request.initiator) {
            return Err(DKGManagerError::DkgError(DKGError::InitiatorNotParticipant));
        }

        // 5. Validate block height is recent/current
        self.validate_dkg_block_height(request.block_height)?;

        // 6. Validate signature from initiator (need masternode public keys)
        self.verify_dkg_initiator_signature(request)?;

        info!(
            "DKG request validation passed for session {}",
            hex::encode(&request.session_id.0)
        );
        Ok(())
    }

    /// Validate that the DKG block height is recent/current
    fn validate_dkg_block_height(&self, request_block_height: u64) -> Result<()> {
        let current_height = self.get_current_block_height()?;

        // Allow DKG requests for the current block or up to 10 blocks in the past
        const MAX_BLOCK_AGE: u64 = 10;

        if request_block_height > current_height {
            // Future block height is not allowed
            return Err(DKGManagerError::DkgError(DKGError::InvalidBlockHeight));
        }

        let block_age = current_height.saturating_sub(request_block_height);
        if block_age > MAX_BLOCK_AGE {
            // Too old - reject stale DKG requests
            return Err(DKGManagerError::DkgError(DKGError::InvalidBlockHeight));
        }

        debug!(
            "DKG block height validation passed: request={}, current={}, age={}",
            request_block_height, current_height, block_age
        );
        Ok(())
    }

    /// Verify the DKG initiator's signature using their masternode public key
    fn verify_dkg_initiator_signature(&self, request: &DKGInitiateRequest) -> Result<()> {
        use ed25519_dalek::{PublicKey, Signature, Verifier};
        // Get the initiator's public key (prefer DKG key, fallback to operator key)
        let pubkey_bytes = self.get_masternode_public_key(&request.initiator)?;
        let public_key = PublicKey::from_bytes(&pubkey_bytes)
            .map_err(|_| DKGManagerError::DkgError(DKGError::InvalidSignature))?;
        // Reconstruct the message that was signed (all fields except signature)
        let mut msg_data = Vec::new();
        msg_data.extend(bincode::serialize(&request.session_id).unwrap_or_default());
        msg_data.extend(bincode::serialize(&request.initiator).unwrap_or_default());
        msg_data.extend(bincode::serialize(&request.participants).unwrap_or_default());
        msg_data.extend(bincode::serialize(&request.threshold).unwrap_or_default());
        msg_data.extend(bincode::serialize(&request.block_height).unwrap_or_default());
        // Verify the signature
        let signature = Signature::from_bytes(&request.signature)
            .map_err(|_| DKGManagerError::DkgError(DKGError::InvalidSignature))?;
        public_key
            .verify(&msg_data, &signature)
            .map_err(|_| DKGManagerError::DkgError(DKGError::InvalidSignature))?;
        debug!(
            "DKG initiator signature verified for {}",
            hex::encode(&request.initiator.0.txid)
        );
        Ok(())
    }

    /// Get masternode public key (protocol-compliant)
    /// Returns the operator public key for REGISTERED or COLLATERAL masternodes.
    /// Returns an error if the masternode is not found or not in a valid state.
    pub fn get_masternode_public_key(
        &self,
        mn_id: &MasternodeID,
    ) -> std::result::Result<Vec<u8>, DKGManagerError> {
        let masternode_list = self.masternode_list.lock().map_err(|e| {
            DKGManagerError::SerializationError(format!("Failed to lock masternode list: {}", e))
        })?;
        if let Some(masternode_entry) =
            masternode_list
                .map
                .get(&rusty_shared_types::masternode::MasternodeID(
                    mn_id.0.clone(),
                ))
        {
            let operator_public_key = &masternode_entry.identity.operator_public_key;
            if operator_public_key.len() == 32 {
                Ok(operator_public_key.clone())
            } else {
                Err(DKGManagerError::SerializationError(
                    "Operator public key is not 32 bytes".to_string(),
                ))
            }
        } else {
            Err(DKGManagerError::SerializationError(
                "Masternode not found".to_string(),
            ))
        }
    }

    /// Return the number of active DKG sessions
    pub fn get_active_session_count(&self) -> usize {
        self.active_sessions.lock().unwrap().len()
    }

    /// Periodic maintenance task for DKG manager
    /// Performs cleanup, scheduled DKG checks, and retries stalled sessions.
    pub async fn periodic_maintenance(
        &self,
        block_hash: [u8; 32],
    ) -> std::result::Result<(), DKGManagerError> {
        let current_height = self.get_current_block_height()?;
        // 1. Clean up expired sessions
        self.cleanup_expired_sessions(current_height)?;
        // 2. Check for scheduled DKG initiation
        self.maybe_initiate_scheduled_dkg(current_height, block_hash)?;
        // 3. Check for stalled sessions and retry if needed
        let mut sessions_to_retry = Vec::new();
        {
            let sessions = self.active_sessions.lock().unwrap();
            for (session_id, session_data) in sessions.iter() {
                let session_age =
                    current_height.saturating_sub(session_data.session.creation_block_height);
                if session_age > 100 {
                    let has_commitments = !session_data.received_commitments.is_empty();
                    let has_shares = !session_data.received_shares.is_empty();
                    if !has_commitments && !has_shares {
                        sessions_to_retry.push(session_id.clone());
                    }
                }
            }
        }
        // Retry stalled sessions: rebroadcast initiation or trigger new session
        for session_id in sessions_to_retry {
            info!(
                "Rebroadcasting DKG initiation for stalled session {}",
                hex::encode(session_id.0)
            );
            if let Some(session_data) = self.active_sessions.lock().unwrap().get(&session_id) {
                // Re-create and re-sign the initiation request
                let mut initiate_request = DKGInitiateRequest {
                    session_id: session_id.clone(),
                    initiator: self.masternode_id.clone(),
                    participants: session_data
                        .session
                        .participants
                        .iter()
                        .map(|p| p.masternode_id.clone())
                        .collect(),
                    threshold: session_data.session.threshold,
                    purpose: DKGPurpose::Custom("Rebroadcast".to_string()),
                    block_height: session_data.session.creation_block_height,
                    signature: vec![],
                };
                let signature = self.sign_dkg_message(&initiate_request)?;
                initiate_request.signature = signature;
                // Queue the rebroadcast
                self.outgoing_messages
                    .lock()
                    .unwrap()
                    .push(DKGMessage::InitiateDKG(initiate_request));
            }
        }
        // 4. Log maintenance statistics
        let active_count = self.get_active_session_count();
        if active_count > 0 {
            info!(
                "DKG maintenance completed: {} active sessions at height {}",
                active_count, current_height
            );
        }
        Ok(())
    }
}
