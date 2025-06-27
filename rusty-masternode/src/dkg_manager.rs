//! DKG Manager for coordinating distributed key generation across masternode quorums

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{info, warn, error, debug};
use hex;

use rusty_shared_types::dkg::{
    DKGSession, DKGSessionID, DKGParticipant, DKGSessionState, DKGParams, 
    DKGCommitment, DKGSecretShare, DKGComplaint, DKGJustification, DKGError
};
use rusty_shared_types::dkg_messages::{
    DKGMessage, DKGInitiateRequest, DKGCommitmentMessage, DKGShareMessage,
    DKGComplaintMessage, DKGJustificationMessage, DKGCompleteMessage, DKGPurpose
};
use rusty_shared_types::{MasternodeID, Hash};
use rusty_crypto::dkg::DKGProtocol;
use threshold_crypto::{SecretKeyShare, PublicKey as ThresholdPublicKey};

/// DKG Manager handles all DKG sessions for a masternode
pub struct DKGManager {
    /// Our masternode ID
    masternode_id: MasternodeID,
    /// Our authentication private key
    auth_private_key: ed25519_dalek::SigningKey,
    /// Active DKG sessions we're participating in
    active_sessions: Arc<Mutex<HashMap<DKGSessionID, DKGSessionData>>>,
    /// DKG protocol parameters
    params: DKGParams,
    /// Message queue for outgoing DKG messages
    outgoing_messages: Arc<Mutex<Vec<DKGMessage>>>,
}

/// Internal data for a DKG session
struct DKGSessionData {
    session: DKGSession,
    protocol: DKGProtocol,
    our_participant_index: u32,
    received_commitments: HashMap<u32, DKGCommitment>,
    received_shares: HashMap<u32, DKGSecretShare>,
    our_secret_key_share: Option<SecretKeyShare>,
    group_public_key: Option<ThresholdPublicKey>,
}

impl DKGManager {
    /// Create a new DKG manager
    pub fn new(
        masternode_id: MasternodeID,
        auth_private_key: ed25519_dalek::SigningKey,
        params: DKGParams,
    ) -> Self {
        Self {
            masternode_id,
            auth_private_key: auth_private_key.clone(),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            params,
            outgoing_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Initiate a new DKG session
    pub fn initiate_dkg_session(
        &self,
        participants: Vec<MasternodeID>,
        purpose: DKGPurpose,
        current_block_height: u64,
    ) -> Result<DKGSessionID, DKGError> {
        let threshold = DKGSession::calculate_threshold(participants.len() as u32, self.params.threshold_percentage);
        
        // Generate session ID
        let mut session_data = Vec::new();
        session_data.extend_from_slice(&self.masternode_id.0);
        session_data.extend_from_slice(&current_block_height.to_le_bytes());
        for participant in &participants {
            session_data.extend_from_slice(&participant.0);
        }
        let session_id = DKGSessionID(blake3::hash(&session_data).into());

        // Create DKG participants
        let dkg_participants: Vec<DKGParticipant> = participants
            .iter()
            .enumerate()
            .map(|(index, mn_id)| DKGParticipant {
                masternode_id: mn_id.clone(),
                participant_index: index as u32,
                public_key: vec![0u8; 32], // TODO: Get actual public key from masternode list
            })
            .collect();

        // Find our participant index
        let our_index = dkg_participants
            .iter()
            .find(|p| p.masternode_id == self.masternode_id)
            .map(|p| p.participant_index)
            .ok_or(DKGError::InvalidParticipant)?;

        // Create DKG session
        let session = DKGSession::new(
            session_id.clone(),
            dkg_participants,
            threshold,
            current_block_height,
            &self.params,
        );

        // Create DKG protocol instance
        let protocol = DKGProtocol::new(our_index, self.auth_private_key.clone());

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

        // Create initiation request message
        let initiate_request = DKGInitiateRequest {
            session_id: session_id.clone(),
            initiator: self.masternode_id.clone(),
            participants,
            threshold,
            purpose,
            block_height: current_block_height,
            signature: vec![], // TODO: Sign the request
        };

        // Queue the message for broadcast
        {
            let mut messages = self.outgoing_messages.lock().unwrap();
            messages.push(DKGMessage::InitiateDKG(initiate_request));
        }

        info!("Initiated DKG session {} with {} participants", 
              hex::encode(session_id.0), threshold);

        Ok(session_id)
    }

    /// Handle incoming DKG message
    pub fn handle_dkg_message(&self, message: DKGMessage) -> Result<(), DKGError> {
        match message {
            DKGMessage::InitiateDKG(request) => self.handle_initiate_request(request),
            DKGMessage::CommitmentBroadcast(msg) => self.handle_commitment_message(msg),
            DKGMessage::ShareDistribution(msg) => self.handle_share_message(msg),
            DKGMessage::ComplaintBroadcast(msg) => self.handle_complaint_message(msg),
            DKGMessage::JustificationBroadcast(msg) => self.handle_justification_message(msg),
            DKGMessage::DKGComplete(msg) => self.handle_completion_message(msg),
            _ => {
                debug!("Ignoring non-DKG message type");
                Ok(())
            }
        }
    }

    /// Handle DKG initiation request
    fn handle_initiate_request(&self, request: DKGInitiateRequest) -> Result<(), DKGError> {
        // Check if we're in the participant list
        if !request.participants.contains(&self.masternode_id) {
            debug!("Not a participant in DKG session {}", hex::encode(request.session_id.0));
            return Ok(());
        }

        // TODO: Validate the request (signature, parameters, etc.)

        // Find our participant index
        let our_index = request.participants
            .iter()
            .position(|id| *id == self.masternode_id)
            .ok_or(DKGError::InvalidParticipant)? as u32;

        // Create DKG participants
        let dkg_participants: Vec<DKGParticipant> = request.participants
            .iter()
            .enumerate()
            .map(|(index, mn_id)| DKGParticipant {
                masternode_id: mn_id.clone(),
                participant_index: index as u32,
                public_key: vec![0u8; 32], // TODO: Get actual public key
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
        let protocol = DKGProtocol::new(our_index, self.auth_private_key.clone());

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

        info!("Joined DKG session {} as participant {}", 
              hex::encode(request.session_id.0), our_index);

        Ok(())
    }

    /// Handle commitment message
    fn handle_commitment_message(&self, msg: DKGCommitmentMessage) -> Result<(), DKGError> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let session_data = sessions.get_mut(&msg.session_id)
            .ok_or(DKGError::SessionNotFound)?;

        if session_data.session.state != DKGSessionState::CommitmentPhase {
            return Err(DKGError::InvalidSessionState);
        }

        // TODO: Verify the commitment signature

        // Store the commitment
        session_data.received_commitments.insert(
            msg.commitment.participant_index,
            msg.commitment.clone(),
        );

        // Add to session commitments
        session_data.session.commitments.insert(
            msg.commitment.participant_index,
            msg.commitment,
        );

        debug!("Received commitment from participant {} for session {}", 
               msg.commitment.participant_index, hex::encode(msg.session_id.0));

        // Check if we have all commitments
        if session_data.session.all_commitments_received() {
            session_data.session.advance_phase()?;
            info!("DKG session {} advanced to share distribution phase", 
                  hex::encode(msg.session_id.0));
        }

        Ok(())
    }

    /// Handle share distribution message
    fn handle_share_message(&self, msg: DKGShareMessage) -> Result<(), DKGError> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let session_data = sessions.get_mut(&msg.session_id)
            .ok_or(DKGError::SessionNotFound)?;

        if session_data.session.state != DKGSessionState::ShareDistribution {
            return Err(DKGError::InvalidSessionState);
        }

        // Process shares intended for us
        for share in &msg.shares {
            if share.to_participant == session_data.our_participant_index {
                // TODO: Verify the share
                session_data.received_shares.insert(share.from_participant, share.clone());
                debug!("Received share from participant {} for session {}", 
                       share.from_participant, hex::encode(msg.session_id.0));
            }
        }

        Ok(())
    }

    /// Handle complaint message
    fn handle_complaint_message(&self, msg: DKGComplaintMessage) -> Result<(), DKGError> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let session_data = sessions.get_mut(&msg.session_id)
            .ok_or(DKGError::SessionNotFound)?;

        if session_data.session.state != DKGSessionState::ComplaintPhase {
            return Err(DKGError::InvalidSessionState);
        }

        // TODO: Process the complaint
        session_data.session.complaints.push(msg.complaint);

        debug!("Received complaint for session {}", hex::encode(msg.session_id.0));

        Ok(())
    }

    /// Handle justification message
    fn handle_justification_message(&self, msg: DKGJustificationMessage) -> Result<(), DKGError> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let session_data = sessions.get_mut(&msg.session_id)
            .ok_or(DKGError::SessionNotFound)?;

        if session_data.session.state != DKGSessionState::JustificationPhase {
            return Err(DKGError::InvalidSessionState);
        }

        // TODO: Process the justification
        session_data.session.justifications.push(msg.justification);

        debug!("Received justification for session {}", hex::encode(msg.session_id.0));

        Ok(())
    }

    /// Handle completion message
    fn handle_completion_message(&self, msg: DKGCompleteMessage) -> Result<(), DKGError> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let session_data = sessions.get_mut(&msg.session_id)
            .ok_or(DKGError::SessionNotFound)?;

        // TODO: Verify the completion message and group public key
        session_data.session.group_public_key = Some(msg.group_public_key.clone());
        session_data.session.state = DKGSessionState::Completed;

        info!("DKG session {} completed successfully", hex::encode(msg.session_id.0));

        Ok(())
    }

    /// Get pending outgoing messages
    pub fn get_outgoing_messages(&self) -> Vec<DKGMessage> {
        let mut messages = self.outgoing_messages.lock().unwrap();
        let result = messages.clone();
        messages.clear();
        result
    }

    /// Get the status of a DKG session
    pub fn get_session_status(&self, session_id: &DKGSessionID) -> Option<DKGSessionState> {
        let sessions = self.active_sessions.lock().unwrap();
        sessions.get(session_id).map(|data| data.session.state.clone())
    }

    /// Get the group public key for a completed DKG session
    pub fn get_group_public_key(&self, session_id: &DKGSessionID) -> Option<Vec<u8>> {
        let sessions = self.active_sessions.lock().unwrap();
        sessions.get(session_id)
            .and_then(|data| data.session.group_public_key.clone())
    }

    /// Clean up expired or failed DKG sessions
    pub fn cleanup_expired_sessions(&self, current_block_height: u64) {
        let mut sessions = self.active_sessions.lock().unwrap();
        let expired_sessions: Vec<DKGSessionID> = sessions
            .iter()
            .filter(|(_, data)| data.session.is_timed_out(current_block_height))
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in expired_sessions {
            sessions.remove(&session_id);
            warn!("Removed expired DKG session {}", hex::encode(session_id.0));
        }
    }
}
