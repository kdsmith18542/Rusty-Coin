//! DKG Manager for coordinating threshold signature operations
//! 
//! This module provides a high-level interface for managing DKG sessions,
//! threshold signatures, and integration with the masternode network.

use std::collections::HashMap;
use bls12_381::Scalar;
use std::time::Instant;
use log::{info, warn};
use threshold_crypto::{PublicKey, SecretKeyShare, Signature, SignatureShare};
use hex;

use rusty_shared_types::dkg::{
    DKGSession, DKGSessionID, DKGParticipant, DKGCommitment, DKGSecretShare,
    DKGSessionState, DKGError, DKGParams,
    SignatureShare as DKGSignatureShare,
};
use crate::dkg::{DKGProtocol, DKGParticipantState};

/// Configuration for DKG operations
#[derive(Debug, Clone)]
pub struct DKGManagerConfig {
    /// Minimum number of participants required for DKG
    pub min_participants: u32,
    /// Maximum number of participants allowed in DKG
    pub max_participants: u32,
    /// Default threshold ratio (e.g., 0.67 for 2/3 threshold)
    pub default_threshold_ratio: f64,
    /// Timeout for DKG sessions in blocks
    pub session_timeout_blocks: u64,
    /// Maximum concurrent DKG sessions
    pub max_concurrent_sessions: usize,
    /// Enable automatic session cleanup
    pub enable_auto_cleanup: bool,
}

impl Default for DKGManagerConfig {
    fn default() -> Self {
        Self {
            min_participants: 3,
            max_participants: 100,
            default_threshold_ratio: 0.67,
            session_timeout_blocks: 1000,
            max_concurrent_sessions: 10,
            enable_auto_cleanup: true,
        }
    }
}

/// Status of a DKG session
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DKGSessionStatus {
    /// Session is being initialized
    Initializing,
    /// Waiting for participants to join
    WaitingForParticipants,
    /// Collecting commitments from participants
    CollectingCommitments { received: u32, total: u32 },
    /// Distributing secret shares
    DistributingShares,
    /// Processing complaints
    ProcessingComplaints { complaints: u32 },
    /// Processing justifications
    ProcessingJustifications,
    /// Session completed successfully
    Completed { group_public_key: PublicKey },
    /// Session failed
    Failed { reason: String },
    /// Session timed out
    TimedOut,
}

/// DKG Manager for coordinating threshold signature operations
pub struct DKGManager {
    config: DKGManagerConfig,
    /// Our DKG protocol instance
    dkg_protocol: DKGProtocol,
    /// Active DKG sessions
    active_sessions: HashMap<DKGSessionID, DKGSession>,
    /// Session status tracking
    session_status: HashMap<DKGSessionID, DKGSessionStatus>,
    /// Completed sessions with their keys
    completed_sessions: HashMap<DKGSessionID, (SecretKeyShare, PublicKey)>,
    /// Session creation times for timeout tracking
    session_timestamps: HashMap<DKGSessionID, Instant>,
    /// Current block height for timeout calculations
    current_block_height: u64,
}

impl DKGManager {
    /// Create a new DKG manager
    pub fn new(
        config: DKGManagerConfig,
        participant_index: u32,
        auth_secret_key: ed25519_dalek::Keypair,
    ) -> Self {
        let dkg_protocol = DKGProtocol::new(participant_index, auth_secret_key);
        
        Self {
            config,
            dkg_protocol,
            active_sessions: HashMap::new(),
            session_status: HashMap::new(),
            completed_sessions: HashMap::new(),
            session_timestamps: HashMap::new(),
            current_block_height: 0,
        }
    }

    /// Start a new DKG session
    pub fn start_dkg_session(
        &mut self,
        session_id: DKGSessionID,
        participants: Vec<DKGParticipant>,
        threshold: Option<u32>,
        params: &DKGParams,
    ) -> Result<(), DKGError> {
        // Validate parameters
        if participants.len() < self.config.min_participants as usize {
            return Err(DKGError::InsufficientParticipants);
        }

        if participants.len() > self.config.max_participants as usize {
            return Err(DKGError::CryptographicError("Too many participants".to_string()));
        }

        if self.active_sessions.len() >= self.config.max_concurrent_sessions {
            return Err(DKGError::CryptographicError("Too many concurrent sessions".to_string()));
        }

        // Calculate threshold if not provided
        let threshold = threshold.unwrap_or_else(|| {
            ((participants.len() as f64 * self.config.default_threshold_ratio).ceil() as u32)
                .max(1)
                .min(participants.len() as u32)
        });

        // Create new session
        let timeout_height = self.current_block_height + self.config.session_timeout_blocks;
        let session = DKGSession::new(session_id.clone(), participants, threshold, timeout_height, params);

        // Track session
        self.active_sessions.insert(session_id.clone(), session);
        self.session_status.insert(session_id.clone(), DKGSessionStatus::Initializing);
        self.session_timestamps.insert(session_id.clone(), Instant::now());

        info!("Started DKG session {} with {} participants, threshold {}", 
              hex::encode(&session_id), 
              self.active_sessions[&session_id].participants.len(), 
              threshold);

        Ok(())
    }

    /// Process a DKG commitment from a participant
    pub fn process_commitment(
        &mut self,
        session_id: &DKGSessionID,
        commitment: DKGCommitment,
        sender_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<(), DKGError> {
        let session = self.active_sessions.get_mut(session_id)
            .ok_or(DKGError::SessionNotFound)?;

        // Verify the commitment
        if !self.dkg_protocol.verify_commitment(&commitment, sender_public_key)? {
            return Err(DKGError::InvalidCommitment);
        }

        // Add commitment to session
        session.add_commitment(commitment)?;

        // Update status
        let total_participants = session.participants.len() as u32;
        let received_commitments = session.commitments.len() as u32;
        
        self.session_status.insert(
            session_id.clone(),
            DKGSessionStatus::CollectingCommitments {
                received: received_commitments,
                total: total_participants,
            }
        );

        // Check if we can advance to next phase
        if session.all_commitments_received() {
            session.advance_phase()?;
            self.session_status.insert(session_id.clone(), DKGSessionStatus::DistributingShares);
        }

        Ok(())
    }

    /// Generate our commitment for a DKG session
    pub fn generate_commitment(&mut self, session_id: &DKGSessionID) -> Result<DKGCommitment, DKGError> {
        let session = self.active_sessions.get(session_id)
            .ok_or(DKGError::SessionNotFound)?;

        self.dkg_protocol.generate_commitments(session)
    }

    /// Process a secret share received from another participant
    pub fn process_secret_share(
        &mut self,
        session_id: &DKGSessionID,
        share: DKGSecretShare,
        sender_commitment: &DKGCommitment,
        sender_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<(), DKGError> {
        let session = self.active_sessions.get_mut(session_id)
            .ok_or(DKGError::SessionNotFound)?;

        // Verify the share
        if !self.dkg_protocol.verify_secret_share(&share, sender_commitment, sender_public_key)? {
            return Err(DKGError::InvalidShare);
        }

        // Add share to session
        session.add_secret_share(share)?;

        // Check if we have enough shares to proceed to complaint phase
        if session.secret_shares.len() >= session.threshold as usize {
            session.state = DKGSessionState::ComplaintPhase;
            info!("DKG session {} received sufficient shares, moved to complaint phase", hex::encode(session_id));
            
            // Update session status to ProcessingComplaints
            self.session_status.insert(
                session_id.clone(),
                DKGSessionStatus::ProcessingComplaints { 
                    complaints: 0 // Initialize with 0 complaints
                }
            );
        }

        Ok(())
    }

    /// Complete a DKG session
    pub fn complete_dkg_session(&mut self, session_id: &DKGSessionID) -> Result<(SecretKeyShare, PublicKey), DKGError> {
        let mut session = self.active_sessions.remove(session_id)
            .ok_or(DKGError::SessionNotFound)?;

        if session.state != DKGSessionState::ComplaintPhase {
            return Err(DKGError::InvalidSessionState);
        }

        // Verify we have enough shares to complete the DKG
        if session.secret_shares.len() < session.threshold as usize {
            return Err(DKGError::InsufficientShares);
        }

        // Build participant state from shares
        let mut received_shares = HashMap::new();
        for (from, share) in &session.secret_shares {
            // Deserialize the encrypted share into a Scalar
            // Note: In a real implementation, we would decrypt the share first
            // For now, we'll assume the share is a direct serialization of the Scalar
            let scalar_bytes: [u8; 32] = share.encrypted_share.as_slice()
                .try_into()
                .map_err(|_| DKGError::InvalidShare)?;
            let scalar = Scalar::from_bytes(&scalar_bytes);
            if scalar.is_none().into() {
                return Err(DKGError::InvalidShare);
            }
            received_shares.insert(*from, scalar.unwrap());
        }

        let participant_state = DKGParticipantState {
            secret_coefficients: Vec::new(), // Not needed for verification
            public_commitments: Vec::new(),  // Not needed for verification
            received_shares,
            secret_key_share: None, // Will be set by complete_dkg
            group_public_key: None,  // Will be set by complete_dkg
        };

        // Update session state to Completed
        session.state = DKGSessionState::Completed;
        
        // Complete the DKG protocol to get the final keys
        let (secret_key_share, group_public_key) = self.dkg_protocol.complete_dkg(&session, &participant_state)?;
        
        // Store the completed session
        self.completed_sessions.insert(session_id.clone(), (secret_key_share.clone(), group_public_key.clone()));
        self.session_status.insert(session_id.clone(), DKGSessionStatus::Completed { group_public_key: group_public_key.clone() });
        self.session_timestamps.remove(session_id);

        info!("Completed DKG session {}", hex::encode(session_id));

        Ok((secret_key_share, group_public_key))
    }

    /// Create a signature share for a given message using a completed DKG session's key
    pub fn create_signature_share(
        &self,
        session_id: &DKGSessionID,
        message: &[u8],
    ) -> Result<DKGSignatureShare, DKGError> {
        let (secret_key_share, _) = self.completed_sessions.get(session_id)
            .ok_or(DKGError::SessionNotFound)?;
        
        self.dkg_protocol.create_signature_share(message, secret_key_share, session_id)
    }

    /// Aggregate signature shares to form a final threshold signature
    pub fn aggregate_signature_shares(
        &self,
        signature_shares: &HashMap<u32, SignatureShare>,
        threshold: u32,
    ) -> Result<Signature, DKGError> {
        self.dkg_protocol.aggregate_signature_shares(signature_shares, threshold)
    }

    /// Update the current block height (used for session timeouts)
    pub fn update_block_height(&mut self, block_height: u64) {
        self.current_block_height = block_height;
        self.cleanup_timed_out_sessions();
    }

    /// Get the status of a DKG session
    pub fn get_session_status(&self, session_id: &DKGSessionID) -> Option<DKGSessionStatus> {
        self.session_status.get(session_id).cloned()
    }

    /// Get a list of active DKG session IDs
    pub fn get_active_sessions(&self) -> Vec<DKGSessionID> {
        self.active_sessions.keys().cloned().collect()
    }

    /// Get a list of completed DKG session IDs
    pub fn get_completed_sessions(&self) -> Vec<DKGSessionID> {
        self.completed_sessions.keys().cloned().collect()
    }

    /// Get DKG manager statistics
    pub fn get_stats(&self) -> DKGManagerStats {
        DKGManagerStats {
            active_sessions: self.active_sessions.len(),
            completed_sessions: self.completed_sessions.len(),
            current_block_height: self.current_block_height,
            config: self.config.clone(),
        }
    }

    /// Clean up sessions that have timed out
    fn cleanup_timed_out_sessions(&mut self) {
        if !self.config.enable_auto_cleanup {
            return;
        }

        let mut timed_out_sessions = Vec::new();
        for (session_id, session) in &self.active_sessions {
            if self.current_block_height >= session.timeout_block_height {
                timed_out_sessions.push(session_id.clone());
            }
        }

        for session_id in timed_out_sessions {
            warn!("DKG session {} timed out", hex::encode(&session_id));
            self.session_status.insert(session_id.clone(), DKGSessionStatus::TimedOut);
            self.cleanup_session(&session_id);
        }
    }

    /// Clean up a specific DKG session
    pub fn cleanup_session(&mut self, session_id: &DKGSessionID) {
        self.active_sessions.remove(session_id);
        self.session_timestamps.remove(session_id);
    }

    /// Check if a session is in a state where it can sign (i.e., completed)
    pub fn can_sign(&self, session_id: &DKGSessionID) -> bool {
        matches!(self.session_status.get(session_id), Some(DKGSessionStatus::Completed { .. }))
    }

    /// Get the group public key for a completed session
    pub fn get_group_public_key(&self, session_id: &DKGSessionID) -> Option<PublicKey> {
        self.completed_sessions.get(session_id).map(|(_, pk)| pk.clone())
    }
}

/// Statistics about DKG manager operations
#[derive(Debug, Clone)]
pub struct DKGManagerStats {
    pub active_sessions: usize,
    pub completed_sessions: usize,
    pub current_block_height: u64,
    pub config: DKGManagerConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use rusty_shared_types::dkg::DKGParticipant;
    use crate::dkg::DKGProtocol;

    #[test]
    fn test_dkg_manager_start_session() {
        let config = DKGManagerConfig::default();
        let keypair = Keypair::generate(&mut OsRng);
        let mut manager = DKGManager::new(config, 1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 3, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let session_id = DKGSessionID::new([1u8; 32]);
        let params = DKGParams::default();

        manager.start_dkg_session(session_id.clone(), participants.clone(), None, &params).unwrap();

        assert!(manager.active_sessions.contains_key(&session_id));
        assert_eq!(manager.get_session_status(&session_id), Some(DKGSessionStatus::Initializing));
    }

    #[test]
    fn test_dkg_manager_process_commitment() {
        let config = DKGManagerConfig::default();
        let keypair = Keypair::generate(&mut OsRng);
        let mut manager = DKGManager::new(config, 1, keypair.clone());

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: keypair.public.to_bytes().to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 3, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let session_id = DKGSessionID::new([1u8; 32]);
        let params = DKGParams::default();

        manager.start_dkg_session(session_id.clone(), participants.clone(), None, &params).unwrap();

        let commitment = manager.dkg_protocol.generate_commitments(
            manager.active_sessions.get(&session_id).unwrap()
        ).unwrap();

        manager.process_commitment(&session_id, commitment.clone(), &keypair.public).unwrap();

        assert_eq!(
            manager.get_session_status(&session_id),
            Some(DKGSessionStatus::CollectingCommitments { received: 1, total: 3 })
        );
    }

    #[test]
    fn test_dkg_manager_complete_session() {
        let config = DKGManagerConfig::default();
        let keypair = Keypair::generate(&mut OsRng);
        let mut manager = DKGManager::new(config, 1, keypair.clone());

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: keypair.public.to_bytes().to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let session_id = DKGSessionID::new([1u8; 32]);
        let params = DKGParams::default();

        manager.start_dkg_session(session_id.clone(), participants.clone(), Some(2), &params).unwrap();

        // Simulate commitments and shares (simplified for test)
        let commitment1 = manager.dkg_protocol.generate_commitments(
            manager.active_sessions.get(&session_id).unwrap()
        ).unwrap();
        manager.process_commitment(&session_id, commitment1.clone(), &keypair.public).unwrap();

        let mut dkg_session = manager.active_sessions.get_mut(&session_id).unwrap();
        dkg_session.state = DKGSessionState::ShareDistribution;
        dkg_session.commitments.insert(1, commitment1);

        // Simulate receiving a share from participant 2
        let secret_key_share_2 = SecretKeyShare::new(threshold_crypto::Fr::from(10));
        let share_bytes = secret_key_share_2.to_bytes().to_vec();
        let dummy_signature = keypair.sign(&share_bytes).to_bytes().to_vec();

        dkg_session.add_secret_share(DKGSecretShare {
            from_participant: 2,
            to_participant: 1,
            encrypted_share: share_bytes,
            signature: dummy_signature,
        }).unwrap();

        dkg_session.state = DKGSessionState::ComplaintPhase;

        let (secret_key_share, group_public_key) = manager.complete_dkg_session(&session_id).unwrap();

        assert!(manager.completed_sessions.contains_key(&session_id));
        assert_eq!(manager.get_session_status(&session_id), Some(DKGSessionStatus::Completed { group_public_key: group_public_key.clone() }));
        assert!(!secret_key_share.to_bytes().is_empty());
        assert!(!group_public_key.to_bytes().is_empty());
    }

    #[test]
    fn test_dkg_manager_create_signature_share() {
        let config = DKGManagerConfig::default();
        let keypair = Keypair::generate(&mut OsRng);
        let mut manager = DKGManager::new(config, 1, keypair.clone());

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: keypair.public.to_bytes().to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let session_id = DKGSessionID::new([1u8; 32]);
        let params = DKGParams::default();

        manager.start_dkg_session(session_id.clone(), participants.clone(), Some(2), &params).unwrap();

        // Simulate completion
        manager.completed_sessions.insert(session_id.clone(), (SecretKeyShare::new(threshold_crypto::Fr::from(10)), PublicKey::new()));
        manager.session_status.insert(session_id.clone(), DKGSessionStatus::Completed { group_public_key: PublicKey::new() });

        let message = b"test message";
        let signature_share = manager.create_signature_share(&session_id, message).unwrap();

        assert_eq!(signature_share.from_participant, 1);
        assert!(!signature_share.signature_share.is_empty());
    }

    #[test]
    fn test_dkg_manager_aggregate_signature_shares() {
        let config = DKGManagerConfig::default();
        let keypair = Keypair::generate(&mut OsRng);
        let manager = DKGManager::new(config, 1, keypair);

        let mut signature_shares = HashMap::new();
        // Generate dummy signature shares for testing
        for i in 1..=2 {
            let secret_key_share = SecretKeyShare::new(threshold_crypto::Fr::from(i as u64));
            let message = b"test message";
            let signature_share = secret_key_share.sign(message);
            signature_shares.insert(i, signature_share);
        }

        let threshold = 2;
        let aggregated_signature = manager.aggregate_signature_shares(&signature_shares, threshold).unwrap();

        assert!(!aggregated_signature.to_bytes().is_empty());
    }

    #[test]
    fn test_dkg_manager_timeout_cleanup() {
        let mut config = DKGManagerConfig::default();
        config.session_timeout_blocks = 10; // Shorter timeout for testing
        let keypair = Keypair::generate(&mut OsRng);
        let mut manager = DKGManager::new(config, 1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let session_id = DKGSessionID::new([1u8; 32]);
        let params = DKGParams::default();

        manager.start_dkg_session(session_id.clone(), participants.clone(), None, &params).unwrap();

        // Advance block height past timeout
        manager.update_block_height(100);

        assert_eq!(manager.get_session_status(&session_id), Some(DKGSessionStatus::TimedOut));
        assert!(!manager.active_sessions.contains_key(&session_id));
    }
}
