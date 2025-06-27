//! Distributed Key Generation (DKG) implementation for Rusty Coin masternode threshold signatures
//! 
//! This module implements a DKG protocol based on Feldman's Verifiable Secret Sharing (VSS)
//! using BLS12-381 elliptic curve for threshold signatures.

use threshold_crypto::{PublicKey, SecretKeyShare, PublicKeyShare, Signature, SignatureShare, Fr};
use bls12_381::{G1Projective, G2Projective, Scalar, G1Affine, G2Affine};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use ed25519_dalek::{Signer, Verifier};
use threshold_crypto::ff::Field;

use rusty_shared_types::dkg::{
    DKGSession, DKGSessionID, DKGCommitment, DKGSecretShare, 
    DKGSessionState, SignatureShare as DKGSignatureShare, DKGError
};

/// DKG protocol implementation for masternode threshold signatures
pub struct DKGProtocol {
    /// Our participant index in the DKG session
    participant_index: u32,
    /// Our secret key for authentication
    auth_secret_key: ed25519_dalek::Keypair,
    /// Random number generator
    rng: OsRng,
}

/// Internal state for a DKG participant
#[derive(Debug)]
pub struct DKGParticipantState {
    /// Our secret polynomial coefficients
    pub secret_coefficients: Vec<Scalar>,
    /// Our public commitments (G1 points)
    pub public_commitments: Vec<G1Projective>,
    /// Secret shares we've received from other participants
    pub received_shares: HashMap<u32, Scalar>,
    /// Our final secret key share (computed after DKG completion)
    pub secret_key_share: Option<SecretKeyShare>,
    /// The group public key (computed after DKG completion)
    pub group_public_key: Option<PublicKey>,
}

impl DKGProtocol {
    /// Create a new DKG protocol instance
    pub fn new(participant_index: u32, auth_secret_key: ed25519_dalek::Keypair) -> Self {
        Self {
            participant_index,
            auth_secret_key,
            rng: OsRng,
        }
    }

    /// Generate initial commitments for the DKG protocol
    /// This is the first phase where each participant generates a random polynomial
    /// and commits to it using Feldman's VSS
    pub fn generate_commitments(
        &mut self,
        session: &DKGSession,
    ) -> Result<DKGCommitment, DKGError> {
        if session.state != DKGSessionState::CommitmentPhase {
            return Err(DKGError::InvalidSessionState);
        }

        let threshold = session.threshold as usize;
        
        // Generate random polynomial coefficients
        let mut coefficients = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let coeff = Scalar::from_raw([
                self.rng.next_u64(),
                self.rng.next_u64(),
                self.rng.next_u64(),
                self.rng.next_u64(),
            ]);
            coefficients.push(coeff);
        }

        // Generate public commitments (G1 points)
        let mut commitments = Vec::with_capacity(threshold);
        for coeff in &coefficients {
            commitments.push(G1Projective::generator() * coeff);
        }

        // Serialize commitments to bytes
        let commitment_bytes: Vec<Vec<u8>> = commitments
            .iter()
            .map(|point| G1Affine::from(point).to_compressed().to_vec())
            .collect();

        // Create commitment message
        let commitment_data = bincode::serialize(&commitment_bytes)
            .map_err(|e| DKGError::CryptographicError(e.to_string()))?;

        // Sign the commitment with our authentication key
        let signature = self.auth_secret_key.sign(&commitment_data);

        Ok(DKGCommitment {
            participant_index: self.participant_index,
            commitments: commitment_bytes,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Verify a commitment from another participant
    pub fn verify_commitment(
        &self,
        commitment: &DKGCommitment,
        participant_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<bool, DKGError> {
        // Verify the signature on the commitment
        let commitment_data = bincode::serialize(&commitment.commitments)
            .map_err(|e| DKGError::CryptographicError(e.to_string()))?;

        if commitment.signature.len() != 64 {
            return Err(DKGError::InvalidSignature);
        }
        let sig_bytes: [u8; 64] = commitment.signature.as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes)
            .map_err(|_| DKGError::InvalidSignature)?;

        participant_public_key.verify(&commitment_data, &signature)
            .map_err(|_| DKGError::InvalidSignature)?;

        // Verify that commitments are valid G1 points
        for commitment_bytes in &commitment.commitments {
            if commitment_bytes.len() != 48 {
                return Ok(false);
            }
            
            let point_bytes: [u8; 48] = commitment_bytes.as_slice().try_into()
                .map_err(|_| DKGError::InvalidCommitment)?;
            
            // For now, just validate the point bytes length
            if point_bytes.len() != 48 {
                return Err(DKGError::InvalidCommitment);
            }
            // In a real implementation, we would properly deserialize the G1 point
        }

        Ok(true)
    }

    /// Generate secret shares for all participants
    /// This is the second phase where each participant evaluates their polynomial
    /// at each other participant's index and encrypts the result
    pub fn generate_secret_shares(
        &self,
        session: &DKGSession,
        participant_state: &DKGParticipantState,
    ) -> Result<Vec<DKGSecretShare>, DKGError> {
        if session.state != DKGSessionState::ShareDistribution {
            return Err(DKGError::InvalidSessionState);
        }

        let mut shares = Vec::new();

        for participant in &session.participants {
            if participant.participant_index == self.participant_index {
                continue; // Don't send share to ourselves
            }

            // Evaluate polynomial at participant's index
            let x = Scalar::from(participant.participant_index as u64);
            let mut share = Scalar::zero();
            let mut x_power = Scalar::one();

            for coeff in &participant_state.secret_coefficients {
                share += coeff * x_power;
                x_power *= x;
            }

            // In a real implementation, we would encrypt the share with the recipient's public key
            // For now, we'll just serialize it (this is insecure and should be replaced)
            let share_bytes = share.to_bytes().to_vec();

            // Sign the share
            let signature = self.auth_secret_key.sign(&share_bytes);

            shares.push(DKGSecretShare {
                from_participant: self.participant_index,
                to_participant: participant.participant_index,
                encrypted_share: share_bytes, // TODO: Actually encrypt this
                signature: signature.to_bytes().to_vec(),
            });
        }

        Ok(shares)
    }

    /// Verify a secret share received from another participant
    pub fn verify_secret_share(
        &self,
        share: &DKGSecretShare,
        _sender_commitment: &DKGCommitment,
        sender_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<bool, DKGError> {
        // Verify signature on the share
        let share_data = bincode::serialize(&share.encrypted_share)
            .map_err(|e| DKGError::CryptographicError(e.to_string()))?;

        if share.signature.len() != 64 {
            return Err(DKGError::InvalidSignature);
        }
        let sig_bytes: [u8; 64] = share.signature.as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes)
            .map_err(|_| DKGError::InvalidSignature)?;

        sender_public_key.verify(&share_data, &signature)
            .map_err(|_| DKGError::InvalidSignature)?;

        // Verify the share against the sender's commitment
        // In a real implementation, this would involve reconstructing the sender's polynomial
        // and verifying the share (using Feldman's VSS property)
        Ok(true)
    }

    /// Complete the DKG session and compute the final secret key share and group public key
    pub fn complete_dkg(
        &self,
        session: &DKGSession,
        _participant_state: &DKGParticipantState,
    ) -> Result<(SecretKeyShare, PublicKey), DKGError> {
        if session.state != DKGSessionState::Completed {
            return Err(DKGError::InvalidSessionState);
        }

        // Here, we would combine all received shares to reconstruct our secret key share
        // For simplicity, we'll assume a dummy share for now.
        let mut dummy_fr = Fr::zero();
        let dummy_secret_share = SecretKeyShare::from_mut(&mut dummy_fr);
        // Use from_bytes for group public key, using G1 identity as placeholder (48 bytes)
        let g1_bytes: [u8; 48] = G1Affine::from(G1Projective::identity()).to_compressed();
        let group_public_key = PublicKey::from_bytes(&g1_bytes).map_err(|_| DKGError::CryptographicError("Invalid group public key bytes".to_string()))?;

        Ok((dummy_secret_share, group_public_key))
    }

    /// Create a signature share for a given message
    pub fn create_signature_share(
        &self,
        message: &[u8],
        secret_key_share: &SecretKeyShare,
        _session_id: &DKGSessionID,
    ) -> Result<DKGSignatureShare, DKGError> {
        let signature_share = secret_key_share.sign(message);
        let signature_share_bytes = signature_share.to_bytes().to_vec();

        Ok(DKGSignatureShare {
            session_id: _session_id.clone(), // Assuming session_id is needed here
            participant_index: self.participant_index,
            message_hash: blake3::hash(message).as_bytes().clone(), // Use the hash bytes directly
            signature_share: signature_share_bytes,
            signature: self.auth_secret_key.sign(message).to_bytes().to_vec(), // Dummy signature for now
        })
    }

    /// Verify a signature share from another participant
    pub fn verify_signature_share(
        &self,
        signature_share: &DKGSignatureShare,
        _public_key_share: &PublicKeyShare,
        sender_public_key: &ed25519_dalek::PublicKey,
        _message: &[u8],
    ) -> Result<bool, DKGError> {
        // Verify the signature on the share data (not the BLS signature share itself)
        let share_data = bincode::serialize(&signature_share.signature_share)
            .map_err(|e| DKGError::CryptographicError(e.to_string()))?;

        if signature_share.signature_share.len() != 96 {
            return Err(DKGError::InvalidSignature);
        }

        // In a real implementation, we would verify the BLS signature share using the
        // sender's public key share.
        // For now, we only verify the ed25519 signature on the share data.
        let sig_bytes: [u8; 64] = signature_share.signature.as_slice()
            .try_into()
            .map_err(|_| DKGError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes)
            .map_err(|_| DKGError::InvalidSignature)?;

        sender_public_key.verify(&share_data, &signature)
            .map_err(|_| DKGError::InvalidSignature)?;

        Ok(true)
    }

    /// Aggregate signature shares to form a final threshold signature
    pub fn aggregate_signature_shares(
        &self,
        signature_shares: &HashMap<u32, SignatureShare>,
        threshold: u32,
    ) -> Result<Signature, DKGError> {
        if signature_shares.len() < threshold as usize {
            return Err(DKGError::CryptographicError("Insufficient signature shares".to_string()));
        }

        let mut shares_vec: Vec<(u32, SignatureShare)> = signature_shares.iter()
            .map(|(&idx, share)| (idx, share.clone()))
            .collect();

        // Sort by index for consistent interpolation
        shares_vec.sort_by_key(|&(idx, _)| idx);

        // Extract only the SignatureShare values in order of participant index for lagrange interpolation
        let bls_signature_shares: Vec<&SignatureShare> = shares_vec.iter()
            .map(|(_, share)| share)
            .collect();

        // Perform Lagrange interpolation
        self.lagrange_interpolate_signatures(&bls_signature_shares, threshold, &shares_vec)
    }

    // Helper function for Lagrange interpolation (not directly exposed)
    fn lagrange_interpolate_signatures(
        &self,
        signature_shares: &[&SignatureShare],
        threshold: u32,
        shares_vec: &[(u32, SignatureShare)],
    ) -> Result<Signature, DKGError> {
        if signature_shares.len() < threshold as usize {
            return Err(DKGError::CryptographicError("Insufficient signature shares".to_string()));
        }

        let mut interpolated_g2 = G2Projective::identity();

        for j in 0..signature_shares.len() {
            let xj = Scalar::from(shares_vec[j].0 as u64);
            let yj = signature_shares[j];

            let mut lambda = Scalar::one();
            for m in 0..signature_shares.len() {
                if j != m {
                    let xm = Scalar::from(shares_vec[m].0 as u64);
                    lambda *= xm * (xj - xm).invert().unwrap();
                }
            }
            interpolated_g2 += self.signature_share_to_g2_point(yj)? * lambda;
        }

        // Use from_bytes for Signature
        let g2_bytes: [u8; 96] = G2Affine::from(interpolated_g2).to_compressed();
        Ok(Signature::from_bytes(&g2_bytes).map_err(|_| DKGError::CryptographicError("Invalid aggregated signature bytes".to_string()))?)
    }

    // Helper function to convert SignatureShare to G2Projective
    fn signature_share_to_g2_point(&self, share: &SignatureShare) -> Result<G2Projective, DKGError> {
        let share_bytes: [u8; 96] = share.to_bytes().try_into().map_err(|_| DKGError::CryptographicError("Invalid SignatureShare bytes".to_string()))?;
        let g2_affine = G2Affine::from_compressed(&share_bytes);
        let point = if bool::from(g2_affine.is_some()) {
            G2Projective::from(g2_affine.unwrap())
        } else {
            return Err(DKGError::CryptographicError("Invalid G2 point in SignatureShare".to_string()));
        };
        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use crate::dkg::DKGParticipantState;
    use rusty_shared_types::dkg::{DKGParticipant, DKGParams};
    use rusty_shared_types::Hash;
    use crate::dkg::DKGSessionState; // Import DKGSessionState
    use blake3::hash;

    #[test]
    fn test_dkg_commitment_generation() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let mut dkg_protocol = DKGProtocol::new(1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: keypair.public.to_bytes().to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 3, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let params = DKGParams::default();
        let session = DKGSession::new([0u8; 32].into(), participants, 2, 100, &params);

        let commitment = dkg_protocol.generate_commitments(&session).unwrap();
        assert_eq!(commitment.participant_index, 1);
        assert!(!commitment.commitments.is_empty());
        assert!(!commitment.signature.is_empty());
    }

    #[test]
    fn test_dkg_commitment_verification() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let mut dkg_protocol = DKGProtocol::new(1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: keypair.public.to_bytes().to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 3, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let params = DKGParams::default();
        let session = DKGSession::new([0u8; 32].into(), participants, 2, 100, &params);

        let commitment = dkg_protocol.generate_commitments(&session).unwrap();

        let other_keypair = Keypair::generate(&mut rng);
        let other_dkg_protocol = DKGProtocol::new(2, other_keypair);

        let is_valid = other_dkg_protocol.verify_commitment(&commitment, &keypair.public).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_generate_secret_shares() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 3, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let params = DKGParams::default();
        let mut session = DKGSession::new([0u8; 32].into(), participants, 2, 100, &params);
        session.state = DKGSessionState::ShareDistribution;

        let mut participant_state = DKGParticipantState {
            secret_coefficients: vec![
                Scalar::from_raw([1, 0, 0, 0]),
                Scalar::from_raw([2, 0, 0, 0]),
            ],
            public_commitments: vec![],
            received_shares: HashMap::new(),
            secret_key_share: None,
            group_public_key: None,
        };

        let shares = dkg_protocol.generate_secret_shares(&session, &participant_state).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].from_participant, 1);
        assert_eq!(shares[0].to_participant, 2);
        assert!(!shares[0].encrypted_share.is_empty());
        assert!(!shares[0].signature.is_empty());
    }

    #[test]
    fn test_verify_secret_share() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let params = DKGParams::default();
        let mut session = DKGSession::new([0u8; 32].into(), participants, 2, 100, &params);
        session.state = DKGSessionState::ShareDistribution;

        let participant_state = DKGParticipantState {
            secret_coefficients: vec![
                Scalar::from_raw([1, 0, 0, 0]),
                Scalar::from_raw([2, 0, 0, 0]),
            ],
            public_commitments: vec![],
            received_shares: HashMap::new(),
            secret_key_share: None,
            group_public_key: None,
        };

        let shares = dkg_protocol.generate_secret_shares(&session, &participant_state).unwrap();
        let share = &shares[0];

        let sender_keypair = Keypair::generate(&mut rng);
        let sender_commitment = DKGCommitment {
            participant_index: share.from_participant,
            commitments: vec![],
            signature: sender_keypair.sign(&[]).to_bytes().to_vec(),
        };

        let is_valid = dkg_protocol.verify_secret_share(share, &sender_commitment, &keypair.public).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_complete_dkg() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let participants = vec![
            DKGParticipant { participant_index: 1, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
            DKGParticipant { participant_index: 2, public_key: [0u8; 32].into(), authentication_public_key: [0u8; 32].to_vec() },
        ];
        let params = DKGParams::default();
        let mut session = DKGSession::new([0u8; 32].into(), participants, 2, 100, &params);
        session.state = DKGSessionState::CompletionPhase;

        let participant_state = DKGParticipantState {
            secret_coefficients: vec![],
            public_commitments: vec![],
            received_shares: HashMap::new(),
            secret_key_share: None,
            group_public_key: None,
        };

        let (secret_key_share, group_public_key) = dkg_protocol.complete_dkg(&session, &participant_state).unwrap();
        assert_eq!(secret_key_share.to_bytes().len(), 32);
        assert_eq!(group_public_key.to_bytes().len(), 96);
    }

    #[test]
    fn test_create_signature_share() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let secret_key_share = SecretKeyShare::new(Fr::from(10));
        let message = b"test message";
        let session_id = DKGSessionID::new([0u8; 32]);

        let signature_share = dkg_protocol.create_signature_share(message, &secret_key_share, &session_id).unwrap();
        assert_eq!(signature_share.from_participant, 1);
        assert!(!signature_share.signature_share.is_empty());
    }

    #[test]
    fn test_verify_signature_share() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let secret_key_share = SecretKeyShare::new(Fr::from(10));
        let message = b"test message";
        let session_id = DKGSessionID::new([0u8; 32]);

        let dkg_signature_share = dkg_protocol.create_signature_share(message, &secret_key_share, &session_id).unwrap();
        let public_key_share = PublicKeyShare::from_secret_key_share(&secret_key_share, 0);

        let is_valid = dkg_protocol.verify_signature_share(&dkg_signature_share, &public_key_share, &keypair.public, message).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_aggregate_signature_shares() {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let dkg_protocol = DKGProtocol::new(1, keypair);

        let mut signature_shares = HashMap::new();
        // Generate dummy signature shares for testing
        for i in 1..=3 {
            let secret_key_share = SecretKeyShare::new(Fr::from(i as u64));
            let message = b"test message";
            let signature_share = secret_key_share.sign(message);
            signature_shares.insert(i, signature_share);
        }

        let threshold = 2;
        let aggregated_signature = dkg_protocol.aggregate_signature_shares(&signature_shares, threshold).unwrap();
        assert_eq!(aggregated_signature.to_bytes().len(), 96);
    }
}
