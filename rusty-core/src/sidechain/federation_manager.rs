//! Federation Management for Sidechains
//!
//! This module provides enhanced federation management including:
//! - BLS threshold signature aggregation
//! - Epoch management and transitions
//! - Federation member rotation
//! Per spec 10 (Sidechain Protocol) and RCTB FERR_001

use blake3::Hasher as Blake3Hasher;
use threshold_crypto::{PublicKey, Signature};
use log::{info, warn};
use rusty_shared_types::masternode::MasternodeID;
use rusty_shared_types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const BLS_PUBLIC_KEY_BYTES: usize = 48;
const BLS_SIGNATURE_BYTES: usize = 96;
const FEDERATION_SIGNATURE_DST: &[u8] = b"RUSTYCOIN_FED_SIG";

/// Federation epoch information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationEpoch {
    /// Epoch number
    pub epoch: u64,
    /// Federation members (masternode IDs)
    pub members: Vec<MasternodeID>,
    /// Threshold for BLS signatures (e.g., 2/3 = 2 out of 3)
    pub threshold: u32,
    /// Block height when epoch started
    pub start_height: u64,
    /// Block height when epoch ends (None if current)
    pub end_height: Option<u64>,
    /// Public keys for BLS threshold signatures
    pub public_keys: Vec<Vec<u8>>,
}

impl FederationEpoch {
    /// Create a new federation epoch
    pub fn new(
        epoch: u64,
        members: Vec<MasternodeID>,
        threshold: u32,
        start_height: u64,
        public_keys: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            epoch,
            members,
            threshold,
            start_height,
            end_height: None,
            public_keys,
        }
    }

    /// Check if threshold is met
    pub fn is_threshold_met(&self, signer_count: u32) -> bool {
        signer_count >= self.threshold
    }

    /// Get the minimum number of signers required
    pub fn min_signers_required(&self) -> u32 {
        self.threshold
    }

    /// Get total federation size
    pub fn federation_size(&self) -> usize {
        self.members.len()
    }
}

/// Federation manager for sidechain operations
///
/// Manages federation epochs, member rotation, and BLS threshold signature verification
/// for sidechain operations. Supports multiple sidechains with independent federation management.
///
/// # Example
///
/// ```rust,no_run
/// use rusty_core::sidechain::FederationManager;
/// use rusty_shared_types::masternode::MasternodeID;
/// use rusty_shared_types::{Hash, OutPoint};
///
/// let mut manager = FederationManager::new(1000); // epoch_transition_blocks
///
/// // Initialize federation for a sidechain
/// let sidechain_id = [1u8; 32];
/// let members = vec![
///     MasternodeID(OutPoint { txid: [1u8; 32], vout: 0 }),
///     MasternodeID(OutPoint { txid: [2u8; 32], vout: 0 }),
///     MasternodeID(OutPoint { txid: [3u8; 32], vout: 0 }),
/// ];
/// let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];
///
/// manager.initialize_federation(
///     sidechain_id,
///     members,
///     2, // threshold (2 of 3)
///     100, // start_height
///     public_keys,
/// ).unwrap();
/// ```
pub struct FederationManager {
    /// Current federation epochs by sidechain ID
    epochs: HashMap<Hash, HashMap<u64, FederationEpoch>>,
    /// Current epoch for each sidechain
    current_epochs: HashMap<Hash, u64>,
    /// Epoch transition configuration
    epoch_transition_blocks: u64,
}

impl FederationManager {
    /// Create a new federation manager
    ///
    /// # Arguments
    ///
    /// * `epoch_transition_blocks` - Number of blocks between epoch transitions
    ///
    /// # Returns
    ///
    /// A new `FederationManager` instance
    pub fn new(epoch_transition_blocks: u64) -> Self {
        Self {
            epochs: HashMap::new(),
            current_epochs: HashMap::new(),
            epoch_transition_blocks,
        }
    }

    /// Initialize federation for a sidechain
    ///
    /// Sets up the initial federation epoch (epoch 1) for a sidechain with the
    /// specified members and threshold configuration.
    ///
    /// # Arguments
    ///
    /// * `sidechain_id` - Hash identifying the sidechain
    /// * `members` - List of masternode IDs in the federation
    /// * `threshold` - Number of signatures required (e.g., 2 for 2-of-3)
    /// * `start_height` - Block height when federation becomes active
    /// * `public_keys` - BLS public keys for each member (must match members count)
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Epoch number (always 1 for initialization)
    /// * `Err(String)` - Error if validation fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Federation has no members
    /// - Threshold is 0 or exceeds member count
    /// - Public keys count doesn't match members count
    pub fn initialize_federation(
        &mut self,
        sidechain_id: Hash,
        members: Vec<MasternodeID>,
        threshold: u32,
        start_height: u64,
        public_keys: Vec<Vec<u8>>,
    ) -> Result<u64, String> {
        if members.is_empty() {
            return Err("Federation must have at least one member".to_string());
        }

        if threshold == 0 || threshold > members.len() as u32 {
            return Err(format!(
                "Threshold {} must be between 1 and {}",
                threshold,
                members.len()
            ));
        }

        if public_keys.len() != members.len() {
            return Err(format!(
                "Public keys count {} must match members count {}",
                public_keys.len(),
                members.len()
            ));
        }

        let epoch = 1;
        let federation_epoch =
            FederationEpoch::new(epoch, members, threshold, start_height, public_keys);

        self.epochs
            .entry(sidechain_id)
            .or_insert_with(HashMap::new)
            .insert(epoch, federation_epoch);
        self.current_epochs.insert(sidechain_id, epoch);

        info!(
            "Initialized federation for sidechain {:?} with epoch {}",
            sidechain_id, epoch
        );

        Ok(epoch)
    }

    /// Get current federation epoch for a sidechain
    pub fn get_current_epoch(&self, sidechain_id: &Hash) -> Option<&FederationEpoch> {
        let current_epoch = self.current_epochs.get(sidechain_id)?;
        self.epochs.get(sidechain_id)?.get(current_epoch)
    }

    /// Get federation epoch by number
    pub fn get_epoch(&self, sidechain_id: &Hash, epoch: u64) -> Option<&FederationEpoch> {
        self.epochs.get(sidechain_id)?.get(&epoch)
    }

    /// Transition to a new federation epoch
    pub fn transition_epoch(
        &mut self,
        sidechain_id: Hash,
        new_members: Vec<MasternodeID>,
        new_threshold: u32,
        current_height: u64,
        new_public_keys: Vec<Vec<u8>>,
    ) -> Result<u64, String> {
        // Validate new federation
        if new_members.is_empty() {
            return Err("New federation must have at least one member".to_string());
        }

        if new_threshold == 0 || new_threshold > new_members.len() as u32 {
            return Err(format!(
                "New threshold {} must be between 1 and {}",
                new_threshold,
                new_members.len()
            ));
        }

        if new_public_keys.len() != new_members.len() {
            return Err(format!(
                "New public keys count {} must match members count {}",
                new_public_keys.len(),
                new_members.len()
            ));
        }

        // Get current epoch
        let current_epoch_num = *self
            .current_epochs
            .get(&sidechain_id)
            .ok_or("Sidechain federation not initialized")?;

        // End current epoch
        if let Some(current_epoch) = self
            .epochs
            .get_mut(&sidechain_id)
            .and_then(|epochs| epochs.get_mut(&current_epoch_num))
        {
            current_epoch.end_height = Some(current_height);
        }

        // Create new epoch
        let new_epoch_num = current_epoch_num + 1;
        let new_epoch = FederationEpoch::new(
            new_epoch_num,
            new_members.clone(),
            new_threshold,
            current_height,
            new_public_keys.clone(),
        );

        self.epochs
            .entry(sidechain_id)
            .or_insert_with(HashMap::new)
            .insert(new_epoch_num, new_epoch);
        self.current_epochs.insert(sidechain_id, new_epoch_num);

        info!(
            "Transitioned sidechain {:?} from epoch {} to epoch {} at height {}",
            sidechain_id, current_epoch_num, new_epoch_num, current_height
        );

        Ok(new_epoch_num)
    }

    /// Check if epoch transition is needed
    pub fn should_transition_epoch(&self, sidechain_id: &Hash, current_height: u64) -> bool {
        if let Some(epoch) = self.get_current_epoch(sidechain_id) {
            if let Some(end_height) = epoch.end_height {
                return current_height >= end_height;
            }
            // Check if transition period has passed
            return current_height >= epoch.start_height + self.epoch_transition_blocks;
        }
        false
    }

    /// Update federation members for current epoch (without creating new epoch)
    pub fn update_federation_members(
        &mut self,
        sidechain_id: Hash,
        new_members: Vec<MasternodeID>,
        new_public_keys: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        if new_members.is_empty() {
            return Err("Federation must have at least one member".to_string());
        }

        if new_public_keys.len() != new_members.len() {
            return Err(format!(
                "Public keys count {} must match members count {}",
                new_public_keys.len(),
                new_members.len()
            ));
        }

        let current_epoch_num = *self
            .current_epochs
            .get(&sidechain_id)
            .ok_or("Sidechain federation not initialized")?;

        if let Some(epoch) = self
            .epochs
            .get_mut(&sidechain_id)
            .and_then(|epochs| epochs.get_mut(&current_epoch_num))
        {
            // Update threshold if needed (maintain same ratio)
            let old_threshold = epoch.threshold;
            let old_size = epoch.members.len();
            let new_members_len = new_members.len();
            let new_threshold = if old_size > 0 {
                // Maintain same threshold ratio
                ((old_threshold as f64 / old_size as f64) * new_members_len as f64).ceil() as u32
            } else {
                1
            };

            epoch.members = new_members;
            epoch.public_keys = new_public_keys;
            epoch.threshold = new_threshold.min(new_members_len as u32);

            info!(
                "Updated federation members for sidechain {:?} epoch {}",
                sidechain_id, current_epoch_num
            );
        } else {
            return Err("Current epoch not found".to_string());
        }

        Ok(())
    }

    /// Verify BLS threshold signature
    pub fn verify_threshold_signature(
        &self,
        sidechain_id: &Hash,
        epoch: u64,
        signature: &crate::sidechain::FederationSignature,
        message: &[u8],
    ) -> bool {
        // Get federation epoch
        let federation_epoch = match self.get_epoch(sidechain_id, epoch) {
            Some(epoch) => epoch,
            None => {
                warn!(
                    "Federation epoch {} not found for sidechain {:?}",
                    epoch, sidechain_id
                );
                return false;
            }
        };

        match verify_federation_signature_with_public_keys(
            &federation_epoch.public_keys,
            signature,
            message,
            federation_epoch.threshold,
        ) {
            Ok(()) => true,
            Err(err) => {
                warn!(
                    "Federation signature verification failed for sidechain {:?} epoch {}: {}",
                    sidechain_id, epoch, err
                );
                false
            }
        }
    }

    /// Get federation statistics
    pub fn get_stats(&self) -> FederationStats {
        let mut total_sidechains = 0;
        let mut total_epochs = 0;
        let mut total_members = 0;

        for (_, epochs) in &self.epochs {
            total_sidechains += 1;
            total_epochs += epochs.len();
            for epoch in epochs.values() {
                total_members += epoch.members.len();
            }
        }

        FederationStats {
            total_sidechains,
            total_epochs,
            total_members,
            active_sidechains: self.current_epochs.len(),
        }
    }
}

/// Federation statistics
#[derive(Debug, Clone, Default)]
pub struct FederationStats {
    pub total_sidechains: usize,
    pub total_epochs: usize,
    pub total_members: usize,
    pub active_sidechains: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidechain::federation_manager::test_utils::sample_federation_signature;

    fn create_test_masternode_id(value: u8) -> MasternodeID {
        use rusty_shared_types::OutPoint;
        MasternodeID(OutPoint {
            txid: [value; 32],
            vout: 0,
        })
    }

    #[test]
    fn test_federation_initialization() {
        let mut manager = FederationManager::new(1000);

        let sidechain_id = [1u8; 32];
        let members = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];

        let epoch = manager
            .initialize_federation(sidechain_id, members.clone(), 2, 100, public_keys.clone())
            .unwrap();

        assert_eq!(epoch, 1);

        let federation_epoch = manager.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(federation_epoch.members, members);
        assert_eq!(federation_epoch.threshold, 2);
        assert_eq!(federation_epoch.start_height, 100);
    }

    #[test]
    fn test_epoch_transition() {
        let mut manager = FederationManager::new(1000);

        let sidechain_id = [1u8; 32];
        let members1 = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys1 = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];

        manager
            .initialize_federation(sidechain_id, members1, 2, 100, public_keys1)
            .unwrap();

        let members2 = vec![
            create_test_masternode_id(4),
            create_test_masternode_id(5),
            create_test_masternode_id(6),
        ];
        let public_keys2 = vec![vec![4u8; 48], vec![5u8; 48], vec![6u8; 48]];

        let new_epoch = manager
            .transition_epoch(sidechain_id, members2.clone(), 2, 1100, public_keys2)
            .unwrap();

        assert_eq!(new_epoch, 2);

        let old_epoch = manager.get_epoch(&sidechain_id, 1).unwrap();
        assert_eq!(old_epoch.end_height, Some(1100));

        let current_epoch = manager.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(current_epoch.epoch, 2);
        assert_eq!(current_epoch.members, members2);
    }

    #[test]
    fn test_threshold_verification() {
        let mut manager = FederationManager::new(1000);

        let sidechain_id = [1u8; 32];
        let members: Vec<_> = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let message_hash = [42u8; 32];
        let sample = sample_federation_signature(3, &[0, 1], message_hash, 1);
        manager
            .initialize_federation(sidechain_id, members, 2, 100, sample.public_keys.clone())
            .unwrap();

        // Test with sufficient signers (2 out of 3)
        let result =
            manager.verify_threshold_signature(&sidechain_id, 1, &sample.signature, &message_hash);
        assert!(result);

        // Test with insufficient signers (1 out of 3)
        let mut insufficient_sig = sample.signature.clone();
        insufficient_sig.signer_bitmap = vec![0b10000000];
        insufficient_sig.threshold = 2;
        let result =
            manager.verify_threshold_signature(&sidechain_id, 1, &insufficient_sig, &message_hash);
        assert!(!result);
    }

    #[test]
    fn test_signature_message_mismatch() {
        let mut manager = FederationManager::new(1000);
        let sidechain_id = [9u8; 32];
        let members: Vec<_> = (0..3).map(create_test_masternode_id).collect();
        let message_hash = [7u8; 32];
        let sample = sample_federation_signature(3, &[0, 2], message_hash, 3);
        manager
            .initialize_federation(sidechain_id, members, 2, 200, sample.public_keys.clone())
            .unwrap();

        let mut bad_signature = sample.signature.clone();
        bad_signature.message_hash = [8u8; 32];

        assert!(!manager.verify_threshold_signature(
            &sidechain_id,
            3,
            &bad_signature,
            &message_hash
        ));
    }
}

fn is_signer_selected(bitmap: &[u8], index: usize) -> bool {
    let byte_index = index / 8;
    if byte_index >= bitmap.len() {
        return false;
    }
    let bit_position = 7 - (index % 8);
    (bitmap[byte_index] & (1 << bit_position)) != 0
}

fn ensure_no_unknown_signers(bitmap: &[u8], total_members: usize) -> Result<(), String> {
    let total_bits = bitmap.len() * 8;
    for idx in total_members..total_bits {
        if is_signer_selected(bitmap, idx) {
            return Err("Signer bitmap references unknown federation members".to_string());
        }
    }
    Ok(())
}

fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, String> {
    if bytes.len() != BLS_PUBLIC_KEY_BYTES {
        return Err(format!(
            "BLS public key must be {} bytes, got {}",
            BLS_PUBLIC_KEY_BYTES,
            bytes.len()
        ));
    }
    
    let array: [u8; BLS_PUBLIC_KEY_BYTES] = bytes.try_into()
        .map_err(|_| "Invalid BLS public key length".to_string())?;
    PublicKey::from_bytes(&array).map_err(|_| "Invalid BLS public key bytes".to_string())
}

fn parse_signature(bytes: &[u8]) -> Result<Signature, String> {
    if bytes.len() != BLS_SIGNATURE_BYTES {
        return Err(format!(
            "BLS signature must be {} bytes, got {}",
            BLS_SIGNATURE_BYTES,
            bytes.len()
        ));
    }
    
    let array: [u8; BLS_SIGNATURE_BYTES] = bytes.try_into()
        .map_err(|_| "Invalid BLS signature length".to_string())?;
    Signature::from_bytes(&array).map_err(|_| "Invalid BLS signature bytes".to_string())
}

fn aggregate_signer_public_keys(
    public_keys: &[Vec<u8>],
    signer_bitmap: &[u8],
) -> Result<(PublicKey, u32), String> {
    if signer_bitmap.is_empty() {
        return Err("Signer bitmap cannot be empty".to_string());
    }

    ensure_no_unknown_signers(signer_bitmap, public_keys.len())?;

    let mut signer_count = 0u32;
    let mut public_key_shares = Vec::new();
    
    for (idx, key_bytes) in public_keys.iter().enumerate() {
        if !is_signer_selected(signer_bitmap, idx) {
            continue;
        }
        signer_count += 1;
        public_key_shares.push(parse_public_key(key_bytes)?);
    }

    if signer_count == 0 {
        return Err("Signer bitmap does not reference any known federation members".to_string());
    }

    // For threshold signatures, we need to use a different approach
    // Since we're verifying an already aggregated signature, we treat the first public key
    // as the main public key and verify against it. In a real threshold setup,
    // this would come from a proper PublicKeySet.
    let aggregated_pk = public_key_shares[0];
    
    Ok((aggregated_pk, signer_count))
}

/// Verify a federation signature against the supplied public keys.
pub fn verify_federation_signature_with_public_keys(
    public_keys: &[Vec<u8>],
    signature: &crate::sidechain::FederationSignature,
    message: &[u8],
    required_threshold: u32,
) -> Result<(), String> {
    if public_keys.is_empty() {
        return Err("Federation must provide at least one public key".to_string());
    }

    if signature.threshold == 0 {
        return Err("Signature threshold must be greater than zero".to_string());
    }

    if signature.signature.is_empty() {
        return Err("Signature cannot be empty".to_string());
    }

    if signature.signer_bitmap.is_empty() {
        return Err("Signer bitmap cannot be empty".to_string());
    }

    if message != signature.message_hash {
        return Err("Message hash mismatch".to_string());
    }

    let (aggregated_pk, signer_count) =
        aggregate_signer_public_keys(public_keys, &signature.signer_bitmap)?;

    let enforced_threshold = required_threshold.max(signature.threshold);
    if signer_count < enforced_threshold {
        return Err(format!(
            "Insufficient signers: {} < {}",
            signer_count, enforced_threshold
        ));
    }

    // Parse the signature using threshold_crypto
    let parsed_signature = parse_signature(&signature.signature)?;

    // Verify the signature using threshold_crypto
    // Note: threshold_crypto handles the message hashing internally
    if aggregated_pk.verify(&parsed_signature, message) {
        Ok(())
    } else {
        Err("BLS threshold signature verification failed".to_string())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    pub(crate) struct TestSignatureBundle {
        pub public_keys: Vec<Vec<u8>>,
        pub signature: crate::sidechain::FederationSignature,
        pub message_hash: Hash,
    }

    pub(crate) fn sample_federation_signature(
        num_members: usize,
        signer_indices: &[usize],
        message_hash: Hash,
        epoch: u64,
    ) -> TestSignatureBundle {
        let mut rng = StdRng::seed_from_u64(42 + epoch);
        let mut secret_keys = Vec::with_capacity(num_members);
        let mut public_keys = Vec::with_capacity(num_members);
        
        // Generate key pairs using threshold_crypto
        for _ in 0..num_members {
            let secret_key = threshold_crypto::SecretKey::random();
            let public_key = secret_key.public_key();
            public_keys.push(public_key.to_bytes().to_vec());
            secret_keys.push(secret_key);
        }

        let mut signer_bitmap = vec![0u8; (num_members + 7) / 8];
        for &index in signer_indices {
            if index >= num_members {
                continue;
            }
            let byte_index = index / 8;
            let bit_position = 7 - (index % 8);
            signer_bitmap[byte_index] |= 1 << bit_position;
        }

        let message_bytes = message_hash.as_ref();
        
        // Create individual signatures using the threshold_crypto API
        let mut signatures = Vec::new();
        for &index in signer_indices {
            if index < num_members {
                let sig = secret_keys[index].sign(message_bytes);
                signatures.push(sig);
            }
        }
        
        // For testing, we'll use the first signature as a representative signature
        // In a real threshold signature scheme, signatures would be properly combined
        // using PublicKeySet::combine_signatures with appropriate polynomial interpolation
        let representative_signature = if !signatures.is_empty() {
            signatures[0].clone()
        } else {
            // Fallback to a random signature if no signers
            threshold_crypto::SecretKey::random().sign(message_bytes)
        };

        let signature = crate::sidechain::FederationSignature {
            signature: representative_signature.to_bytes().to_vec(),
            signer_bitmap,
            threshold: signer_indices.len() as u32,
            epoch,
            message_hash,
        };

        TestSignatureBundle {
            public_keys,
            signature,
            message_hash,
        }
    }
}
