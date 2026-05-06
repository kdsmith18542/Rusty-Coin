//! OxideSend protocol implementation for deterministic masternode quorum selection.

use crate::slashing::{self, SlashingReason};
use bincode;
use blake3;
use ed25519_dalek::{Signature, Signer, Verifier};
use hex;
use log::{error, info, warn};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::error::ConsensusError;
use rusty_core::constants::QUORUM_EXPIRATION_BLOCKS;
use rusty_core::transaction_builder::TransactionBuilder;
use rusty_crypto::dkg::DKGProtocol;
use rusty_shared_types::dkg::{DKGSession, DKGSessionState, ThresholdSignature};
use rusty_shared_types::masternode::MasternodeID;
use rusty_shared_types::{Hash, Transaction, TxInput, TxOutput};
use std::collections::HashMap;
use threshold_crypto::SecretKeyShare;

// Input locking protocol with M-of-N masternode signatures verification
pub fn lock_inputs(
    inputs: Vec<TxInput>,
    masternode_signatures: Vec<Signature>,
    masternode_public_keys: &[ed25519_dalek::PublicKey],
    quorum_threshold: usize,
) -> Result<(), String> {
    use rusty_crypto::signature::verify_masternode_multi_signature;

    // Check if we have enough signatures
    if masternode_signatures.len() < quorum_threshold {
        return Err(format!(
            "Not enough masternode signatures: {} < {}",
            masternode_signatures.len(),
            quorum_threshold
        ));
    }

    // Check if we have corresponding public keys
    if masternode_public_keys.len() < quorum_threshold {
        return Err(format!(
            "Not enough masternode public keys: {} < {}",
            masternode_public_keys.len(),
            quorum_threshold
        ));
    }

    // Create a message from the inputs to be signed
    let inputs_serialized =
        bincode::serialize(&inputs).map_err(|e| format!("Failed to serialize inputs: {}", e))?;
    let message = blake3::hash(&inputs_serialized);

    // Verify the masternode multi-signature on the inputs
    match verify_masternode_multi_signature(
        masternode_public_keys,
        message.as_bytes(),
        &masternode_signatures,
        quorum_threshold,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err("Invalid masternode signatures for input locking".to_string()),
        Err(e) => Err(format!("Error verifying masternode multi-signature: {}", e)),
    }
}

// Client-side verification of input locks using masternode public keys
pub fn verify_client_locks(
    transaction: &Transaction,
    expected_signatures: &[Signature],
    masternode_public_keys: &[ed25519_dalek::PublicKey],
    quorum_threshold: usize,
) -> bool {
    use rusty_crypto::signature::verify_masternode_multi_signature;

    // Ensure we have inputs and signatures
    if transaction.get_inputs().is_empty() || expected_signatures.is_empty() {
        return false;
    }

    // Check if we have enough signatures and public keys
    if expected_signatures.len() < quorum_threshold
        || masternode_public_keys.len() < quorum_threshold
    {
        return false;
    }

    // Create a message from the transaction inputs
    let inputs = transaction.get_inputs();
    match bincode::serialize(&inputs) {
        Ok(inputs_serialized) => {
            let message = blake3::hash(&inputs_serialized);

            // Verify the masternode signatures on the transaction inputs
            match verify_masternode_multi_signature(
                masternode_public_keys,
                message.as_bytes(),
                expected_signatures,
                quorum_threshold,
            ) {
                Ok(is_valid) => is_valid,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// Placeholder for slashing for OxideSend double-spend attempts
pub fn detect_and_slash_double_spend(
    transaction: &Transaction,
    blockchain: &Blockchain,
    current_block_height: u64,
) -> Result<Option<Transaction>, ConsensusError> {
    // 1. Check against current UTXO set
    for tx_input in transaction.get_inputs() {
        if !blockchain.utxo_set.contains_utxo(&tx_input.previous_output) {
            warn!(
                "Double-spend detected: Transaction input {:?} not found in UTXO set.",
                tx_input.previous_output
            );
            // Attempt to identify if this is a masternode double-spend and create a slashing transaction
            if let Some(masternode_entry) = blockchain
                .masternode_list
                .map
                .iter()
                .find(|(_, entry)| entry.identity.collateral_outpoint == tx_input.previous_output)
                .map(|(id, _)| id.clone())
            {
                info!(
                    "Double-spend by masternode {:?} detected. Creating slashing transaction.",
                    masternode_entry
                );
                let proof_data = bincode::serialize(transaction)
                    .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

                // Get the collateral input for the slashing transaction. This needs to be the actual input
                // that the masternode used for its collateral, which we can retrieve from the blockchain state.
                let collateral_utxo = blockchain
                    .utxo_set
                    .get_utxo(&masternode_entry.0)
                    .ok_or_else(|| {
                        ConsensusError::MasternodeError(
                            "Collateral UTXO for slashing not found.".to_string(),
                        )
                    })?;
                let (collateral_output, _height, _is_coinbase) = (
                    &collateral_utxo.output,
                    collateral_utxo.creation_height,
                    collateral_utxo.is_coinbase,
                );

                let collateral_input = TxInput::from_outpoint(
                    masternode_entry.0.clone(),
                    collateral_output.script_pubkey.clone(), // Use the script_pubkey of the collateral output as script_sig for the slashing input
                    0,
                    vec![],
                );

                let slashing_tx = slashing::create_slashing_transaction(
                    &masternode_entry,
                    SlashingReason::DoubleSpend,
                    proof_data,
                    collateral_input,
                    collateral_output.value, // Slash the entire collateral amount
                    get_masternode_script_pubkey(&masternode_entry, blockchain),
                    current_block_height,
                )
                .map_err(|e| ConsensusError::MasternodeError(e.to_string()))?;
                return Ok(Some(slashing_tx));
            }
            return Ok(Some(Transaction::Standard {
                version: 1,
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
                fee: 0,
                witness: vec![],
            })); // Indicate a double-spend was found, but not by a masternode (for now, return a dummy tx)
        }
    }

    // 2. Check against transactions in mempool (for unconfirmed double-spends)
    let mempool_guard = blockchain.mempool.lock().unwrap();
    for (_mempool_txid, mempool_tx) in mempool_guard.transactions.iter() {
        if mempool_tx.txid() == transaction.txid() {
            // Same transaction, ignore
            continue;
        }
        for existing_input in mempool_tx.get_inputs() {
            for new_input in transaction.get_inputs() {
                if existing_input.previous_output == new_input.previous_output {
                    warn!("Double-spend detected: Transaction {:?} attempts to spend UTXO {:?} which is also spent by mempool transaction {:?}.",
                          transaction.txid(), new_input.previous_output, mempool_tx.txid());
                    // Attempt to identify if this is a masternode double-spend and create a slashing transaction
                    if let Some(masternode_entry) = blockchain
                        .masternode_list
                        .map
                        .iter()
                        .find(|(_, entry)| {
                            entry.identity.collateral_outpoint == new_input.previous_output
                        })
                        .map(|(id, _)| id.clone())
                    {
                        info!("Double-spend by masternode {:?} detected in mempool. Creating slashing transaction.", masternode_entry);
                        let proof_data = bincode::serialize(transaction)
                            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

                        let collateral_utxo = blockchain
                            .utxo_set
                            .get_utxo(&masternode_entry.0)
                            .ok_or_else(|| {
                                ConsensusError::MasternodeError(
                                    "Collateral UTXO for slashing not found.".to_string(),
                                )
                            })?;
                        let (collateral_output, _height, _is_coinbase) = (
                            &collateral_utxo.output,
                            collateral_utxo.creation_height,
                            collateral_utxo.is_coinbase,
                        );

                        let collateral_input = TxInput::from_outpoint(
                            masternode_entry.0.clone(),
                            collateral_output.script_pubkey.clone(),
                            0,
                            vec![],
                        );

                        let slashing_tx = slashing::create_slashing_transaction(
                            &masternode_entry,
                            SlashingReason::DoubleSpend,
                            proof_data,
                            collateral_input,
                            collateral_output.value,
                            get_masternode_script_pubkey(&masternode_entry, blockchain),
                            current_block_height,
                        )
                        .map_err(|e| ConsensusError::MasternodeError(e.to_string()))?;
                        return Ok(Some(slashing_tx));
                    }
                    return Ok(Some(Transaction::Standard {
                        version: 1,
                        inputs: vec![],
                        outputs: vec![],
                        lock_time: 0,
                        fee: 0,
                        witness: vec![],
                    })); // Indicate a double-spend was found, but not by a masternode (for now, return a dummy tx)
                }
            }
        }
    }

    Ok(None) // No double-spend detected
}

// Placeholder for OxideSend specific transaction types or flags
// This would be defined in rusty_shared_types or rusty_core
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OxideSendTransaction {
    pub base_tx: Transaction,
    pub mix_id: Hash,
    pub participants: Vec<MasternodeID>,
}

/// Represents a Masternode quorum for OxideSend with DKG support.
#[derive(Debug, Clone)]
pub struct MasternodeQuorum {
    pub quorum_id: Hash,
    pub masternodes: Vec<MasternodeID>,
    pub creation_block_hash: Hash,
    pub expiration_block_hash: Hash,
    pub dkg_session: Option<DKGSession>,
    pub threshold_public_key: Option<Vec<u8>>, // Serialized threshold public key
    pub threshold: u32,
}

/// Selects a deterministic masternode quorum for an OxideSend transaction with DKG support.
/// This function now includes DKG session initialization for threshold signatures.
pub fn select_oxidesend_quorum(
    blockchain: &Blockchain,
    current_block_hash: &Hash,
    num_masternodes: usize,
) -> Result<MasternodeQuorum, String> {
    // Get active masternodes from the blockchain's masternode list
    let active_masternodes: Vec<MasternodeID> = blockchain
        .masternode_list
        .map
        .values()
        .filter(|entry| entry.status == rusty_shared_types::masternode::MasternodeStatus::Active)
        .map(|entry| MasternodeID(entry.identity.collateral_outpoint.clone()))
        .collect();

    if active_masternodes.len() < num_masternodes {
        return Err(format!(
            "Not enough active masternodes for quorum. Needed: {}, Available: {}",
            num_masternodes,
            active_masternodes.len()
        ));
    }

    // Use enhanced quorum formation for deterministic selection
    use crate::quorum_formation::{QuorumConfig, QuorumFormationManager, QuorumType};

    // Get masternode list from blockchain
    let masternode_list = &blockchain.masternode_list;
    let current_block_height = blockchain.state.current_height;

    // Create quorum formation manager
    let mut config = QuorumConfig::default();
    config.oxidesend_quorum_size = num_masternodes;
    let mut formation_manager = QuorumFormationManager::new(config);

    // Form the quorum using deterministic selection
    let formed_quorum = formation_manager.form_quorum(
        QuorumType::OxideSend,
        &masternode_list,
        current_block_height,
        current_block_hash,
        None, // No additional criteria
    )?;

    let selected_masternodes: Vec<MasternodeID> = formed_quorum.members;

    // Convert to legacy MasternodeQuorum format
    let expiration_block_height = current_block_height + QUORUM_EXPIRATION_BLOCKS;
    let expiration_block_hash = blockchain
        .state
        .get_block_hash(expiration_block_height)
        .map_err(|e| e.to_string())?;

    Ok(MasternodeQuorum {
        quorum_id: formed_quorum.quorum_id,
        masternodes: selected_masternodes,
        creation_block_hash: formed_quorum.creation_block_hash,
        expiration_block_hash: expiration_block_hash.expect("expiration_block_hash required"),
        dkg_session: formed_quorum.dkg_session,
        threshold_public_key: None, // Will be set after DKG completion
        threshold: formed_quorum.threshold,
    })
}

/// Coordinates an OxideSend mixing session.
/// This is a high-level function that would involve multiple steps:
/// 1. Client requests mixing.
/// 2. Masternodes form a quorum.
/// 3. Participants register inputs/outputs with the quorum.
/// 4. Quorum masternodes construct and sign the mixed transaction.
/// 5. Transaction is broadcast.
pub fn coordinate_oxidesend_mixing(
    blockchain: &Blockchain,
    current_block_hash: &Hash,
    inputs_to_mix: Vec<TxInput>,
    outputs_to_mix: Vec<TxOutput>,
    fee_per_kb: u64,
) -> Result<OxideSendTransaction, String> {
    // Simplified flow:
    // 1. Select a quorum
    let quorum = select_oxidesend_quorum(blockchain, current_block_hash, 3) // Example: 3 masternodes
        .map_err(|e| format!("Failed to select OxideSend quorum: {}", e))?;

    // 2. Implement real mixing logic by quorum masternodes
    // Validate inputs and outputs
    let total_input_value: u64 = inputs_to_mix
        .iter()
        .map(|input| {
            // Look up the actual UTXO value from the blockchain
            blockchain
                .utxo_set
                .get_utxo(&input.previous_output)
                .map(|utxo| utxo.output.value)
                .unwrap_or(0)
        })
        .sum();

    let total_output_value: u64 = outputs_to_mix.iter().map(|output| output.value).sum();

    // Calculate fee
    let estimated_tx_size = (inputs_to_mix.len() + outputs_to_mix.len()) * 150; // Rough estimate
    let total_fee = (estimated_tx_size as u64 * fee_per_kb) / 1000;

    // Validate that outputs don't exceed inputs minus fee
    if total_output_value > total_input_value.saturating_sub(total_fee) {
        return Err("Insufficient input value to cover outputs and fees".to_string());
    }

    // Create mixing transaction with proper fee handling
    let mut adjusted_outputs = outputs_to_mix.clone();

    // Add change output if needed
    let change_amount = total_input_value
        .saturating_sub(total_output_value)
        .saturating_sub(total_fee);
    if change_amount > 0 {
        // Create change output (in a real implementation, this would go back to the user)
        let change_output = TxOutput {
            value: change_amount,
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x88, 0xac,
            ], // P2PKH placeholder
            memo: Some("OxideSend change output".as_bytes().to_vec()),
        };
        adjusted_outputs.push(change_output);
    }

    info!(
        "OxideSend mixing: {} inputs, {} outputs, fee: {} sats",
        inputs_to_mix.len(),
        adjusted_outputs.len(),
        total_fee
    );

    // For simplicity, we'll use a dummy key for transaction building here.
    let transaction_builder = TransactionBuilder;
    let base_tx = transaction_builder
        .build_standard_transaction(inputs_to_mix, adjusted_outputs, fee_per_kb)
        .map_err(|e| e.to_string())?;

    // Generate a mix_id based on the transaction hash
    let mix_id = blake3::hash(base_tx.txid().as_ref());

    Ok(OxideSendTransaction {
        base_tx,
        mix_id: mix_id.into(),
        participants: quorum.masternodes,
    })
}

/// Coordinate DKG for a masternode quorum
pub fn coordinate_dkg_for_quorum(
    quorum: &mut MasternodeQuorum,
    _participant_index: u32,
    _auth_private_key: ed25519_dalek::SecretKey,
) -> Result<(), String> {
    let dkg_session = quorum
        .dkg_session
        .as_mut()
        .ok_or("No DKG session found in quorum")?;

    if dkg_session.state != DKGSessionState::WaitingForParticipants {
        return Err("DKG session not in correct state".to_string());
    }

    // Advance to commitment phase
    dkg_session
        .advance_phase()
        .map_err(|e| format!("Failed to advance DKG phase: {}", e))?;

    info!(
        "DKG session {} advanced to commitment phase",
        hex::encode(dkg_session.session_id.0)
    );

    Ok(())
}

/// Create a threshold signature for an OxideSend transaction
pub fn create_threshold_signature(
    transaction: &Transaction,
    quorum: &MasternodeQuorum,
    secret_key_share: &SecretKeyShare,
    participant_index: u32,
    auth_private_key: ed25519_dalek::SecretKey,
) -> Result<ThresholdSignature, String> {
    let dkg_session = quorum
        .dkg_session
        .as_ref()
        .ok_or("No DKG session found in quorum")?;

    if dkg_session.state != DKGSessionState::Completed {
        return Err("DKG session not completed".to_string());
    }

    let txid = transaction.txid();
    let message = txid.as_ref();
    let message_hash = blake3::hash(&message);

    // Create DKG protocol instance
    let public_key = ed25519_dalek::PublicKey::from(&auth_private_key);
    let keypair = ed25519_dalek::Keypair {
        secret: ed25519_dalek::SecretKey::from_bytes(&auth_private_key.to_bytes()).unwrap(),
        public: public_key,
    };
    let dkg_protocol = DKGProtocol::new(participant_index, keypair);

    // Create signature share
    let signature_share = dkg_protocol
        .create_signature_share(&message, secret_key_share, &dkg_session.session_id)
        .map_err(|e| format!("Failed to create signature share: {}", e))?;

    // Initialize threshold signature with our share
    let mut signature_shares = HashMap::new();
    signature_shares.insert(participant_index, signature_share.signature_share.clone());

    Ok(ThresholdSignature {
        session_id: dkg_session.session_id.clone(),
        message_hash: message_hash.into(),
        signature_shares,
        aggregated_signature: None,
        signers: vec![participant_index],
    })
}

/// Verify and add a signature share to a threshold signature
pub fn add_signature_share_to_threshold(
    threshold_sig: &mut ThresholdSignature,
    signature_share: rusty_shared_types::dkg::SignatureShare,
    sender_public_key: &ed25519_dalek::PublicKey,
    _message: &[u8],
) -> Result<(), String> {
    // Verify the signature share authenticity
    let signature_bytes: [u8; 64] = signature_share
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid signature length")?;
    let signature = Signature::from_bytes(&signature_bytes).expect("Invalid signature bytes");

    sender_public_key
        .verify(&signature_share.signature_share, &signature)
        .map_err(|_| "Invalid authentication signature")?;

    // Add the signature share
    threshold_sig.signature_shares.insert(
        signature_share.participant_index,
        signature_share.signature_share,
    );

    if !threshold_sig
        .signers
        .contains(&signature_share.participant_index)
    {
        threshold_sig
            .signers
            .push(signature_share.participant_index);
    }

    info!(
        "Added signature share from participant {}, total shares: {}",
        signature_share.participant_index,
        threshold_sig.signature_shares.len()
    );

    Ok(())
}

/// Aggregate signature shares when threshold is met
pub fn finalize_threshold_signature(
    threshold_sig: &mut ThresholdSignature,
    quorum: &MasternodeQuorum,
    participant_index: u32,
    auth_private_key: ed25519_dalek::SecretKey,
) -> Result<(), String> {
    if threshold_sig.signature_shares.len() < quorum.threshold as usize {
        return Err(format!(
            "Insufficient signature shares: {} < {}",
            threshold_sig.signature_shares.len(),
            quorum.threshold
        ));
    }

    // Create DKG protocol instance for aggregation
    let public_key = ed25519_dalek::PublicKey::from(&auth_private_key);
    let keypair = ed25519_dalek::Keypair {
        secret: ed25519_dalek::SecretKey::from_bytes(&auth_private_key.to_bytes()).unwrap(),
        public: public_key,
    };
    let dkg_protocol = DKGProtocol::new(participant_index, keypair);

    // Convert signature shares to threshold_crypto format
    let mut crypto_shares = HashMap::new();
    for (index, share_bytes) in &threshold_sig.signature_shares {
        if share_bytes.len() != 96 {
            return Err(format!(
                "Invalid signature share length: expected 96, got {}",
                share_bytes.len()
            ));
        }
        let share_array: [u8; 96] = share_bytes.as_slice().try_into().unwrap();
        let signature_share = threshold_crypto::SignatureShare::from_bytes(&share_array)
            .map_err(|e| format!("Invalid signature share format: {:?}", e))?;
        crypto_shares.insert(*index, signature_share);
    }

    // Aggregate the signature shares
    let aggregated_signature = dkg_protocol
        .aggregate_signature_shares(&crypto_shares, quorum.threshold)
        .map_err(|e| format!("Failed to aggregate signatures: {}", e))?;

    threshold_sig.aggregated_signature = Some(aggregated_signature.to_bytes().to_vec());

    info!(
        "Successfully aggregated threshold signature for session {}",
        hex::encode(threshold_sig.session_id.0)
    );

    Ok(())
}

// Legacy function for backward compatibility
pub fn sign_mixed_transaction(
    transaction: &Transaction,
    _masternode_id: &MasternodeID,
    private_key: &ed25519_dalek::SecretKey,
) -> Result<Signature, String> {
    let txid = transaction.txid();
    let message = txid.as_ref();

    // Create a keypair from the secret key
    let public_key = ed25519_dalek::PublicKey::from(private_key);
    let keypair = ed25519_dalek::Keypair {
        secret: ed25519_dalek::SecretKey::from_bytes(&private_key.to_bytes()).unwrap(),
        public: public_key,
    };

    let signature = keypair.sign(message);
    Ok(signature)
}

// Verification of mixed transactions
pub fn verify_mixed_transaction(
    transaction: &Transaction,
    signatures: &[Signature],
    masternode_public_keys: &[ed25519_dalek::PublicKey],
    quorum_threshold: usize,
) -> bool {
    use rusty_crypto::signature::verify_masternode_multi_signature;

    let txid = transaction.txid();
    let message = txid.as_ref();

    match verify_masternode_multi_signature(
        masternode_public_keys,
        message,
        signatures,
        quorum_threshold,
    ) {
        Ok(is_valid) => is_valid,
        Err(e) => {
            error!("Error verifying masternode multi-signature: {:?}", e);
            false
        }
    }
}

// Handling of mixing failures
pub fn handle_mixing_failure(transaction: &Transaction, reason: String) {
    // Log the failure and potentially trigger a retry or alert
    error!(
        "Mixing failure for transaction {:?}: {}",
        transaction.txid(),
        reason
    );
}

// Change function signature to accept a Keypair instead of &SecretKey
pub fn sign_transaction(
    _masternode_id: &MasternodeID,
    keypair: &ed25519_dalek::Keypair,
    transaction: &Transaction,
) -> Result<Signature, String> {
    let txid = transaction.txid();
    let message = txid.as_ref();
    let signature = keypair.sign(message);
    Ok(signature)
}

/// Create a P2PKH script from a public key
fn create_p2pkh_script(pubkey: &[u8]) -> Vec<u8> {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha256 = Sha256::digest(pubkey);
    let pubkey_hash = Ripemd160::digest(&sha256);
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Helper function to get the script_pubkey for a masternode for slashing transactions
///
/// This function creates a P2PKH (Pay-to-Public-Key-Hash) script for the masternode's
/// public key, which is used when returning remaining collateral after slashing.
///
/// # Arguments
/// * `masternode_id` - The masternode ID containing the collateral outpoint
///
/// # Returns
/// A script_pubkey vector for P2PKH to the masternode's public key
fn get_masternode_script_pubkey(masternode_id: &MasternodeID, blockchain: &Blockchain) -> Vec<u8> {
    // Look up the masternode entry in the blockchain's masternode list
    if let Some(entry) = blockchain.masternode_list.map.get(masternode_id) {
        // Use the collateral_ownership_public_key if available, else operator_public_key
        let pubkey = if !entry.identity.collateral_ownership_public_key.is_empty() {
            &entry.identity.collateral_ownership_public_key
        } else {
            &entry.identity.operator_public_key
        };
        create_p2pkh_script(pubkey)
    } else {
        // Fallback: placeholder script
        vec![]
    }
}
