use ed25519_dalek::{PublicKey, Signature};
use rusty_crypto::signature::verify_signature;
use rusty_shared_types::{Transaction, TxInput, TxOutput, Hash};
use rusty_shared_types::masternode::{MasternodeRegistration, MasternodeIdentity, MasternodeID, MasternodeStatus, MasternodeCollateralTx};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::constants::MASTERNODE_COLLATERAL_AMOUNT;

pub mod oxidesend; // Declare the new oxidesend module
pub mod ferrous_shield; // Declare the new ferrous_shield module
pub mod pose;
pub mod slashing;
pub mod mn_list; // Declare the new pose module
pub mod dkg_manager; // DKG coordination module
pub mod mn_list_propagation; // Masternode list propagation
pub mod network_coordinator; // Network coordination for masternode operations
pub mod pose_coordinator; // PoSe coordination and management
pub mod quorum_formation; // Deterministic quorum formation

fn convert_core_to_shared_identity(core: &MasternodeIdentity) -> rusty_shared_types::MasternodeIdentity {
    rusty_shared_types::MasternodeIdentity {
        collateral_outpoint: core.collateral_outpoint.clone(),
        operator_public_key: core.operator_public_key.clone(),
        collateral_ownership_public_key: core.collateral_ownership_public_key.clone(),
        network_address: core.network_address.clone(),
    }
}

pub fn register_masternode(
    registration: MasternodeRegistration,
    blockchain: &Blockchain,
) -> Result<Transaction, String> {
    // 1. Validate collateral UTXO
    let collateral_outpoint = &registration.masternode_identity.collateral_outpoint;
    let collateral_tx_output_tuple = blockchain.get_utxo(collateral_outpoint).map_err(|e| e.to_string())?;
    let (collateral_tx_output, _height, _is_coinbase) = collateral_tx_output_tuple.ok_or_else(|| "Collateral UTXO not found".to_string())?;
    if collateral_tx_output.value < MASTERNODE_COLLATERAL_AMOUNT {
        return Err("Collateral amount is insufficient".to_string());
    }

    // 2. Verify signature of the masternode identity by the collateral owner
    let identity_bytes = bincode::serialize(&registration.masternode_identity)
        .map_err(|e| format!("Failed to serialize masternode identity: {:?}", e))?;

    // Convert Vec<u8> to [u8; 32] for public key
    let pubkey_bytes: [u8; 32] = registration.masternode_identity.collateral_ownership_public_key.clone().try_into()
        .map_err(|_| "Invalid public key length".to_string())?;
    let pubkey = PublicKey::from_bytes(&pubkey_bytes)
        .map_err(|_| "Invalid public key bytes".to_string())?;

    // Convert Vec<u8> to [u8; 64] for signature
    let sig_bytes: [u8; 64] = registration.signature.clone().try_into()
        .map_err(|_| "Invalid signature length".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|_| "Invalid signature bytes".to_string())?;

    verify_signature(&pubkey, &identity_bytes, &sig)
        .map_err(|_| "Invalid collateral ownership signature".to_string())?;

    // 3. Create a MasternodeCollateralTx
    let collateral_input = TxInput {
        previous_output: collateral_outpoint.clone(),
        script_sig: vec![],
        sequence: 0,
    };

    let collateral_output = TxOutput {
        value: MASTERNODE_COLLATERAL_AMOUNT,
        script_pubkey: collateral_tx_output.script_pubkey.clone(),
    };

    let masternode_collateral_tx = MasternodeCollateralTx {
        version: 1,
        inputs: vec![collateral_input],
        outputs: vec![collateral_output],
        masternode_identity: convert_core_to_shared_identity(&registration.masternode_identity),
        collateral_amount: MASTERNODE_COLLATERAL_AMOUNT,
        lock_time: 0,
    };

    Ok(Transaction::MasternodeCollateral(masternode_collateral_tx))
}

pub fn deregister_masternode(
    _masternode_id: &MasternodeID,
    _blockchain: &Blockchain,
) -> Result<Transaction, String> {
    // Placeholder for deregistration logic
    // This would involve creating a transaction that unlocks the collateral
    // and potentially penalizes the masternode if deregistering due to slashing.
    Err("Deregistration not yet implemented".to_string())
}

// Placeholder for a function that uses OxideSend functionality
pub fn initiate_oxidesend_mixing(
    blockchain: &Blockchain,
    current_block_hash: &Hash,
    inputs_to_mix: Vec<TxInput>,
    outputs_to_mix: Vec<TxOutput>,
    fee_per_kb: u64,
) -> Result<oxidesend::OxideSendTransaction, String> {
    oxidesend::coordinate_oxidesend_mixing(
        blockchain,
        current_block_hash,
        inputs_to_mix,
        outputs_to_mix,
        fee_per_kb,
    )
}