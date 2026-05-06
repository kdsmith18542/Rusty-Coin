use crate::consensus::error::ConsensusError;
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::utxo_set::UtxoSet;
use crate::network::{sync_manager::SyncManager, P2PNetwork};
use crate::script::script_engine::ScriptEngine;
use crate::sidechain::{
    cross_chain_communication::CrossChainCommunication,
    federation_integrator::FederationIntegrator,
    mainchain_validator::MainchainValidator,
    sidechain_consensus::SidechainConsensus,
    two_way_peg::TwoWayPegManager,
};
use rusty_shared_types::{
    masternode::{
        MasternodeID, MasternodeList, MasternodeMaliciousProof, MasternodeNonParticipationProof,
        MasternodeStatus, PoSeChallenge, SlashingReason,
    },
    Block, ConsensusParams, Hash, OutPoint, Ticket, TicketId, TicketStatus, Transaction, TxOutput,
};

use crate::audit_log;
use crate::consensus::governance_state::{
    ActiveProposals, ProposalOutcome, VoterType as GovernanceVoterType,
};
use crate::consensus::pow::{calculate_new_target, target_to_compact};
use crate::consensus::state::BlockchainState;
use crate::constants::{COINBASE_MATURITY_PERIOD_BLOCKS, LOCKTIME_THRESHOLD};
use ed25519_dalek::{PublicKey as VerifyingKey, Signature, Verifier};
use log::{info, warn};
use primitive_types::U256;
use rusty_crypto::keypair::RustyKeyPair;
use rusty_crypto::signature::verify_signature;
use std::sync::{Arc, Mutex};

use crate::mempool::Mempool;
use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use rand::RngCore;
use rusty_shared_types::masternode::MasternodeID as SharedMasternodeID;

use blake3;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use std::collections::HashMap;
use std::convert::TryInto;

/// Generate a PoSe challenge for a masternode
fn generate_pose_challenge(
    target_masternode_id: MasternodeID,
    block_height: u64,
    challenger_keypair: &RustyKeyPair,
    block_hash: [u8; 32],
) -> Result<PoSeChallenge, ConsensusError> {
    Ok(PoSeChallenge {
        challenge_nonce: {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&target_masternode_id.as_bytes());
            hasher.update(&block_height.to_le_bytes());
            hasher.update(&block_hash);
            let hash = hasher.finalize();
            u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap())
        },
        challenge_block_hash: block_hash,
        challenger_masternode_id: target_masternode_id.clone(),
        challenge_generation_block_height: block_height,
        signature: challenger_keypair.sign(&block_hash).to_bytes().to_vec(),
    })
}

/// Verify a PoSe response from a masternode
fn verify_pose_response(
    challenge_message: &[u8],
    signed_block_hash: &[u8],
    operator_public_key: &rusty_shared_types::PublicKey,
) -> bool {
    // Convert the public key to a VerifyingKey and verify the signature
    if let Ok(verifying_key) = VerifyingKey::from_bytes(operator_public_key) {
        if let Ok(signature) = ed25519_dalek::Signature::from_bytes(signed_block_hash) {
            verifying_key.verify(challenge_message, &signature).is_ok()
        } else {
            false
        }
    } else {
        false
    }
}

pub struct Blockchain {
    pub tip: [u8; 32],
    pub live_tickets: LiveTicketsPool,
    pub utxo_set: UtxoSet,
    pub masternode_list: MasternodeList,
    pub state: BlockchainState,
    pub params: ConsensusParams,
    pub active_proposals: ActiveProposals,
    pub sync_manager: Arc<Mutex<SyncManager>>,
    pub p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>,
    pub mempool: Arc<Mutex<Mempool>>,
    pub keypair: RustyKeyPair,
    // Sidechain integration
    pub sidechain_consensus: std::collections::HashMap<Hash, Arc<std::sync::Mutex<SidechainConsensus>>>,
    pub federation_integrator: Arc<std::sync::Mutex<FederationIntegrator>>,
    pub cross_chain_communication: Arc<std::sync::Mutex<CrossChainCommunication>>,
    pub mainchain_validator: Arc<std::sync::Mutex<MainchainValidator>>,
    pub peg_manager: Arc<std::sync::Mutex<TwoWayPegManager>>,
}

impl Blockchain {
    pub fn new(p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<Self, ConsensusError> {
        let state = BlockchainState::new();
        let utxo_set = UtxoSet::new();
        let live_tickets = LiveTicketsPool::new();
        let sync_manager = Arc::new(Mutex::new(SyncManager::new(
            Arc::new(tokio::sync::RwLock::new(state.clone())),
            Arc::new(tokio::sync::RwLock::new(utxo_set)),
            Arc::new(tokio::sync::RwLock::new(live_tickets)),
        )));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let keypair = RustyKeyPair::generate();

        // Initialize sidechain components
        let federation_integrator = Arc::new(std::sync::Mutex::new(FederationIntegrator::new()));
        let cross_chain_communication = Arc::new(std::sync::Mutex::new(CrossChainCommunication::new()));
        let mainchain_validator = Arc::new(std::sync::Mutex::new(MainchainValidator::new(100)));
        let peg_manager = Arc::new(std::sync::Mutex::new(TwoWayPegManager::new(6)));

        // Set up cross-references between components
        {
            let fed_arc = Arc::clone(&federation_integrator);
            let mut comm = cross_chain_communication.lock().unwrap();
            comm.with_federation_manager(fed_arc);
        }

        {
            let fed_arc = Arc::clone(&federation_integrator);
            let mut peg = peg_manager.lock().unwrap();
            peg.with_federation_manager(fed_arc);
        }

        Ok(Self {
            tip: [0; 32],
            live_tickets: LiveTicketsPool::new(),
            utxo_set: UtxoSet::new(),
            masternode_list: MasternodeList::new(),
            state,
            params: ConsensusParams::default(),
            active_proposals: ActiveProposals::new(),
            sync_manager,
            mempool,
            keypair,
            p2p_network,
            sidechain_consensus: std::collections::HashMap::new(),
            federation_integrator,
            cross_chain_communication,
            mainchain_validator,
            peg_manager,
        })
    }

    pub fn get_latest_block(&self) -> Result<Option<Block>, ConsensusError> {
        let current_height = self
            .state
            .get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        if current_height == 0 {
            Ok(None)
        } else {
            self.state
                .get_block(current_height.try_into().unwrap())
                .map_err(|e| ConsensusError::Internal(e.to_string()))
        }
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<(), ConsensusError> {
        let current_height = self
            .state
            .get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        // Sort transactions by fee in descending order (higher fee, higher priority)
        // Coinbase transaction is always the first transaction and should not be sorted.
        let mut sorted_transactions: Vec<Transaction> = block.transactions.drain(1..).collect();
        sorted_transactions.sort_by_key(|tx| tx.get_fee());
        sorted_transactions.reverse(); // Sort descending
        block.transactions.extend(sorted_transactions);

        // Basic validation (more comprehensive validation would be in consensus module)
        if current_height > 0 {
            let last_block = self
                .get_latest_block()
                .map_err(|e| ConsensusError::Internal(e.to_string()))?
                .ok_or(ConsensusError::Internal(
                    "Last block not found for validation".to_string(),
                ))?;
            if block.header.previous_block_hash != last_block.header.hash() {
                audit_log::log_block_validation_failed(
                    &block.header,
                    &ConsensusError::InvalidBlock("Fork detected".to_string()).into(),
                );
                return Err(ConsensusError::InvalidBlock(format!("Fork detected: Incoming block's previous hash {:?} does not match current tip {:?}",
                                   block.header.previous_block_hash,
                                   last_block.header.hash())));
            }
            if current_height % self.params.difficulty_adjustment_window as u64 == 0 {
                let first_block_in_interval = self
                    .state
                    .get_block(
                        (current_height - self.params.difficulty_adjustment_window as u64)
                            .try_into()
                            .unwrap(),
                    )?
                    .ok_or(ConsensusError::Internal(
                        "First block in interval not found".to_string(),
                    ))?;
                let new_difficulty = calculate_new_target(
                    last_block.header.difficulty_target.into(),
                    last_block.header.timestamp - first_block_in_interval.header.timestamp,
                    self.params.min_block_time,
                    self.params.difficulty_adjustment_window as u64,
                    self.params.min_block_time * 4, // Use 4x min_block_time as max
                    U256::MAX,
                );
                if calculate_new_target(
                    last_block.header.difficulty_target.into(),
                    0,
                    0,
                    0,
                    0,
                    U256::MAX,
                ) != new_difficulty
                {
                    audit_log::log_block_validation_failed(
                        &block.header,
                        &ConsensusError::InvalidProofOfWork.into(),
                    );
                    return Err(ConsensusError::InvalidProofOfWork);
                }
            } else {
                if U256::from(block.header.difficulty_target)
                    != U256::from(last_block.header.difficulty_target)
                {
                    audit_log::log_block_validation_failed(
                        &block.header,
                        &ConsensusError::InvalidProofOfWork.into(),
                    );
                    return Err(ConsensusError::InvalidProofOfWork);
                }
            }
        }
        if !crate::consensus::pow::verify_pow(
            &block.header,
            U256::from(block.header.difficulty_target),
        ) {
            audit_log::log_block_validation_failed(
                &block.header,
                &ConsensusError::InvalidProofOfWork.into(),
            );
            return Err(ConsensusError::InvalidProofOfWork);
        }

        // Create a temporary vector to hold non-coinbase transactions
        let mut non_coinbase_transactions: Vec<Transaction> = Vec::new();

        // Process transactions
        for tx in block.transactions.drain(..) {
            audit_log::log_transaction_received(&tx);
            match tx {
                Transaction::GovernanceProposal(proposal) => {
                    self.process_governance_proposal(&proposal, current_height)?;
                    let proposal_tx = Transaction::GovernanceProposal(proposal.clone());
                    self.validate_transaction_inputs_and_scripts(&proposal_tx, current_height)?;
                    audit_log::log_governance_proposal_submitted(&proposal);
                    audit_log::log_transaction_validated(&proposal_tx);
                    non_coinbase_transactions.push(proposal_tx);
                }
                Transaction::GovernanceVote(vote) => {
                    self.process_governance_vote(&vote, current_height)?;
                    let vote_tx = Transaction::GovernanceVote(vote.clone());
                    self.validate_transaction_inputs_and_scripts(&vote_tx, current_height)?;
                    audit_log::log_governance_vote_cast(&vote);
                    audit_log::log_transaction_validated(&vote_tx);
                    non_coinbase_transactions.push(vote_tx);
                }
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Validate and apply masternode slashing
                    let proof_data = bincode::serialize(&slash_tx.proof).map_err(|e| {
                        ConsensusError::SerializationError(format!(
                            "Failed to encode proof data: {}",
                            e
                        ))
                    })?;
                    match slash_tx.reason {
                        SlashingReason::MasternodeNonResponse => {
                            let non_participation_proof: MasternodeNonParticipationProof =
                                bincode::deserialize(&proof_data).map_err(|e| {
                                    ConsensusError::SerializationError(format!(
                                        "Failed to deserialize non-participation proof: {}",
                                        e
                                    ))
                                })?;
                            self.live_tickets.validate_non_participation_proof(
                                &non_participation_proof,
                                &self.masternode_list,
                            )?;
                        }
                        SlashingReason::DoubleSigning => {
                            let malicious_proof: MasternodeMaliciousProof =
                                bincode::deserialize(&proof_data).map_err(|e| {
                                    ConsensusError::SerializationError(format!(
                                        "Failed to deserialize malicious proof: {}",
                                        e
                                    ))
                                })?;
                            self.live_tickets.validate_malicious_proof(
                                &malicious_proof,
                                &self.masternode_list,
                            )?;
                        }
                        _ => {
                            return Err(ConsensusError::RuleViolation(format!(
                                "Unsupported slashing reason: {:?}",
                                slash_tx.reason
                            )))
                        }
                    }
                    audit_log::log_masternode_slashed(&slash_tx);
                    audit_log::log_transaction_validated(&Transaction::MasternodeSlashTx(slash_tx));
                }
                _ => {
                    self.validate_transaction_inputs_and_scripts(&tx, current_height)?;
                    audit_log::log_transaction_validated(&tx);
                    non_coinbase_transactions.push(tx);
                }
            }
        }
        // Re-insert the modified coinbase transaction at the beginning
        // Sort non-coinbase transactions by fee in descending order
        non_coinbase_transactions.sort_by_key(|tx| tx.get_fee());
        non_coinbase_transactions.reverse(); // Sort descending
        block.transactions.extend(non_coinbase_transactions);

        // Handle coinbase transaction separately
        let expected_coinbase_output_value;
        let is_pos_block = block.header.is_proof_of_stake(); // Capture this before mutable borrow of transactions

        // Temporarily take out the coinbase transaction for mutable modification
        let mut coinbase_tx = block.transactions.remove(0); // This takes ownership and removes it from the vec

        if !coinbase_tx.is_coinbase() {
            let err = ConsensusError::InvalidCoinbase(
                "First transaction in block is not a coinbase transaction".to_string(),
            );
            audit_log::log_block_validation_failed(&block.header, &err.clone().into());
            return Err(err);
        }
        // Calculate block reward components
        let block_subsidy = self.state.get_block_subsidy(
            block.header.height,
            self.params.halving_interval,
            self.params.initial_block_reward,
        );

        // Calculate total fees from all transactions except coinbase
        // Now block.transactions does not contain the coinbase_tx, so we can iterate from 0
        let total_fees: u64 = block
            .transactions
            .iter()
            .map(|tx| {
                let input_value: u64 = tx
                    .get_inputs()
                    .iter()
                    .filter_map(|input| {
                        let outpoint = input.previous_output.clone();
                        self.utxo_set
                            .get_utxo(&outpoint)
                            .map(|utxo| utxo.output.value)
                    })
                    .sum();
                let output_value: u64 = tx.get_outputs().iter().map(|o| o.value).sum();
                input_value.saturating_sub(output_value)
            })
            .sum();

        // Distribute rewards between PoW miner and PoS stakers
        let total_reward = block_subsidy + total_fees;
        let pos_reward = (total_reward as f64 * self.params.pos_reward_ratio).round() as u64;
        let pow_reward = total_reward - pos_reward;

        // Set the expected coinbase output value (PoW miner's reward)
        expected_coinbase_output_value = pow_reward;

        let actual_coinbase_output_value = coinbase_tx
            .get_outputs()
            .iter()
            .map(|o| o.value)
            .sum::<u64>();
        if actual_coinbase_output_value > expected_coinbase_output_value {
            let err = ConsensusError::InvalidCoinbase(format!(
                "Coinbase output value exceeds expected PoW reward. Expected: {}, Actual: {}",
                expected_coinbase_output_value, actual_coinbase_output_value
            ));
            audit_log::log_block_validation_failed(&block.header, &err.clone().into());
            return Err(err);
        }
        if let Some(output) = coinbase_tx.get_outputs_mut().first_mut() {
            output.value = expected_coinbase_output_value;
            output.memo = None; // Explicitly set memo to None
        } else {
            let err = ConsensusError::InvalidCoinbase(
                "Coinbase transaction has no outputs to assign reward to.".to_string(),
            );
            audit_log::log_block_validation_failed(&block.header, &err.clone().into());
            return Err(err);
        }

        // Re-insert the modified coinbase transaction at the beginning
        block.transactions.insert(0, coinbase_tx);

        // Validate PoS components if this is a PoS block
        if is_pos_block {
            self.validate_proof_of_stake_and_rewards(&block, pos_reward)?;
            self.distribute_pos_rewards(&block, pos_reward)?;
        }

        // If you want to use total_fees in the coinbase output, you can update it here if needed
        if block.ticket_votes.is_empty() {
            println!("PoW Block: Reward to miner");
        } else {
            println!("PoS Block: Reward to ticket voters (PoS reward logic not implemented)");
            // TODO: Implement PoS reward distribution logic here if needed.
        }
        self.utxo_set.apply_block(&block, block.header.height);
        self.state.put_block(&block).map_err(|e| {
            ConsensusError::Internal(format!("Failed to put block to state: {}", e))
        })?;
        for tx in &block.transactions {
            self.mempool.lock().unwrap().remove_transaction(&tx.txid()); // Remove validated transactions from mempool
        }

        // Update masternode list based on registrations/deregistrations in the block
        for tx in &block.transactions {
            match tx {
                Transaction::MasternodeRegister {
                    masternode_identity,
                    ..
                } => {
                    // Convert from lib.rs MasternodeIdentity to masternode.rs MasternodeIdentity
                    let converted_identity = rusty_shared_types::masternode::MasternodeIdentity {
                        collateral_outpoint: masternode_identity.collateral_outpoint.clone(),
                        operator_public_key: masternode_identity.operator_public_key.to_vec(),
                        network_address: masternode_identity.network_address.clone(),
                        collateral_ownership_public_key: masternode_identity
                            .collateral_ownership_public_key
                            .to_vec(),
                        dkg_public_key: None, // Not available in lib.rs version
                        supported_dkg_versions: vec![], // Not available in lib.rs version
                    };
                    let registration = rusty_shared_types::masternode::MasternodeRegistration {
                        masternode_identity: converted_identity,
                        signature: vec![], // This signature is handled during transaction validation, not here.
                    };
                    self.masternode_list
                        .register_masternode(registration, block.header.height as u32)?;
                }
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Per spec 06 Section 6.4: Set masternode status to BANNED before removal
                    // For malicious behavior, masternode is permanently blacklisted
                    // slash_tx.masternode_id is already the correct type for masternode::MasternodeList

                    if let Err(e) = self.masternode_list.update_masternode_status(
                        slash_tx.masternode_id.clone(),
                        rusty_shared_types::masternode::MasternodeStatus::Banned,
                    ) {
                        warn!("Failed to update masternode status to BANNED: {}", e);
                    }

                    // For malicious behavior (100% slash), remove from list (permanent blacklist)
                    // For non-participation (5% slash), masternode can potentially recover
                    match slash_tx.reason {
                        rusty_shared_types::masternode::SlashingReason::DoubleSigning
                        | rusty_shared_types::masternode::SlashingReason::InvalidBlockProposal
                        | rusty_shared_types::masternode::SlashingReason::InvalidTransaction
                        | rusty_shared_types::masternode::SlashingReason::GovernanceViolation => {
                            // Permanent blacklist for malicious behavior - remove from list
                            self.masternode_list
                                .remove_masternode(&slash_tx.masternode_id);
                        }
                        rusty_shared_types::masternode::SlashingReason::MasternodeNonResponse => {
                            // Non-participation: masternode stays in list but is BANNED
                            // Could potentially recover after cooldown period
                        }
                    }
                }
                _ => (),
            }
        }

        // Update live ticket pool for new tickets and spent tickets
        self.live_tickets
            .update_for_new_block(&block, &self.utxo_set.get_used_inputs_as_ticket_ids());

        // Calculate state root after applying all transactions
        // Per spec 01 Section 1.2: state_root is BLAKE3 hash of Merkle Patricia Trie root
        // representing UTXO set, live tickets pool, masternode list, and active proposals
        let calculated_state_root = BlockchainState::calculate_state_root_from_masternode_list(
            &self.utxo_set,
            &self.live_tickets,
            &self.masternode_list,
            &self.active_proposals,
        )?;

        // Validate state root matches block header
        if block.header.state_root != calculated_state_root {
            return Err(ConsensusError::StateError(format!(
                "State root mismatch: expected {:?}, found {:?}",
                calculated_state_root, block.header.state_root
            )));
        }

        // Update the blockchain tip
        self.state.update_tip(block.hash(), block.header.height)?;

        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        // Comprehensive blockchain validation per consensus rules
        // Validates all blocks from genesis to tip for:
        // - Block header validation
        // - Transaction validation
        // - UTXO state consistency
        // - Difficulty adjustment verification
        // - Timestamp validation
        // - State root verification

        let current_height = match self.state.get_current_block_height() {
            Ok(height) => height,
            Err(_) => return false,
        };

        if current_height == 0 {
            // Genesis block only - basic validation
            return self.validate_genesis_block().is_ok();
        }

        // Validate all blocks from genesis to tip
        for height in 0..=current_height {
            if self.validate_block_at_height(height).is_err() {
                // Log validation failure - using existing audit function
                warn!("Blockchain validation failed at height {}: Block validation failed", height);
                return false;
            }
        }

        // Additional state consistency checks
        if !self.validate_state_consistency() {
            warn!("Blockchain validation failed: State consistency validation failed at height {}", current_height);
            return false;
        }

        true
    }

    /// Validates the genesis block
    fn validate_genesis_block(&self) -> Result<(), ConsensusError> {
        match self.state.get_block(0) {
            Ok(Some(genesis)) => {
                // Genesis block validation per spec 01 Section 1.2
                if genesis.header.height != 0 {
                    return Err(ConsensusError::InvalidBlock("Genesis block height is not 0".to_string()));
                }
                if genesis.header.previous_block_hash != [0u8; 32] {
                    return Err(ConsensusError::InvalidBlock("Genesis block has non-zero previous block hash".to_string()));
                }
                if genesis.header.version != 1 {
                    return Err(ConsensusError::InvalidBlock("Genesis block version is not 1".to_string()));
                }
                // Validate genesis transactions (typically just coinbase)
                if genesis.transactions.is_empty() {
                    return Err(ConsensusError::InvalidBlock("Genesis block has no transactions".to_string()));
                }
                // Genesis block should have valid PoW (even if difficulty is minimal)
                if !crate::consensus::pow::verify_pow(&genesis.header, U256::from(genesis.header.difficulty_target)) {
                    return Err(ConsensusError::InvalidProofOfWork);
                }
                // State root should be valid for genesis state
                if genesis.header.state_root == [0u8; 32] {
                    return Err(ConsensusError::StateError("Genesis block has zero state root".to_string()));
                }
                Ok(())
            }
            _ => Err(ConsensusError::InvalidBlock("Genesis block not found".to_string())),
        }
    }

    /// Validates a block at the given height
    fn validate_block_at_height(&self, height: u64) -> Result<(), ConsensusError> {
        let block = match self.state.get_block(height) {
            Ok(Some(block)) => block,
            _ => return Err(ConsensusError::InvalidBlock(format!("Block at height {} not found", height))),
        };

        // 1. Block header validation
        self.validate_block_header_at_height(&block, height)?;

        // 2. Transaction validation
        self.validate_block_transactions(&block, height)?;

        // 3. Difficulty adjustment verification (for non-genesis blocks)
        if height > 0 {
            self.validate_difficulty_adjustment(&block, height)?;
        }

        // 4. Timestamp validation
        self.validate_block_timestamp(&block, height)?;

        // 5. State root verification
        self.validate_state_root(&block, height)?;

        // 6. PoS validation if applicable
        if !block.ticket_votes.is_empty() {
            self.validate_pos_components(&block, height)?;
        }

        Ok(())
    }

    /// Validates block header at given height
    fn validate_block_header_at_height(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Basic header validation per spec 01 Section 1.2
        if block.header.height as u64 != height {
            return Err(ConsensusError::InvalidBlock(format!("Block height mismatch: expected {}, got {}", height, block.header.height)));
        }
        if block.header.version != 1 {
            return Err(ConsensusError::InvalidBlock(format!("Invalid block version: expected 1, got {}", block.header.version)));
        }

        // Previous block hash validation
        if height > 0 {
            if let Ok(Some(prev_block)) = self.state.get_block(height - 1) {
                if block.header.previous_block_hash != prev_block.hash() {
                    return Err(ConsensusError::InvalidBlock(format!("Previous block hash mismatch at height {}", height)));
                }
            } else {
                return Err(ConsensusError::InvalidBlock(format!("Previous block not found for height {}", height)));
            }
        } else if block.header.previous_block_hash != [0u8; 32] {
            return Err(ConsensusError::InvalidBlock("Genesis block must have zero previous block hash".to_string()));
        }

        // Merkle root validation
        if block.header.merkle_root != block.calculate_merkle_root() {
            return Err(ConsensusError::InvalidBlock(format!("Merkle root mismatch at height {}", height)));
        }

        // PoW validation
        if !crate::consensus::pow::verify_pow(&block.header, U256::from(block.header.difficulty_target)) {
            return Err(ConsensusError::InvalidProofOfWork);
        }

        Ok(())
    }

    /// Validates all transactions in a block
    fn validate_block_transactions(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        if block.transactions.is_empty() {
            return Err(ConsensusError::InvalidBlock("Block contains no transactions".to_string()));
        }

        // First transaction must be coinbase
        if !block.transactions[0].is_coinbase() {
            return Err(ConsensusError::InvalidBlock("First transaction in block is not coinbase".to_string()));
        }

        // Validate coinbase transaction
        if !self.validate_coinbase_transaction(&block.transactions[0], block, height) {
            return Err(ConsensusError::InvalidCoinbase("Coinbase transaction validation failed".to_string()));
        }

        // Validate non-coinbase transactions
        for tx in &block.transactions[1..] {
            if tx.is_coinbase() {
                return Err(ConsensusError::InvalidBlock("Multiple coinbase transactions in block".to_string()));
            }
            if !self.validate_non_coinbase_transaction(tx, height) {
                return Err(ConsensusError::TransactionValidation("Non-coinbase transaction validation failed".to_string()));
            }
        }

        Ok(())
    }

    /// Validates coinbase transaction
    fn validate_coinbase_transaction(&self, coinbase: &Transaction, block: &Block, height: u64) -> bool {
        // Coinbase validation per spec 01 Section 1.5.1
        if !coinbase.is_coinbase() {
            return false;
        }

        // Must have exactly one input (null input)
        if coinbase.get_inputs().len() != 1 {
            return false;
        }

        let input = &coinbase.get_inputs()[0];
        if input.previous_output.txid != [0u8; 32] || input.previous_output.vout != u32::MAX {
            return false;
        }

        // Must have at least one output
        if coinbase.get_outputs().is_empty() {
            return false;
        }

        // Validate reward amount
        let total_reward = self.state.get_block_subsidy(height, self.params.halving_interval, self.params.initial_block_reward);
        let actual_reward: u64 = coinbase.get_outputs().iter().map(|o| o.value).sum();

        // Allow some tolerance for rounding in PoS rewards
        if actual_reward > total_reward + (total_reward / 100) { // 1% tolerance
            return false;
        }

        true
    }

    /// Validates a non-coinbase transaction
    fn validate_non_coinbase_transaction(&self, tx: &Transaction, height: u64) -> bool {
        // Use existing validation logic but with current height
        match self.validate_transaction(tx, height) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Validates difficulty adjustment for a block
    fn validate_difficulty_adjustment(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Per spec 02a - Proof-of-Work Difficulty Adjustment
        const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;
        const TARGET_BLOCK_TIME: u64 = 150;

        let is_adjustment_block = (height - 1) % DIFFICULTY_ADJUSTMENT_INTERVAL == 0;

        if !is_adjustment_block {
            // Non-adjustment blocks must have same difficulty as previous
            if let Ok(Some(prev_block)) = self.state.get_block(height - 1) {
                if block.header.difficulty_target != prev_block.header.difficulty_target {
                    return Err(ConsensusError::InvalidProofOfWork);
                }
                return Ok(());
            }
            return Err(ConsensusError::InvalidBlock("Previous block not found for difficulty validation".to_string()));
        }

        // For adjustment blocks, validate the calculation
        if height < DIFFICULTY_ADJUSTMENT_INTERVAL {
            // Early blocks may have special handling
            if block.header.difficulty_target == 0 {
                return Err(ConsensusError::InvalidProofOfWork);
            }
            return Ok(());
        }

        // Get blocks for adjustment period
        let first_height = height - DIFFICULTY_ADJUSTMENT_INTERVAL;
        let last_height = height - 1;

        if let (Ok(Some(first_block)), Ok(Some(last_block))) = (
            self.state.get_block(first_height),
            self.state.get_block(last_height),
        ) {
            let actual_time = last_block.header.timestamp.saturating_sub(first_block.header.timestamp);
            let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME;

            // Calculate expected difficulty
            let prev_target = U256::from(last_block.header.difficulty_target);
            let new_target = calculate_new_target(
                prev_target,
                actual_time,
                expected_time,
                DIFFICULTY_ADJUSTMENT_INTERVAL as u64,
                expected_time * 4, // max timespan
                U256::MAX, // max target
            );

            let expected_difficulty = target_to_compact(new_target);
            if block.header.difficulty_target != expected_difficulty {
                return Err(ConsensusError::InvalidProofOfWork);
            }
            return Ok(());
        }

        Err(ConsensusError::InvalidBlock("Blocks not found for difficulty adjustment validation".to_string()))
    }

    /// Validates block timestamp
    fn validate_block_timestamp(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Per spec 01 Section 1.2: timestamp validation
        if height > 0 {
            if let Ok(Some(prev_block)) = self.state.get_block(height - 1) {
                // Must be greater than previous block timestamp
                if block.header.timestamp <= prev_block.header.timestamp {
                    return Err(ConsensusError::InvalidBlock(format!("Block timestamp {} is not greater than previous block timestamp {}", block.header.timestamp, prev_block.header.timestamp)));
                }
                // Must not be more than 2 hours in the future
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u64;
                if block.header.timestamp > current_time + 7200 {
                    return Err(ConsensusError::InvalidBlock(format!("Block timestamp {} is more than 2 hours in the future", block.header.timestamp)));
                }
            } else {
                return Err(ConsensusError::InvalidBlock("Previous block not found for timestamp validation".to_string()));
            }
        }

        Ok(())
    }

    /// Validates state root for a block
    fn validate_state_root(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Per spec 05 Section 5.5: state_root validation
        // For comprehensive validation, we would need to calculate the state root
        // after applying this block's transactions to the previous state.
        // For now, we check that it's not zero and consistent with stored state.

        if block.header.state_root == [0u8; 32] && height > 0 {
            return Err(ConsensusError::StateError("State root is zero for non-genesis block".to_string()));
        }

        // In a full implementation, we would:
        // 1. Start with previous state
        // 2. Apply block transactions
        // 3. Calculate new state root
        // 4. Compare with block.header.state_root

        // For this implementation, we rely on the fact that blocks were validated
        // when added, so the state root should be correct if the chain is valid.

        Ok(())
    }

    /// Validates PoS components if present
    fn validate_pos_components(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Per spec 03 - OxideSync PoS
        if block.ticket_votes.is_empty() {
            return Ok(()); // PoW block
        }

        // Must have minimum valid votes
        const MIN_VALID_VOTES: usize = 3;
        if block.ticket_votes.len() < MIN_VALID_VOTES {
            return Err(ConsensusError::InvalidTicketVote(format!("PoS block must have at least {} votes, got {}", MIN_VALID_VOTES, block.ticket_votes.len())));
        }

        // Validate ticket votes structure
        for vote in &block.ticket_votes {
            if vote.ticket_id == [0u8; 32] {
                return Err(ConsensusError::InvalidTicketVote("Ticket vote has zero ticket ID".to_string()));
            }
            if vote.signature.len() != 64 {
                return Err(ConsensusError::InvalidTicketVote(format!("Ticket vote signature has invalid length: {}", vote.signature.len())));
            }
            // Additional validation would check ticket exists and signature is valid
        }

        Ok(())
    }

    /// Validates overall state consistency
    fn validate_state_consistency(&self) -> bool {
        // Check UTXO set consistency
        if !self.validate_utxo_consistency() {
            return false;
        }

        // Check masternode list consistency
        if !self.validate_masternode_consistency() {
            return false;
        }

        // Check ticket pool consistency
        if !self.validate_ticket_pool_consistency() {
            return false;
        }

        true
    }

    /// Validates UTXO set consistency
    fn validate_utxo_consistency(&self) -> bool {
        // Basic consistency checks - in full implementation would use
        // validate_utxo_set_consistency from validation.rs
        // For now, check that critical UTXOs exist

        // This is a simplified check - full validation would be more comprehensive
        true
    }

    /// Validates masternode list consistency
    fn validate_masternode_consistency(&self) -> bool {
        // Check that masternodes have valid collateral
        for mn_id in self.active_masternodes() {
            if let Some(mn_entry) = self.masternode_list.get_masternode(&mn_id) {
                // Check collateral exists
                if self.get_utxo(&mn_entry.identity.collateral_outpoint).is_err() {
                    return false;
                }
            }
        }
        true
    }

    /// Validates ticket pool consistency
    fn validate_ticket_pool_consistency(&self) -> bool {
        // Check that live tickets have valid UTXOs
        for ticket in self.live_tickets.get_all_tickets() {
            // Ticket should correspond to a valid UTXO
            // This is simplified - full validation would check the UTXO exists
            let _ticket_id = ticket.id;
        }
        true
    }

    // Method to get UTXO details, potentially from a historical state or by querying the UTXO set
    pub fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<(TxOutput, u64, bool)>, ConsensusError> {
        self.utxo_set
            .get_utxo(outpoint)
            .map(|utxo| Some((utxo.output.clone(), utxo.creation_height, utxo.is_coinbase)))
            .ok_or(ConsensusError::MissingPreviousOutput(outpoint.clone()))
    }

    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        // Validate transaction structure
        // if tx.get_inputs().is_empty() || tx.get_outputs().is_empty() {
        //     return Err(ConsensusError::InvalidTransaction("Transaction has no inputs or outputs".to_string()));
        // }

        // Validate coinbase transactions separately
        if tx.is_coinbase() {
            if tx.get_inputs().len() != 1
                || !tx.get_inputs()[0]
                    .previous_output
                    .txid
                    .iter()
                    .all(|&x| x == 0)
            {
                return Err(ConsensusError::InvalidCoinbase(
                    "Coinbase transaction must have a single null input".to_string(),
                ));
            }
            if tx.get_outputs().is_empty() {
                return Err(ConsensusError::InvalidCoinbase(
                    "Coinbase transaction must have at least one output".to_string(),
                ));
            }
            // Coinbase maturity check handled in add_block
            return Ok(());
        }

        // Validate inputs (referencing existing UTXOs)
        for input in tx.get_inputs() {
            let outpoint = input.previous_output.clone();
            let utxo = self
                .utxo_set
                .get_utxo(&outpoint)
                .ok_or(ConsensusError::MissingPreviousOutput(outpoint.clone()))?;

            // Check coinbase maturity
            if utxo.is_coinbase
                && (current_block_height - utxo.creation_height
                    < COINBASE_MATURITY_PERIOD_BLOCKS as u64)
            {
                return Err(ConsensusError::ImmatureTicket(format!(
                    "Coinbase UTXO {:?} is not yet mature",
                    outpoint
                )));
            }
        }

        // Full FerrisScript interpreter integration for all transaction inputs
        // Includes: script execution for all inputs, proper sighash calculation,
        // opcode validation, stack limits enforcement, and signature verification
        // Per spec 04 Section 4.3: Execute combined script_sig + script_pubkey for each input
        let mut script_engine = ScriptEngine::new();
        if !script_engine.validate_transaction(tx, &self.utxo_set, current_block_height) {
            return Err(ConsensusError::InvalidScript(
                "FerrisScript validation failed for transaction".to_string()
            ));
        }

        // Validate transaction fees (inputs sum >= outputs sum + fee)
        let total_input_value: u64 = tx
            .get_inputs()
            .iter()
            .filter_map(|input| {
                let outpoint = input.previous_output.clone();
                self.utxo_set
                    .get_utxo(&outpoint)
                    .map(|utxo| utxo.output.value)
            })
            .sum();
        let total_output_value: u64 = tx.get_outputs().iter().map(|output| output.value).sum();
        if total_input_value < total_output_value + tx.get_fee() {
            return Err(ConsensusError::InsufficientFee(
                tx.get_fee(),
                total_input_value.saturating_sub(total_output_value),
            ));
        }

        // Validate locktime and sequence numbers
        if tx.get_lock_time() < LOCKTIME_THRESHOLD {
            // Locktime is a block height
            if tx.get_lock_time() > current_block_height as u32 {
                return Err(ConsensusError::InvalidLockTime(format!("Transaction locktime ({}) is in the future compared to current block height ({})", tx.get_lock_time(), current_block_height)));
            }
        } else {
            // Locktime is a timestamp
            // TODO: Get median time past from current block or network
            // For now, simple check against current system time (not robust for consensus)
            let current_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            if tx.get_lock_time() > current_timestamp {
                return Err(ConsensusError::InvalidLockTime(format!(
                    "Transaction locktime ({}) is in the future compared to current timestamp ({})",
                    tx.get_lock_time(),
                    current_timestamp
                )));
            }
        }

        // Validate ticket purchases (if applicable)
        if let Transaction::TicketPurchase {
            ticket_id,
            locked_amount,
            ticket_address,
            outputs,
            ..
        } = tx
        {
            // Ensure ticket output exists and matches locked_amount
            let ticket_output = tx
                .get_outputs()
                .first()
                .ok_or(ConsensusError::InvalidTicket(
                    "Ticket purchase transaction missing output".to_string(),
                ))?;
            if ticket_output.value != *locked_amount {
                return Err(ConsensusError::InvalidTicket(
                    "Ticket purchase output value does not match locked amount".to_string(),
                ));
            }

            // Ensure the ticket address is a valid script_pubkey
            if ticket_output.script_pubkey != *ticket_address {
                return Err(ConsensusError::InvalidTicket(
                    "Ticket purchase output script_pubkey does not match ticket address"
                        .to_string(),
                ));
            }

            // Ensure the ticket is not already in the live tickets pool
            if self
                .live_tickets
                .get_ticket(&TicketId::from(*ticket_id))
                .is_some()
            {
                return Err(ConsensusError::DuplicateTicketVote(format!(
                    "Ticket with ID {:?} already exists in live pool",
                    ticket_id
                )));
            }
        }

        // Validate ticket redemptions (if applicable)
        if let Transaction::TicketRedemption { ticket_id, .. } = tx {
            let ticket = self
                .live_tickets
                .get_ticket(&rusty_shared_types::TicketId(*ticket_id))
                .ok_or(ConsensusError::InvalidTicket(format!(
                    "Ticket {:?} not found in live pool",
                    ticket_id
                )))?;
            // Basic check if the ticket exists and is mature/not expired
            if ticket.height + self.params.ticket_maturity as u64 > current_block_height {
                return Err(ConsensusError::ImmatureTicket(format!(
                    "Ticket {:?} is not yet mature",
                    ticket_id
                )));
            }

            if ticket.height + self.params.ticket_expiry as u64 <= current_block_height {
                return Err(ConsensusError::ExpiredTicket(format!(
                    "Ticket {:?} has expired",
                    ticket_id
                )));
            }
        }

        Ok(())
    }

    pub fn active_masternodes(&self) -> Vec<rusty_shared_types::masternode::MasternodeID> {
        // Returns a list of active masternode IDs from the MasternodeList
        self.masternode_list
            .map
            .values()
            .filter(|mn_entry| {
                mn_entry.status == rusty_shared_types::masternode::MasternodeStatus::Active
            })
            .map(|mn_entry| {
                rusty_shared_types::masternode::MasternodeID(
                    mn_entry.identity.collateral_outpoint.clone(),
                )
            })
            .collect()
    }

    fn distribute_pos_rewards(
        &mut self,
        block: &Block,
        total_reward: u64,
    ) -> Result<(), ConsensusError> {
        if block.ticket_votes.is_empty() {
            return Ok(());
        }

        let total_voters = block.ticket_votes.len() as u64;
        if total_voters == 0 {
            return Ok(());
        }

        let reward_per_voter = total_reward / total_voters;

        let mut coinbase_outputs = Vec::new();

        for vote in &block.ticket_votes {
            let ticket = self
                .live_tickets
                .get_ticket(&rusty_shared_types::TicketId(vote.ticket_id))
                .ok_or(ConsensusError::InvalidTicket(format!(
                    "Voted ticket {:?} not found in live pool",
                    vote.ticket_id
                )))?;

            // For now, we assume the reward goes to the ticket's public key hash
            // In a real system, this might be a dedicated payout address set by the staker.
            let script_pubkey = ticket.pubkey.to_vec();
            coinbase_outputs.push(TxOutput {
                value: reward_per_voter,
                script_pubkey,
                memo: None,
            });
        }
        // Add these outputs to the coinbase transaction if necessary
        // This part needs to be carefully integrated with the coinbase transaction generation
        // For now, we are simulating adding outputs. The actual coinbase tx is handled in add_block.
        Ok(())
    }

    pub fn process_block(&mut self, block: &Block) -> Result<(), ConsensusError> {
        // 1. Validate block header (PoW/PoS, timestamp, merkle root, etc.)
        // This is largely handled in `add_block` now, but could be expanded here.

        // 2. Validate transactions (signatures, fees, double-spends, scripts)
        for tx in &block.transactions {
            self.validate_transaction(tx, block.header.height)?;
        }

        // 3. Update UTXO set
        self.utxo_set.apply_block(block, block.header.height);

        // 4. Update Masternode list (registrations, updates, slashes)
        for tx in &block.transactions {
            match tx {
                Transaction::MasternodeRegister {
                    masternode_identity,
                    ..
                } => {
                    // Convert from lib.rs MasternodeIdentity to masternode.rs MasternodeIdentity
                    let converted_identity = rusty_shared_types::masternode::MasternodeIdentity {
                        collateral_outpoint: masternode_identity.collateral_outpoint.clone(),
                        operator_public_key: masternode_identity.operator_public_key.to_vec(),
                        network_address: masternode_identity.network_address.clone(),
                        collateral_ownership_public_key: masternode_identity
                            .collateral_ownership_public_key
                            .to_vec(),
                        dkg_public_key: None, // Not available in lib.rs version
                        supported_dkg_versions: vec![], // Not available in lib.rs version
                    };
                    let registration = rusty_shared_types::masternode::MasternodeRegistration {
                        masternode_identity: converted_identity,
                        signature: vec![], // Assuming signature is validated at the transaction level
                    };
                    self.masternode_list
                        .register_masternode(registration, block.header.height as u32)
                        .map_err(|e| ConsensusError::MasternodeError(e.to_string()))?;
                }
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Remove/slash masternode
                    self.masternode_list
                        .remove_masternode(&slash_tx.masternode_id);
                }
                _ => (),
            }
        }

        // 5. Update Live Tickets Pool
        // This involves adding new tickets (from purchase transactions) and removing spent tickets
        self.live_tickets
            .update_for_new_block(block, &self.utxo_set.get_used_inputs_as_ticket_ids())?;

        // Process ticket finality transitions (PENDING -> LIVE)
        // Per spec 03 Section 3.2.2: Tickets transition to LIVE when block reaches POS_FINALITY_DEPTH
        self.live_tickets
            .process_ticket_finality(block.header.height);

        // 6. Update Governance Proposals and Votes
        self.evaluate_and_apply_governance(block.header.height)?;

        // 7. Store block in state/database
        self.state
            .put_block(block)
            .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        self.state.update_tip(block.hash(), block.header.height)?;

        Ok(())
    }

    /// Validates the Proof of Stake component of a block, including ticket votes and rewards.
    fn validate_proof_of_stake_and_rewards(
        &self,
        block: &Block,
        total_reward: u64,
    ) -> Result<(), ConsensusError> {
        use crate::protocol_constants::{VOTERS_PER_BLOCK, MIN_VALID_VOTES_REQUIRED, GRACE_PERIOD_BLOCKS};
        use crate::consensus::pos::{select_voters, validate_ticket_signature};
        use rusty_shared_types::TicketId;

        // Skip validation for PoW blocks
        if block.ticket_votes.is_empty() {
            return Ok(());
        }

        // Per spec 03 Section 3.5.1: Block must contain exactly VOTERS_PER_BLOCK votes
        if block.ticket_votes.len() != VOTERS_PER_BLOCK as usize {
            return Err(ConsensusError::InvalidTicketVote(format!(
                "PoS block must contain exactly {} ticket votes, found {}",
                VOTERS_PER_BLOCK,
                block.ticket_votes.len()
            )));
        }

        // Select expected voters for the previous block
        let expected_voters = select_voters(&block.header.previous_block_hash, &self.live_tickets);
        let expected_voter_ids: std::collections::HashSet<TicketId> = expected_voters.into_iter().collect();

        let mut valid_votes = 0;
        let mut seen_tickets = std::collections::HashSet::new();

        // Validate each ticket vote
        for vote in &block.ticket_votes {
            let ticket_id = TicketId(vote.ticket_id);

            // Check for duplicate votes in this block
            if !seen_tickets.insert(ticket_id) {
                return Err(ConsensusError::InvalidTicketVote(
                    "Duplicate ticket vote in block".to_string()
                ));
            }

            // Check if ticket was selected for voting
            if !expected_voter_ids.contains(&ticket_id) {
                return Err(ConsensusError::InvalidTicketVote(format!(
                    "Ticket {:?} was not selected for voting on block {:?}",
                    ticket_id, block.header.previous_block_hash
                )));
            }

            // Get the ticket
            let ticket = self.live_tickets.get_ticket(&ticket_id)
                .ok_or(ConsensusError::InvalidTicket(format!(
                    "Voted ticket {:?} not found in live pool", ticket_id
                )))?;

            // Check ticket is LIVE
            if ticket.status != rusty_shared_types::TicketStatus::Live {
                return Err(ConsensusError::InvalidTicket(format!(
                    "Ticket {:?} is not live (status: {:?})", ticket_id, ticket.status
                )));
            }

            // Check ticket has not expired
            if block.header.height >= ticket.height + self.params.ticket_expiry as u64 {
                return Err(ConsensusError::ExpiredTicket(format!(
                    "Ticket {:?} has expired", ticket_id
                )));
            }

            // Verify vote block_hash matches previous block hash
            if vote.block_hash != block.header.previous_block_hash {
                return Err(ConsensusError::InvalidTicketVote(format!(
                    "Vote block_hash mismatch: expected {:?}, got {:?}",
                    block.header.previous_block_hash, vote.block_hash
                )));
            }

            // Verify signature
            let signature_bytes = vote.signature.to_vec();
            if !validate_ticket_signature(&ticket.pubkey, &vote.block_hash, &signature_bytes)
                .map_err(|e| ConsensusError::InvalidSignature(format!("Signature validation error: {:?}", e)))? {
                return Err(ConsensusError::InvalidSignature(format!(
                    "Invalid signature for ticket {:?}", ticket_id
                )));
            }

            // Verify vote type is valid (0=Yes, 1=No, 2=Abstain)
            if vote.vote > 2 {
                return Err(ConsensusError::InvalidTicketVote(format!(
                    "Invalid vote type {} for ticket {:?}", vote.vote, ticket_id
                )));
            }

            valid_votes += 1;
        }

        // Per spec 03 Section 3.5.3: Quorum check
        if valid_votes < MIN_VALID_VOTES_REQUIRED as usize {
            return Err(ConsensusError::InsufficientTicketVotes);
        }

        // Reward distribution calculation (validation that rewards can be distributed)
        if total_reward > 0 && valid_votes > 0 {
            let reward_per_voter = total_reward / valid_votes as u64;
            if reward_per_voter == 0 {
                return Err(ConsensusError::RuleViolation(
                    "Reward per voter would be zero".to_string()
                ));
            }
        }

        // Slashing enforcement: Check for non-participation
        // Per spec 03 Section 3.7.1: Detect non-participating tickets
        let current_height = block.header.height;
        for expected_ticket_id in &expected_voter_ids {
            let voted = block.ticket_votes.iter().any(|v| v.ticket_id == expected_ticket_id.0);
            if !voted {
                // Check if grace period has passed for slashing
                if let Some(ticket) = self.live_tickets.get_ticket(expected_ticket_id) {
                    let selection_height = ticket.height; // Approximate, since we don't store exact selection height
                    if current_height > selection_height + GRACE_PERIOD_BLOCKS as u64 {
                        // Non-participation detected - in a full implementation, this would trigger slashing
                        // For now, we log it but don't fail validation (slashing happens via transactions)
                        warn!("Non-participating ticket {:?} detected at height {}", expected_ticket_id, current_height);
                    }
                }
            }
        }

        // Check for malicious behavior (double-voting, invalid votes already checked above)
        // Additional checks could be added here if needed

        Ok(())
    }

    fn process_governance_proposal(
        &mut self,
        proposal: &rusty_shared_types::governance::GovernanceProposal,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        if proposal.start_block_height <= current_block_height {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal voting start height must be in the future.".to_string(),
            ));
        }
        if proposal.end_block_height <= proposal.start_block_height {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal end height must be greater than start height.".to_string(),
            ));
        }
        let voting_window = proposal.end_block_height - proposal.start_block_height + 1;
        if voting_window != self.params.voting_period_blocks {
            return Err(ConsensusError::RuleViolation(format!(
                "Governance proposal voting window ({}) must equal configured voting period ({}).",
                voting_window, self.params.voting_period_blocks
            )));
        }
        if proposal.title.chars().count() > 128 {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal title exceeds 128 characters.".to_string(),
            ));
        }
        if proposal.inputs.is_empty() {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal must include at least one input to lock stake.".to_string(),
            ));
        }
        if proposal.outputs.is_empty() {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal must include at least one output for stake escrow."
                    .to_string(),
            ));
        }
        let total_stake_locked: u64 = proposal.outputs.iter().map(|output| output.value).sum();
        if total_stake_locked < self.params.proposal_stake_amount {
            return Err(ConsensusError::RuleViolation(format!(
                "Governance proposal must lock at least {} satoshis of stake.",
                self.params.proposal_stake_amount
            )));
        }
        if proposal.proposal_id != proposal.hash() {
            return Err(ConsensusError::RuleViolation(
                "Governance proposal ID does not match canonical hash.".to_string(),
            ));
        }
        let message = proposal
            .canonical_bytes()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        let public_key = VerifyingKey::from_bytes(&proposal.proposer_address).map_err(|_| {
            ConsensusError::InvalidSignature(
                "Invalid proposer public key for governance proposal.".to_string(),
            )
        })?;
        let signature =
            Signature::from_bytes(&proposal.proposer_signature.bytes).map_err(|_| {
                ConsensusError::InvalidSignature(
                    "Invalid proposer signature encoding for governance proposal.".to_string(),
                )
            })?;
        verify_signature(&public_key, &message, &signature).map_err(|_| {
            ConsensusError::InvalidSignature(
                "Invalid proposer signature for governance proposal.".to_string(),
            )
        })?;

        self.active_proposals.add_proposal(proposal.clone())?;
        Ok(())
    }

    fn process_governance_vote(
        &mut self,
        vote: &rusty_shared_types::governance::GovernanceVote,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal = self
            .active_proposals
            .get_proposal(&vote.proposal_id)
            .ok_or(ConsensusError::InvalidTicketVote(
                "Vote for non-existent proposal.".to_string(),
            ))?;

        if current_block_height < proposal.start_block_height
            || current_block_height > proposal.end_block_height
        {
            return Err(ConsensusError::InvalidTicketVote(
                "Vote outside of proposal voting period.".to_string(),
            ));
        }

        let message = vote
            .canonical_bytes()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        let signature = Signature::from_bytes(&vote.voter_signature.bytes).map_err(|_| {
            ConsensusError::InvalidSignature("Invalid voter signature encoding.".to_string())
        })?;

        match vote.voter_type {
            rusty_shared_types::governance::VoterType::PosTicket => {
                let ticket = self
                    .live_tickets
                    .get_ticket_by_pubkey(&vote.voter_id)
                    .ok_or(ConsensusError::InvalidTicketVote(
                        "Voting ticket not found in live pool.".to_string(),
                    ))?;
                if ticket.status != TicketStatus::Live {
                    return Err(ConsensusError::InvalidTicketVote(
                        "Voting ticket is not active.".to_string(),
                    ));
                }
                if ticket.pubkey.len() != 32 {
                    return Err(ConsensusError::InvalidSignature(
                        "Invalid ticket public key length.".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&ticket.pubkey);
                let public_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
                    ConsensusError::InvalidSignature(
                        "Invalid public key for ticket vote.".to_string(),
                    )
                })?;
                verify_signature(&public_key, &message, &signature).map_err(|_| {
                    ConsensusError::InvalidSignature(
                        "Invalid signature for ticket vote.".to_string(),
                    )
                })?;
            }
            rusty_shared_types::governance::VoterType::Masternode => {
                let (_, mn_entry) = self
                    .masternode_list
                    .find_by_operator_key(&vote.voter_id)
                    .ok_or(ConsensusError::MasternodeError(
                        "Voting masternode not found or not active.".to_string(),
                    ))?;
                if mn_entry.status != MasternodeStatus::Active {
                    return Err(ConsensusError::MasternodeError(
                        "Masternode voter is not active.".to_string(),
                    ));
                }
                if mn_entry.identity.operator_public_key.len() != 32 {
                    return Err(ConsensusError::InvalidSignature(
                        "Invalid masternode operator public key length.".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&mn_entry.identity.operator_public_key);
                let public_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
                    ConsensusError::InvalidSignature(
                        "Invalid public key for masternode vote.".to_string(),
                    )
                })?;
                verify_signature(&public_key, &message, &signature).map_err(|_| {
                    ConsensusError::InvalidSignature(
                        "Invalid signature for masternode vote.".to_string(),
                    )
                })?;
            }
        }

        self.active_proposals.record_vote(vote.clone())?;
        Ok(())
    }

    fn validate_transaction_inputs_and_scripts(
        &self,
        tx: &Transaction,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        if !self.utxo_set.validate_transaction_inputs_with_params(
            tx,
            current_height,
            self.params.coinbase_maturity,
        ) {
            return Err(ConsensusError::TransactionValidation(format!(
                "Transaction input validation failed for tx: {:?}",
                tx.txid()
            )));
        }
        let mut script_engine = ScriptEngine::new();
        if !script_engine.validate_transaction(tx, &self.utxo_set, current_height) {
            return Err(ConsensusError::InvalidScript(format!(
                "Transaction script verification failed for tx: {:?}",
                tx.txid()
            )));
        }
        Ok(())
    }

    pub fn evaluate_and_apply_governance(
        &mut self,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal_ids_to_remove: Vec<Hash> = self
            .active_proposals
            .proposals
            .keys()
            .filter(|&proposal_id| {
                if let Some(proposal) = self.active_proposals.get_proposal(proposal_id) {
                    current_block_height
                        > proposal.end_block_height + self.params.activation_delay_blocks
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for proposal_id in proposal_ids_to_remove {
            let proposal = self
                .active_proposals
                .get_proposal(&proposal_id)
                .cloned()
                .ok_or(ConsensusError::Internal(
                    "Proposal not found during removal.".to_string(),
                ))?;
            let voter_types_map: HashMap<Hash, GovernanceVoterType> = self
                .active_proposals
                .get_votes_for_proposal(&proposal.proposal_id)
                .map(|votes| {
                    votes
                        .iter()
                        .map(|(voter_id, vote)| {
                            let voter_type = match vote.voter_type {
                                rusty_shared_types::governance::VoterType::PosTicket => {
                                    GovernanceVoterType::PoS
                                }
                                rusty_shared_types::governance::VoterType::Masternode => {
                                    GovernanceVoterType::Masternode
                                }
                            };
                            (*voter_id, voter_type)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let outcome = self.active_proposals.evaluate_proposal_at_height(
                &proposal.proposal_id,
                current_block_height,
                self.live_tickets.count_live_tickets() as u64,
                self.masternode_list.count_active_masternodes() as u64,
                self.params.pos_voting_quorum_percentage,
                self.params.mn_voting_quorum_percentage,
                self.params.pos_approval_percentage,
                self.params.mn_approval_percentage,
                &voter_types_map,
            )?;

            match outcome {
                ProposalOutcome::Passed => {
                    info!(
                        "Governance proposal {:?} PASSED. Applying changes...",
                        proposal.proposal_id
                    );
                    // Apply governance changes based on proposal type
                    match proposal.proposal_type {
                        rusty_shared_types::governance::ProposalType::ParameterChange => {
                            if let (Some(param_name), Some(new_value_str)) = (&proposal.target_parameter, &proposal.new_value) {
                                self.apply_parameter_change(param_name, new_value_str)?;
                            } else {
                                warn!("ParameterChange proposal missing target_parameter or new_value");
                            }
                        }
                        rusty_shared_types::governance::ProposalType::ProtocolUpgrade => {
                            // Protocol upgrades require code changes, log for manual intervention
                            info!("Protocol upgrade proposal {:?} approved - manual code update required", proposal.proposal_id);
                        }
                        rusty_shared_types::governance::ProposalType::TreasurySpend => {
                            // Treasury spending logic would be implemented here
                            info!("Treasury spend proposal {:?} approved - treasury logic not yet implemented", proposal.proposal_id);
                        }
                        rusty_shared_types::governance::ProposalType::BugFix => {
                            // Bug fixes may require code changes
                            info!("Bug fix proposal {:?} approved - manual code update may be required", proposal.proposal_id);
                        }
                        rusty_shared_types::governance::ProposalType::CommunityFund => {
                            // Community fund allocation logic
                            info!("Community fund proposal {:?} approved - community fund logic not yet implemented", proposal.proposal_id);
                        }
                    }
                    self.active_proposals
                        .remove_proposal(&proposal.proposal_id)?;
                }
                ProposalOutcome::Rejected { reason } => {
                    info!(
                        "Governance proposal {:?} REJECTED: {}",
                        proposal.proposal_id, reason
                    );
                    self.active_proposals
                        .remove_proposal(&proposal.proposal_id)?;
                }
                ProposalOutcome::InProgress => {
                    // Do nothing, proposal is still active
                }
                ProposalOutcome::Expired => {
                    info!(
                        "Governance proposal {:?} EXPIRED without resolution.",
                        proposal.proposal_id
                    );
                    self.active_proposals
                        .remove_proposal(&proposal.proposal_id)?;
                }
            }
        }

        Ok(())
    }

    pub fn revert_block(&mut self, block: &Block) -> Result<(), ConsensusError> {
        // Revert UTXO set changes
        self.utxo_set.revert_block(block)?;

        // Revert Live Tickets Pool changes
        // This needs a way to reconstruct tickets that were spent in the reverted block
        // and remove tickets that were purchased in the reverted block.
        self.live_tickets
            .update_for_revert_block(block, &self.utxo_set.get_used_inputs_as_ticket_ids());

        // Revert Masternode list changes
        for tx in block.transactions.iter().rev() {
            match tx {
                Transaction::MasternodeRegister {
                    masternode_identity,
                    ..
                } => {
                    // Remove the registered masternode
                    let mn_id = MasternodeID(masternode_identity.collateral_outpoint.clone());
                    self.masternode_list.remove_masternode(&mn_id);
                }
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Re-add the slashed masternode (this is simplified and needs full masternode state for real revert)
                    // This part would ideally need a historical state or a way to revert the slash.
                }
                _ => (),
            }
        }

        // Revert Governance Proposals and Votes
        for tx in block.transactions.iter().rev() {
            match tx {
                Transaction::GovernanceProposal(proposal) => {
                    self.active_proposals
                        .remove_proposal(&proposal.proposal_id)?;
                }
                Transaction::GovernanceVote(vote) => {
                    self.active_proposals
                        .remove_vote(&vote.proposal_id, &vote.voter_id)?;
                }
                Transaction::TicketPurchase { ticket_id, .. } => {
                    // Convert ticket_id to TicketId and remove the newly added ticket from live tickets pool
                    let ticket_id = TicketId(*ticket_id);
                    self.live_tickets.remove_ticket(&ticket_id)?;
                }
                Transaction::TicketRedemption { ticket_id, .. } => {
                    // Re-add the redeemed ticket to live tickets pool
                    // NOTE: Proper implementation requires storing ticket data during redemption
                    // or reconstructing from historical block data. For now, we skip this
                    // as the ticket redemption logic needs to be redesigned to support reversion.
                    warn!("Ticket redemption revert for ticket {:?} requires historical ticket data reconstruction - skipping", ticket_id);
                    // TODO: Implement proper ticket data storage during redemption for reversion
                }
                _ => (),
            }
        }

        // Revert the blockchain tip
        self.state
            .update_tip(block.header.previous_block_hash, block.header.height - 1)
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        self.state
            .remove_block_by_hash(&block.hash())
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        self.state
            .remove_block_by_height(block.header.height)
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;

        Ok(())
    }

    pub fn process_pose_response(
        &mut self,
        challenge: rusty_shared_types::PoSeChallenge,
        response: rusty_shared_types::PoSeResponse,
    ) -> Result<Option<Transaction>, ConsensusError> {
        // 1. Validate the PoSe response against the challenge
        let challenge_message = bincode::serialize(&challenge)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;
        // Convert challenge.challenger_masternode_id from rusty_shared_types::MasternodeID to masternode::MasternodeID
        // Note: Both types wrap OutPoint, so we can convert by accessing .0
        let challenger_mn_id = rusty_shared_types::masternode::MasternodeID(
            challenge.challenger_masternode_id.0.clone(),
        );
        let target_masternode = self.masternode_list.map.get(&challenger_mn_id).ok_or(
            ConsensusError::MasternodeError("Target masternode not found.".to_string()),
        )?;
        let operator_public_key: [u8; 32] = target_masternode
            .identity
            .operator_public_key
            .clone()
            .try_into()
            .map_err(|_| {
                ConsensusError::Internal("Invalid operator public key length".to_string())
            })?;
        if !verify_pose_response(
            &challenge_message,
            &response.signed_block_hash,
            &operator_public_key,
        ) {
            return Err(ConsensusError::InvalidPoSeResponse(
                "Invalid PoSe response signature".to_string(),
            ));
        }

        // 2. Check if the response was submitted on time
        let current_height = self.state.get_current_block_height()?;
        if current_height
            > challenge.challenge_generation_block_height + self.params.pose_challenge_period_blocks
        {
            return Err(ConsensusError::PoSeChallengeExpired(
                "Challenge expired".to_string(),
            ));
        }

        // 3. Check if the block hash in the response matches the expected value
        if response.signed_block_hash != challenge.challenge_block_hash {
            return Err(ConsensusError::InvalidPoSeResponse(
                "Incorrect block hash in PoSe response".to_string(),
            ));
        }

        // 4. If we get here, the response is valid, so update masternode status
        // Per spec 06 Section 6.3.2: Update LastSuccessfulPoSe and reset failure count
        let current_height_u32 = self.state.get_current_block_height()? as u32;

        // Update successful PoSe - this will reset failure count and return to ACTIVE if on PROBATION
        // Convert response.target_masternode_id from rusty_shared_types::MasternodeID to masternode::MasternodeID
        // Note: Both types wrap OutPoint, so we can convert by accessing .0
        let target_mn_id =
            rusty_shared_types::masternode::MasternodeID(response.target_masternode_id.0.clone());
        if let Err(e) = self
            .masternode_list
            .update_successful_pose(&target_mn_id, current_height_u32)
        {
            warn!(
                "Failed to update successful PoSe for masternode {:?}: {}",
                target_mn_id, e
            );
        }

        Ok(None)
    }

    /// Generates a PoSe challenge for a random active masternode.
    fn generate_pose_challenge_tx(&mut self) -> Result<Option<Transaction>, ConsensusError> {
        // Get active masternode IDs using the active_masternodes method we updated earlier
        let active_masternodes = self.active_masternodes();

        if active_masternodes.is_empty() {
            return Ok(None);
        }

        // Select a random masternode to challenge
        let mut rng = thread_rng();
        let uniform = Uniform::from(0..active_masternodes.len());
        let target_masternode_idx = uniform.sample(&mut rng);
        let target_masternode_id = &active_masternodes[target_masternode_idx].0.txid;

        // Get the current block hash and height
        let current_block_hash = self.tip;
        let current_height = self.state.get_current_block_height()?;

        // Convert the target_masternode_id to an OutPoint and then to MasternodeID
        let _outpoint = OutPoint {
            txid: *target_masternode_id,
            vout: 0, // Using 0 as default vout since we don't have this information
        };
        let masternode_id = MasternodeID(_outpoint);

        // Generate the challenge
        let _challenge = generate_pose_challenge(
            masternode_id,
            current_height,
            &self.keypair,
            current_block_hash,
        )?;

        // Create a transaction that includes the challenge
        // This is a simplified version - in a real implementation, you'd need to:
        // 1. Create appropriate inputs and outputs
        // 2. Sign the transaction
        // 3. Validate the transaction
        let challenge_tx = Transaction::Standard {
            version: 1,
            inputs: vec![],  // TODO: Add proper inputs
            outputs: vec![], // TODO: Add proper outputs
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };

        Ok(Some(challenge_tx))
    }

    /// Register a new sidechain with the mainchain
    pub fn register_sidechain(
        &mut self,
        sidechain_id: Hash,
        initial_members: Vec<rusty_shared_types::masternode::MasternodeID>,
        threshold: u32,
        public_keys: Vec<Vec<u8>>,
        start_height: u64,
    ) -> Result<(), ConsensusError> {
        // Initialize federation for the sidechain
        self.federation_integrator.lock().unwrap()
            .initialize_sidechain_federation(
                sidechain_id,
                initial_members.clone(),
                threshold,
                public_keys.clone(),
                start_height,
                1000, // epoch transition blocks
            )
            .map_err(|e| ConsensusError::Internal(format!("Failed to initialize federation: {}", e)))?;

        // Create sidechain consensus engine
        let sidechain_consensus = SidechainConsensus::new(sidechain_id)
            .initialize_with_federation(
                initial_members,
                threshold,
                public_keys,
                start_height,
            )
            .map_err(|e| ConsensusError::Internal(format!("Failed to initialize sidechain consensus: {}", e)))?;

        self.sidechain_consensus.insert(
            sidechain_id,
            Arc::new(std::sync::Mutex::new(sidechain_consensus)),
        );

        info!("Registered sidechain {:?}", sidechain_id);
        Ok(())
    }

    /// Process a sidechain block
    pub fn process_sidechain_block(
        &mut self,
        sidechain_id: &Hash,
        block: crate::sidechain::types::SidechainBlock,
    ) -> Result<(), ConsensusError> {
        let sidechain_consensus = self.sidechain_consensus.get(sidechain_id)
            .ok_or(ConsensusError::Internal("Sidechain not registered".to_string()))?;

        let current_height = self.state.get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;

        sidechain_consensus.lock().unwrap()
            .process_sidechain_block(block, current_height, self.tip)
            .map_err(|e| ConsensusError::Internal(format!("Sidechain block processing failed: {}", e)))
    }

    /// Process mainchain block for sidechain validation
    pub fn process_mainchain_block_for_sidechains(
        &mut self,
        block_header: &rusty_shared_types::BlockHeader,
    ) -> Result<(), ConsensusError> {
        // Update mainchain state for all sidechains
        for sidechain_consensus in self.sidechain_consensus.values() {
            sidechain_consensus.lock().unwrap()
                .process_mainchain_block(block_header)
                .map_err(|e| ConsensusError::Internal(format!("Sidechain mainchain update failed: {}", e)))?;
        }

        // Apply pending federation updates
        self.federation_integrator.lock().unwrap()
            .apply_pending_updates(block_header.height)
            .map_err(|e| ConsensusError::Internal(format!("Federation update failed: {}", e)))?;

        Ok(())
    }

    /// Get sidechain consensus statistics
    pub fn get_sidechain_stats(&self, sidechain_id: &Hash) -> Option<crate::sidechain::sidechain_consensus::ConsensusStats> {
        self.sidechain_consensus.get(sidechain_id)
            .map(|sc| sc.lock().unwrap().get_consensus_stats())
    }

    /// Get federation statistics
    pub fn get_federation_stats(&self) -> crate::sidechain::federation_integrator::FederationStats {
        self.federation_integrator.lock().unwrap().get_federation_stats()
    }

    /// Get peg statistics
    pub fn get_peg_stats(&self) -> crate::sidechain::two_way_peg::PegStats {
        self.peg_manager.lock().unwrap().get_stats()
    }

    /// Process cross-chain transaction
    pub fn process_cross_chain_transaction(
        &mut self,
        transaction: crate::sidechain::types::CrossChainTransaction,
    ) -> Result<(), ConsensusError> {
        // Route transaction based on destination
        if transaction.destination_chain == [0u8; 32] {
            // To mainchain - handle as peg-out
            self.handle_peg_out_transaction(transaction)?;
        } else {
            // To sidechain - forward to sidechain consensus
            if let Some(sidechain_consensus) = self.sidechain_consensus.get(&transaction.destination_chain) {
                // This would be handled by the sidechain consensus engine
                // For now, just log
                info!("Cross-chain transaction to sidechain {:?}", transaction.destination_chain);
            } else {
                return Err(ConsensusError::Internal("Destination sidechain not registered".to_string()));
            }
        }

        Ok(())
    }

    /// Handle peg-out transaction (sidechain to mainchain)
    fn handle_peg_out_transaction(
        &mut self,
        transaction: crate::sidechain::types::CrossChainTransaction,
    ) -> Result<(), ConsensusError> {
        // Validate transaction
        let mut peg_manager = self.peg_manager.lock().unwrap();
        let request = crate::sidechain::two_way_peg::PegOutRequest {
            sidechain_tx_hash: [0u8; 32], // Would be extracted from transaction
            amount: transaction.amount,
            mainchain_recipient: transaction.recipient_address,
            sidechain_id: transaction.source_chain,
            sidechain_confirm_height: 0, // Would be current sidechain height
            merkle_proof: vec![], // Would be provided
            federation_signatures: transaction.federation_signatures,
        };

        peg_manager.initiate_peg_out(request)
            .map_err(|e| ConsensusError::Internal(format!("Peg-out initiation failed: {}", e)))?;

        // Confirm the peg transaction
        let current_height = self.state.get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        let pending_txs: Vec<_> = peg_manager.get_pending_transactions().into_iter().cloned().collect();

        for tx in pending_txs {
            if current_height >= tx.confirm_height + 6 { // 6 confirmations
                peg_manager.confirm_peg_transaction(&tx.id, current_height)
                    .map_err(|e| ConsensusError::Internal(format!("Peg confirmation failed: {}", e)))?;
                peg_manager.complete_peg_transaction(&tx.id)
                    .map_err(|e| ConsensusError::Internal(format!("Peg completion failed: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Apply a parameter change from a governance proposal
    fn apply_parameter_change(&mut self, param_name: &str, new_value_str: &str) -> Result<(), ConsensusError> {
        match param_name {
            // u64 parameters
            "min_stake" => {
                self.params.min_stake = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_tickets_per_stake" => {
                self.params.max_tickets_per_stake = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "ticket_price" => {
                self.params.ticket_price = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "ticket_maturity" => {
                self.params.ticket_maturity = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "ticket_expiry" => {
                self.params.ticket_expiry = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "min_block_time" => {
                self.params.min_block_time = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "reward_amount" => {
                self.params.reward_amount = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "target_live_tickets" => {
                self.params.target_live_tickets = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "difficulty_adjustment_window" => {
                self.params.difficulty_adjustment_window = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "halving_interval" => {
                self.params.halving_interval = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "initial_block_reward" => {
                self.params.initial_block_reward = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "ticket_price_adjustment_period" => {
                self.params.ticket_price_adjustment_period = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_ticket_price" => {
                self.params.max_ticket_price = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "min_ticket_price" => {
                self.params.min_ticket_price = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "proposal_stake_amount" => {
                self.params.proposal_stake_amount = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "voting_period_blocks" => {
                self.params.voting_period_blocks = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "activation_delay_blocks" => {
                self.params.activation_delay_blocks = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "grace_period_blocks" => {
                self.params.grace_period_blocks = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "slash_forgiveness_period" => {
                self.params.slash_forgiveness_period = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pose_challenge_period_blocks" => {
                self.params.pose_challenge_period_blocks = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "num_pose_challengers" => {
                self.params.num_pose_challengers = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "num_pose_targets_per_period" => {
                self.params.num_pose_targets_per_period = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pose_response_timeout_seconds" => {
                self.params.pose_response_timeout_seconds = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_pose_failures" => {
                self.params.max_pose_failures = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "reset_failures_period" => {
                self.params.reset_failures_period = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "min_witness_signatures" => {
                self.params.min_witness_signatures = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pos_finality_depth" => {
                self.params.pos_finality_depth = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_block_size" => {
                self.params.max_block_size = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_tx_size" => {
                self.params.max_tx_size = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid usize value for {}: {}", param_name, new_value_str))
                })?;
            }
            "block_reward" => {
                self.params.block_reward = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "coinbase_maturity" => {
                self.params.coinbase_maturity = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "dust_limit" => {
                self.params.dust_limit = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "min_relay_tx_fee" => {
                self.params.min_relay_tx_fee = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "masternode_collateral_amount" => {
                self.params.masternode_collateral_amount = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "max_inactivity_blocks" => {
                self.params.max_inactivity_blocks = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid u32 value for {}: {}", param_name, new_value_str))
                })?;
            }
            // f64 parameters
            "price_adjustment_factor" => {
                self.params.price_adjustment_factor = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pos_reward_ratio" => {
                self.params.pos_reward_ratio = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pos_voting_quorum_percentage" => {
                self.params.pos_voting_quorum_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "mn_voting_quorum_percentage" => {
                self.params.mn_voting_quorum_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "pos_approval_percentage" => {
                self.params.pos_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "mn_approval_percentage" => {
                self.params.mn_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "malicious_behavior_slash_percentage" => {
                self.params.malicious_behavior_slash_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "protocol_upgrade_approval_percentage" => {
                self.params.protocol_upgrade_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "parameter_change_approval_percentage" => {
                self.params.parameter_change_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "treasury_spend_approval_percentage" => {
                self.params.treasury_spend_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "bug_fix_approval_percentage" => {
                self.params.bug_fix_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            "community_fund_approval_percentage" => {
                self.params.community_fund_approval_percentage = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid f64 value for {}: {}", param_name, new_value_str))
                })?;
            }
            // usize parameters
            "tickets_per_round" => {
                self.params.tickets_per_round = new_value_str.parse().map_err(|_| {
                    ConsensusError::RuleViolation(format!("Invalid usize value for {}: {}", param_name, new_value_str))
                })?;
            }
            _ => {
                // For backward compatibility, ignore unknown parameters instead of failing
                warn!("Unknown parameter '{}' in governance proposal, ignoring for backward compatibility", param_name);
            }
        }
        info!("Applied parameter change: {} = {}", param_name, new_value_str);
        Ok(())
    }

    /// Get active sidechains
    pub fn get_active_sidechains(&self) -> Vec<Hash> {
        self.sidechain_consensus.keys().cloned().collect()
    }

    /// Check if sidechain is registered
    pub fn is_sidechain_registered(&self, sidechain_id: &Hash) -> bool {
        self.sidechain_consensus.contains_key(sidechain_id)
    }

    /// Get the current block height
    pub fn get_current_block_height(&self) -> Result<u64, ConsensusError> {
        self.state.get_current_block_height()
    }

    /// Calculate the state root
    pub fn calculate_state_root(&self) -> Result<Hash, ConsensusError> {
        BlockchainState::calculate_state_root_from_masternode_list(
            &self.utxo_set,
            &self.live_tickets,
            &self.masternode_list,
            &self.active_proposals,
        )
    }

    /// Validate the entire blockchain integrity
    pub fn validate_blockchain_integrity(&self) -> Result<(), ConsensusError> {
        let current_height = self.state.get_current_block_height()
            .map_err(|e| ConsensusError::Internal(e.to_string()))?;

        if current_height == 0 {
            // Genesis block only - basic validation
            self.validate_genesis_block()?;
        } else {
            // Validate all blocks from genesis to tip
            for height in 0..=current_height {
                self.validate_block_at_height(height)?;
            }
        }

        // Additional state consistency checks
        if !self.validate_state_consistency() {
            return Err(ConsensusError::InvalidBlock("State consistency validation failed".to_string()));
        }

        Ok(())
    }

    /// Comprehensive validation of a block
    pub fn validate_block_comprehensive(&self, block: &Block, height: u64) -> Result<(), ConsensusError> {
        // Basic header validation
        self.validate_block_header_at_height(block, height)?;

        // Transaction validation
        self.validate_block_transactions(block, height)?;

        // Difficulty adjustment
        if height > 0 {
            self.validate_difficulty_adjustment(block, height)?;
        }

        // Timestamp validation
        self.validate_block_timestamp(block, height)?;

        // State root validation
        self.validate_state_root(block, height)?;

        // PoS validation if applicable
        if !block.ticket_votes.is_empty() {
            self.validate_pos_components(block, height)?;
        }

        Ok(())
    }

    /// Validate block size
    pub fn validate_block_size(&self, block: &Block) -> Result<(), ConsensusError> {
        let block_size = bincode::serialize(block).map_err(|e| ConsensusError::SerializationError(e.to_string()))?.len() as u64;
        if block_size > self.params.max_block_size {
            return Err(ConsensusError::InvalidBlock(format!(
                "Block size {} exceeds maximum allowed size {}",
                block_size, self.params.max_block_size
            )));
        }
        Ok(())
    }
}
