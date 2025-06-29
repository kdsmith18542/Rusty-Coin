use crate::script::script_engine::ScriptEngine;
use rusty_shared_types::{
    Block, Transaction, TxOutput, Hash,
    ConsensusParams, OutPoint, Ticket, TicketId,
    masternode::{MasternodeList, MasternodeID, PoSeChallenge,
        SlashingReason, MasternodeNonParticipationProof, MasternodeMaliciousProof}
};
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::utxo_set::UtxoSet;
use crate::consensus::error::ConsensusError;

use primitive_types::U256;
use crate::consensus::pow::{calculate_new_target, calculate_target};
use crate::constants::{COINBASE_MATURITY_PERIOD_BLOCKS, LOCKTIME_THRESHOLD};
use crate::consensus::state::BlockchainState;
use crate::consensus::governance_state::{ActiveProposals, ProposalOutcome};
use rusty_crypto::signature::verify_signature;
use ed25519_dalek::{Verifier, Signature, PublicKey as VerifyingKey};
use rusty_crypto::keypair::RustyKeyPair;
use crate::audit_log;
use log::info;

use rand::RngCore;
use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use rusty_shared_types::masternode::MasternodeID as SharedMasternodeID;

use std::convert::TryInto;

use rand::rngs::ThreadRng;
use rand::thread_rng;
use crate::network::sync_manager::SyncManager;
use blake3;
use std::sync::{Arc, Mutex};

use crate::mempool::Mempool;

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
    pub mempool: Arc<Mutex<Mempool>>,
    pub keypair: RustyKeyPair,
}

impl Blockchain {
    pub fn new() -> Result<Self, ConsensusError> {
        let state = BlockchainState::new();
        let sync_manager = Arc::new(Mutex::new(SyncManager::new()));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let keypair = RustyKeyPair::generate();

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
        })
    }

    pub fn get_latest_block(&self) -> Result<Option<Block>, ConsensusError> {
        let current_height = self.state.get_current_block_height().map_err(|e| ConsensusError::Internal(e.to_string()))?;
        if current_height == 0 {
            Ok(None)
        } else {
            self.state.get_block(current_height.try_into().unwrap()).map_err(|e| ConsensusError::Internal(e.to_string()))
        }
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<(), ConsensusError> {
        let current_height = self.state.get_current_block_height().map_err(|e| ConsensusError::Internal(e.to_string()))?;
        // Sort transactions by fee in descending order (higher fee, higher priority)
        // Coinbase transaction is always the first transaction and should not be sorted.
        let mut sorted_transactions: Vec<Transaction> = block.transactions.drain(1..).collect();
        sorted_transactions.sort_by_key(|tx| tx.get_fee());
        sorted_transactions.reverse(); // Sort descending
        block.transactions.extend(sorted_transactions);

        // Basic validation (more comprehensive validation would be in consensus module)
        if current_height > 0 {
            let last_block = self.get_latest_block().map_err(|e| ConsensusError::Internal(e.to_string()))?.ok_or(ConsensusError::Internal("Last block not found for validation".to_string()))?;
            if block.header.previous_block_hash != last_block.header.hash() {
                audit_log::log_block_validation_failed(&block.header, &ConsensusError::InvalidBlock("Fork detected".to_string()).into());
                return Err(ConsensusError::InvalidBlock(format!("Fork detected: Incoming block's previous hash {:?} does not match current tip {:?}",
                                   block.header.previous_block_hash,
                                   last_block.header.hash())));
            }
            if current_height % self.params.difficulty_adjustment_window as u64 == 0 {
                let first_block_in_interval = self.state.get_block((current_height - self.params.difficulty_adjustment_window as u64).try_into().unwrap())?.ok_or(ConsensusError::Internal("First block in interval not found".to_string()))?;
                let new_difficulty = calculate_new_target(
                    calculate_target(last_block.header.difficulty_target).into(),
                    last_block.header.timestamp - first_block_in_interval.header.timestamp,
                    self.params.min_block_time,
                    self.params.difficulty_adjustment_window as u64,
                    self.params.min_block_time * 4, // Use 4x min_block_time as max
                    calculate_target(self.params.max_ticket_price as u32).into()
                );
                if calculate_target(last_block.header.difficulty_target) != new_difficulty {
                    audit_log::log_block_validation_failed(&block.header, &ConsensusError::InvalidProofOfWork.into());
                    return Err(ConsensusError::InvalidProofOfWork);
                }
            } else {
                if U256::from(block.header.difficulty_target) != U256::from(last_block.header.difficulty_target) {
                    audit_log::log_block_validation_failed(&block.header, &ConsensusError::InvalidProofOfWork.into());
                    return Err(ConsensusError::InvalidProofOfWork);
                }
            }
        }
        if !crate::consensus::pow::verify_pow(&block.header, U256::from(block.header.difficulty_target)) {
            audit_log::log_block_validation_failed(&block.header, &ConsensusError::InvalidProofOfWork.into());
            return Err(ConsensusError::InvalidProofOfWork);
        }

        // Create a temporary vector to hold non-coinbase transactions
        let mut non_coinbase_transactions: Vec<Transaction> = Vec::new();

        // Process transactions
        for tx in block.transactions.drain(..) {
            audit_log::log_transaction_received(&tx);
            match tx {
                Transaction::GovernanceProposal(proposal) => {
                    // Basic validation for governance proposal
                    // TODO: Implement full validation including stake amount, proposer signature, etc.
                    if proposal.start_block_height <= current_height || proposal.end_block_height <= proposal.start_block_height {
                        let err = ConsensusError::RuleViolation("Invalid governance proposal block heights.".to_string());
                        audit_log::log_transaction_validation_failed(&Transaction::GovernanceProposal(proposal), &err.clone().into());
                        return Err(err);
                    }
                    self.active_proposals.add_proposal(proposal.clone())?;
                    audit_log::log_governance_proposal_submitted(&proposal);
                    audit_log::log_transaction_validated(&Transaction::GovernanceProposal(proposal));
                },
                Transaction::GovernanceVote(vote) => {
                    // Basic validation for governance vote
                    // TODO: Implement full validation including voter eligibility (PoS/MN), signature, etc.
                    self.active_proposals.record_vote(vote.clone())?;
                    audit_log::log_governance_vote_cast(&vote);
                    audit_log::log_transaction_validated(&Transaction::GovernanceVote(vote));
                },
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Validate and apply masternode slashing
                    let proof_data = bincode::serialize(&slash_tx.proof)
                        .map_err(|e| ConsensusError::SerializationError(format!("Failed to encode proof data: {}", e)))?;
                    match slash_tx.reason {
                        SlashingReason::MasternodeNonResponse => {
                            let non_participation_proof: MasternodeNonParticipationProof = bincode::deserialize(&proof_data)
                                .map_err(|e| ConsensusError::SerializationError(format!("Failed to deserialize non-participation proof: {}", e)))?;
                            self.live_tickets.validate_non_participation_proof(&non_participation_proof, &self.masternode_list)?;
                        },
                        SlashingReason::DoubleSigning => {
                            let malicious_proof: MasternodeMaliciousProof = bincode::deserialize(&proof_data)
                                .map_err(|e| ConsensusError::SerializationError(format!("Failed to deserialize malicious proof: {}", e)))?;
                            self.live_tickets.validate_malicious_proof(&malicious_proof, &self.masternode_list)?;
                        },
                        _ => return Err(ConsensusError::RuleViolation(format!("Unsupported slashing reason: {:?}", slash_tx.reason))),
                    }
                    audit_log::log_masternode_slashed(&slash_tx);
                    audit_log::log_transaction_validated(&Transaction::MasternodeSlashTx(slash_tx));
                },
                _ => {
                    if !self.utxo_set.validate_transaction_inputs(&tx) {
                        let err = ConsensusError::TransactionValidation(format!("Transaction input validation failed for tx: {:?}", tx.txid()));
                        audit_log::log_transaction_validation_failed(&tx, &err.clone().into());
                        return Err(err);
                    }
                    let mut script_engine = ScriptEngine::new();
                    if !script_engine.validate_transaction(&tx, &self.utxo_set, current_height) {
                        let err = ConsensusError::InvalidScript(format!("Transaction script verification failed for tx: {:?}", tx.txid()));
                        audit_log::log_transaction_validation_failed(&tx, &err.clone().into());
                        return Err(err);
                    }
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
            let err = ConsensusError::InvalidCoinbase("First transaction in block is not a coinbase transaction".to_string());
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
        let total_fees: u64 = block.transactions.iter()
            .map(|tx| {
        let input_value: u64 = tx.get_inputs().iter()
            .filter_map(|input| {
                let outpoint = input.previous_output.clone();
                self.utxo_set.get_utxo(&outpoint)
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

        let actual_coinbase_output_value = coinbase_tx.get_outputs().iter().map(|o| o.value).sum::<u64>();
        if actual_coinbase_output_value > expected_coinbase_output_value {
            let err = ConsensusError::InvalidCoinbase(format!("Coinbase output value exceeds expected PoW reward. Expected: {}, Actual: {}", expected_coinbase_output_value, actual_coinbase_output_value));
            audit_log::log_block_validation_failed(&block.header, &err.clone().into());
            return Err(err);
        }
        if let Some(output) = coinbase_tx.get_outputs_mut().first_mut() {
            output.value = expected_coinbase_output_value;
            output.memo = None; // Explicitly set memo to None
        } else {
            let err = ConsensusError::InvalidCoinbase("Coinbase transaction has no outputs to assign reward to.".to_string());
            audit_log::log_block_validation_failed(&block.header, &err.clone().into());
            return Err(err);
        }

        // Re-insert the modified coinbase transaction at the beginning
        block.transactions.insert(0, coinbase_tx);

        // Distribute PoS rewards to stakers if this is a PoS block
        if is_pos_block {
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
        self.state
             .put_block(&block)
             .map_err(|e| ConsensusError::Internal(format!("Failed to put block to state: {}", e)))?;
        for tx in &block.transactions {
            self.mempool.lock().unwrap().remove_transaction(&tx.txid()); // Remove validated transactions from mempool
        }

        // Update masternode list based on registrations/deregistrations in the block
        for tx in &block.transactions {
            match tx {
                Transaction::MasternodeRegister { masternode_identity, .. } => {
                    // Convert from lib.rs MasternodeIdentity to masternode.rs MasternodeIdentity
                    let converted_identity = rusty_shared_types::masternode::MasternodeIdentity {
                        collateral_outpoint: masternode_identity.collateral_outpoint.clone(),
                        operator_public_key: masternode_identity.operator_public_key.to_vec(),
                        network_address: masternode_identity.network_address.clone(),
                        collateral_ownership_public_key: masternode_identity.collateral_ownership_public_key.to_vec(),
                        dkg_public_key: None, // Not available in lib.rs version
                        supported_dkg_versions: vec![], // Not available in lib.rs version
                    };
                    let registration = rusty_shared_types::masternode::MasternodeRegistration {
                        masternode_identity: converted_identity,
                        signature: vec![], // This signature is handled during transaction validation, not here.
                    };
                    self.masternode_list.register_masternode(registration, block.header.height as u32)?;
                },
                Transaction::MasternodeSlashTx(slash_tx) => {
                    self.masternode_list.remove_masternode(&slash_tx.masternode_id);
                }
                _ => (),
            }
        }

        // Update live ticket pool for new tickets and spent tickets
        self.live_tickets.update_for_new_block(&block, &self.utxo_set.get_used_inputs_as_ticket_ids());

        // Update the blockchain tip
        self.state.update_tip(block.hash(), block.header.height)?;

        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        // TODO: Implement comprehensive blockchain validation
        true
    }

    // Method to get UTXO details, potentially from a historical state or by querying the UTXO set
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<(TxOutput, u64, bool)>, ConsensusError> {
        self.utxo_set.get_utxo(outpoint)
            .map(|utxo| Some((utxo.output.clone(), utxo.creation_height, utxo.is_coinbase)))
            .ok_or(ConsensusError::MissingPreviousOutput(outpoint.clone()))
    }

    pub fn validate_transaction(
        &mut self,
        tx: &Transaction,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        // Validate transaction structure
        // if tx.get_inputs().is_empty() || tx.get_outputs().is_empty() {
        //     return Err(ConsensusError::InvalidTransaction("Transaction has no inputs or outputs".to_string()));
        // }

        // Validate coinbase transactions separately
        if tx.is_coinbase() {
            if tx.get_inputs().len() != 1 || !tx.get_inputs()[0].previous_output.txid.iter().all(|&x| x == 0) {
                return Err(ConsensusError::InvalidCoinbase("Coinbase transaction must have a single null input".to_string()));
            }
            if tx.get_outputs().is_empty() {
                return Err(ConsensusError::InvalidCoinbase("Coinbase transaction must have at least one output".to_string()));
            }
            // Coinbase maturity check handled in add_block
            return Ok(());
        }

        // Validate inputs (referencing existing UTXOs)
        for input in tx.get_inputs() {
            let outpoint = input.previous_output.clone();
            let utxo = self.utxo_set.get_utxo(&outpoint)
                .ok_or(ConsensusError::MissingPreviousOutput(outpoint.clone()))?;

            // Check coinbase maturity
            if utxo.is_coinbase && (current_block_height - utxo.creation_height < COINBASE_MATURITY_PERIOD_BLOCKS as u64) {
                return Err(ConsensusError::ImmatureTicket(format!("Coinbase UTXO {:?} is not yet mature", outpoint)));
            }

            // Validate scriptSigs and scriptPubKeys
            // This would involve a script interpreter. For now, a placeholder.
            let mut script_engine = ScriptEngine::new();
            let tx_hash = tx.txid();
            if script_engine.execute_standard_script(&input.script_sig, &utxo.output.script_pubkey, tx, 0).is_err() {
                 return Err(ConsensusError::InvalidScript(format!("Script verification failed for input {:?}", outpoint)));
            }
        }

        // Validate transaction fees (inputs sum >= outputs sum + fee)
        let total_input_value: u64 = tx.get_inputs().iter()
            .filter_map(|input| {
                let outpoint = input.previous_output.clone();
                self.utxo_set.get_utxo(&outpoint).map(|utxo| utxo.output.value)
            })
            .sum();
        let total_output_value: u64 = tx.get_outputs().iter().map(|output| output.value).sum();
        if total_input_value < total_output_value + tx.get_fee() {
            return Err(ConsensusError::InsufficientFee(tx.get_fee(), total_input_value.saturating_sub(total_output_value)));
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
            let current_timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
            if tx.get_lock_time() > current_timestamp {
                return Err(ConsensusError::InvalidLockTime(format!("Transaction locktime ({}) is in the future compared to current timestamp ({})", tx.get_lock_time(), current_timestamp)));
            }
        }

        // Validate ticket purchases (if applicable)
        if let Transaction::TicketPurchase { ticket_id, locked_amount, ticket_address, outputs, .. } = tx {
            // Ensure ticket output exists and matches locked_amount
            let ticket_output = tx.get_outputs().first().ok_or(ConsensusError::InvalidTicket("Ticket purchase transaction missing output".to_string()))?;
            if ticket_output.value != *locked_amount {
                return Err(ConsensusError::InvalidTicket("Ticket purchase output value does not match locked amount".to_string()));
            }

            // Ensure the ticket address is a valid script_pubkey
            if ticket_output.script_pubkey != *ticket_address {
                return Err(ConsensusError::InvalidTicket("Ticket purchase output script_pubkey does not match ticket address".to_string()));
            }

            // Ensure the ticket is not already in the live tickets pool
            if self.live_tickets.get_ticket(&TicketId::from(*ticket_id)).is_some() {
                return Err(ConsensusError::DuplicateTicketVote(format!("Ticket with ID {:?} already exists in live pool", ticket_id)));
            }
        }

        // Validate ticket redemptions (if applicable)
        if let Transaction::TicketRedemption { ticket_id, .. } = tx {
            let ticket = self.live_tickets.remove_ticket(&rusty_shared_types::TicketId(*ticket_id))?;
            // Basic check if the ticket exists and is mature/not expired
            if ticket.height + self.params.ticket_maturity as u64 > current_block_height {
                return Err(ConsensusError::ImmatureTicket(format!("Ticket {:?} is not yet mature", ticket_id)));
            }

            if ticket.height + self.params.ticket_expiry as u64 <= current_block_height {
                return Err(ConsensusError::ExpiredTicket(format!("Ticket {:?} has expired", ticket_id)));
            }
        }

        Ok(())
    }

    pub fn active_masternodes(&self) -> Vec<rusty_shared_types::masternode::MasternodeID> {
        // Returns a list of active masternode IDs from the MasternodeList
        self.masternode_list.map.values()
            .filter(|mn_entry| mn_entry.status == rusty_shared_types::masternode::MasternodeStatus::Active)
                    .map(|mn_entry| rusty_shared_types::masternode::MasternodeID(mn_entry.identity.collateral_outpoint.clone()))
                    .collect()
    }

    fn distribute_pos_rewards(&mut self, block: &Block, total_reward: u64) -> Result<(), ConsensusError> {
        if block.ticket_votes.is_empty() {
            return Ok(());
        }

        let total_voters = block.ticket_votes.len() as u64;
        if total_voters == 0 { return Ok(()); }

        let reward_per_voter = total_reward / total_voters;

        let mut coinbase_outputs = Vec::new();

        for vote in &block.ticket_votes {
            let ticket = self.live_tickets.get_ticket(&rusty_shared_types::TicketId(vote.ticket_id))
                .ok_or(ConsensusError::InvalidTicket(format!("Voted ticket {:?} not found in live pool", vote.ticket_id)))?;

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
                Transaction::MasternodeRegister { masternode_identity, .. } => {
                    // Convert from lib.rs MasternodeIdentity to masternode.rs MasternodeIdentity
                    let converted_identity = rusty_shared_types::masternode::MasternodeIdentity {
                        collateral_outpoint: masternode_identity.collateral_outpoint.clone(),
                        operator_public_key: masternode_identity.operator_public_key.to_vec(),
                        network_address: masternode_identity.network_address.clone(),
                        collateral_ownership_public_key: masternode_identity.collateral_ownership_public_key.to_vec(),
                        dkg_public_key: None, // Not available in lib.rs version
                        supported_dkg_versions: vec![], // Not available in lib.rs version
                    };
                    let registration = rusty_shared_types::masternode::MasternodeRegistration {
                        masternode_identity: converted_identity,
                        signature: vec![], // Assuming signature is validated at the transaction level
                    };
                    self.masternode_list.register_masternode(registration, block.header.height as u32)
                        .map_err(|e| ConsensusError::MasternodeError(e.to_string()))?;
                },
                Transaction::MasternodeSlashTx(slash_tx) => {
                    // Remove/slash masternode
                    self.masternode_list.remove_masternode(&slash_tx.masternode_id);
                }
                _ => (),
            }
        }

        // 5. Update Live Tickets Pool
        // This involves adding new tickets (from purchase transactions) and removing spent tickets
        self.live_tickets.update_for_new_block(block, &self.utxo_set.get_used_inputs_as_ticket_ids());

        // 6. Update Governance Proposals and Votes
        self.evaluate_and_apply_governance(block.header.height)?;

        // 7. Store block in state/database
        self.state.put_block(block).map_err(|e| ConsensusError::DatabaseError(e.to_string()))?;
        self.state.update_tip(block.hash(), block.header.height)?;

        Ok(())
    }

    /// Validates the Proof of Stake component of a block, including ticket votes and rewards.
    fn validate_proof_of_stake_and_rewards(
        &self,
        _block: &Block,
        _total_reward: u64,
    ) -> Result<(), ConsensusError> {
        // TODO: Implement proper PoS validation
        // This is a placeholder that needs to be implemented with actual PoS validation logic
        // including ticket selection, vote verification, and reward distribution
        Ok(())
    }

    fn process_governance_proposal(
        &mut self,
        proposal: &rusty_shared_types::governance::GovernanceProposal,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        // Basic validation for governance proposal
        if proposal.start_block_height <= current_block_height || proposal.end_block_height <= proposal.start_block_height {
            return Err(ConsensusError::RuleViolation("Invalid governance proposal block heights.".to_string()));
        }

        // Verify proposer signature (assuming public key is part of the proposal or derivable)
        // For example, if proposer_address is a PubKeyHash, you'd need the full public key from the UTXO.
        // let public_key_hash = proposal.proposer_address.extract_public_key_hash();
        let public_key = VerifyingKey::from_bytes(&proposal.proposer_address).map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
        let message = bincode::serialize(&proposal)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

        if verify_signature(&public_key, &message, &Signature::from_bytes(&proposal.proposer_signature.bytes).map_err(|_| ConsensusError::InvalidSignature("Invalid proposer signature for governance proposal.".to_string()))?).is_err() {
            return Err(ConsensusError::InvalidSignature("Invalid proposer signature for governance proposal.".to_string()));
        }

        self.active_proposals.add_proposal(proposal.clone())?;
        Ok(())
    }

    fn process_governance_vote(
        &mut self,
        vote: &rusty_shared_types::governance::GovernanceVote,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal = self.active_proposals.get_proposal(&vote.proposal_id)
            .ok_or(ConsensusError::InvalidTicketVote("Vote for non-existent proposal.".to_string()))?;

        if current_block_height < proposal.start_block_height || current_block_height > proposal.end_block_height {
            return Err(ConsensusError::InvalidTicketVote("Vote outside of proposal voting period.".to_string()));
        }

        // Validate voter eligibility and signature
        // This logic depends on whether the voter is a PoS ticket or a Masternode
        match vote.voter_type {
            rusty_shared_types::governance::VoterType::PosTicket => {
                let ticket = self.live_tickets.get_ticket(&rusty_shared_types::TicketId(vote.voter_id))
                    .ok_or(ConsensusError::InvalidTicketVote("Voting ticket not found in live pool.".to_string()))?;
                // Verify signature using the ticket's public key
                let public_key = VerifyingKey::from_bytes(&ticket.pubkey)
                    .map_err(|_| ConsensusError::InvalidSignature("Invalid public key for ticket vote.".to_string()))?;
                let message = bincode::serialize(&vote.vote_choice)
                    .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

                if verify_signature(&public_key, &message, &Signature::from_bytes(&vote.voter_signature.bytes).map_err(|_| ConsensusError::InvalidSignature("Invalid signature for ticket vote.".to_string()))?).is_err() {
                    return Err(ConsensusError::InvalidSignature("Invalid signature for ticket vote.".to_string()));
                }
            },
            rusty_shared_types::governance::VoterType::Masternode => {
                let masternode_id = rusty_shared_types::masternode::MasternodeID(vote.voter_id.clone().try_into().map_err(|_| ConsensusError::Internal("Invalid MasternodeID for vote.".to_string()))?);
                let mn_entry = self.masternode_list.get_masternode(&masternode_id)
                    .ok_or(ConsensusError::MasternodeError("Voting masternode not found or not active.".to_string()))?;
                // Verify signature using the masternode's operator public key
                let public_key = VerifyingKey::from_bytes(&mn_entry.identity.operator_public_key)
                    .map_err(|_| ConsensusError::InvalidSignature("Invalid public key for masternode vote.".to_string()))?;
                let message = bincode::serialize(&vote.vote_choice)
                    .map_err(|e| ConsensusError::SerializationError(e.to_string()))?;

                if verify_signature(&public_key, &message, &Signature::from_bytes(&vote.voter_signature.bytes).map_err(|_| ConsensusError::InvalidSignature("Invalid signature for masternode vote.".to_string()))?).is_err() {
                    return Err(ConsensusError::InvalidSignature("Invalid signature for masternode vote.".to_string()));
                }
            }
        }

        self.active_proposals.record_vote(vote.clone())?;
        Ok(())
    }



    pub fn evaluate_and_apply_governance(
        &mut self,
        current_block_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal_ids_to_remove: Vec<Hash> = self.active_proposals.proposals.keys()
            .filter(|&proposal_id| {
                if let Some(proposal) = self.active_proposals.get_proposal(proposal_id) {
                    current_block_height > proposal.end_block_height + self.params.activation_delay_blocks
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for proposal_id in proposal_ids_to_remove {
            let proposal = self.active_proposals.get_proposal(&proposal_id).cloned().ok_or(ConsensusError::Internal("Proposal not found during removal.".to_string()))?;
            let outcome = self.active_proposals.evaluate_proposal_at_height(
                &proposal.proposal_id,
                current_block_height,
                self.live_tickets.count_live_tickets() as u64,
                self.masternode_list.count_active_masternodes() as u64,
                self.params.pos_voting_quorum_percentage,
                self.params.mn_voting_quorum_percentage,
                self.params.pos_approval_percentage,
                self.params.mn_approval_percentage,
            )?;

            match outcome {
            ProposalOutcome::Passed => {
                info!("Governance proposal {:?} PASSED. Applying changes...", proposal.proposal_id);
                // TODO: Apply governance changes (e.g., update consensus parameters, activate features)
                // This would involve direct modification of self.params or other state.
                self.active_proposals.remove_proposal(&proposal.proposal_id)?;
            },
            ProposalOutcome::Rejected { reason } => {
                info!("Governance proposal {:?} REJECTED: {}", proposal.proposal_id, reason);
                self.active_proposals.remove_proposal(&proposal.proposal_id)?;
            },
            ProposalOutcome::InProgress => {
                // Do nothing, proposal is still active
            },
            ProposalOutcome::Expired => {
                info!("Governance proposal {:?} EXPIRED without resolution.", proposal.proposal_id);
                self.active_proposals.remove_proposal(&proposal.proposal_id)?;
            },
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
        self.live_tickets.update_for_revert_block(block, &self.utxo_set.get_used_inputs_as_ticket_ids());

        // Revert Masternode list changes
        for tx in block.transactions.iter().rev() {
            match tx {
                Transaction::MasternodeRegister { masternode_identity, .. } => {
                    // Remove the registered masternode
                    let mn_id = MasternodeID(masternode_identity.collateral_outpoint.clone());
                    self.masternode_list.remove_masternode(&mn_id);
                },
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
                    self.active_proposals.remove_proposal(&proposal.proposal_id)?;
                },
                Transaction::GovernanceVote(vote) => {
                    self.active_proposals.remove_vote(&vote.proposal_id, &vote.voter_id)?;
                },
                Transaction::TicketPurchase { ticket_id, .. } => {
                    // Convert ticket_id to TicketId and remove the newly added ticket from live tickets pool
                    let ticket_id = TicketId(*ticket_id);
                    self.live_tickets.remove_ticket(&ticket_id)?;
                },
                Transaction::TicketRedemption { ticket_id, .. } => {
                    // Re-add the redeemed ticket to live tickets pool
                    // This is a simplification; a real system needs to reconstruct the full ticket from history.
                    let tx_hash = tx.txid();
                    let outpoint = OutPoint { txid: tx_hash, vout: 0 }; // Assuming it's the first output
                    let _redeemed_ticket_public_key_hash = tx.get_outputs()[0].extract_public_key_hash().ok_or(ConsensusError::Internal("Failed to extract public key for ticket redemption revert.".to_string()))?;
                    // This is incorrect: `redeemed_ticket_public_key_hash` is 20 bytes, `PublicKey` is 32.
                    // Need to find the actual public key associated with the ticket_id from historical data.
                    // For now, creating a dummy public key. THIS IS A SIMPLIFICATION.
                    let dummy_public_key = vec![0u8; 32];
                    let redeemed_ticket = Ticket {
                    id: rusty_shared_types::TicketId(*ticket_id),
                    pubkey: dummy_public_key,
                    height: 0, // Placeholder - should be actual purchase height
                    value: 0, // Placeholder - should be actual value
                    status: rusty_shared_types::TicketStatus::Live,
                };
                self.live_tickets.add_ticket(redeemed_ticket)?;
                },
                _ => (),
            }
        }

        // Revert the blockchain tip
        self.state.update_tip(block.header.previous_block_hash, block.header.height - 1).map_err(|e| ConsensusError::Internal(e.to_string()))?;
        self.state.remove_block_by_hash(&block.hash()).map_err(|e| ConsensusError::Internal(e.to_string()))?;
        self.state.remove_block_by_height(block.header.height).map_err(|e| ConsensusError::Internal(e.to_string()))?;

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
        let target_masternode = self.masternode_list.get_masternode(&SharedMasternodeID(challenge.challenger_masternode_id.0))
            .ok_or(ConsensusError::MasternodeError("Target masternode not found.".to_string()))?;
        let operator_public_key: [u8; 32] = target_masternode.identity.operator_public_key.clone().try_into().map_err(|_| ConsensusError::Internal("Invalid operator public key length".to_string()))?;
        if !verify_pose_response(
            &challenge_message,
            &response.signed_block_hash,
            &operator_public_key,
        ) {
            return Err(ConsensusError::InvalidPoSeResponse("Invalid PoSe response signature".to_string()));
        }

        // 2. Check if the response was submitted on time
        let current_height = self.state.get_current_block_height()?;
        if current_height > challenge.challenge_generation_block_height + self.params.pose_challenge_period_blocks {
            return Err(ConsensusError::PoSeChallengeExpired("Challenge expired".to_string()));
        }

        // 3. Check if the block hash in the response matches the expected value
        if response.signed_block_hash != challenge.challenge_block_hash {
            return Err(ConsensusError::InvalidPoSeResponse("Incorrect block hash in PoSe response".to_string()));
        }

        // 4. If we get here, the response is valid, so we can clear the challenge
        // and optionally reward the masternode for responding
        // TODO: Implement reward distribution logic

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
            inputs: vec![], // TODO: Add proper inputs
            outputs: vec![], // TODO: Add proper outputs
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };

        Ok(Some(challenge_tx))
    }
}
