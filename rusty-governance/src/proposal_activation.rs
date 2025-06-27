//! Proposal activation logic for approved governance proposals
//! 
//! This module implements the ACTIVATE_PROPOSAL_TX transaction type and
//! the logic for activating approved governance proposals.

use std::collections::HashMap;
use log::{info, warn, error, debug};
use ed25519_dalek::Signer;

use rusty_shared_types::{
    Hash, Transaction, TxInput, TxOutput, OutPoint, TransactionSignature,
    governance::{GovernanceProposal, ProposalType, ApprovalProof},
    ConsensusParams,
};
use rusty_core::consensus::state::BlockchainState;
use rusty_core::consensus::state::Blockchain;

/// Represents an activation transaction for an approved governance proposal
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActivateProposalTx {
    /// Version of the activation transaction format
    pub version: u32,
    /// The proposal ID being activated
    pub proposal_id: Hash,
    /// The block height at which activation occurs
    pub activation_block_height: u64,
    /// Proof that the proposal was approved (vote summary)
    pub approval_proof: ApprovalProof,
    /// Signature by the activator (can be any network participant)
    pub activator_signature: TransactionSignature,
    /// Transaction inputs (minimal, just for fees)
    pub inputs: Vec<TxInput>,
    /// Transaction outputs (minimal, just for change)
    pub outputs: Vec<TxOutput>,
    /// Lock time
    pub lock_time: u32,
    /// Witness data
    pub witness: Vec<Vec<u8>>,
}

/// Configuration for proposal activation
#[derive(Debug, Clone)]
pub struct ActivationConfig {
    /// Delay in blocks between approval and activation
    pub activation_delay_blocks: u64,
    /// Maximum time in blocks to activate after approval
    pub max_activation_window: u64,
    /// Minimum fee for activation transaction
    pub min_activation_fee: u64,
}

impl Default for ActivationConfig {
    fn default() -> Self {
        Self {
            activation_delay_blocks: 1000,  // ~2.5 days delay
            max_activation_window: 10000,   // ~25 days window
            min_activation_fee: 100_000,    // 0.1 RUST
        }
    }
}

/// Manages proposal activation process
pub struct ProposalActivationManager {
    config: ActivationConfig,
    pending_activations: HashMap<Hash, PendingActivation>,
    activated_proposals: HashMap<Hash, ActivatedProposal>,
}

/// Represents a proposal pending activation
#[derive(Debug, Clone)]
struct PendingActivation {
    proposal: GovernanceProposal,
    approval_proof: ApprovalProof,
    earliest_activation_height: u64,
    latest_activation_height: u64,
}

/// Represents an activated proposal
#[derive(Debug, Clone)]
struct ActivatedProposal {
    proposal: GovernanceProposal,
    activation_height: u64,
    activation_tx_hash: Hash,
    applied: bool,
}

impl ProposalActivationManager {
    /// Create a new proposal activation manager
    pub fn new(config: ActivationConfig) -> Self {
        Self {
            config,
            pending_activations: HashMap::new(),
            activated_proposals: HashMap::new(),
        }
    }

    /// Schedule a proposal for activation after it's been approved
    pub fn schedule_activation(
        &mut self,
        proposal: GovernanceProposal,
        approval_proof: ApprovalProof,
        current_block_height: u64,
    ) -> Result<(), String> {
        // Validate approval proof
        self.validate_approval_proof(&proposal, &approval_proof)?;

        let earliest_activation_height = current_block_height + self.config.activation_delay_blocks;
        let latest_activation_height = earliest_activation_height + self.config.max_activation_window;

        let pending_activation = PendingActivation {
            proposal: proposal.clone(),
            approval_proof,
            earliest_activation_height,
            latest_activation_height,
        };

        self.pending_activations.insert(proposal.proposal_id, pending_activation);

        info!("Scheduled activation for proposal {} at height {} (latest: {})",
              hex::encode(proposal.proposal_id), earliest_activation_height, latest_activation_height);

        Ok(())
    }

    /// Create an activation transaction for a pending proposal
    pub fn create_activation_transaction(
        &self,
        proposal_id: &Hash,
        activator_private_key: &ed25519_dalek::SigningKey,
        current_block_height: u64,
        fee_input: TxInput,
        change_output: Option<TxOutput>,
    ) -> Result<ActivateProposalTx, String> {
        let pending = self.pending_activations.get(proposal_id)
            .ok_or("Proposal not found in pending activations")?;

        // Check if activation is allowed at current height
        if current_block_height < pending.earliest_activation_height {
            return Err(format!("Too early to activate. Current: {}, Earliest: {}", 
                              current_block_height, pending.earliest_activation_height));
        }

        if current_block_height > pending.latest_activation_height {
            return Err(format!("Activation window expired. Current: {}, Latest: {}", 
                              current_block_height, pending.latest_activation_height));
        }

        // Create transaction inputs and outputs
        let inputs = vec![fee_input];
        let outputs = change_output.map(|o| vec![o]).unwrap_or_default();

        // Create the activation transaction
        let mut activation_tx = ActivateProposalTx {
            version: 1,
            proposal_id: *proposal_id,
            activation_block_height: current_block_height,
            approval_proof: pending.approval_proof.clone(),
            activator_signature: vec![], // Will be filled below
            inputs,
            outputs,
            lock_time: 0,
            witness: vec![],
        };

        // Sign the transaction
        let signature = self.sign_activation_transaction(&activation_tx, activator_private_key)?;
        activation_tx.activator_signature = signature;

        Ok(activation_tx)
    }

    /// Validate an activation transaction
    pub fn validate_activation_transaction(
        &self,
        activation_tx: &ActivateProposalTx,
        current_block_height: u64,
    ) -> Result<(), String> {
        // Check if proposal is pending activation
        let pending = self.pending_activations.get(&activation_tx.proposal_id)
            .ok_or("Proposal not found in pending activations")?;

        // Validate timing
        if activation_tx.activation_block_height < pending.earliest_activation_height {
            return Err("Activation too early".to_string());
        }

        if activation_tx.activation_block_height > pending.latest_activation_height {
            return Err("Activation window expired".to_string());
        }

        // Validate approval proof matches
        if activation_tx.approval_proof != pending.approval_proof {
            return Err("Approval proof mismatch".to_string());
        }

        // Validate signature (simplified)
        if activation_tx.activator_signature.is_empty() {
            return Err("Missing activator signature".to_string());
        }

        // Validate fee
        let input_value: u64 = activation_tx.inputs.iter()
            .map(|_| 1000000) // Simplified - would need UTXO lookup
            .sum();
        let output_value: u64 = activation_tx.outputs.iter()
            .map(|o| o.value)
            .sum();
        let fee = input_value.saturating_sub(output_value);

        if fee < self.config.min_activation_fee {
            return Err(format!("Insufficient fee: {} < {}", fee, self.config.min_activation_fee));
        }

        Ok(())
    }

    /// Process an activation transaction and apply the proposal
    pub fn process_activation(
        &mut self,
        activation_tx: &ActivateProposalTx,
        blockchain: &mut Blockchain,
    ) -> Result<(), String> {
        // Check if proposal is pending activation
        let pending = self.pending_activations.remove(&activation_tx.proposal_id)
            .ok_or("Proposal not found in pending activations")?;

        // Apply the proposal changes to the blockchain state
        self.apply_proposal_changes(&pending.proposal, blockchain)?;

        // Mark as activated
        let activated_proposal = ActivatedProposal {
            proposal: pending.proposal,
            activation_height: activation_tx.activation_block_height,
            activation_tx_hash: activation_tx.txid(),
            applied: true,
        };
        self.activated_proposals.insert(activated_proposal.proposal.proposal_id, activated_proposal);

        info!("Proposal {} activated and applied at height {}", 
              hex::encode(activation_tx.proposal_id), activation_tx.activation_block_height);

        Ok(())
    }

    /// Apply the changes specified by a governance proposal to the blockchain state
    fn apply_proposal_changes(
        &self,
        proposal: &GovernanceProposal,
        blockchain: &mut Blockchain,
    ) -> Result<(), String> {
        match proposal.proposal_type {
            ProposalType::ParameterChange => {
                self.apply_parameter_change(proposal, blockchain)
            }
            ProposalType::ProtocolUpgrade => {
                self.apply_protocol_upgrade(proposal, blockchain)
            }
            ProposalType::TreasurySpend => {
                self.apply_treasury_spend(proposal, blockchain)
            }
        }
    }

    /// Apply a parameter change proposal
    fn apply_parameter_change(
        &self,
        proposal: &GovernanceProposal,
        blockchain: &mut Blockchain,
    ) -> Result<(), String> {
        let target_param = proposal.target_parameter.as_ref()
            .ok_or("Missing target parameter")?;
        let new_value = proposal.new_value.as_ref()
            .ok_or("Missing new value")?;

        // Get mutable reference to consensus parameters
        let consensus_params = &mut blockchain.params;

        match target_param.as_str() {
            "block_time" => {
                let new_time = new_value.parse::<u64>()
                    .map_err(|_| "Invalid block time value")?;
                consensus_params.min_block_time = new_time;
                info!("Updated block_time to {}", new_time);
            }
            "max_block_size" => {
                let new_size = new_value.parse::<u64>()
                    .map_err(|_| "Invalid block size value")?;
                consensus_params.max_block_size = new_size;
                info!("Updated max_block_size to {}", new_size);
            }
            "difficulty_adjustment_window" => {
                let new_window = new_value.parse::<u64>()
                    .map_err(|_| "Invalid difficulty window value")?;
                consensus_params.difficulty_adjustment_window = new_window;
                info!("Updated difficulty_adjustment_window to {}", new_window);
            }
            "masternode_collateral" => {
                let new_collateral = new_value.parse::<u64>()
                    .map_err(|_| "Invalid collateral value")?;
                consensus_params.masternode_collateral_amount = new_collateral;
                info!("Updated masternode_collateral to {}", new_collateral);
            }
            "proposal_stake_amount" => {
                let new_stake = new_value.parse::<u64>()
                    .map_err(|_| "Invalid stake amount value")?;
                consensus_params.proposal_stake_amount = new_stake;
                info!("Updated proposal_stake_amount to {}", new_stake);
            }
            _ => {
                return Err(format!("Unknown parameter: {}", target_param));
            }
        }

        Ok(())
    }

    /// Apply a protocol upgrade proposal
    fn apply_protocol_upgrade(
        &self,
        proposal: &GovernanceProposal,
        _blockchain: &mut Blockchain,
    ) -> Result<(), String> {
        // Protocol upgrades would typically require a coordinated client update
        // For now, we just log the activation
        info!("Protocol upgrade proposal {} activated - requires client update", 
              hex::encode(proposal.proposal_id));
        
        if let Some(ref code_hash) = proposal.code_change_hash {
            info!("Code change hash: {}", hex::encode(code_hash));
        }

        // In a real implementation, this might:
        // 1. Set a flag indicating the upgrade is active
        // 2. Schedule the upgrade for a future block height
        // 3. Notify the network about the required upgrade

        Ok(())
    }

    /// Apply a treasury spend proposal
    fn apply_treasury_spend(
        &self,
        proposal: &GovernanceProposal,
        _blockchain: &mut Blockchain,
    ) -> Result<(), String> {
        let amount_str = proposal.new_value.as_ref()
            .ok_or("Missing spend amount")?;
        let amount = amount_str.parse::<u64>()
            .map_err(|_| "Invalid spend amount")?;

        // In a real implementation, this would:
        // 1. Check treasury balance
        // 2. Create a spend transaction
        // 3. Update treasury balance

        info!("Treasury spend proposal {} activated for {} RUST", 
              hex::encode(proposal.proposal_id), amount);

        Ok(())
    }

    /// Validate approval proof for a proposal
    fn validate_approval_proof(
        &self,
        proposal: &GovernanceProposal,
        proof: &ApprovalProof,
    ) -> Result<(), String> {
        // Check that approval threshold was met
        if proof.approval_percentage < proof.required_threshold {
            return Err(format!("Insufficient approval: {:.2}% < {:.2}%", 
                              proof.approval_percentage * 100.0, proof.required_threshold * 100.0));
        }

        // Check that voting ended after proposal end height
        if proof.voting_end_height < proposal.end_block_height {
            return Err("Voting ended before proposal end height".to_string());
        }

        // Validate vote counts
        let total_votes = proof.yes_votes + proof.no_votes + proof.abstain_votes;
        if total_votes == 0 {
            return Err("No votes recorded".to_string());
        }

        let calculated_approval = proof.yes_votes as f64 / (proof.yes_votes + proof.no_votes) as f64;
        if (calculated_approval - proof.approval_percentage).abs() > 0.001 {
            return Err("Approval percentage calculation mismatch".to_string());
        }

        Ok(())
    }

    /// Sign an activation transaction
    fn sign_activation_transaction(
        &self,
        activation_tx: &ActivateProposalTx,
        private_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<u8>, String> {
        // Serialize transaction data for signing
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&activation_tx.version.to_le_bytes());
        sign_data.extend_from_slice(&activation_tx.proposal_id);
        sign_data.extend_from_slice(&activation_tx.activation_block_height.to_le_bytes());
        
        // Sign the data
        let signature = private_key.sign(&sign_data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Calculate hash of activation transaction
    fn calculate_activation_tx_hash(&self, activation_tx: &ActivateProposalTx) -> Hash {
        let serialized = bincode::serialize(activation_tx).unwrap_or_default();
        blake3::hash(&serialized).into()
    }

    /// Get pending activations that can be activated at current height
    pub fn get_activatable_proposals(&self, current_block_height: u64) -> Vec<Hash> {
        self.pending_activations
            .iter()
            .filter(|(_, pending)| {
                current_block_height >= pending.earliest_activation_height &&
                current_block_height <= pending.latest_activation_height
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get activation statistics
    pub fn get_activation_stats(&self) -> ActivationStats {
        ActivationStats {
            pending_activations: self.pending_activations.len(),
            activated_proposals: self.activated_proposals.len(),
            applied_proposals: self.activated_proposals.values()
                .filter(|a| a.applied)
                .count(),
        }
    }

    /// Check if a proposal has been activated
    pub fn is_proposal_activated(&self, proposal_id: &Hash) -> bool {
        self.activated_proposals.contains_key(proposal_id)
    }

    /// Get activation details for a proposal
    pub fn get_activation_details(&self, proposal_id: &Hash) -> Option<&ActivatedProposal> {
        self.activated_proposals.get(proposal_id)
    }
}

/// Statistics about proposal activation
#[derive(Debug, Clone)]
pub struct ActivationStats {
    pub pending_activations: usize,
    pub activated_proposals: usize,
    pub applied_proposals: usize,
}
