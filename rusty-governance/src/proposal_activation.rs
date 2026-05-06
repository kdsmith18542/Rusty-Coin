//! Proposal activation logic for approved governance proposals
//!
//! This module implements the ACTIVATE_PROPOSAL_TX transaction type and
//! the logic for activating approved governance proposals.

use ed25519_dalek::Signer;
use log::info;
use std::collections::HashMap;

use rusty_core::consensus::state::BlockchainState;
use rusty_shared_types::{
    governance::{ApprovalProof, GovernanceProposal, ProposalType},
    Hash, TransactionSignature, TxInput, TxOutput,
};

use crate::proposal_validation::ProposalValidationError;

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
            activation_delay_blocks: 1000, // ~2.5 days delay
            max_activation_window: 10000,  // ~25 days window
            min_activation_fee: 100_000,   // 0.1 RUST
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
pub struct ActivatedProposal {
    proposal: GovernanceProposal,
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
        let latest_activation_height =
            earliest_activation_height + self.config.max_activation_window;

        let pending_activation = PendingActivation {
            proposal: proposal.clone(),
            approval_proof,
            earliest_activation_height,
            latest_activation_height,
        };

        self.pending_activations
            .insert(proposal.proposal_id, pending_activation);

        info!(
            "Scheduled activation for proposal {} at height {} (latest: {})",
            hex::encode(proposal.proposal_id),
            earliest_activation_height,
            latest_activation_height
        );

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
        let pending = self
            .pending_activations
            .get(proposal_id)
            .ok_or("Proposal not found in pending activations")?;

        // Check if activation is allowed at current height
        if current_block_height < pending.earliest_activation_height {
            return Err(format!(
                "Too early to activate. Current: {}, Earliest: {}",
                current_block_height, pending.earliest_activation_height
            ));
        }

        if current_block_height > pending.latest_activation_height {
            return Err(format!(
                "Activation window expired. Current: {}, Latest: {}",
                current_block_height, pending.latest_activation_height
            ));
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
            activator_signature: TransactionSignature::new([0u8; 64]), // Will be filled below
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
        _current_block_height: u64,
    ) -> Result<(), String> {
        // Check if proposal is pending activation
        let pending = self
            .pending_activations
            .get(&activation_tx.proposal_id)
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
        if activation_tx.activator_signature.bytes == [0u8; 64] {
            return Err("Missing activator signature".to_string());
        }

        // Validate fee
        let input_value: u64 = activation_tx
            .inputs
            .iter()
            .map(|_| 1000000) // Simplified - would need UTXO lookup
            .sum();
        let output_value: u64 = activation_tx.outputs.iter().map(|o| o.value).sum();
        let fee = input_value.saturating_sub(output_value);

        if fee < self.config.min_activation_fee {
            return Err(format!(
                "Insufficient fee: {} < {}",
                fee, self.config.min_activation_fee
            ));
        }

        Ok(())
    }

    /// Process an activation transaction and apply the proposal
    pub fn process_activation(
        &mut self,
        activation_tx: &ActivateProposalTx,
        blockchain_state: &mut BlockchainState,
    ) -> Result<(), String> {
        let proposal_id = &activation_tx.proposal_id;
        // Clone the pending activation early to avoid borrow conflicts
        let pending = self
            .pending_activations
            .get(proposal_id)
            .ok_or_else(|| {
                format!(
                    "Proposal {} not found in pending activations",
                    hex::encode(proposal_id)
                )
            })?
            .clone();

        let current_block_height = blockchain_state
            .get_current_block_height()
            .map_err(|e| e.to_string())?;
        if pending.earliest_activation_height <= current_block_height
            && current_block_height <= pending.latest_activation_height
        {
            // Clone the proposal to avoid borrow conflicts
            let proposal_clone = pending.proposal.clone();

            // Apply the changes associated with the proposal
            match proposal_clone.proposal_type {
                ProposalType::ProtocolUpgrade => {
                    self.apply_protocol_upgrade(&proposal_clone, blockchain_state)?;
                }
                ProposalType::ParameterChange => {
                    // Parameter changes are handled by the ParameterManager directly
                }
                ProposalType::TreasurySpend => {
                    self.apply_treasury_spend(&proposal_clone, blockchain_state)?;
                }
                ProposalType::BugFix => {
                    self.apply_bug_fix(&proposal_clone, blockchain_state)?;
                }
                ProposalType::CommunityFund => {
                    self.apply_community_fund(&proposal_clone, blockchain_state)?;
                }
            }

            // Mark as activated
            let activated_proposal = ActivatedProposal {
                proposal: proposal_clone,
                applied: true,
            };
            self.activated_proposals
                .insert(activated_proposal.proposal.proposal_id, activated_proposal);

            // Remove from pending activations after activation
            self.pending_activations.remove(proposal_id);

            info!(
                "Proposal {} activated at height {}",
                hex::encode(proposal_id),
                current_block_height
            );
            Ok(())
        } else {
            Err(format!(
                "Proposal {} is not within its activation window ({} - {}), current height {}",
                hex::encode(proposal_id),
                pending.earliest_activation_height,
                pending.latest_activation_height,
                current_block_height
            ))
        }
    }

    /// Apply a protocol upgrade proposal
    fn apply_protocol_upgrade(
        &self,
        proposal: &GovernanceProposal,
        state: &mut BlockchainState,
    ) -> Result<(), String> {
        info!(
            "Applying protocol upgrade for proposal {}: {}",
            hex::encode(proposal.hash()),
            proposal.title
        );

        // Activate protocol upgrade by setting a flag in blockchain state
        match proposal.target_parameter.as_deref() {
            Some("soft_fork_activation") => {
                // Activate a soft fork
                let fork_id = proposal
                    .new_value
                    .as_ref()
                    .ok_or("Missing fork ID for soft fork activation")?;
                state
                    .set_protocol_flag(format!("soft_fork_{}", fork_id), b"activated".to_vec())
                    .map_err(|e| e.to_string())?;
                info!("Activated soft fork: {}", fork_id);
            }
            Some("hard_fork_activation") => {
                // Schedule a hard fork activation
                let fork_height = proposal
                    .new_value
                    .as_ref()
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or("Invalid fork height for hard fork activation")?;
                state
                    .set_hard_fork_height(fork_height)
                    .map_err(|e| e.to_string())?;
                info!("Scheduled hard fork at height: {}", fork_height);
            }
            Some("protocol_version") => {
                // Update protocol version
                let new_version = proposal
                    .new_value
                    .as_ref()
                    .and_then(|v| v.parse::<u32>().ok())
                    .ok_or("Invalid protocol version")?;
                state
                    .set_protocol_version(new_version)
                    .map_err(|e| e.to_string())?;
                info!("Updated protocol version to: {}", new_version);
            }
            _ => {
                return Err(format!(
                    "Unknown protocol upgrade parameter: {:?}",
                    proposal.target_parameter
                ));
            }
        }

        Ok(())
    }

    /// Apply a treasury spend proposal
    fn apply_treasury_spend(
        &self,
        proposal: &GovernanceProposal,
        state: &mut BlockchainState,
    ) -> Result<(), String> {
        info!(
            "Applying treasury spend for proposal {}: {}",
            hex::encode(proposal.hash()),
            proposal.title
        );

        // Parse the spend amount and recipient
        let spend_amount = proposal
            .new_value
            .as_ref()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or("Invalid spend amount for treasury proposal")?;

        let recipient_address = proposal
            .recipient_address
            .as_ref()
            .ok_or("Missing recipient address for treasury spend")?;

        // Validate recipient address format (simplified)
        if recipient_address.len() < 20 {
            return Err("Invalid recipient address format".to_string());
        }

        // Schedule the treasury spend by creating a record
        let spend_key = format!("treasury_spend_{}", hex::encode(proposal.proposal_id));
        let spend_data = format!("{}:{}", hex::encode(recipient_address), spend_amount);
        state
            .set_protocol_flag(spend_key, spend_data.into_bytes())
            .map_err(|e| e.to_string())?;

        // Update treasury balance (subtract the spend amount)
        let current_balance = state
            .get_protocol_flag("treasury_balance")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        if current_balance < spend_amount {
            return Err(format!(
                "Insufficient treasury funds: {} < {}",
                current_balance, spend_amount
            ));
        }

        let new_balance = current_balance - spend_amount;
        state
            .set_protocol_flag(
                "treasury_balance".to_string(),
                new_balance.to_string().into_bytes(),
            )
            .map_err(|e| e.to_string())?;

        info!(
            "Scheduled treasury spend of {} to {} (remaining balance: {})",
            spend_amount,
            hex::encode(recipient_address),
            new_balance
        );

        Ok(())
    }

    /// Apply a bug fix proposal
    fn apply_bug_fix(
        &self,
        proposal: &GovernanceProposal,
        state: &mut BlockchainState,
    ) -> Result<(), String> {
        info!(
            "Applying bug fix for proposal {}: {}",
            hex::encode(proposal.proposal_id),
            proposal.title
        );

        // Bug fixes can activate emergency patches or disable features
        match proposal.target_parameter.as_deref() {
            Some("emergency_patch") => {
                // Activate an emergency patch
                let patch_id = proposal
                    .new_value
                    .as_ref()
                    .ok_or("Missing patch ID for emergency patch")?;
                state
                    .set_protocol_flag(format!("emergency_patch_{}", patch_id), b"active".to_vec())
                    .map_err(|e| e.to_string())?;
                info!("Activated emergency patch: {}", patch_id);
            }
            Some("disable_feature") => {
                // Disable a problematic feature
                let feature_name = proposal
                    .new_value
                    .as_ref()
                    .ok_or("Missing feature name to disable")?;
                state
                    .set_protocol_flag(
                        format!("feature_{}_disabled", feature_name),
                        b"true".to_vec(),
                    )
                    .map_err(|e| e.to_string())?;
                info!("Disabled feature: {}", feature_name);
            }
            Some("enable_feature") => {
                // Re-enable a previously disabled feature
                let feature_name = proposal
                    .new_value
                    .as_ref()
                    .ok_or("Missing feature name to enable")?;
                state
                    .set_protocol_flag(
                        format!("feature_{}_disabled", feature_name),
                        b"false".to_vec(),
                    )
                    .map_err(|e| e.to_string())?;
                info!("Re-enabled feature: {}", feature_name);
            }
            Some("consensus_rule_override") => {
                // Override a consensus rule temporarily
                let rule_name = proposal
                    .new_value
                    .as_ref()
                    .ok_or("Missing rule name for consensus override")?;
                let bug_description = proposal
                    .bug_description
                    .as_deref()
                    .unwrap_or("No description");
                state
                    .set_protocol_flag(
                        format!("consensus_override_{}", rule_name),
                        bug_description.as_bytes().to_vec(),
                    )
                    .map_err(|e| e.to_string())?;
                info!("Applied consensus rule override for: {}", rule_name);
            }
            _ => {
                return Err(format!(
                    "Unknown bug fix parameter: {:?}",
                    proposal.target_parameter
                ));
            }
        }

        Ok(())
    }

    /// Apply a community fund proposal
    fn apply_community_fund(
        &self,
        proposal: &GovernanceProposal,
        state: &mut BlockchainState,
    ) -> Result<(), String> {
        info!(
            "Applying community fund for proposal {}: {}",
            hex::encode(proposal.proposal_id),
            proposal.title
        );

        // Community fund proposals allocate funds for community projects
        match proposal.target_parameter.as_deref() {
            Some("fund_allocation") => {
                // Allocate funds to a community project
                let allocation_amount = proposal
                    .amount
                    .ok_or("Missing allocation amount for community fund")?;

                // Use recipient address and project description from proposal
                let recipient_address = proposal
                    .recipient_address
                    .as_ref()
                    .ok_or("Missing recipient address for community fund allocation")?;

                let project_description = proposal
                    .project_description
                    .as_deref()
                    .unwrap_or("No description");

                // Generate a simple project ID from the proposal hash
                let project_id = hex::encode(&proposal.proposal_id[..8]);

                // Create allocation record
                let allocation_key = format!("community_fund_allocation_{}", project_id);
                let allocation_data = format!(
                    "{}:{}:{}",
                    hex::encode(recipient_address),
                    allocation_amount,
                    hex::encode(proposal.proposal_id)
                );
                state
                    .set_protocol_flag(allocation_key, allocation_data.into_bytes())
                    .map_err(|e| e.to_string())?;

                // Update community fund balance
                let current_balance = state
                    .get_protocol_flag("community_fund_balance")
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                if current_balance < allocation_amount {
                    return Err(format!(
                        "Insufficient community fund balance: {} < {}",
                        current_balance, allocation_amount
                    ));
                }

                let new_balance = current_balance - allocation_amount;
                state
                    .set_protocol_flag(
                        "community_fund_balance".to_string(),
                        new_balance.to_string().into_bytes(),
                    )
                    .map_err(|e| e.to_string())?;

                info!("Allocated {} from community fund to project {} (recipient: {}, remaining balance: {})", 
                      allocation_amount, project_id, hex::encode(recipient_address), new_balance);
                info!("Project description: {}", project_description);
            }
            Some("fund_deposit") => {
                // Deposit funds into community fund
                let deposit_amount = proposal
                    .amount
                    .ok_or("Missing deposit amount for community fund")?;

                let current_balance = state
                    .get_protocol_flag("community_fund_balance")
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                let new_balance = current_balance + deposit_amount;
                state
                    .set_protocol_flag(
                        "community_fund_balance".to_string(),
                        new_balance.to_string().into_bytes(),
                    )
                    .map_err(|e| e.to_string())?;

                info!(
                    "Deposited {} into community fund (new balance: {})",
                    deposit_amount, new_balance
                );
            }
            _ => {
                return Err(format!(
                    "Unknown community fund parameter: {:?}",
                    proposal.target_parameter
                ));
            }
        }

        Ok(())
    }

    /// Validate approval proof for a proposal
    fn validate_approval_proof(
        &self,
        proposal: &GovernanceProposal,
        proof: &ApprovalProof,
    ) -> Result<(), String> {
        // Check that approval threshold was met
        if proof.approval_percentage_bp < proof.required_threshold_bp {
            return Err(format!(
                "Insufficient approval: {:.2}% < {:.2}%",
                proof.approval_percentage_bp as f64 / 100.0,
                proof.required_threshold_bp as f64 / 100.0
            ));
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

        let calculated_approval =
            proof.yes_votes as f64 / (proof.yes_votes + proof.no_votes) as f64;
        let calculated_approval_bp = (calculated_approval * 10000.0) as u64;
        if calculated_approval_bp.abs_diff(proof.approval_percentage_bp) > 10 {
            return Err("Approval percentage calculation mismatch".to_string());
        }

        Ok(())
    }

    /// Sign an activation transaction
    fn sign_activation_transaction(
        &self,
        activation_tx: &ActivateProposalTx,
        private_key: &ed25519_dalek::SigningKey,
    ) -> Result<TransactionSignature, String> {
        // Serialize transaction data for signing
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&activation_tx.version.to_le_bytes());
        sign_data.extend_from_slice(&activation_tx.proposal_id);
        sign_data.extend_from_slice(&activation_tx.activation_block_height.to_le_bytes());

        // Sign the data
        let signature = private_key.sign(&sign_data);
        Ok(TransactionSignature::new(signature.to_bytes()))
    }

    /// Get pending activations that can be activated at current height
    pub fn get_activatable_proposals(&self, current_block_height: u64) -> Vec<Hash> {
        self.pending_activations
            .iter()
            .filter(|(_, pending)| {
                current_block_height >= pending.earliest_activation_height
                    && current_block_height <= pending.latest_activation_height
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get activation statistics
    pub fn get_activation_stats(&self) -> ActivationStats {
        ActivationStats {
            pending_activations: self.pending_activations.len(),
            activated_proposals: self.activated_proposals.len(),
            applied_proposals: self
                .activated_proposals
                .values()
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

impl From<ProposalValidationError> for String {
    fn from(err: ProposalValidationError) -> Self {
        err.to_string()
    }
}
