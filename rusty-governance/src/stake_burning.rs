//! Stake burning mechanism for failed and malicious governance proposals
//! 
//! This module implements the collateral slashing system for governance proposals
//! that fail to meet requirements or are deemed malicious.

use std::collections::HashMap;
use log::{info, warn, error, debug};

use rusty_shared_types::{
    Hash, Transaction, TxInput, TxOutput, OutPoint,
    governance::{GovernanceProposal, ProposalType},
    masternode::{MasternodeID, SlashingReason, MasternodeEntry},
    ConsensusParams,
};
use rusty_core::consensus::state::BlockchainState;

use crate::{ProposalOutcome, ProposalVotingStats, VotingConfig};

/// Reasons for burning proposal stakes
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Hash)]
pub enum StakeBurningReason {
    /// Proposal was rejected by governance vote
    ProposalRejected,
    /// Proposal expired without sufficient participation
    InsufficientParticipation,
    /// Proposal contained malicious or invalid content
    MaliciousProposal,
    /// Proposer failed to provide required documentation
    InsufficientDocumentation,
    /// Proposal violated protocol rules
    ProtocolViolation,
    /// Duplicate or spam proposal
    SpamProposal,
}

/// Configuration for stake burning
#[derive(Debug, Clone)]
pub struct StakeBurningConfig {
    /// Percentage of stake to burn for rejected proposals (0.0 to 1.0)
    pub rejection_burn_percentage: f64,
    /// Percentage of stake to burn for malicious proposals (0.0 to 1.0)
    pub malicious_burn_percentage: f64,
    /// Percentage of stake to burn for insufficient participation (0.0 to 1.0)
    pub participation_burn_percentage: f64,
    /// Percentage of stake to burn for protocol violations (0.0 to 1.0)
    pub violation_burn_percentage: f64,
    /// Minimum participation threshold to avoid burning (0.0 to 1.0)
    pub min_participation_threshold: f64,
    /// Grace period in blocks before burning for insufficient participation
    pub participation_grace_period: u64,
}

impl Default for StakeBurningConfig {
    fn default() -> Self {
        Self {
            rejection_burn_percentage: 0.1,      // 10% for normal rejections
            malicious_burn_percentage: 1.0,      // 100% for malicious proposals
            participation_burn_percentage: 0.25, // 25% for insufficient participation
            violation_burn_percentage: 0.5,      // 50% for protocol violations
            min_participation_threshold: 0.33,   // 33% minimum participation
            participation_grace_period: 1000,    // ~2.5 days grace period
        }
    }
}

/// Manages stake burning for governance proposals
pub struct StakeBurningManager {
    config: StakeBurningConfig,
    pending_burns: HashMap<Hash, PendingBurn>,
    executed_burns: HashMap<Hash, ExecutedBurn>,
}

/// Represents a pending stake burn
#[derive(Debug, Clone)]
pub struct PendingBurn {
    proposal_id: Hash,
    proposer_address: Vec<u8>,
    stake_amount: u64,
    burn_amount: u64,
    reason: StakeBurningReason,
    scheduled_block_height: u64,
    collateral_outpoint: OutPoint,
}

/// Represents an executed stake burn
#[derive(Debug, Clone)]
pub struct ExecutedBurn {
    proposal_id: Hash,
    burn_amount: u64,
    reason: StakeBurningReason,
    burn_transaction_hash: Hash,
    execution_block_height: u64,
}

impl StakeBurningManager {
    /// Create a new stake burning manager
    pub fn new(config: StakeBurningConfig) -> Self {
        Self {
            config,
            pending_burns: HashMap::new(),
            executed_burns: HashMap::new(),
        }
    }

    /// Evaluate a proposal for potential stake burning
    pub fn evaluate_proposal_for_burning(
        &mut self,
        proposal: &GovernanceProposal,
        current_block_height: u64,
        total_voting_power: u64,
        yes_votes: u64,
        no_votes: u64,
        total_votes_cast: u64,
        consensus_params: &ConsensusParams,
    ) -> Result<Option<PendingBurn>, String> {
        // Check if proposal has ended
        if current_block_height <= proposal.end_block_height {
            return Ok(None); // Proposal still active
        }

        // Calculate participation rate
        let participation_rate = if total_voting_power > 0 {
            total_votes_cast as f64 / total_voting_power as f64
        } else {
            0.0
        };

        // Determine if burning is warranted
        let burn_reason = if self.is_malicious_proposal(proposal) {
            Some(StakeBurningReason::MaliciousProposal)
        } else if participation_rate < self.config.min_participation_threshold {
            // Check if grace period has passed
            let grace_period_end = proposal.end_block_height + self.config.participation_grace_period;
            if current_block_height >= grace_period_end {
                Some(StakeBurningReason::InsufficientParticipation)
            } else {
                None // Still in grace period
            }
        } else if self.is_spam_proposal(proposal) {
            Some(StakeBurningReason::SpamProposal)
        } else if self.violates_protocol_rules(proposal) {
            Some(StakeBurningReason::ProtocolViolation)
        } else if self.has_insufficient_documentation(proposal) {
            Some(StakeBurningReason::InsufficientDocumentation)
        } else {
            // Check if proposal was rejected
            let approval_threshold = match proposal.proposal_type {
                ProposalType::ProtocolUpgrade => consensus_params.protocol_upgrade_approval_percentage,
                ProposalType::ParameterChange => consensus_params.parameter_change_approval_percentage,
                ProposalType::TreasurySpend => consensus_params.treasury_spend_approval_percentage,
                ProposalType::BugFix => consensus_params.bug_fix_approval_percentage,
                ProposalType::CommunityFund => consensus_params.community_fund_approval_percentage,
            };

            let approval_rate = if total_votes_cast > 0 {
                yes_votes as f64 / total_votes_cast as f64
            } else {
                0.0
            };

            if approval_rate < approval_threshold {
                Some(StakeBurningReason::ProposalRejected)
            } else {
                None // Proposal was approved or neutral
            }
        };

        if let Some(reason) = burn_reason {
            // Calculate burn amount
            let burn_percentage = self.get_burn_percentage(&reason);
            let stake_amount = consensus_params.proposal_stake_amount;
            let burn_amount = (stake_amount as f64 * burn_percentage) as u64;

            // Find collateral outpoint (simplified - would need actual UTXO lookup)
            let collateral_outpoint = self.find_proposal_collateral(proposal)?;

            let pending_burn = PendingBurn {
                proposal_id: proposal.proposal_id,
                proposer_address: proposal.proposer_address.to_vec(),
                stake_amount,
                burn_amount,
                reason: reason.clone(),
                scheduled_block_height: current_block_height + 10, // Small delay for finalization
                collateral_outpoint,
            };

            self.pending_burns.insert(proposal.proposal_id, pending_burn.clone());

            info!("Scheduled stake burn for proposal {} due to {:?}. Burn amount: {} RUST",
                  hex::encode(proposal.proposal_id), reason, burn_amount);

            Ok(Some(pending_burn))
        } else {
            Ok(None)
        }
    }

    /// Execute pending burns that are ready
    pub fn execute_pending_burns(
        &mut self,
        current_block_height: u64,
        _blockchain_state: &mut BlockchainState,
    ) -> Result<Vec<Transaction>, String> {
        let ready_burns: Vec<Hash> = self.pending_burns
            .iter()
            .filter(|(_, burn)| current_block_height >= burn.scheduled_block_height)
            .map(|(id, _)| *id)
            .collect();

        let mut burn_transactions = Vec::new();

        for proposal_id in ready_burns {
            if let Some(pending_burn) = self.pending_burns.remove(&proposal_id) {
                match self.create_burn_transaction(&pending_burn) {
                    Ok(burn_tx) => {
                        let tx_hash = burn_tx.txid();
                        
                        // Record the executed burn
                        let executed_burn = ExecutedBurn {
                            proposal_id: pending_burn.proposal_id,
                            burn_amount: pending_burn.burn_amount,
                            reason: pending_burn.reason.clone(),
                            burn_transaction_hash: tx_hash,
                            execution_block_height: current_block_height,
                        };

                        self.executed_burns.insert(proposal_id, executed_burn);
                        burn_transactions.push(burn_tx);

                        info!("Executed stake burn for proposal {} - burned {} RUST",
                              hex::encode(proposal_id), pending_burn.burn_amount);
                    }
                    Err(e) => {
                        error!("Failed to create burn transaction for proposal {}: {}", 
                               hex::encode(proposal_id), e);
                    }
                }
            }
        }

        Ok(burn_transactions)
    }

    /// Create a burn transaction for a pending burn
    fn create_burn_transaction(&self, pending_burn: &PendingBurn) -> Result<Transaction, String> {
        // Create input from the collateral
        let input = TxInput {
            previous_output: pending_burn.collateral_outpoint.clone(),
            script_sig: vec![], // Would be filled with proper unlocking script
            sequence: 0xffffffff,
            witness: vec![], // Witness data for the transaction
        };

        // Create burn output (unspendable)
        let burn_output = self.create_burn_output(pending_burn.burn_amount);

        // Create change output if there's remaining stake
        let mut outputs = vec![burn_output];
        if pending_burn.burn_amount < pending_burn.stake_amount {
            let change_amount = pending_burn.stake_amount - pending_burn.burn_amount;
            let change_output = TxOutput {
                value: change_amount,
                script_pubkey: pending_burn.proposer_address.clone(),
                memo: Some(format!("Partial stake return for proposal {}",
                hex::encode(pending_burn.proposal_id)).into()),
            };
            outputs.push(change_output);
        }

        // Create the transaction
        Ok(Transaction::Standard {
            version: 1,
            inputs: vec![input],
            outputs,
            lock_time: 0,
            fee: 1000, // Small fee for the burn transaction
            witness: vec![],
        })
    }

    /// Create an unspendable burn output
    fn create_burn_output(&self, amount: u64) -> TxOutput {
        // OP_RETURN script that makes the output provably unspendable
        let burn_script = vec![
            0x6a, // OP_RETURN
            0x20, // Push 32 bytes
            // "RUSTY_GOVERNANCE_STAKE_BURN" as bytes
            0x52, 0x55, 0x53, 0x54, 0x59, 0x5f, 0x47, 0x4f,
            0x56, 0x45, 0x52, 0x4e, 0x41, 0x4e, 0x43, 0x45,
            0x5f, 0x53, 0x54, 0x41, 0x4b, 0x45, 0x5f, 0x42,
            0x55, 0x52, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        TxOutput {
            value: amount,
            script_pubkey: burn_script,
            memo: Some("Governance stake burn".to_string().into()),
        }
    }

    /// Get burn percentage for a specific reason
    fn get_burn_percentage(&self, reason: &StakeBurningReason) -> f64 {
        match reason {
            StakeBurningReason::ProposalRejected => self.config.rejection_burn_percentage,
            StakeBurningReason::InsufficientParticipation => self.config.participation_burn_percentage,
            StakeBurningReason::MaliciousProposal => self.config.malicious_burn_percentage,
            StakeBurningReason::InsufficientDocumentation => self.config.rejection_burn_percentage,
            StakeBurningReason::ProtocolViolation => self.config.violation_burn_percentage,
            StakeBurningReason::SpamProposal => self.config.malicious_burn_percentage,
        }
    }

    /// Check if a proposal is malicious
    fn is_malicious_proposal(&self, proposal: &GovernanceProposal) -> bool {
        // Simplified malicious detection - in reality this would be more sophisticated
        
        // Check for obviously malicious content
        if proposal.title.contains("hack") || proposal.title.contains("exploit") {
            return true;
        }

        // Check for unreasonable parameter changes
        if proposal.proposal_type == ProposalType::ParameterChange {
            if let Some(ref new_value) = proposal.new_value {
                // Check for extreme values that could break the network
                if let Ok(value) = new_value.parse::<f64>() {
                    if value < 0.0 || value > 1000000.0 {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if a proposal is spam
    fn is_spam_proposal(&self, proposal: &GovernanceProposal) -> bool {
        // Check for very short or nonsensical titles
        if proposal.title.len() < 10 || proposal.title.chars().all(|c| !c.is_alphabetic()) {
            return true;
        }

        // Check for duplicate proposals (simplified)
        let similar_proposals = self.executed_burns.values()
            .filter(|burn| {
                // Very basic similarity check
                burn.proposal_id != proposal.proposal_id
            })
            .count();

        similar_proposals > 5 // If proposer has had many burns, likely spam
    }

    /// Check if proposal violates protocol rules
    fn violates_protocol_rules(&self, proposal: &GovernanceProposal) -> bool {
        // Check voting period validity
        if proposal.end_block_height <= proposal.start_block_height {
            return true;
        }

        // Check if voting period is too short or too long
        let voting_period = proposal.end_block_height - proposal.start_block_height;
        if voting_period < 1000 || voting_period > 100000 { // ~2.5 days to ~250 days
            return true;
        }

        false
    }

    /// Check if proposal has insufficient documentation
    fn has_insufficient_documentation(&self, proposal: &GovernanceProposal) -> bool {
        // Check if description hash is provided
        if proposal.description_hash == [0u8; 32] {
            return true;
        }

        // For protocol upgrades, code change hash should be provided
        if proposal.proposal_type == ProposalType::ProtocolUpgrade && proposal.code_change_hash.is_none() {
            return true;
        }

        // For parameter changes, target parameter should be specified
        if proposal.proposal_type == ProposalType::ParameterChange && proposal.target_parameter.is_none() {
            return true;
        }

        false
    }

    /// Find the collateral outpoint for a proposal (simplified)
    fn find_proposal_collateral(&self, proposal: &GovernanceProposal) -> Result<OutPoint, String> {
        // In a real implementation, this would look up the actual UTXO
        // that was used as collateral for the proposal
        if proposal.inputs.is_empty() {
            return Err("No collateral input found for proposal".to_string());
        }

        Ok(proposal.inputs[0].previous_output.clone())
    }

    /// Get statistics about stake burning
    pub fn get_burn_statistics(&self) -> StakeBurnStatistics {
        let total_burned = self.executed_burns.values()
            .map(|burn| burn.burn_amount)
            .sum();

        let burns_by_reason = self.executed_burns.values()
            .fold(HashMap::new(), |mut acc, burn| {
                *acc.entry(burn.reason.clone()).or_insert(0) += burn.burn_amount;
                acc
            });

        StakeBurnStatistics {
            total_proposals_burned: self.executed_burns.len(),
            total_amount_burned: total_burned,
            pending_burns: self.pending_burns.len(),
            burns_by_reason,
        }
    }

    /// Check if a proposal has been burned
    pub fn is_proposal_burned(&self, proposal_id: &Hash) -> bool {
        self.executed_burns.contains_key(proposal_id)
    }

    /// Get burn details for a proposal
    pub fn get_burn_details(&self, proposal_id: &Hash) -> Option<&ExecutedBurn> {
        self.executed_burns.get(proposal_id)
    }
}

/// Statistics about stake burning
#[derive(Debug, Clone)]
pub struct StakeBurnStatistics {
    pub total_proposals_burned: usize,
    pub total_amount_burned: u64,
    pub pending_burns: usize,
    pub burns_by_reason: HashMap<StakeBurningReason, u64>,
}
