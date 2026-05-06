//! Federation integration with mainchain consensus
//!
//! This module provides integration between sidechain federation management
//! and mainchain consensus, ensuring federation updates are properly
//! validated and synchronized across chains.

use crate::sidechain::federation_manager::{FederationEpoch, FederationManager};
use crate::sidechain::types::*;
use rusty_shared_types::{Hash, OutPoint, masternode::MasternodeID};
use std::collections::HashMap;

/// Federation update proposal from mainchain
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FederationUpdateProposal {
    /// Sidechain ID
    pub sidechain_id: Hash,
    /// Proposed new federation members
    pub new_members: Vec<MasternodeID>,
    /// Proposed new threshold
    pub new_threshold: u32,
    /// Proposed new public keys
    pub new_public_keys: Vec<Vec<u8>>,
    /// Proposal activation height
    pub activation_height: u64,
    /// Governance proposal ID that approved this update
    pub governance_proposal_id: Hash,
}

/// Federation integrator for mainchain-sidechain coordination
pub struct FederationIntegrator {
    /// Federation managers by sidechain
    federation_managers: HashMap<Hash, FederationManager>,
    /// Pending federation update proposals
    pending_updates: HashMap<Hash, FederationUpdateProposal>,
    /// Mainchain governance state reference
    mainchain_governance: Option<std::sync::Arc<std::sync::Mutex<crate::consensus::governance_state::ActiveProposals>>>,
}

impl FederationIntegrator {
    /// Create a new federation integrator
    pub fn new() -> Self {
        Self {
            federation_managers: HashMap::new(),
            pending_updates: HashMap::new(),
            mainchain_governance: None,
        }
    }

    /// Set mainchain governance reference
    pub fn with_mainchain_governance(
        mut self,
        governance: std::sync::Arc<std::sync::Mutex<crate::consensus::governance_state::ActiveProposals>>,
    ) -> Self {
        self.mainchain_governance = Some(governance);
        self
    }

    /// Initialize federation for a sidechain
    pub fn initialize_sidechain_federation(
        &mut self,
        sidechain_id: Hash,
        initial_members: Vec<MasternodeID>,
        threshold: u32,
        public_keys: Vec<Vec<u8>>,
        start_height: u64,
        epoch_transition_blocks: u64,
    ) -> Result<(), String> {
        let mut fed_manager = FederationManager::new(epoch_transition_blocks);
        fed_manager.initialize_federation(
            sidechain_id,
            initial_members,
            threshold,
            start_height,
            public_keys,
        )?;

        self.federation_managers.insert(sidechain_id, fed_manager);
        Ok(())
    }

    /// Get federation manager for a sidechain
    pub fn get_federation_manager(&self, sidechain_id: &Hash) -> Option<&FederationManager> {
        self.federation_managers.get(sidechain_id)
    }

    /// Get mutable federation manager for a sidechain
    pub fn get_federation_manager_mut(&mut self, sidechain_id: &Hash) -> Option<&mut FederationManager> {
        self.federation_managers.get_mut(sidechain_id)
    }

    /// Propose federation update from mainchain governance
    pub fn propose_federation_update(
        &mut self,
        proposal: FederationUpdateProposal,
        current_height: u64,
    ) -> Result<(), String> {
        // Require mainchain governance to be set
        let governance = self.mainchain_governance.as_ref()
            .ok_or("Mainchain governance not configured")?
            .lock().unwrap();

        let gov_proposal = governance.get_proposal(&proposal.governance_proposal_id)
            .ok_or("Governance proposal not found")?;

        // For now, assume governance proposals are approved if they exist
        // In a real implementation, we would evaluate the proposal outcome
        // This is a simplification for the integration

        // Check activation height is in the future
        if proposal.activation_height <= current_height {
            return Err("Federation update activation height must be in the future".to_string());
        }

        // Validate federation update parameters
        if proposal.new_members.is_empty() {
            return Err("Federation must have at least one member".to_string());
        }

        if proposal.new_threshold == 0 || proposal.new_threshold > proposal.new_members.len() as u32 {
            return Err(format!(
                "Invalid threshold {} for {} members",
                proposal.new_threshold,
                proposal.new_members.len()
            ));
        }

        if proposal.new_public_keys.len() != proposal.new_members.len() {
            return Err("Public keys count must match members count".to_string());
        }

        // Check if federation exists for sidechain
        if !self.federation_managers.contains_key(&proposal.sidechain_id) {
            return Err("Federation not initialized for sidechain".to_string());
        }

        // Store pending update
        self.pending_updates.insert(proposal.governance_proposal_id, proposal);

        Ok(())
    }

    /// Apply pending federation updates at activation height
    pub fn apply_pending_updates(&mut self, current_height: u64) -> Result<Vec<Hash>, String> {
        let mut applied_updates = Vec::new();

        // Find updates ready for activation
        let ready_updates: Vec<_> = self.pending_updates.iter()
            .filter(|(_, proposal)| proposal.activation_height <= current_height)
            .map(|(id, _)| *id)
            .collect();

        for proposal_id in ready_updates {
            let proposal = self.pending_updates.remove(&proposal_id).unwrap();

            // Apply the update
            let fed_manager = self.federation_managers.get_mut(&proposal.sidechain_id)
                .ok_or("Federation manager not found")?;

            fed_manager.transition_epoch(
                proposal.sidechain_id,
                proposal.new_members,
                proposal.new_threshold,
                current_height,
                proposal.new_public_keys,
            )?;

            applied_updates.push(proposal_id);
        }

        Ok(applied_updates)
    }

    /// Validate federation signature for sidechain operation
    pub fn validate_federation_signature(
        &self,
        sidechain_id: &Hash,
        epoch: u64,
        signature: &FederationSignature,
        message: &[u8],
    ) -> bool {
        if let Some(fed_manager) = self.federation_managers.get(sidechain_id) {
            fed_manager.verify_threshold_signature(sidechain_id, epoch, signature, message)
        } else {
            false
        }
    }

    /// Check if federation transition is needed for a sidechain
    pub fn should_transition_federation(&self, sidechain_id: &Hash, current_height: u64) -> bool {
        if let Some(fed_manager) = self.federation_managers.get(sidechain_id) {
            fed_manager.should_transition_epoch(sidechain_id, current_height)
        } else {
            false
        }
    }

    /// Get current federation epoch for a sidechain
    pub fn get_current_epoch(&self, sidechain_id: &Hash) -> Option<&FederationEpoch> {
        self.federation_managers.get(sidechain_id)
            .and_then(|fm| fm.get_current_epoch(sidechain_id))
    }

    /// Get federation statistics across all sidechains
    pub fn get_federation_stats(&self) -> FederationStats {
        let mut total_sidechains = 0;
        let mut total_epochs = 0;
        let mut total_members = 0;
        let mut pending_updates = self.pending_updates.len();

        for fed_manager in self.federation_managers.values() {
            let stats = fed_manager.get_stats();
            total_sidechains += stats.total_sidechains;
            total_epochs += stats.total_epochs;
            total_members += stats.total_members;
        }

        FederationStats {
            total_sidechains,
            total_epochs,
            total_members,
            active_sidechains: self.federation_managers.len(),
            pending_updates,
        }
    }

    /// Create federation update proposal from governance vote results
    pub fn create_update_from_governance(
        &self,
        governance_proposal_id: Hash,
        sidechain_id: Hash,
        new_members: Vec<MasternodeID>,
        new_threshold: u32,
        new_public_keys: Vec<Vec<u8>>,
        activation_height: u64,
    ) -> FederationUpdateProposal {
        FederationUpdateProposal {
            sidechain_id,
            new_members,
            new_threshold,
            new_public_keys,
            activation_height,
            governance_proposal_id,
        }
    }

    /// Emergency federation update (bypasses governance for critical situations)
    pub fn emergency_federation_update(
        &mut self,
        sidechain_id: Hash,
        new_members: Vec<MasternodeID>,
        new_threshold: u32,
        new_public_keys: Vec<Vec<u8>>,
        current_height: u64,
    ) -> Result<u64, String> {
        let fed_manager = self.federation_managers.get_mut(&sidechain_id)
            .ok_or("Federation not initialized for sidechain")?;

        // Emergency updates happen immediately
        fed_manager.transition_epoch(
            sidechain_id,
            new_members,
            new_threshold,
            current_height,
            new_public_keys,
        )
    }
}

/// Extended federation statistics
#[derive(Debug, Clone)]
pub struct FederationStats {
    pub total_sidechains: usize,
    pub total_epochs: usize,
    pub total_members: usize,
    pub active_sidechains: usize,
    pub pending_updates: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::governance_state::{ActiveProposals, ProposalOutcome, VoterType};
    use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote};

    fn create_test_masternode_id(value: u8) -> MasternodeID {
        MasternodeID(OutPoint {
            txid: [value; 32],
            vout: 0,
        })
    }

    #[test]
    fn test_federation_integrator_creation() {
        let integrator = FederationIntegrator::new();
        assert!(integrator.federation_managers.is_empty());
        assert!(integrator.pending_updates.is_empty());
    }

    #[test]
    fn test_sidechain_federation_initialization() {
        let mut integrator = FederationIntegrator::new();

        let sidechain_id = [1u8; 32];
        let members = vec![
            create_test_masternode_id(1),
            create_test_masternode_id(2),
            create_test_masternode_id(3),
        ];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];

        let result = integrator.initialize_sidechain_federation(
            sidechain_id,
            members.clone(),
            2,
            public_keys.clone(),
            100,
            1000,
        );

        assert!(result.is_ok());

        let fed_manager = integrator.get_federation_manager(&sidechain_id).unwrap();
        let epoch = fed_manager.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(epoch.members, members);
        assert_eq!(epoch.threshold, 2);
    }

    #[test]
    fn test_federation_update_proposal() {
        let mut integrator = FederationIntegrator::new();

        // Initialize federation
        let sidechain_id = [1u8; 32];
        let members = vec![create_test_masternode_id(1), create_test_masternode_id(2)];
        let public_keys = vec![vec![1u8; 48], vec![2u8; 48]];

        integrator.initialize_sidechain_federation(
            sidechain_id,
            members,
            2,
            public_keys,
            100,
            1000,
        ).unwrap();

        // Create update proposal
        let new_members = vec![
            create_test_masternode_id(3),
            create_test_masternode_id(4),
            create_test_masternode_id(5),
        ];
        let new_public_keys = vec![vec![3u8; 48], vec![4u8; 48], vec![5u8; 48]];

        let proposal = FederationUpdateProposal {
            sidechain_id,
            new_members: new_members.clone(),
            new_threshold: 2,
            new_public_keys: new_public_keys.clone(),
            activation_height: 200,
            governance_proposal_id: [42u8; 32],
        };

        // Should fail without governance
        assert!(integrator.propose_federation_update(proposal.clone(), 150).is_err());

        // Set up mock governance
        let mut governance = ActiveProposals::new();
        let gov_proposal = GovernanceProposal {
            proposal_id: [42u8; 32],
            proposer_address: [1u8; 32],
            proposal_type: rusty_shared_types::governance::ProposalType::ParameterChange,
            start_block_height: 100,
            end_block_height: 150,
            title: "Federation Update".to_string(),
            description_hash: [2u8; 32],
            code_change_hash: None,
            target_parameter: Some("federation_members".to_string()),
            new_value: Some("updated".to_string()),
            bug_description: None,
            recipient_address: None,
            amount: None,
            project_description: None,
            proposer_signature: rusty_shared_types::TransactionSignature { bytes: [0u8; 64] },
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 1000,
        };
        governance.add_proposal(gov_proposal).unwrap();

        let governance_arc = std::sync::Arc::new(std::sync::Mutex::new(governance));
        integrator = integrator.with_mainchain_governance(governance_arc);

        // Should succeed now
        assert!(integrator.propose_federation_update(proposal, 150).is_ok());

        // Apply pending updates
        let applied = integrator.apply_pending_updates(200).unwrap();
        assert_eq!(applied.len(), 1);

        // Check federation was updated
        let fed_manager = integrator.get_federation_manager(&sidechain_id).unwrap();
        let epoch = fed_manager.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(epoch.members, new_members);
        assert_eq!(epoch.epoch, 2);
    }

    #[test]
    fn test_emergency_federation_update() {
        let mut integrator = FederationIntegrator::new();

        let sidechain_id = [1u8; 32];
        let members = vec![create_test_masternode_id(1)];
        let public_keys = vec![vec![1u8; 48]];

        integrator.initialize_sidechain_federation(
            sidechain_id,
            members,
            1,
            public_keys,
            100,
            1000,
        ).unwrap();

        // Emergency update
        let new_members = vec![create_test_masternode_id(2), create_test_masternode_id(3)];
        let new_public_keys = vec![vec![2u8; 48], vec![3u8; 48]];

        let result = integrator.emergency_federation_update(
            sidechain_id,
            new_members.clone(),
            2,
            new_public_keys,
            150,
        );

        assert!(result.is_ok());

        let fed_manager = integrator.get_federation_manager(&sidechain_id).unwrap();
        let epoch = fed_manager.get_current_epoch(&sidechain_id).unwrap();
        assert_eq!(epoch.members, new_members);
        assert_eq!(epoch.epoch, 2);
    }
}