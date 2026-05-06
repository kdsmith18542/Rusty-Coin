//! Unit tests for governance vote validation

#[cfg(test)]
mod tests {
    use crate::vote_validation::{VoteValidationError, VoteValidator};
    use rusty_core::consensus::pos::LiveTicketsPool;
    use rusty_shared_types::governance::{GovernanceVote, VoteChoice, VoterType};
    use rusty_shared_types::masternode::{
        MasternodeEntry, MasternodeID, MasternodeIdentity, MasternodeList, MasternodeStatus,
    };
    use rusty_shared_types::Ticket;
    use rusty_shared_types::{OutPoint, TicketId};
    use rusty_shared_types::{PublicKey, TransactionSignature};

    fn dummy_pubkey(byte: u8) -> PublicKey {
        [byte; 32]
    }
    fn dummy_signature() -> TransactionSignature {
        TransactionSignature { bytes: [1u8; 64] }
    }

    #[test]
    fn test_pos_vote_ineligible() {
        let vote = GovernanceVote {
            proposal_id: [0u8; 32],
            voter_type: VoterType::PosTicket,
            voter_id: dummy_pubkey(1),
            vote_choice: VoteChoice::Yes,
            voter_signature: dummy_signature(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };
        let live_tickets = LiveTicketsPool::new();
        let masternode_list = MasternodeList::new();
        let res = VoteValidator::validate_vote(
            &vote,
            &vote.voter_id,
            &live_tickets,
            &masternode_list,
            100,
            1000,
        );
        assert!(matches!(res, Err(VoteValidationError::IneligibleVoter)));
    }

    #[test]
    fn test_masternode_vote_ineligible() {
        let vote = GovernanceVote {
            proposal_id: [0u8; 32],
            voter_type: VoterType::Masternode,
            voter_id: dummy_pubkey(2),
            vote_choice: VoteChoice::No,
            voter_signature: dummy_signature(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };
        let live_tickets = LiveTicketsPool::new();
        let masternode_list = MasternodeList::new();
        let res = VoteValidator::validate_vote(
            &vote,
            &vote.voter_id,
            &live_tickets,
            &masternode_list,
            100,
            1000,
        );
        assert!(matches!(res, Err(VoteValidationError::IneligibleVoter)));
    }

    #[test]
    fn test_pos_vote_valid() {
        let mut live_tickets = LiveTicketsPool::new();
        let ticket = Ticket {
            id: TicketId([1u8; 32]),
            pubkey: dummy_pubkey(1).to_vec(),
            height: 0,
            value: 1000,
            status: rusty_shared_types::TicketStatus::Live,
        };
        live_tickets.add_ticket(ticket.clone()).unwrap();
        let vote = GovernanceVote {
            proposal_id: [0u8; 32],
            voter_type: VoterType::PosTicket,
            voter_id: dummy_pubkey(1),
            vote_choice: VoteChoice::Yes,
            voter_signature: dummy_signature(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };
        let masternode_list = MasternodeList::new();
        let res = VoteValidator::validate_vote(
            &vote,
            &vote.voter_id,
            &live_tickets,
            &masternode_list,
            100,
            1000,
        );
        // Signature is dummy, so this will fail on signature, but eligibility/stake should pass
        assert!(matches!(res, Err(VoteValidationError::InvalidSignature)));
    }

    #[test]
    fn test_pos_vote_insufficient_stake() {
        let mut live_tickets = LiveTicketsPool::new();
        let ticket = Ticket {
            id: TicketId([2u8; 32]),
            pubkey: dummy_pubkey(2).to_vec(),
            height: 0,
            value: 50,
            status: rusty_shared_types::TicketStatus::Live,
        };
        live_tickets.add_ticket(ticket.clone()).unwrap();
        let vote = GovernanceVote {
            proposal_id: [0u8; 32],
            voter_type: VoterType::PosTicket,
            voter_id: dummy_pubkey(2),
            vote_choice: VoteChoice::Yes,
            voter_signature: dummy_signature(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };
        let masternode_list = MasternodeList::new();
        let res = VoteValidator::validate_vote(
            &vote,
            &vote.voter_id,
            &live_tickets,
            &masternode_list,
            100,
            1000,
        );
        assert!(matches!(res, Err(VoteValidationError::InsufficientStake)));
    }

    #[test]
    fn test_masternode_vote_valid() {
        let mut masternode_list = MasternodeList::new();
        let identity = MasternodeIdentity {
            collateral_outpoint: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            operator_public_key: dummy_pubkey(3).to_vec(),
            network_address: "127.0.0.1:1234".to_string(),
            collateral_ownership_public_key: vec![0u8; 32],
            dkg_public_key: None,
            supported_dkg_versions: vec![],
        };
        let entry = MasternodeEntry {
            identity: identity.clone(),
            status: MasternodeStatus::Active,
            last_successful_pose_height: 0,
            pose_failure_count: 0,
            last_slashed_height: None,
            dkg_participation_count: 0,
            dkg_success_rate: 1.0,
            active_dkg_sessions: vec![],
            collateral_amount: 1000000, // 1 million satoshis
        };
        masternode_list
            .map
            .insert(MasternodeID(identity.collateral_outpoint.clone()), entry);
        let vote = GovernanceVote {
            proposal_id: [0u8; 32],
            voter_type: VoterType::Masternode,
            voter_id: dummy_pubkey(3),
            vote_choice: VoteChoice::Yes,
            voter_signature: dummy_signature(),
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
            fee: 0,
        };
        let live_tickets = LiveTicketsPool::new();
        let res = VoteValidator::validate_vote(
            &vote,
            &vote.voter_id,
            &live_tickets,
            &masternode_list,
            100,
            1000,
        );
        // Signature is dummy, so this will fail on signature, but eligibility/stake should pass
        assert!(matches!(res, Err(VoteValidationError::InvalidSignature)));
    }

    // Add more tests for valid votes, insufficient stake, and invalid signature as needed
}
