use rusty_core::consensus::error::ConsensusError;
use rusty_core::consensus::governance_state::{ActiveProposals, ProposalOutcome};
use rusty_shared_types::governance::{
    GovernanceProposal, GovernanceVote, ProposalType, VoteChoice, VoterType,
};
use rusty_shared_types::TransactionSignature;
use rusty_shared_types::{Hash, PublicKey, Signature};

// Helper functions for creating dummy data
fn dummy_hash(seed: u8) -> Hash {
    [seed; 32]
}

fn dummy_public_key(seed: u8) -> PublicKey {
    [seed; 32]
}

fn dummy_signature(seed: u8) -> Signature {
    [seed; 64]
}

fn create_test_proposal(
    proposal_id_seed: u8,
    start_block: u64,
    end_block: u64,
) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: dummy_hash(proposal_id_seed),
        proposer_address: dummy_public_key(proposal_id_seed + 10),
        proposal_type: ProposalType::ProtocolUpgrade, // Fix: Use correct variant name for ProposalType::ProtocolUpgrade (not PROTOCOL_UPGRADE)
        start_block_height: start_block,
        end_block_height: end_block,
        title: format!("Test Proposal {}", proposal_id_seed),
        description_hash: dummy_hash(proposal_id_seed + 20),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        bug_description: None,
        recipient_address: None,
        amount: None,
        project_description: None,
        proposer_signature: TransactionSignature::new(dummy_signature(proposal_id_seed + 30)),
        inputs: vec![],
        // Fix: Use get_outputs() instead of outputs field
        outputs: vec![],
        lock_time: 0,
        fee: 0,          // Add missing fee field
        witness: vec![], // Add missing witness field
    }
}

fn create_test_vote(
    proposal_id_seed: u8,
    voter_id_seed: u8,
    voter_type: VoterType,
    choice: VoteChoice,
) -> GovernanceVote {
    GovernanceVote {
        proposal_id: dummy_hash(proposal_id_seed),
        voter_type: voter_type,
        voter_id: dummy_public_key(voter_id_seed),
        vote_choice: choice,
        // Fix: Use TransactionSignature::from_bytes([0u8; 64]) or similar for signatures
        voter_signature: TransactionSignature::new(dummy_signature(voter_id_seed + 40)),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
        fee: 0,
    }
}

#[test]
fn test_add_proposal() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;

    assert!(active_proposals.add_proposal(proposal.clone()).is_ok());
    assert_eq!(active_proposals.proposals.len(), 1);
    assert!(active_proposals.get_proposal(&proposal_id).is_some());
    assert!(active_proposals
        .get_votes_for_proposal(&proposal_id)
        .is_some());
    assert!(active_proposals
        .get_votes_for_proposal(&proposal_id)
        .unwrap()
        .is_empty());
}

#[test]
fn test_add_duplicate_proposal() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);

    active_proposals.add_proposal(proposal.clone()).unwrap();
    let err = active_proposals.add_proposal(proposal.clone()).unwrap_err();
    assert!(matches!(err, ConsensusError::RuleViolation(_)));
}

#[test]
fn test_record_vote() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    let vote = create_test_vote(1, 1, VoterType::PosTicket, VoteChoice::Yes);
    let voter_id = vote.voter_id;

    assert!(active_proposals.record_vote(vote.clone()).is_ok());
    assert_eq!(
        active_proposals
            .get_votes_for_proposal(&proposal_id)
            .unwrap()
            .len(),
        1
    );
    assert!(active_proposals
        .get_votes_for_proposal(&proposal_id)
        .unwrap()
        .contains_key(&voter_id));
}

#[test]
fn test_record_duplicate_vote() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    active_proposals.add_proposal(proposal).unwrap();

    let vote = create_test_vote(1, 1, VoterType::PosTicket, VoteChoice::Yes);

    active_proposals.record_vote(vote.clone()).unwrap();
    let err = active_proposals.record_vote(vote.clone()).unwrap_err();
    assert!(matches!(err, ConsensusError::RuleViolation(_)));
}

#[test]
fn test_evaluate_proposal_passed() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    // Simulate enough votes to pass quorum and supermajority
    for i in 0..100 {
        let vote_choice = if i < 80 {
            VoteChoice::Yes
        } else {
            VoteChoice::No
        };
        let vote = create_test_vote(1, i as u8, VoterType::PosTicket, vote_choice);
        active_proposals.record_vote(vote).unwrap();
    }

    let voter_types = std::collections::HashMap::new();
    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count (PoS quorum target)
        100, // total active masternodes count (MN quorum target)
        0.50, // PoS quorum: 50% of 200 = 100. We cast 100 votes.
        0.50, // MN quorum: 50% of 100 = 50. Not casting MN votes for this test, but the logic handles.
        0.75, // PoS approval: 75% of 100 = 75. We cast 80 YES.
        0.66, // MN approval
        &voter_types,
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::Passed);
}

#[test]
fn test_evaluate_proposal_rejected_quorum() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    // Simulate not enough votes for quorum
    for i in 0..10 {
        let vote = create_test_vote(1, i as u8, VoterType::PosTicket, VoteChoice::Yes);
        active_proposals.record_vote(vote).unwrap();
    }

    let voter_types = std::collections::HashMap::new();
    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count
        100, // total active masternodes count
        0.50, // PoS quorum: 50% of 200 = 100. We cast 10 votes.
        0.50, // MN quorum
        0.75, // PoS approval
        0.66, // MN approval
        &voter_types,
    ).unwrap();

    assert_eq!(
        outcome,
        ProposalOutcome::Rejected {
            reason: "Quorum not met".to_string()
        }
    );
}

#[test]
fn test_evaluate_proposal_rejected_supermajority() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    // Simulate enough votes for quorum but not for supermajority
    for i in 0..100 {
        let vote_choice = if i < 60 {
            VoteChoice::Yes
        } else {
            VoteChoice::No
        }; // 60% YES, 40% NO
        let vote = create_test_vote(1, i as u8, VoterType::PosTicket, vote_choice);
        active_proposals.record_vote(vote).unwrap();
    }

    let voter_types = std::collections::HashMap::new();
    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count
        100, // total active masternodes count
        0.50, // PoS quorum
        0.50, // MN quorum
        0.75, // PoS approval: 75% required, we have 60%
        0.66, // MN approval
        &voter_types,
    ).unwrap();

    assert_eq!(
        outcome,
        ProposalOutcome::Rejected {
            reason: "Supermajority not met".to_string()
        }
    );
}

#[test]
fn test_evaluate_proposal_in_progress() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    let voter_types = std::collections::HashMap::new();
    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        50, // Before start height
        200,
        100,
        0.50,
        0.50,
        0.75,
        0.66,
        &voter_types,
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::InProgress);
}

#[test]
fn test_evaluate_proposal_expired() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    let voter_types = std::collections::HashMap::new();
    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        250, // Past end height
        200,
        100,
        0.50,
        0.50,
        0.75,
        0.66,
        &voter_types,
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::Expired);
}
