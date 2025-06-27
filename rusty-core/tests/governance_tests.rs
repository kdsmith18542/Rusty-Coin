use rusty_core::consensus::governance_state::{ActiveProposals, ProposalOutcome};
use rusty_shared_types::{Hash, PublicKey, Signature};
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote, ProposalType, VoterType, VoteChoice};
use rusty_core::consensus::ConsensusError;
use std::collections::HashMap;

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

fn create_test_proposal(proposal_id_seed: u8, start_block: u64, end_block: u64) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: dummy_hash(proposal_id_seed),
        proposer_address: dummy_public_key(proposal_id_seed + 10),
        proposal_type: ProposalType::PROTOCOL_UPGRADE,
        start_block_height: start_block,
        end_block_height: end_block,
        title: format!("Test Proposal {}", proposal_id_seed),
        description_hash: dummy_hash(proposal_id_seed + 20),
        code_change_hash: None,
        target_parameter: None,
        new_value: None,
        proposer_signature: dummy_signature(proposal_id_seed + 30),
        inputs: vec![],
        outputs: vec![], // Stake handled by consensus layer, not directly in proposal
        lock_time: 0,
    }
}

fn create_test_vote(proposal_id_seed: u8, voter_id_seed: u8, voter_type: VoterType, choice: VoteChoice) -> GovernanceVote {
    GovernanceVote {
        proposal_id: dummy_hash(proposal_id_seed),
        voter_type: voter_type,
        voter_id: dummy_public_key(voter_id_seed),
        vote_choice: choice,
        voter_signature: dummy_signature(voter_id_seed + 40),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
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
    assert!(active_proposals.get_votes_for_proposal(&proposal_id).is_some());
    assert!(active_proposals.get_votes_for_proposal(&proposal_id).unwrap().is_empty());
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

    let vote = create_test_vote(1, 1, VoterType::POS_TICKET, VoteChoice::YES);
    let voter_id = vote.voter_id;

    assert!(active_proposals.record_vote(vote.clone()).is_ok());
    assert_eq!(active_proposals.get_votes_for_proposal(&proposal_id).unwrap().len(), 1);
    assert!(active_proposals.get_votes_for_proposal(&proposal_id).unwrap().contains_key(&voter_id));
}

#[test]
fn test_record_duplicate_vote() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    active_proposals.add_proposal(proposal).unwrap();

    let vote = create_test_vote(1, 1, VoterType::POS_TICKET, VoteChoice::YES);

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
        let vote_choice = if i < 80 { VoteChoice::YES } else { VoteChoice::NO };
        let vote = create_test_vote(1, i as u8, VoterType::POS_TICKET, vote_choice);
        active_proposals.record_vote(vote).unwrap();
    }

    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count (PoS quorum target)
        100, // total active masternodes count (MN quorum target)
        0.50, // PoS quorum: 50% of 200 = 100. We cast 100 votes.
        0.50, // MN quorum: 50% of 100 = 50. Not casting MN votes for this test, but the logic handles.
        0.75, // PoS approval: 75% of 100 = 75. We cast 80 YES.
        0.66, // MN approval
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
        let vote = create_test_vote(1, i as u8, VoterType::POS_TICKET, VoteChoice::YES);
        active_proposals.record_vote(vote).unwrap();
    }

    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count
        100, // total active masternodes count
        0.50, // PoS quorum: 50% of 200 = 100. We cast 10 votes.
        0.50, // MN quorum
        0.75, // PoS approval
        0.66, // MN approval
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::Rejected { reason: "Quorum not met".to_string() });
}

#[test]
fn test_evaluate_proposal_rejected_supermajority() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    // Simulate enough votes for quorum but not for supermajority
    for i in 0..100 {
        let vote_choice = if i < 60 { VoteChoice::YES } else { VoteChoice::NO }; // 60% YES, 40% NO
        let vote = create_test_vote(1, i as u8, VoterType::POS_TICKET, vote_choice);
        active_proposals.record_vote(vote).unwrap();
    }

    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        200, // End block height
        200, // total live tickets count
        100, // total active masternodes count
        0.50, // PoS quorum: 50% of 200 = 100. We cast 100 votes.
        0.50, // MN quorum
        0.75, // PoS approval: 75% needed. We have 60%.
        0.66, // MN approval
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::Rejected { reason: "Supermajority not met".to_string() });
}

#[test]
fn test_evaluate_proposal_in_progress() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        150, // Current height is within voting period
        200, 
        100, 
        0.50,
        0.50,
        0.75,
        0.66,
    ).unwrap();

    assert_eq!(outcome, ProposalOutcome::InProgress);
}

#[test]
fn test_evaluate_proposal_expired() {
    let mut active_proposals = ActiveProposals::new();
    let proposal = create_test_proposal(1, 100, 200);
    let proposal_id = proposal.proposal_id;
    active_proposals.add_proposal(proposal).unwrap();

    let outcome = active_proposals.evaluate_proposal_at_height(
        &proposal_id,
        201, // Current height is past end block height
        200, 
        100, 
        0.50,
        0.50,
        0.75,
        0.66,
    ).unwrap();

    // If quorum is not met, it's rejected. If it's past end_block_height, it's considered expired.
    // In this case, no votes are cast, so it should be rejected due to quorum not met.
    // The `evaluate_proposal_at_height` already handles the `current_height > proposal.end_block_height` 
    // by returning InProgress or allowing evaluation if it's exactly end_block_height. 
    // If it's *past* end_block_height and quorum is not met, it's rejected. 
    // If it passes all checks, it's passed.
    // The `Expired` outcome is primarily for cases where it's passed end_block_height and fails for other reasons.
    assert!(matches!(outcome, ProposalOutcome::Rejected { reason: _ }));
} 