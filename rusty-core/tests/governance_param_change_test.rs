//! Test for governance ParameterChange proposal application

use std::sync::{Arc, Mutex};
use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::error::ConsensusError;
use rusty_core::network::{P2PNetwork, PeerId};
use rusty_shared_types::governance::{GovernanceProposal, ProposalType};
use rusty_shared_types::{Block, Hash, PublicKey, Transaction, TransactionSignature, TxInput, TxOutput, P2PMessage, PeerInfo, BlockRequest, BlockResponse, GetHeaders, Headers};

fn dummy_hash(seed: u8) -> Hash {
    [seed; 32]
}
fn dummy_public_key(seed: u8) -> PublicKey {
    [seed; 32]
}
fn dummy_signature(seed: u8) -> TransactionSignature {
    TransactionSignature::new([seed; 64])
}

#[test]
fn test_parameter_change_proposal_applies() {
    struct MockP2PNetwork;
    impl P2PNetwork for MockP2PNetwork {
        fn send_message(&self, _peer_id: PeerId, _message: P2PMessage) -> Result<(), String> { Ok(()) }
        fn broadcast_message(&self, _message: P2PMessage) -> Result<(), String> { Ok(()) }
        fn receive_message(&mut self) -> Option<(PeerId, P2PMessage)> { None }
        fn get_peer_info(&self, _peer_id: PeerId) -> Option<PeerInfo> { None }
        fn get_connected_peers(&self) -> Vec<PeerId> { vec![] }
        fn request_blocks(&self, _peer_id: PeerId, _request: BlockRequest) -> Option<BlockResponse> { None }
        fn request_headers(&self, _peer_id: PeerId, _request: GetHeaders) -> Option<Headers> { None }
    }
    let p2p_network = Arc::new(Mutex::new(MockP2PNetwork));
    let mut blockchain = Blockchain::new(p2p_network).unwrap();
    let old_ticket_price = blockchain.params.ticket_price;
    let new_ticket_price = old_ticket_price + 12345;
    let proposal = GovernanceProposal {
        proposal_id: dummy_hash(42),
        proposer_address: dummy_public_key(1),
        proposal_type: ProposalType::ParameterChange,
        start_block_height: 1,
        end_block_height: 2,
        title: "Change ticket price".to_string(),
        description_hash: dummy_hash(2),
        code_change_hash: None,
        target_parameter: Some("ticket_price".to_string()),
        new_value: Some(new_ticket_price.to_string()),
        bug_description: None,
        recipient_address: None,
        amount: None,
        project_description: None,
        proposer_signature: dummy_signature(3),
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
        fee: 0,
    };
    blockchain
        .active_proposals
        .add_proposal(proposal.clone())
        .unwrap();
    // Simulate proposal passing
    blockchain
        .active_proposals
        .proposals
        .get_mut(&proposal.proposal_id)
        .unwrap()
        .0
        .end_block_height = 0;
    blockchain.evaluate_and_apply_governance(100).unwrap();
    assert_eq!(blockchain.params.ticket_price, new_ticket_price);
}
