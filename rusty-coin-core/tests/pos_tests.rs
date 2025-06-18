use rusty_coin_core::{
    consensus::pos::{VotingTicket, TicketSelectionParams, select_quorum, validate_quorum},
    crypto::{Hash, KeyPair},
    types::Block,
};

fn create_test_block() -> Block {
    Block {
        header: rusty_coin_core::types::BlockHeader {
            version: 1,
            prev_block_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            timestamp: 0,
            bits: 0,
            nonce: 0,
            ticket_hash: Hash::zero(),
            cumulative_work: 0,
            height: 0,
            pos_votes: Vec::new(),
        },
        transactions: vec![],
    }
}

#[test]
fn test_ticket_creation_and_verification() {
    let keypair = KeyPair::generate().unwrap();
    let ticket = VotingTicket::new(&keypair, 1000, 1).unwrap();
    
    assert!(ticket.verify());
    assert_eq!(ticket.stake_amount, 1000);
    assert_eq!(ticket.creation_height, 1);
}

#[test]
fn test_quorum_selection() {
    let mut tickets = vec![];
    let keypair = KeyPair::generate().unwrap();
    
    // Create 10 valid tickets
    for i in 0..10 {
        tickets.push(VotingTicket::new(&keypair, 1000 + i, 1).unwrap());
    }
    
    let params = TicketSelectionParams {
        min_confirmations: 0,
        max_ticket_age: 100,
        min_stake: 1000,
        quorum_size: 5,
        min_pos_votes: 3,
    };
    
    let quorum = select_quorum(&tickets, &Hash::zero(), 10, &params).unwrap();
    assert_eq!(quorum.len(), 5);
}

#[test]
fn test_quorum_validation() {
    let keypair = KeyPair::generate().unwrap();
    let block = create_test_block();
    
    let mut tickets = vec![];
    for i in 0..5 {
        // Create valid ticket
        let ticket = VotingTicket::new(&keypair, 1000 + i, 1).unwrap();
        
        // Create block approval signature separately
        let mut approved_ticket = ticket.clone();
        approved_ticket.signature = keypair.sign(block.header.hash().as_bytes()).unwrap();
        
        tickets.push(approved_ticket);
    }
    
    let params = TicketSelectionParams::default();
    assert!(validate_quorum(&block, &tickets, &params).is_ok());
}

#[test]
fn test_invalid_quorum_detection() {
    let keypair1 = KeyPair::generate().unwrap();
    let _keypair2 = KeyPair::generate().unwrap();
    let block = create_test_block();
    
    // Create tickets with insufficient stake
    let mut tickets = vec![];
    for _ in 0..5 {
        tickets.push(VotingTicket::new(&keypair1, 500, 1).unwrap());
    }
    
    let params = TicketSelectionParams::default();
    assert!(validate_quorum(&block, &tickets, &params).is_err());
    
    // Create tickets with duplicate ticket
    let mut tickets = vec![];
    let ticket = VotingTicket::new(&keypair1, 1000, 1).unwrap();
    tickets.push(ticket.clone());
    tickets.push(ticket); // Duplicate
    
    assert!(validate_quorum(&block, &tickets, &params).is_err());
}
