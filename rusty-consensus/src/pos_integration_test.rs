//! Integration tests for the OxideSync PoS implementation
//! These tests verify that the PoS ticket selection, validation, and lifecycle
//! management work correctly together as a system.

use crate::pos::LiveTicketsPool;
use crate::pos_selection::{adjust_ticket_price, is_block_final, select_tickets_for_voting};
use crate::pos_selection::{TICKET_EXPIRATION_BLOCKS, TICKET_MATURITY_BLOCKS};
use crate::validation::validate_ticket_votes;
use rusty_shared_types::{ConsensusParams, Ticket, TicketId, TicketStatus, TicketVote};
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a test ticket
    fn create_test_ticket(id: u8, height: u64, status: TicketStatus) -> Ticket {
        let mut ticket_id = [0u8; 32];
        ticket_id[0] = id;

        Ticket {
            id: TicketId::from(ticket_id),
            pubkey: vec![0u8; 32], // Dummy public key
            height,
            value: 100_000_000, // 1 RCN
            status,
        }
    }

    /// Helper function to create a test vote
    fn create_test_vote(ticket_id: &TicketId, block_hash: &[u8; 32], vote_type: u8) -> TicketVote {
        let mut signature = [0u8; 64];
        // Create a simple deterministic signature for testing
        for i in 0..32 {
            signature[i] = ticket_id.0[i];
            signature[i + 32] = block_hash[i];
        }

        TicketVote {
            ticket_id: ticket_id.0,
            block_hash: *block_hash,
            vote: vote_type,
            signature,
        }
    }

    /// Test the full ticket lifecycle
    #[test]
    fn test_ticket_lifecycle() {
        // Initialize a ticket pool
        let mut pool = LiveTicketsPool::new();

        // Add some tickets (they start as Live in the actual enum)
        let ticket1 = create_test_ticket(1, 100, TicketStatus::Live);
        let ticket2 = create_test_ticket(2, 100, TicketStatus::Live);
        let ticket3 = create_test_ticket(3, 100, TicketStatus::Live);

        pool.add_ticket(ticket1.clone());
        pool.add_ticket(ticket2.clone());
        pool.add_ticket(ticket3.clone());

        // Verify tickets are in the pool but not live yet
        assert_eq!(pool.count(), 3);
        assert_eq!(pool.count_live(), 0);

        // Process ticket maturity at a height before they mature
        let matured = pool.process_ticket_maturity(100 + TICKET_MATURITY_BLOCKS - 1);
        assert_eq!(matured.len(), 0);
        assert_eq!(pool.count_live(), 0);

        // Process ticket maturity at the height they should mature
        let matured = pool.process_ticket_maturity(100 + TICKET_MATURITY_BLOCKS);
        assert_eq!(matured.len(), 3);
        assert_eq!(pool.count_live(), 3);

        // Verify tickets are now live
        assert_eq!(
            pool.get_ticket(&ticket1.id).unwrap().status,
            TicketStatus::Live
        );
        assert_eq!(
            pool.get_ticket(&ticket2.id).unwrap().status,
            TicketStatus::Live
        );
        assert_eq!(
            pool.get_ticket(&ticket3.id).unwrap().status,
            TicketStatus::Live
        );

        // Mark a ticket as voted
        assert!(pool.mark_ticket_voted(&ticket1.id).is_ok());
        assert_eq!(
            pool.get_ticket(&ticket1.id).unwrap().status,
            TicketStatus::Voted
        );
        assert_eq!(pool.count_live(), 2);

        // Mark a ticket as missed
        assert!(pool
            .mark_ticket_missed(&ticket2.id, 100 + TICKET_MATURITY_BLOCKS + 10)
            .is_ok());
        assert_eq!(pool.get_non_participation_count(&ticket2.id), 1);
        assert_eq!(
            pool.get_last_missed_height(&ticket2.id),
            Some(100 + TICKET_MATURITY_BLOCKS + 10)
        );

        // Revoke the missed ticket
        assert!(pool.revoke_ticket(&ticket2.id).is_ok());
        assert_eq!(
            pool.get_ticket(&ticket2.id).unwrap().status,
            TicketStatus::Revoked
        );
        assert_eq!(pool.count_live(), 1);

        // Process ticket expiration at a height before they expire
        let expired = pool.process_ticket_expiration(100 + TICKET_EXPIRATION_BLOCKS - 1);
        assert_eq!(expired.len(), 0);

        // Process ticket expiration at the height they should expire
        let expired = pool.process_ticket_expiration(100 + TICKET_EXPIRATION_BLOCKS);
        assert_eq!(expired.len(), 1); // Only ticket3 is still live
        assert_eq!(expired[0], ticket3.id);

        // Verify ticket3 is now expired
        assert_eq!(
            pool.get_ticket(&ticket3.id).unwrap().status,
            TicketStatus::Expired
        );
        assert_eq!(pool.count_live(), 0);
    }

    /// Test the ticket selection algorithm
    #[test]
    fn test_ticket_selection_integration() {
        // Create a pool of live tickets
        let mut live_tickets = HashMap::new();
        for i in 1..=100 {
            let ticket = create_test_ticket(i as u8, 100, TicketStatus::Live);
            live_tickets.insert(ticket.id.clone(), ticket);
        }

        // Create a block hash for selection
        let block_hash = [42u8; 32];

        // Select tickets for voting
        let selected = select_tickets_for_voting(&live_tickets, &block_hash, 5);

        // Verify we got the expected number of tickets
        assert_eq!(selected.len(), 5);

        // Verify selections are deterministic
        let selected2 = select_tickets_for_voting(&live_tickets, &block_hash, 5);
        assert_eq!(selected, selected2);

        // Verify different block hash gives different selection
        let different_block_hash = [24u8; 32];
        let selected3 = select_tickets_for_voting(&live_tickets, &different_block_hash, 5);
        assert_ne!(selected, selected3);
    }

    /// Test the ticket price adjustment algorithm
    #[test]
    fn test_ticket_price_adjustment_integration() {
        // Test price increases when pool size is below target
        let new_price = adjust_ticket_price(
            100_000_000, // 1 RCN
            30000,       // Current pool size
            40960,       // Target pool size
            5,           // Max adjustment percent
        );
        assert!(new_price > 100_000_000);

        // Test price decreases when pool size is above target
        let new_price = adjust_ticket_price(
            100_000_000, // 1 RCN
            50000,       // Current pool size
            40960,       // Target pool size
            5,           // Max adjustment percent
        );
        assert!(new_price < 100_000_000);

        // Test price stays the same when pool size equals target
        let new_price = adjust_ticket_price(
            100_000_000, // 1 RCN
            40960,       // Current pool size
            40960,       // Target pool size
            5,           // Max adjustment percent
        );
        assert_eq!(new_price, 100_000_000);
    }

    /// Test the vote validation system
    #[test]
    fn test_vote_validation_integration() {
        // Initialize a ticket pool
        let mut pool = LiveTicketsPool::new();

        // Add some live tickets
        for i in 1..=10 {
            let ticket = create_test_ticket(i as u8, 100, TicketStatus::Live);
            pool.add_ticket(ticket);
        }

        // Create a previous block hash
        let prev_block_hash = [42u8; 32];

        // Create consensus params
        let mut params = ConsensusParams::default();
        // Use the ticket_maturity field from ConsensusParams
        params.ticket_maturity = TICKET_MATURITY_BLOCKS as u32;
        params.ticket_expiry = TICKET_EXPIRATION_BLOCKS as u32;
        params.tickets_per_round = 5; // Number of tickets to select

        // Get live tickets
        let live_tickets = pool.get_live_tickets();

        // Select tickets for voting
        let selected_tickets = select_tickets_for_voting(&live_tickets, &prev_block_hash, 5);
        assert_eq!(selected_tickets.len(), 5);

        // Create valid votes for the selected tickets
        let mut votes = Vec::new();
        for ticket_id in &selected_tickets[0..3] {
            votes.push(create_test_vote(ticket_id, &prev_block_hash, 0)); // Yes vote
        }

        // Create a HashMap of all tickets for validation
        let _all_tickets_map: HashMap<TicketId, Ticket> = pool.get_all_tickets().clone();

        // Validate the votes - should pass
        let result = validate_ticket_votes(
            &votes, 200, // Current height
            &prev_block_hash,
        );
        assert!(result.is_ok());

        // Test with insufficient votes
        let result = validate_ticket_votes(&votes[0..2], 200, &prev_block_hash);
        assert!(result.is_err());

        // Test with an invalid ticket (not selected)
        let invalid_ticket = create_test_ticket(20, 100, TicketStatus::Live);
        pool.add_ticket(invalid_ticket.clone());

        let mut invalid_votes = votes.clone();
        invalid_votes.push(create_test_vote(&invalid_ticket.id, &prev_block_hash, 0));

        let result = validate_ticket_votes(&invalid_votes, 200, &prev_block_hash);
        assert!(result.is_err());

        // Test with duplicate votes
        let mut duplicate_votes = votes.clone();
        duplicate_votes.push(votes[0].clone());

        let result = validate_ticket_votes(&duplicate_votes, 200, &prev_block_hash);
        assert!(result.is_err());
    }

    /// Test block finality determination
    #[test]
    fn test_block_finality_integration() {
        // Initialize a ticket pool
        let mut pool = LiveTicketsPool::new();

        // Add some live tickets
        for i in 1..=10 {
            let ticket = create_test_ticket(i as u8, 100, TicketStatus::Live);
            pool.add_ticket(ticket);
        }

        // Create a previous block hash
        let prev_block_hash = [42u8; 32];

        // Get live tickets
        let live_tickets = pool.get_live_tickets();

        // Select tickets for voting
        let selected_tickets = select_tickets_for_voting(&live_tickets, &prev_block_hash, 5);
        assert_eq!(selected_tickets.len(), 5);

        // Create votes for 3 out of 5 tickets (not enough for finality)
        let mut votes = Vec::new();
        for ticket_id in &selected_tickets[0..3] {
            votes.push(create_test_vote(ticket_id, &prev_block_hash, 0)); // Yes vote
        }

        // Check finality - should not be final yet (need 2/3 = 4 votes)
        let is_final = is_block_final(&prev_block_hash, &votes, &selected_tickets);
        assert!(!is_final);

        // Add one more vote to reach finality
        votes.push(create_test_vote(&selected_tickets[3], &prev_block_hash, 0));

        // Check finality again - should be final now
        let is_final = is_block_final(&prev_block_hash, &votes, &selected_tickets);
        assert!(is_final);
    }
}
