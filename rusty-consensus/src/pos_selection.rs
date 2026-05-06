use log::{debug, info, warn};
use rusty_shared_types::{Ticket, TicketId, TicketStatus};
use std::collections::HashMap;

/// Constants for the OxideSync PoS system
pub const TICKET_MATURITY_BLOCKS: u64 = 256;
pub const TICKET_EXPIRATION_BLOCKS: u64 = 40960;
pub const DEFAULT_TARGET_POOL_SIZE: usize = 40960;
pub const DEFAULT_MIN_TICKETS_REQUIRED: usize = 3;
pub const DEFAULT_MAX_PRICE_ADJUSTMENT_PERCENT: u8 = 5;

/// Deterministic Pseudo-Random Function (DPRF) for ticket selection
/// Per spec 03 Section 3.4: DPRF(seed, ticket_id) generates a pseudo-random 256-bit number
/// Seed: BLAKE3(BlockH-1.hash)
/// Returns a 256-bit (32-byte) lottery score
fn dprf(seed: &[u8; 32], ticket_id: &TicketId) -> [u8; 32] {
    // Per spec: DPRF uses BLAKE3 hash of seed || ticket_id
    // This provides deterministic, unpredictable selection
    use blake3;
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&ticket_id.0);
    let hash = hasher.finalize();
    hash.into()
}

/// Selects tickets for voting based on DPRF lottery as specified in OxideSync PoS spec
/// Per spec 03 Section 3.4: TICKET_VOTER_SELECTION
///
/// Algorithm:
/// 1. Seed = BLAKE3(BlockH-1.hash)
/// 2. For each ticket T_i: lottery_score = DPRF(seed, T_i.ticket_id)
/// 3. Select VOTERS_PER_BLOCK tickets with numerically lowest lottery_score
/// 4. Use TicketID as tie-breaker if scores are equal
pub fn select_tickets_for_voting(
    live_tickets: &HashMap<TicketId, Ticket>,
    previous_block_hash: &[u8; 32],
    num_tickets_required: usize,
) -> Vec<TicketId> {
    if live_tickets.is_empty() {
        debug!("No live tickets available for selection");
        return Vec::new();
    }

    // Filter only live tickets
    let live_tickets: HashMap<_, _> = live_tickets
        .iter()
        .filter(|(_, ticket)| ticket.status == TicketStatus::Live)
        .map(|(id, ticket)| (id.clone(), ticket.clone()))
        .collect();

    if live_tickets.is_empty() {
        debug!("No tickets with Live status available for selection");
        return Vec::new();
    }

    // Per spec 03 Section 3.4: Seed = BLAKE3(BlockH-1.hash)
    use blake3;
    let seed = blake3::hash(previous_block_hash).into();

    debug!("Using DPRF seed derived from BLAKE3(BlockH-1.hash) for ticket selection");

    // Calculate lottery score for each ticket using DPRF
    // Per spec: lottery_score = DPRF(seed, ticket_id) for each ticket
    let mut ticket_scores: Vec<(TicketId, [u8; 32])> = live_tickets
        .keys()
        .map(|ticket_id| {
            let lottery_score = dprf(&seed, ticket_id);
            (ticket_id.clone(), lottery_score)
        })
        .collect();

    // Sort by lottery score (numerically lowest first)
    // Per spec: Select tickets with numerically lowest lottery_score
    // If scores are equal, use TicketID as tie-breaker
    ticket_scores.sort_by(|a, b| {
        // Compare lottery scores (256-bit numbers)
        let score_cmp = a.1.cmp(&b.1);
        if score_cmp == std::cmp::Ordering::Equal {
            // Tie-breaker: use TicketID (as byte array)
            a.0 .0.cmp(&b.0 .0)
        } else {
            score_cmp
        }
    });

    // Select the first num_tickets_required tickets (lowest scores)
    let selected_tickets: Vec<TicketId> = ticket_scores
        .into_iter()
        .take(num_tickets_required)
        .map(|(ticket_id, _)| ticket_id)
        .collect();

    info!(
        "Selected {} tickets for voting from a pool of {} live tickets using DPRF lottery",
        selected_tickets.len(),
        live_tickets.len()
    );

    selected_tickets
}

/// Adjusts ticket price based on the current live tickets pool size
/// as specified in OxideSync PoS spec
pub fn adjust_ticket_price(
    current_price: u64,
    current_pool_size: usize,
    target_pool_size: usize,
    max_adjustment_percent: u8,
) -> u64 {
    if current_pool_size == 0 || target_pool_size == 0 {
        warn!("Cannot adjust ticket price: invalid pool sizes");
        return current_price;
    }

    // Calculate ratio of current to target pool size
    let ratio = current_pool_size as f64 / target_pool_size as f64;

    // Calculate adjustment factor (limited by max_adjustment_percent)
    let adjustment_factor = if ratio > 1.0 {
        // Too many tickets, increase price
        (1.0 + (max_adjustment_percent as f64 / 100.0)).min(ratio)
    } else {
        // Too few tickets, decrease price
        (1.0 - (max_adjustment_percent as f64 / 100.0)).max(ratio)
    };

    // Apply adjustment to current price
    let new_price = (current_price as f64 * adjustment_factor) as u64;

    // Ensure price doesn't go below minimum (1 RCN)
    let min_price = 100_000_000; // 1 RCN in satoshis
    let final_price = new_price.max(min_price);

    info!(
        "Adjusted ticket price from {} to {} (pool size: {}, target: {})",
        current_price, final_price, current_pool_size, target_pool_size
    );

    final_price
}

/// Determines if a block is final based on ticket votes
/// A block is considered final when it has received votes from at least
/// 2/3 of the selected tickets as specified in the OxideSync PoS spec
pub fn is_block_final(
    block_hash: &[u8; 32],
    votes: &[rusty_shared_types::TicketVote],
    selected_tickets: &[TicketId],
) -> bool {
    if selected_tickets.is_empty() {
        debug!("Cannot determine finality: no selected tickets");
        return false;
    }

    // Count valid votes for this block
    let valid_votes = votes.iter().filter(|v| v.block_hash == *block_hash).count();

    // Calculate 2/3 threshold
    let threshold = (selected_tickets.len() * 2) / 3;

    // Block is final if it has at least 2/3 of the votes
    let is_final = valid_votes >= threshold;

    debug!(
        "Block finality check: {} votes out of {} selected tickets (threshold: {}), final: {}",
        valid_votes,
        selected_tickets.len(),
        threshold,
        is_final
    );

    is_final
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::TicketVote;

    #[test]
    fn test_ticket_selection() {
        // Create a set of test tickets
        let mut live_tickets = HashMap::new();
        for i in 0..100 {
            let id = TicketId::from([i as u8; 32]);
            let ticket = Ticket {
                id: id.clone(),
                pubkey: vec![i as u8; 32],
                height: 1000,
                value: 100_000_000,
                status: TicketStatus::Live,
            };
            live_tickets.insert(id, ticket);
        }

        // Test selection with a specific block hash
        let block_hash = [42u8; 32];
        let selected = select_tickets_for_voting(&live_tickets, &block_hash, 5);

        // Verify we got the expected number of tickets
        assert_eq!(selected.len(), 5);

        // Verify determinism - same hash should produce same selection
        let selected2 = select_tickets_for_voting(&live_tickets, &block_hash, 5);
        assert_eq!(selected, selected2);

        // Different hash should produce different selection
        let block_hash2 = [43u8; 32];
        let selected3 = select_tickets_for_voting(&live_tickets, &block_hash2, 5);
        assert_ne!(selected, selected3);
    }

    #[test]
    fn test_ticket_price_adjustment() {
        // Test price increases when pool is too large
        let price = adjust_ticket_price(100_000_000, 50000, 40000, 5);
        assert!(price > 100_000_000);

        // Test price decreases when pool is too small
        let price = adjust_ticket_price(100_000_000, 30000, 40000, 5);
        assert!(price < 100_000_000);

        // Test price stays the same when pool is at target
        let price = adjust_ticket_price(100_000_000, 40000, 40000, 5);
        assert_eq!(price, 100_000_000);

        // Test minimum price enforcement
        let price = adjust_ticket_price(100_000_000, 10000, 40000, 20);
        assert!(price >= 100_000_000);
    }

    #[test]
    fn test_block_finality() {
        // Create a set of selected tickets
        let mut selected_tickets = Vec::new();
        for i in 0..9 {
            selected_tickets.push(TicketId::from([i as u8; 32]));
        }

        let block_hash = [42u8; 32];

        // Create votes - not enough for finality (need 6 out of 9)
        let mut votes = Vec::new();
        for i in 0..5 {
            votes.push(TicketVote {
                ticket_id: [i as u8; 32],
                block_hash,
                vote: 0, // Yes vote
                signature: [0u8; 64],
            });
        }

        // Should not be final with 5/9 votes (need 2/3)
        assert!(!is_block_final(&block_hash, &votes, &selected_tickets));

        // Add one more vote to reach 6/9 (2/3)
        votes.push(TicketVote {
            ticket_id: [5u8; 32],
            block_hash,
            vote: 0,
            signature: [0u8; 64],
        });

        // Should now be final with 6/9 votes
        assert!(is_block_final(&block_hash, &votes, &selected_tickets));
    }
}
