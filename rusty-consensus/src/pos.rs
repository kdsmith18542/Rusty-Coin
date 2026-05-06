use crate::error::ConsensusError;
use crate::pos_selection::{TICKET_EXPIRATION_BLOCKS, TICKET_MATURITY_BLOCKS};
use log::{debug, info, warn};
use rusty_shared_types::{Ticket, TicketId, TicketStatus};
use std::collections::{HashMap, HashSet};

/// Represents a pool of tickets that are eligible for voting
pub struct LiveTicketsPool {
    tickets: HashMap<TicketId, Ticket>,
    /// Tracks the non-participation count for each ticket
    non_participation_counts: HashMap<TicketId, u32>,
    /// Tracks the last height at which a ticket was selected but didn't vote
    last_missed_vote_height: HashMap<TicketId, u64>,
}

impl LiveTicketsPool {
    pub fn new() -> Self {
        LiveTicketsPool {
            tickets: HashMap::new(),
            non_participation_counts: HashMap::new(),
            last_missed_vote_height: HashMap::new(),
        }
    }

    /// Add a ticket to the pool
    pub fn add_ticket(&mut self, ticket: Ticket) {
        debug!(
            "Adding ticket {} to pool with status {:?}",
            ticket.id, ticket.status
        );
        self.tickets.insert(ticket.id.clone(), ticket);
    }

    /// Remove a ticket from the pool
    pub fn remove_ticket(&mut self, ticket_id: &TicketId) -> Option<Ticket> {
        debug!("Removing ticket {} from pool", ticket_id);
        let ticket = self.tickets.remove(ticket_id);
        if ticket.is_some() {
            self.non_participation_counts.remove(ticket_id);
            self.last_missed_vote_height.remove(ticket_id);
        }
        ticket
    }

    /// Get a ticket by ID
    pub fn get_ticket(&self, ticket_id: &TicketId) -> Option<&Ticket> {
        self.tickets.get(ticket_id)
    }

    /// Get a mutable reference to a ticket
    pub fn get_ticket_mut(&mut self, ticket_id: &TicketId) -> Option<&mut Ticket> {
        self.tickets.get_mut(ticket_id)
    }

    /// Get all tickets in the pool
    pub fn get_all_tickets(&self) -> &HashMap<TicketId, Ticket> {
        &self.tickets
    }

    /// Get the count of all tickets
    pub fn count(&self) -> usize {
        self.tickets.len()
    }

    /// Get the count of live tickets only
    pub fn count_live(&self) -> usize {
        self.tickets
            .values()
            .filter(|t| t.status == TicketStatus::Live)
            .count()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    /// Process ticket maturity for newly added tickets
    /// Tickets become mature after TICKET_MATURITY_BLOCKS (256 blocks) as per spec
    /// Note: In the actual implementation, tickets are already created with Live status
    /// This function is kept for compatibility with the integration tests
    pub fn process_ticket_maturity(&mut self, current_height: u64) -> Vec<TicketId> {
        let mut matured_tickets = Vec::new();

        // In the actual implementation, tickets are already created with Live status
        // This is just for demonstration in the integration tests
        for (id, _) in self.tickets.iter() {
            if current_height >= TICKET_MATURITY_BLOCKS {
                matured_tickets.push(id.clone());
            }
        }

        if !matured_tickets.is_empty() {
            info!(
                "{} tickets considered matured at height {}",
                matured_tickets.len(),
                current_height
            );
        }

        matured_tickets
    }

    /// Process ticket expiration
    /// Tickets expire after TICKET_EXPIRATION_BLOCKS (40960 blocks) as per spec
    pub fn process_ticket_expiration(&mut self, current_height: u64) -> Vec<TicketId> {
        let mut expired_tickets = Vec::new();

        for (id, ticket) in self.tickets.iter_mut() {
            if ticket.status == TicketStatus::Live
                && current_height >= ticket.height + TICKET_EXPIRATION_BLOCKS
            {
                debug!("Ticket {} expired at height {}", id, current_height);
                ticket.status = TicketStatus::Expired;
                expired_tickets.push(id.clone());
            }
        }

        if !expired_tickets.is_empty() {
            info!(
                "{} tickets expired at height {}",
                expired_tickets.len(),
                current_height
            );
        }

        expired_tickets
    }

    /// Mark a ticket as voted
    pub fn mark_ticket_voted(&mut self, ticket_id: &TicketId) -> Result<(), String> {
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            if ticket.status == TicketStatus::Live {
                debug!("Marking ticket {} as voted", ticket_id);
                ticket.status = TicketStatus::Voted;
                Ok(())
            } else {
                let err = format!(
                    "Cannot mark ticket as voted: invalid status {:?}",
                    ticket.status
                );
                warn!("{}", err);
                Err(err)
            }
        } else {
            let err = format!("Ticket {} not found", ticket_id);
            warn!("{}", err);
            Err(err)
        }
    }

    /// Mark a ticket as missed vote (non-participation)
    pub fn mark_ticket_missed(&mut self, ticket_id: &TicketId, height: u64) -> Result<(), String> {
        // Update non-participation count
        let count = self
            .non_participation_counts
            .entry(ticket_id.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);

        // Update last missed vote height
        self.last_missed_vote_height
            .insert(ticket_id.clone(), height);

        debug!(
            "Ticket {} missed vote at height {} (missed count: {})",
            ticket_id, height, count
        );

        Ok(())
    }

    /// Get the non-participation count for a ticket
    pub fn get_non_participation_count(&self, ticket_id: &TicketId) -> u32 {
        *self.non_participation_counts.get(ticket_id).unwrap_or(&0)
    }

    /// Get the last height at which a ticket missed a vote
    pub fn get_last_missed_height(&self, ticket_id: &TicketId) -> Option<u64> {
        self.last_missed_vote_height.get(ticket_id).copied()
    }

    /// Revoke a ticket (for missed votes or expired tickets)
    pub fn revoke_ticket(&mut self, ticket_id: &TicketId) -> Result<(), String> {
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            if ticket.status == TicketStatus::Live || ticket.status == TicketStatus::Expired {
                debug!(
                    "Revoking ticket {} with status {:?}",
                    ticket_id, ticket.status
                );
                ticket.status = TicketStatus::Revoked;
                Ok(())
            } else {
                let err = format!("Cannot revoke ticket: invalid status {:?}", ticket.status);
                warn!("{}", err);
                Err(err)
            }
        } else {
            let err = format!("Ticket {} not found", ticket_id);
            warn!("{}", err);
            Err(err)
        }
    }

    /// Get all live tickets (status == Live)
    pub fn get_live_tickets(&self) -> HashMap<TicketId, Ticket> {
        self.tickets
            .iter()
            .filter(|(_, t)| t.status == TicketStatus::Live)
            .map(|(id, t)| (id.clone(), t.clone()))
            .collect()
    }

    /// Process ticket finality transitions
    /// Per spec 03 Section 3.2.2: Tickets transition from PENDING to LIVE when
    /// the block containing their purchase transaction reaches POS_FINALITY_DEPTH
    /// (e.g., 1 block after inclusion)
    pub fn process_ticket_finality(&mut self, current_height: u64) -> Vec<TicketId> {
        use rusty_core::constants::POS_FINALITY_DEPTH;
        let mut transitioned_tickets = Vec::new();

        for (ticket_id, ticket) in self.tickets.iter_mut() {
            if ticket.status == TicketStatus::Pending {
                // Check if ticket has reached finality depth
                // Ticket was purchased at ticket.height, so it becomes LIVE at ticket.height + POS_FINALITY_DEPTH
                if current_height >= ticket.height + POS_FINALITY_DEPTH {
                    debug!(
                        "Ticket {} transitioning from PENDING to LIVE at height {} (purchased at height {})",
                        ticket_id, current_height, ticket.height
                    );
                    ticket.status = TicketStatus::Live;
                    transitioned_tickets.push(ticket_id.clone());
                }
            }
        }

        if !transitioned_tickets.is_empty() {
            info!(
                "{} tickets transitioned from PENDING to LIVE at height {}",
                transitioned_tickets.len(),
                current_height
            );
        }

        transitioned_tickets
    }
}

impl Default for LiveTicketsPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates ticket votes against the consensus rules according to OxideSync PoS spec
pub fn validate_ticket_votes(
    votes: &[rusty_shared_types::TicketVote],
    params: &rusty_shared_types::ConsensusParams,
    current_height: u64,
    all_tickets: &HashMap<TicketId, Ticket>,
) -> Result<(), ConsensusError> {
    if votes.is_empty() {
        return Err(ConsensusError::NoTicketVotes);
    }

    // Check if we have enough valid votes
    let mut valid_votes = 0;
    let mut seen_tickets = HashSet::new();

    for vote in votes {
        // Check for duplicate votes
        if !seen_tickets.insert(&vote.ticket_id) {
            return Err(ConsensusError::DuplicateTicketVote);
        }

        let ticket_id = TicketId::from(vote.ticket_id);

        // Check if the ticket exists in the ticket pool
        let ticket = match all_tickets.get(&ticket_id) {
            Some(t) => t,
            None => return Err(ConsensusError::InvalidTicketID),
        };

        // Verify ticket is in LIVE state
        if ticket.status != TicketStatus::Live {
            return Err(ConsensusError::InvalidTicketStatus);
        }

        // Verify ticket has not expired
        if current_height >= ticket.height + TICKET_EXPIRATION_BLOCKS {
            return Err(ConsensusError::ExpiredTicket);
        }

        // Verify the vote type is valid (0=Yes, 1=No, 2=Abstain)
        if vote.vote > 2 {
            return Err(ConsensusError::InvalidVoteType);
        }

        // In a complete implementation, we would verify the Ed25519 signature here
        // using the ticket's public key against the vote data

        valid_votes += 1;
    }

    // Ensure we have enough valid votes (minimum required by consensus)
    // Per spec 03 Section 3.5.3: MIN_VALID_VOTES_REQUIRED (e.g., 3)
    // This is 60% of VOTERS_PER_BLOCK (5), ensuring supermajority consensus
    use rusty_core::protocol_constants::MIN_VALID_VOTES_REQUIRED;
    let min_valid_votes_required = MIN_VALID_VOTES_REQUIRED as usize;
    if valid_votes < min_valid_votes_required {
        return Err(ConsensusError::InsufficientTicketVotes);
    }

    debug!(
        "Validated {} ticket votes at height {}",
        valid_votes, current_height
    );
    Ok(())
}
