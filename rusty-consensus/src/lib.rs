pub mod adaptive_block_size;
pub mod error;
pub mod pos;
#[cfg(test)]
pub mod pos_integration_test;
pub mod pos_selection;
pub mod pos_slashing;
#[cfg(test)]
pub mod pos_slashing_tests;
pub mod pow;
#[cfg(test)]
pub mod pow_difficulty_tests;
pub mod state;
pub mod utxo_set;
pub mod validation;
pub mod validation_simple; // Simplified PoS ticket validation

pub use adaptive_block_size::{
    AdaptiveBlockSizeCalculator, AdaptiveBlockSizeParams, AdaptiveBlockSizeStats,
};
pub use pow::OxideHasher;
pub use rusty_shared_types::TicketVote;
// Export the OxideSync PoS components
pub use pos::LiveTicketsPool;
pub use pos_selection::{adjust_ticket_price, is_block_final, select_tickets_for_voting};
pub use pos_selection::{
    DEFAULT_TARGET_POOL_SIZE, TICKET_EXPIRATION_BLOCKS, TICKET_MATURITY_BLOCKS,
};
// Use the enhanced validation function from validation.rs instead of the simplified one
pub use validation::validate_ticket_votes;
