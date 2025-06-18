//! Rusty Coin Core
//! 
//! Core data structures and cryptography for the Rusty Coin cryptocurrency.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Cryptographic primitives and utilities.
pub mod crypto;

/// Core data structures.
pub mod types;

/// Consensus-related functionality.
pub mod consensus;

/// Common error types.
pub mod error;

/// Re-export commonly used types.
pub mod prelude {
    pub use crate::crypto::Hash;
    pub use crate::types::{Block, BlockHeader};
    pub use crate::types::Transaction;
    pub use crate::types::UTXO;
    pub use crate::types::Masternode;
    pub use crate::consensus::pos::VotingTicket;
    pub use crate::types::PoSVote;
    pub use crate::types::BlockchainState;
    
    /// Re-export the error type
    pub type Error = crate::error::Error;
}

#[cfg(feature = "std")]
pub use crate::crypto::Hash;
pub use crate::error::Error;

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    #[test]
    fn test_lib_imports() {
        // Test that the prelude exports are working
        use crate::prelude::*;
        let _ = Hash::zero();
        let _: Result<(), Error> = Err(Error::Other("test".to_string()));
    }
}
