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
    pub use crate::crypto::*;
    pub use crate::types::*;
    pub use crate::consensus::*;
    pub use crate::error::*;
}

/// Re-export the prelude for convenient access to common types.
pub use prelude::*;

#[cfg(feature = "std")]
pub use crate::crypto::Hash;

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    #[test]
    fn test_lib_imports() {
        // Test that the prelude exports are working
        let _ = Hash::zero();
        let _ = Error::Other("test".to_string());
    }
}
