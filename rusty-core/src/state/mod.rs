//! State management for Rusty Coin blockchain
//!
//! This module provides state management functionality including
//! Merkle Patricia Trie for state commitment and UTXO set management.

pub mod fast_sync;
pub mod merkle_patricia_trie;
pub mod proof_manager;
pub mod snapshot_manager;
pub mod state_manager;

pub use fast_sync::{
    FastSyncConfig, FastSyncCoordinator, FastSyncManager, FastSyncStats, FastSyncStatus,
    PeerSnapshot,
};
pub use merkle_patricia_trie::{
    BatchMerkleProof, MerklePatriciaTrie, MerkleProof, RangeProof, TicketData, TrieNode,
};
pub use proof_manager::{
    LightClientProofInterface, ProofConfig, ProofData, ProofRequest, ProofResponse, ProofStats,
    ProofType, StateProofManager,
};
pub use snapshot_manager::{
    IncrementalSnapshot, SnapshotConfig, SnapshotManager, SnapshotMetadata, SnapshotStats,
    StateSnapshot,
};
pub use state_manager::{StateManager, StateManagerConfig, StateManagerStats};
