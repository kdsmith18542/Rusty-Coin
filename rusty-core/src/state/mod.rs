//! State management for Rusty Coin blockchain
//!
//! This module provides state management functionality including
//! Merkle Patricia Trie for state commitment and UTXO set management.

pub mod merkle_patricia_trie;
pub mod proof_manager;
pub mod snapshot_manager;
pub mod fast_sync;
pub mod state_manager;

pub use merkle_patricia_trie::{MerklePatriciaTrie, MerkleProof, BatchMerkleProof, RangeProof, TrieNode, TicketData};
pub use proof_manager::{StateProofManager, ProofRequest, ProofResponse, ProofData, ProofType, ProofConfig, ProofStats, LightClientProofInterface};
pub use snapshot_manager::{SnapshotManager, SnapshotConfig, SnapshotMetadata, StateSnapshot, IncrementalSnapshot, SnapshotStats};
pub use fast_sync::{FastSyncManager, FastSyncCoordinator, FastSyncConfig, FastSyncStatus, FastSyncStats, PeerSnapshot};
pub use state_manager::{StateManager, StateManagerConfig, StateManagerStats};
