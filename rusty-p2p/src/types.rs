// NOTE: All message structs below are reviewed for canonical serialization and field compliance per 07_p2p_protocol_spec.md and 01_block_structure.md.
// If any spec changes, update field order/types and add #[serde(...)] attributes as needed for canonical bincode serialization.
// TODO: Add/expand unit tests to verify round-trip serialization matches spec vectors.

///
/// Re-exported P2P message types for Rusty Coin P2P.
///
/// These types are defined in `rusty_shared_types::p2p` and are used for all
/// protocol messages exchanged over the network. See the protocol specification
/// for details on each message type.
pub use rusty_shared_types::p2p::{P2PMessage, GetHeaders, Headers, Inv};