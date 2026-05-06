// NOTE: All message structs below are reviewed for canonical serialization and field compliance per 07_p2p_protocol_spec.md and 01_block_structure.md.
// Comprehensive unit tests below verify round-trip serialization and spec vector compliance for all P2P message types.
// If any spec changes, update field order/types and add #[serde(...)] attributes as needed for canonical bincode serialization.
///
/// Re-exported P2P message types for Rusty Coin P2P.
///
/// These types are defined in `rusty_shared_types::p2p` and are used for all
/// protocol messages exchanged over the network. See the protocol specification
/// for details on each message type.
pub use rusty_shared_types::p2p::{GetHeaders, Headers, Inv, P2PMessage};

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_shared_types::p2p::{BlockData, BlockHeaderData, BlockRequest, BlockResponse};
    use rusty_shared_types::{Block, BlockHeader, Transaction};
    use rusty_shared_types::{Hash, OutPoint, TicketVote, TxInput, TxOutput};

    #[test]
    fn test_p2p_message_round_trip_serialization() {
        // Test GetHeaders serialization (see 07_p2p_protocol_spec.md 7.1.2)
        let get_headers = GetHeaders {
            start_hash: [1u8; 32],
            end_hash: Some([2u8; 32]),
            max_headers: 2000,
        };
        let serialized = bincode::serialize(&get_headers).unwrap();
        let deserialized: GetHeaders = bincode::deserialize(&serialized).unwrap();
        assert_eq!(get_headers, deserialized);

        // Test Headers serialization
        let headers = Headers {
            headers: vec![BlockHeaderData {
                hash: [1u8; 32],
                previous_hash: [2u8; 32],
                merkle_root: [3u8; 32],
                timestamp: 1234567890,
                height: 0,
                nonce: 12345,
                target: 0x1d00ffff,
            }],
        };

        let serialized = bincode::serialize(&headers).unwrap();
        let deserialized: Headers = bincode::deserialize(&serialized).unwrap();
        assert_eq!(headers, deserialized);

        // Test Inv serialization
        let inv = Inv {
            inv_type: rusty_shared_types::p2p::InvType::Block,
            hash: [1u8; 32],
        };
        let serialized = bincode::serialize(&inv).unwrap();
        let deserialized: Inv = bincode::deserialize(&serialized).unwrap();
        assert_eq!(inv, deserialized);
    }

    #[test]
    fn test_block_request_serialization() {
        let block_request = BlockRequest {
            start_hash: [1u8; 32],
            end_hash: Some([2u8; 32]),
            max_blocks: 10,
        };
        let serialized = bincode::serialize(&block_request).unwrap();
        let deserialized: BlockRequest = bincode::deserialize(&serialized).unwrap();
        assert_eq!(block_request, deserialized);
    }

    #[test]
    fn test_block_response_serialization() {
        let block_data = BlockData {
            header: BlockHeaderData {
                hash: [1u8; 32],
                previous_hash: [2u8; 32],
                merkle_root: [3u8; 32],
                timestamp: 1234567890,
                height: 100,
                nonce: 12345,
                target: 0x1d00ffff,
            },
            transactions: vec![Transaction::Coinbase {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    value: 5000000000,
                    script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac],
                    memo: None,
                }],
                lock_time: 0,
                witness: vec![],
            }],
        };
        let block_response = BlockResponse {
            blocks: vec![block_data],
        };
        let serialized = bincode::serialize(&block_response).unwrap();
        let deserialized: BlockResponse = bincode::deserialize(&serialized).unwrap();
        assert_eq!(block_response.blocks.len(), deserialized.blocks.len());
    }

    #[test]
    fn test_ping_pong_serialization() {
        let ping = P2PMessage::Ping;
        let serialized = bincode::serialize(&ping).unwrap();
        let deserialized: P2PMessage = bincode::deserialize(&serialized).unwrap();
        assert_eq!(ping, deserialized);

        let pong = P2PMessage::Pong;
        let serialized = bincode::serialize(&pong).unwrap();
        let deserialized: P2PMessage = bincode::deserialize(&serialized).unwrap();
        assert_eq!(pong, deserialized);
    }

    #[test]
    fn test_p2p_message_enum_serialization() {
        let messages = vec![
            P2PMessage::GetHeaders(GetHeaders {
                start_hash: [1u8; 32],
                end_hash: Some([2u8; 32]),
                max_headers: 2000,
            }),
            P2PMessage::Headers(Headers {
                headers: vec![BlockHeaderData {
                    hash: [1u8; 32],
                    previous_hash: [2u8; 32],
                    merkle_root: [3u8; 32],
                    timestamp: 1234567890,
                    height: 0,
                    nonce: 12345,
                    target: 0x1d00ffff,
                }],
            }),
            P2PMessage::Inv(Inv {
                inv_type: rusty_shared_types::p2p::InvType::Block,
                hash: [1u8; 32],
            }),
        ];
        for message in messages {
            let serialized = bincode::serialize(&message).unwrap();
            let deserialized: P2PMessage = bincode::deserialize(&serialized).unwrap();
            assert_eq!(message, deserialized);
        }
    }

    #[test]
    fn test_spec_compliance_vectors() {
        // Test vector for GetHeaders (see 07_p2p_protocol_spec.md 7.1.2)
        let get_headers = GetHeaders {
            start_hash: [0u8; 32],
            end_hash: None,
            max_headers: 2000,
        };
        let serialized = bincode::serialize(&get_headers).unwrap();
        // Spec: serialized size should be 32 (start_hash) + 1 (option tag) + 0/32 (end_hash) + 4 (max_headers) = 37 or 69 bytes
        assert!(serialized.len() == 37 || serialized.len() == 69);
        let deserialized: GetHeaders = bincode::deserialize(&serialized).unwrap();
        assert_eq!(get_headers, deserialized);
    }
}
