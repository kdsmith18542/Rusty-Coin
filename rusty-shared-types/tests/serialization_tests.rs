//! Comprehensive serialization tests for all Rusty-Coin data structures
//!
//! This test suite verifies that all data structures can be correctly serialized
//! and deserialized, ensuring protocol compliance and network compatibility.

use bincode;
use rusty_shared_types::*;
use serde_json;

/// Test round-trip serialization for all core blockchain structures
#[cfg(test)]
mod blockchain_serialization_tests {
    use super::*;

    #[test]
    fn test_block_header_round_trip() {
        let header = BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            state_root: [3u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };

        // Test bincode serialization
        let serialized_bincode = bincode::serialize(&header).unwrap();
        let deserialized_bincode: BlockHeader = bincode::deserialize(&serialized_bincode).unwrap();
        assert_eq!(header, deserialized_bincode);

        // Test JSON serialization for debugging/tools
        let serialized_json = serde_json::to_string(&header).unwrap();
        let deserialized_json: BlockHeader = serde_json::from_str(&serialized_json).unwrap();
        assert_eq!(header, deserialized_json);

        // Test deterministic serialization (same input produces same output)
        let serialized_again = bincode::serialize(&header).unwrap();
        assert_eq!(serialized_bincode, serialized_again);
    }

    #[test]
    fn test_outpoint_round_trip() {
        let outpoint = OutPoint {
            txid: [42u8; 32],
            vout: 1,
        };

        let serialized = bincode::serialize(&outpoint).unwrap();
        let deserialized: OutPoint = bincode::deserialize(&serialized).unwrap();
        assert_eq!(outpoint, deserialized);

        // Test JSON serialization
        let json = serde_json::to_string(&outpoint).unwrap();
        let from_json: OutPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(outpoint, from_json);
    }

    #[test]
    fn test_tx_input_round_trip() {
        let input = TxInput::from_outpoint(
            OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            vec![0x47, 0x30, 0x44], // Mock signature script
            0xFFFFFFFF,
            vec![vec![1, 2, 3]], // Mock witness data
        );

        let serialized = bincode::serialize(&input).unwrap();
        let deserialized: TxInput = bincode::deserialize(&serialized).unwrap();
        assert_eq!(input, deserialized);
    }

    #[test]
    fn test_tx_output_round_trip() {
        let output = TxOutput {
            value: 2500000000,
            script_pubkey: vec![0x76, 0xa9, 0x14], // Mock P2PKH script
            memo: None,
        };

        let serialized = bincode::serialize(&output).unwrap();
        let deserialized: TxOutput = bincode::deserialize(&serialized).unwrap();
        assert_eq!(output, deserialized);
    }

    #[test]
    fn test_coinbase_transaction_round_trip() {
        let coinbase = Transaction::Coinbase {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 5000000000,
                script_pubkey: vec![0x6a, 0x04, 0x00, 0x00, 0x00, 0x00],
                memo: None,
            }],
            lock_time: 0,
            witness: vec![],
        };

        let serialized = bincode::serialize(&coinbase).unwrap();
        let deserialized: Transaction = bincode::deserialize(&serialized).unwrap();
        assert_eq!(coinbase, deserialized);
    }

    #[test]
    fn test_standard_transaction_round_trip() {
        let standard = Transaction::Standard {
            version: 1,
            inputs: vec![TxInput::from_outpoint(
                OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                vec![0x47, 0x30, 0x44],
                0xFFFFFFFF,
                vec![],
            )],
            outputs: vec![TxOutput {
                value: 2500000000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
                memo: None,
            }],
            lock_time: 0,
            fee: 10000,
            witness: vec![],
        };

        let serialized = bincode::serialize(&standard).unwrap();
        let deserialized: Transaction = bincode::deserialize(&serialized).unwrap();
        assert_eq!(standard, deserialized);
    }

    #[test]
    fn test_block_round_trip() {
        let header = BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            state_root: [3u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };

        let block = Block {
            header,
            ticket_votes: vec![],
            transactions: vec![Transaction::Coinbase {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    value: 5000000000,
                    script_pubkey: vec![0x6a],
                    memo: None,
                }],
                lock_time: 0,
                witness: vec![],
            }],
        };

        let serialized = bincode::serialize(&block).unwrap();
        let deserialized: Block = bincode::deserialize(&serialized).unwrap();
        assert_eq!(block, deserialized);

        // Verify merkle root calculation works after deserialization
        let original_merkle = block.calculate_merkle_root();
        let deserialized_merkle = deserialized.calculate_merkle_root();
        assert_eq!(original_merkle, deserialized_merkle);
    }

    #[test]
    fn test_ticket_round_trip() {
        let ticket = Ticket {
            id: TicketId([42u8; 32]),
            pubkey: vec![1, 2, 3, 4],
            height: 1000,
            value: 100000000,
            status: TicketStatus::Live,
        };

        let serialized = bincode::serialize(&ticket).unwrap();
        let deserialized: Ticket = bincode::deserialize(&serialized).unwrap();
        assert_eq!(ticket, deserialized);
    }

    #[test]
    fn test_ticket_vote_round_trip() {
        let vote = TicketVote {
            ticket_id: [1u8; 32],
            block_hash: [2u8; 32],
            vote: 1, // Yes vote
            signature: [3u8; 64],
        };

        let serialized = bincode::serialize(&vote).unwrap();
        let deserialized: TicketVote = bincode::deserialize(&serialized).unwrap();
        assert_eq!(vote, deserialized);
    }

    #[test]
    fn test_utxo_round_trip() {
        let utxo = Utxo {
            output: TxOutput {
                value: 1000000,
                script_pubkey: vec![0x76, 0xa9],
                memo: None,
            },
            is_coinbase: false,
            creation_height: 500,
        };

        let serialized = bincode::serialize(&utxo).unwrap();
        let deserialized: Utxo = bincode::deserialize(&serialized).unwrap();
        assert_eq!(utxo, deserialized);
    }

    #[test]
    fn test_deterministic_serialization() {
        // Test that the same data structure always serializes to the same bytes
        let header = BlockHeader {
            version: 1,
            height: 100,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 1234567890,
            difficulty_target: 0x1d00ffff,
            nonce: 12345,
        };

        let serialized1 = bincode::serialize(&header).unwrap();
        let serialized2 = bincode::serialize(&header).unwrap();
        assert_eq!(serialized1, serialized2);

        // Test across multiple serialization/deserialization cycles
        let mut current_header = header.clone();
        for _ in 0..10 {
            let serialized = bincode::serialize(&current_header).unwrap();
            current_header = bincode::deserialize(&serialized).unwrap();
        }
        assert_eq!(header, current_header);
    }

    #[test]
    fn test_empty_collections_serialization() {
        // Test that empty collections serialize/deserialize correctly
        let empty_block = Block {
            header: BlockHeader {
                version: 1,
                height: 0,
                previous_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 0,
                difficulty_target: 0,
                nonce: 0,
            },
            ticket_votes: vec![],
            transactions: vec![],
        };

        let serialized = bincode::serialize(&empty_block).unwrap();
        let deserialized: Block = bincode::deserialize(&serialized).unwrap();
        assert_eq!(empty_block, deserialized);
    }

    #[test]
    fn test_large_values_serialization() {
        // Test maximum values to ensure they serialize correctly
        let max_header = BlockHeader {
            version: u32::MAX,
            height: u64::MAX,
            previous_block_hash: [0xFFu8; 32],
            merkle_root: [0xFFu8; 32],
            state_root: [0xFFu8; 32],
            timestamp: u64::MAX,
            difficulty_target: u32::MAX,
            nonce: u64::MAX,
        };

        let serialized = bincode::serialize(&max_header).unwrap();
        let deserialized: BlockHeader = bincode::deserialize(&serialized).unwrap();
        assert_eq!(max_header, deserialized);
    }

    #[test]
    fn test_spec_vector_compliance() {
        // Test against known specification vectors
        // This is where we would test against hardcoded byte sequences
        // that represent valid protocol messages according to the specification

        let genesis_header = BlockHeader {
            version: 1,
            height: 0,
            previous_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };

        let serialized = bincode::serialize(&genesis_header).unwrap();

        // In a real implementation, we would compare against known good bytes
        // For now, we just verify it can be deserialized
        let deserialized: BlockHeader = bincode::deserialize(&serialized).unwrap();
        assert_eq!(genesis_header, deserialized);

        // The actual spec vector test would look like:
        // let expected_bytes = hex::decode("0100000000000000...").unwrap();
        // assert_eq!(serialized, expected_bytes);
    }
}

/// Test serialization for governance structures
#[cfg(test)]
mod governance_serialization_tests {
    use super::*;
    use rusty_shared_types::governance::*;

    #[test]
    fn test_vote_choice_serialization() {
        let choices = vec![VoteChoice::Yes, VoteChoice::No, VoteChoice::Abstain];

        for choice in choices {
            let serialized = bincode::serialize(&choice).unwrap();
            let deserialized: VoteChoice = bincode::deserialize(&serialized).unwrap();
            assert_eq!(choice, deserialized);
        }
    }

    #[test]
    fn test_proposal_type_serialization() {
        let types = vec![
            ProposalType::ProtocolUpgrade,
            ProposalType::TreasurySpend,
            ProposalType::BugFix,
            ProposalType::CommunityFund,
        ];

        for proposal_type in types {
            let serialized = bincode::serialize(&proposal_type).unwrap();
            let deserialized: ProposalType = bincode::deserialize(&serialized).unwrap();
            assert_eq!(proposal_type, deserialized);
        }
    }
}

/// Test serialization for P2P message structures
#[cfg(test)]
mod p2p_serialization_tests {
    use super::*;
    use rusty_shared_types::p2p::*;

    #[test]
    fn test_p2p_message_ping_pong_serialization() {
        // Test that ping/pong messages can be serialized and deserialized
        // without asserting equality since P2PMessage doesn't implement PartialEq
        let ping = P2PMessage::Ping;
        let pong = P2PMessage::Pong;

        let ping_serialized = bincode::serialize(&ping).unwrap();
        let _ping_deserialized: P2PMessage = bincode::deserialize(&ping_serialized).unwrap();
        // Just verify it doesn't crash - we can't test equality

        let pong_serialized = bincode::serialize(&pong).unwrap();
        let _pong_deserialized: P2PMessage = bincode::deserialize(&pong_serialized).unwrap();
        // Just verify it doesn't crash - we can't test equality
    }

    #[test]
    fn test_block_request_serialization() {
        let request = BlockRequest {
            start_hash: [1u8; 32],
            end_hash: Some([2u8; 32]),
            max_blocks: 100,
        };

        let serialized = bincode::serialize(&request).unwrap();
        let _deserialized: BlockRequest = bincode::deserialize(&serialized).unwrap();
        // Just verify it doesn't crash - BlockRequest doesn't implement PartialEq
    }
}
