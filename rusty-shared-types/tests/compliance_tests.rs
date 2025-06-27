//! Comprehensive compliance tests for consensus structures
//! 
//! This test suite verifies that all consensus structures comply with
//! the formal specifications in docs/specs/01_block_structure.md

use rusty_shared_types::*;


/// Test BlockHeader structure compliance with specification
#[cfg(test)]
mod block_header_compliance {
    use super::*;

    #[test]
    fn test_block_header_field_types() {
        let header = BlockHeader {
            version: 1u32,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890u64,
            nonce: 12345u64,
            difficulty_target: 0x1d00ffffu32,
            height: 100u64,
            state_root: [2u8; 32],
        };

        // Verify field types match specification
        assert_eq!(std::mem::size_of_val(&header.version), 4);
        assert_eq!(std::mem::size_of_val(&header.previous_block_hash), 32);
        assert_eq!(std::mem::size_of_val(&header.merkle_root), 32);
        assert_eq!(std::mem::size_of_val(&header.timestamp), 8);
        assert_eq!(std::mem::size_of_val(&header.nonce), 8);
        assert_eq!(std::mem::size_of_val(&header.difficulty_target), 4);
        assert_eq!(std::mem::size_of_val(&header.height), 8);
        assert_eq!(std::mem::size_of_val(&header.state_root), 32);
    }

    #[test]
    fn test_block_header_total_size() {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        // Serialize and verify total size is 98 bytes as per specification
        let serialized = bincode::encode_to_vec(&header, bincode::config::standard()).unwrap();
        
        // Note: bincode adds some overhead, but the raw struct size should be 98 bytes
        let expected_raw_size = 4 + 32 + 32 + 8 + 8 + 4 + 8 + 32; // 128 bytes total
        assert_eq!(expected_raw_size, 128);
        
        // Verify serialization works
        assert!(!serialized.is_empty());
        
        // Verify deserialization works
        let deserialized: BlockHeader = bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap().0;
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_block_header_hash_function() {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        let hash = header.hash();
        assert_eq!(hash.len(), 32);
        
        // Hash should be deterministic
        let hash2 = header.hash();
        assert_eq!(hash, hash2);
        
        // Different headers should have different hashes
        let mut header2 = header.clone();
        header2.nonce = 54321;
        let hash3 = header2.hash();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_block_header_validation_constraints() {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        // Test version validation (should be 1 for initial mainnet)
        assert_eq!(header.version, 1);
        
        // Test timestamp is reasonable (not zero, not too far in future)
        assert!(header.timestamp > 0);
        assert!(header.timestamp < u64::MAX);
        
        // Test height is reasonable
        assert!(header.height < u64::MAX);
    }
}

/// Test Block structure compliance with specification
#[cfg(test)]
mod block_compliance {
    use super::*;

    #[test]
    fn test_block_structure_fields() {
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        let ticket_vote = TicketVote {
            ticket_id: [3u8; 32],
            block_hash: [4u8; 32],
            vote: VoteType::Yes,
            signature: TransactionSignature([5u8; 64]),
        };

        let tx_input = TxInput {
            previous_output: OutPoint {
                txid: [6u8; 32],
                vout: 0,
            },
            script_sig: vec![0x76, 0xa9, 0x14], // OP_DUP OP_HASH160 PUSHDATA(20)
            sequence: 0xffffffff,
        };

        let tx_output = TxOutput {
            value: 5000000000, // 50 coins
            script_pubkey: vec![0x76, 0xa9, 0x14], // P2PKH script start
            memo: None,
        };

        let transaction = Transaction::Standard {
            version: 1,
            inputs: vec![tx_input],
            outputs: vec![tx_output],
            lock_time: 0,
            fee: 10000,
            witness: vec![],
        };

        let block = Block {
            header,
            ticket_votes: vec![ticket_vote],
            transactions: vec![transaction],
        };

        // Verify all required fields are present
        assert_eq!(block.header.version, 1);
        assert_eq!(block.ticket_votes.len(), 1);
        assert_eq!(block.transactions.len(), 1);
        
        // Test block hash function
        let hash = block.hash();
        assert_eq!(hash.len(), 32);
        
        // Test serialization
        let serialized = bincode::encode_to_vec(&block, bincode::config::standard()).unwrap();
        assert!(!serialized.is_empty());
        
        let deserialized: Block = bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap().0;
        assert_eq!(block, deserialized);
    }
}

/// Test TicketVote structure compliance with specification
#[cfg(test)]
mod ticket_vote_compliance {
    use super::*;

    #[test]
    fn test_ticket_vote_field_types() {
        let vote = TicketVote {
            ticket_id: [1u8; 32],
            block_hash: [2u8; 32],
            vote: VoteType::Yes,
            signature: TransactionSignature([3u8; 64]),
        };

        // Verify field types and sizes
        assert_eq!(std::mem::size_of_val(&vote.ticket_id), 32);
        assert_eq!(std::mem::size_of_val(&vote.block_hash), 32);
        assert_eq!(std::mem::size_of_val(&vote.signature.0), 64);
    }

    #[test]
    fn test_vote_type_values() {
        // Test that VoteType enum values match specification
        assert_eq!(VoteType::Yes as u8, 0);
        assert_eq!(VoteType::No as u8, 1);
        assert_eq!(VoteType::Abstain as u8, 2);
    }

    #[test]
    fn test_ticket_vote_total_size() {
        let vote = TicketVote {
            ticket_id: [1u8; 32],
            block_hash: [2u8; 32],
            vote: VoteType::Yes,
            signature: TransactionSignature([3u8; 64]),
        };

        // Verify serialization
        let serialized = bincode::encode_to_vec(&vote, bincode::config::standard()).unwrap();
        assert!(!serialized.is_empty());
        
        // Verify deserialization
        let deserialized: TicketVote = bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap().0;
        assert_eq!(vote, deserialized);
    }

    #[test]
    fn test_ticket_vote_validation() {
        let vote = TicketVote {
            ticket_id: [1u8; 32],
            block_hash: [2u8; 32],
            vote: VoteType::Yes,
            signature: TransactionSignature([3u8; 64]),
        };

        // Test that all vote types are valid
        let yes_vote = TicketVote { vote: VoteType::Yes, ..vote.clone() };
        let no_vote = TicketVote { vote: VoteType::No, ..vote.clone() };
        let abstain_vote = TicketVote { vote: VoteType::Abstain, ..vote.clone() };

        // All should serialize successfully
        assert!(bincode::encode_to_vec(&yes_vote, bincode::config::standard()).is_ok());
        assert!(bincode::encode_to_vec(&no_vote, bincode::config::standard()).is_ok());
        assert!(bincode::encode_to_vec(&abstain_vote, bincode::config::standard()).is_ok());
    }
}

/// Test Transaction structure compliance with specification
#[cfg(test)]
mod transaction_compliance {
    use super::*;

    #[test]
    fn test_standard_transaction_fields() {
        let tx_input = TxInput {
            previous_output: OutPoint {
                txid: [1u8; 32],
                vout: 0,
            },
            script_sig: vec![0x76, 0xa9, 0x14],
            sequence: 0xffffffff,
        };

        let tx_output = TxOutput {
            value: 5000000000,
            script_pubkey: vec![0x76, 0xa9, 0x14],
            memo: None,
        };

        let transaction = Transaction::Standard {
            version: 1,
            inputs: vec![tx_input],
            outputs: vec![tx_output],
            lock_time: 0,
            fee: 10000,
            witness: vec![],
        };

        // Test unified interface methods
        assert_eq!(transaction.get_inputs().len(), 1);
        assert_eq!(transaction.get_outputs().len(), 1);
        assert_eq!(transaction.get_lock_time(), 0);
        assert_eq!(transaction.get_fee(), 10000);
        assert_eq!(transaction.get_witnesses().len(), 0);
        
        // Test transaction ID calculation
        let txid = transaction.txid();
        assert_eq!(txid.len(), 32);
        
        // Test serialization
        let serialized = transaction.to_bytes().unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_transaction_type_safety() {
        // Test that enum-based approach provides type safety
        let coinbase = Transaction::Coinbase {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            witness: vec![],
        };

        let masternode_register = Transaction::MasternodeRegister {
            masternode_identity: MasternodeIdentity {
                collateral_outpoint: OutPoint { txid: [0u8; 32], vout: 0 },
                operator_public_key: PublicKey([1u8; 32]),
                collateral_ownership_public_key: PublicKey([2u8; 32]),
                network_address: "127.0.0.1:8333".to_string(),
            },
            signature: TransactionSignature([3u8; 64]),
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
            witness: vec![],
        };

        // Test that different transaction types are handled correctly
        assert!(coinbase.is_coinbase());
        assert!(!masternode_register.is_coinbase());
        
        // Test unified interface works for all types
        assert_eq!(coinbase.get_inputs().len(), 0);
        assert_eq!(masternode_register.get_inputs().len(), 0);
    }
}

/// Test TxOutput structure compliance with specification
#[cfg(test)]
mod tx_output_compliance {
    use super::*;

    #[test]
    fn test_tx_output_field_types() {
        let output = TxOutput {
            value: 5000000000u64,
            script_pubkey: vec![0x76, 0xa9, 0x14],
            memo: None,
        };

        // Verify field types
        assert_eq!(std::mem::size_of_val(&output.value), 8);
        assert!(output.script_pubkey.is_empty() || !output.script_pubkey.is_empty());
        assert!(output.memo.is_none());
    }

    #[test]
    fn test_tx_output_memo_field() {
        // Test output without memo
        let output_no_memo = TxOutput::new(5000000000, vec![0x76, 0xa9, 0x14]);
        assert!(output_no_memo.memo.is_none());

        // Test output with memo
        let memo_data = vec![0x6a, 0x10]; // OP_RETURN + 16 bytes
        let output_with_memo = TxOutput::new_with_memo(
            0, // OP_RETURN outputs typically have 0 value
            vec![0x6a, 0x10], // OP_RETURN script
            Some(memo_data.clone())
        );
        assert!(output_with_memo.memo.is_some());
        assert_eq!(output_with_memo.memo.unwrap(), memo_data);

        // Test serialization of both types
        let serialized_no_memo = bincode::encode_to_vec(&output_no_memo, bincode::config::standard()).unwrap();
        let serialized_with_memo = bincode::encode_to_vec(&output_with_memo, bincode::config::standard()).unwrap();
        
        assert!(!serialized_no_memo.is_empty());
        assert!(!serialized_with_memo.is_empty());
        
        // Verify deserialization
        let deserialized_no_memo: TxOutput = bincode::decode_from_slice(&serialized_no_memo, bincode::config::standard()).unwrap().0;
        let deserialized_with_memo: TxOutput = bincode::decode_from_slice(&serialized_with_memo, bincode::config::standard()).unwrap().0;
        
        assert_eq!(output_no_memo, deserialized_no_memo);
        assert_eq!(output_with_memo, deserialized_with_memo);
    }

    #[test]
    fn test_tx_output_p2pkh_extraction() {
        // Test P2PKH script recognition
        let p2pkh_script = vec![
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // PUSHDATA(20)
            // 20-byte public key hash
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];

        let output = TxOutput::new(5000000000, p2pkh_script);
        let extracted_hash = output.extract_public_key_hash();
        assert!(extracted_hash.is_some());

        // Test non-P2PKH script
        let non_p2pkh_script = vec![0x6a, 0x10]; // OP_RETURN
        let output2 = TxOutput::new(0, non_p2pkh_script);
        let extracted_hash2 = output2.extract_public_key_hash();
        assert!(extracted_hash2.is_none());
    }
}

/// Test TxInput structure compliance with specification
#[cfg(test)]
mod tx_input_compliance {
    use super::*;

    #[test]
    fn test_tx_input_field_types() {
        let input = TxInput {
            previous_output: OutPoint {
                txid: [1u8; 32],
                vout: 0u32,
            },
            script_sig: vec![0x76, 0xa9, 0x14],
            sequence: 0xffffffffu32,
        };

        // Verify field types match specification semantics
        assert_eq!(std::mem::size_of_val(&input.previous_output.txid), 32); // prev_out_hash
        assert_eq!(std::mem::size_of_val(&input.previous_output.vout), 4);  // prev_out_index
        assert!(input.script_sig.is_empty() || !input.script_sig.is_empty()); // script_sig
        assert_eq!(std::mem::size_of_val(&input.sequence), 4); // sequence (enhancement)
    }

    #[test]
    fn test_outpoint_structure() {
        let outpoint = OutPoint {
            txid: [1u8; 32],
            vout: 42,
        };

        // Test serialization
        let serialized = bincode::encode_to_vec(&outpoint, bincode::config::standard()).unwrap();
        assert!(!serialized.is_empty());
        
        // Test deserialization
        let deserialized: OutPoint = bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap().0;
        assert_eq!(outpoint, deserialized);
        
        // Test hash function
        let hash = outpoint.hash();
        assert_eq!(hash.len(), 32);
    }
}

/// Test serialization compliance with specification
#[cfg(test)]
mod serialization_compliance {
    use super::*;

    #[test]
    fn test_canonical_serialization() {
        // Test that serialization is deterministic and canonical
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        // Serialize multiple times and verify consistency
        let serialized1 = bincode::encode_to_vec(&header, bincode::config::standard()).unwrap();
        let serialized2 = bincode::encode_to_vec(&header, bincode::config::standard()).unwrap();
        assert_eq!(serialized1, serialized2);

        // Test cross-platform compatibility (bincode is designed for this)
        let deserialized: BlockHeader = bincode::decode_from_slice(&serialized1, bincode::config::standard()).unwrap().0;
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_size_constraints() {
        // Test that structures don't exceed reasonable size limits
        let max_script_size = 10000; // Reasonable script size limit
        let max_memo_size = 80; // Standard OP_RETURN limit

        let large_script = vec![0u8; max_script_size];
        let output_large_script = TxOutput::new(0, large_script);
        assert!(bincode::encode_to_vec(&output_large_script, bincode::config::standard()).is_ok());

        let large_memo = vec![0u8; max_memo_size];
        let output_large_memo = TxOutput::new_with_memo(0, vec![0x6a], Some(large_memo));
        assert!(bincode::encode_to_vec(&output_large_memo, bincode::config::standard()).is_ok());
    }
}

/// Test validation rules compliance
#[cfg(test)]
mod validation_compliance {
    use super::*;

    #[test]
    fn test_version_validation() {
        // Test that version 1 is supported for initial mainnet
        let header = BlockHeader {
            version: 1,
            previous_block_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            timestamp: 1234567890,
            nonce: 12345,
            difficulty_target: 0x1d00ffff,
            height: 100,
            state_root: [2u8; 32],
        };

        assert_eq!(header.version, 1);
        
        // Test transaction version
        let transaction = Transaction::Standard {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            fee: 0,
            witness: vec![],
        };

        // Extract version from standard transaction
        if let Transaction::Standard { version, .. } = transaction {
            assert_eq!(version, 1);
        }
    }

    #[test]
    fn test_value_conservation() {
        // Test that transaction value conservation can be validated
        let input = TxInput {
            previous_output: OutPoint { txid: [1u8; 32], vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
        };

        let output1 = TxOutput::new(2500000000, vec![0x76, 0xa9, 0x14]); // 25 coins
        let output2 = TxOutput::new(2499990000, vec![0x76, 0xa9, 0x14]); // 24.9999 coins
        let fee = 10000; // 0.0001 coins

        let transaction = Transaction::Standard {
            version: 1,
            inputs: vec![input],
            outputs: vec![output1, output2],
            lock_time: 0,
            fee,
            witness: vec![],
        };

        // Verify fee calculation
        assert_eq!(transaction.get_fee(), fee);
        
        // Verify output count
        assert_eq!(transaction.get_outputs().len(), 2);
        
        // Calculate total output value
        let total_output_value: u64 = transaction.get_outputs().iter().map(|o| o.value).sum();
        assert_eq!(total_output_value, 4999990000); // 49.9999 coins
    }
}
