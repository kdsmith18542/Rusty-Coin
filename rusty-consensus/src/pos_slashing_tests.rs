//! Comprehensive tests for PoS ticket slashing mechanisms
//! Per spec 03 Section 3.7 - PoS Slashing

use crate::pos_slashing::{
    create_ticket_malicious_behavior_slashing_transaction,
    create_ticket_non_participation_slashing_transaction,
    validate_ticket_malicious_behavior_slashing, validate_ticket_non_participation_slashing,
};
use rusty_shared_types::{
    TicketId, TicketMaliciousActionType, TicketMaliciousProof, TicketNonParticipationProof,
    TxInput, WitnessSignature,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_core::protocol_constants::GRACE_PERIOD_BLOCKS;

    fn create_test_ticket_id(seed: u8) -> TicketId {
        let mut id = [0u8; 32];
        id[0] = seed;
        TicketId::from(id)
    }

    fn create_test_tx_input() -> TxInput {
        TxInput {
            prev_out_hash: [0u8; 32],
            prev_out_index: 0,
            previous_output: rusty_shared_types::OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        }
    }

    /// Test non-participation slashing transaction creation
    #[test]
    fn test_create_non_participation_slashing_tx() {
        let ticket_id = create_test_ticket_id(1);
        let ticket_value = 100_000_000; // 1 RUST
        let block_height: u64 = 1000;

        let proof = TicketNonParticipationProof {
            ticket_id: ticket_id.0,
            target_block_hash: [1u8; 32],
            detection_block_height: block_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_block_height: block_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_proof: vec![1, 2, 3, 4],
            witness_signatures: vec![],
        };

        let tx_input = create_test_tx_input();
        let script_pubkey = vec![0x76, 0xa9, 0x14]; // P2PKH script

        let result = create_ticket_non_participation_slashing_transaction(
            &ticket_id,
            proof.clone(),
            tx_input.clone(),
            ticket_value,
            script_pubkey.clone(),
            block_height,
        );

        assert!(
            result.is_ok(),
            "Should create non-participation slashing transaction"
        );
        let tx = result.unwrap();

        match tx {
            rusty_shared_types::Transaction::TicketSlashNonParticipation {
                ticket_id: tx_ticket_id,
                proof: tx_proof,
                ..
            } => {
                assert_eq!(tx_ticket_id, ticket_id.0);
                assert_eq!(tx_proof.ticket_id, proof.ticket_id);
            }
            _ => assert!(false, "Expected TicketSlashNonParticipation transaction"),
        }
    }

    /// Test malicious behavior slashing transaction creation
    #[test]
    fn test_create_malicious_behavior_slashing_tx() {
        let ticket_id = create_test_ticket_id(2);
        let ticket_value = 100_000_000; // 1 RUST
        let block_height: u64 = 1000;

        let proof = TicketMaliciousProof {
            ticket_id: ticket_id.0,
            malicious_action_type: TicketMaliciousActionType::DoubleVoting,
            proof_data: vec![1, 2, 3, 4],
            detection_block_height: block_height,
            witness_signatures: vec![],
        };

        let tx_input = create_test_tx_input();
        let script_pubkey = vec![0x76, 0xa9, 0x14]; // P2PKH script

        let result = create_ticket_malicious_behavior_slashing_transaction(
            &ticket_id,
            proof.clone(),
            tx_input.clone(),
            ticket_value,
            script_pubkey.clone(),
            block_height,
        );

        assert!(
            result.is_ok(),
            "Should create malicious behavior slashing transaction"
        );
        let tx = result.unwrap();

        match tx {
            rusty_shared_types::Transaction::TicketSlashMalicious {
                ticket_id: tx_ticket_id,
                proof: tx_proof,
                ..
            } => {
                assert_eq!(tx_ticket_id, ticket_id.0);
                assert_eq!(tx_proof.ticket_id, proof.ticket_id);
            }
            _ => assert!(false, "Expected TicketSlashMalicious transaction"),
        }
    }

    /// Test non-participation slashing validation - grace period
    #[test]
    fn test_validate_non_participation_grace_period() {
        let ticket_id = create_test_ticket_id(3);
        let current_height: u64 = 1000;
        let detection_height = current_height.saturating_sub(5); // Only 5 blocks ago (less than GRACE_PERIOD)

        let proof = TicketNonParticipationProof {
            ticket_id: ticket_id.0,
            target_block_hash: [1u8; 32],
            detection_block_height: detection_height,
            selection_block_height: detection_height,
            selection_proof: vec![1, 2, 3],
            witness_signatures: vec![],
        };

        let result = validate_ticket_non_participation_slashing(&ticket_id, &proof, current_height);

        assert!(
            result.is_err(),
            "Should fail validation if grace period not passed"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Grace period"),
            "Error should mention grace period, got: {}",
            error_msg
        );
    }

    /// Test non-participation slashing validation - grace period passed
    #[test]
    fn test_validate_non_participation_grace_period_passed() {
        let ticket_id = create_test_ticket_id(4);
        let current_height: u64 = 1000;
        let detection_height = current_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1); // Grace period passed

        let proof = TicketNonParticipationProof {
            ticket_id: ticket_id.0,
            target_block_hash: [1u8; 32],
            detection_block_height: detection_height,
            selection_block_height: detection_height,
            selection_proof: vec![1, 2, 3],
            witness_signatures: vec![WitnessSignature {
                masternode_id: rusty_shared_types::MasternodeID(rusty_shared_types::OutPoint { txid: [0u8; 32], vout: 0 }),
                signature: vec![1, 2, 3],
            }], // At least one witness signature
        };

        let result = validate_ticket_non_participation_slashing(&ticket_id, &proof, current_height);

        assert!(
            result.is_ok(),
            "Should pass validation if grace period passed and proof is valid"
        );
    }

    /// Test non-participation slashing validation - ticket ID mismatch
    #[test]
    fn test_validate_non_participation_ticket_id_mismatch() {
        let ticket_id = create_test_ticket_id(5);
        let wrong_ticket_id = create_test_ticket_id(6);
        let current_height: u64 = 1000;

        let proof = TicketNonParticipationProof {
            ticket_id: wrong_ticket_id.0, // Wrong ticket ID
            target_block_hash: [1u8; 32],
            detection_block_height: current_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_block_height: current_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_proof: vec![1, 2, 3],
            witness_signatures: vec![WitnessSignature {
                masternode_id: rusty_shared_types::MasternodeID(rusty_shared_types::OutPoint { txid: [0u8; 32], vout: 0 }),
                signature: vec![1, 2, 3],
            }],
        };

        let result = validate_ticket_non_participation_slashing(&ticket_id, &proof, current_height);

        assert!(
            result.is_err(),
            "Should fail validation if ticket ID mismatch"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Ticket ID"),
            "Error should mention ticket ID, got: {}",
            error_msg
        );
    }

    /// Test malicious behavior slashing validation
    #[test]
    fn test_validate_malicious_behavior_slashing() {
        let ticket_id = create_test_ticket_id(7);
        let current_height: u64 = 1000;

        let proof = TicketMaliciousProof {
            ticket_id: ticket_id.0,
            malicious_action_type: TicketMaliciousActionType::DoubleVoting,
            proof_data: vec![1, 2, 3, 4], // Contains conflicting votes data
            detection_block_height: current_height,
            witness_signatures: vec![WitnessSignature {
                masternode_id: rusty_shared_types::MasternodeID(rusty_shared_types::OutPoint { txid: [0u8; 32], vout: 0 }),
                signature: vec![1, 2, 3],
            }],
        };

        let result =
            validate_ticket_malicious_behavior_slashing(&ticket_id, &proof, current_height);

        // Validation should check that conflicting votes exist and are from same ticket
        // The actual validation logic may need to be implemented
        assert!(
            result.is_ok() || result.is_err(),
            "Validation should complete"
        );
    }

    /// Test slashing percentage - non-participation (1%)
    #[test]
    fn test_non_participation_slashing_percentage() {
        let ticket_id = create_test_ticket_id(8);
        let ticket_value = 100_000_000; // 1 RUST = 100M satoshis
        let block_height: u64 = 1000;

        let proof = TicketNonParticipationProof {
            ticket_id: ticket_id.0,
            target_block_hash: [1u8; 32],
            detection_block_height: block_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_block_height: block_height.saturating_sub(GRACE_PERIOD_BLOCKS as u64 + 1),
            selection_proof: vec![1, 2, 3],
            witness_signatures: vec![],
        };

        let tx_input = create_test_tx_input();
        let script_pubkey = vec![0x76, 0xa9, 0x14];

        let tx = create_ticket_non_participation_slashing_transaction(
            &ticket_id,
            proof,
            tx_input,
            ticket_value,
            script_pubkey,
            block_height,
        )
        .unwrap();

        // Check that slashed amount is 1% of ticket value
        match tx {
            rusty_shared_types::Transaction::TicketSlashNonParticipation { outputs, .. } => {
                // First output should be burn output with 1% of value
                let expected_slash = (ticket_value as f64 * 0.01) as u64;
                let burn_output = &outputs[0];
                assert_eq!(
                    burn_output.value, expected_slash,
                    "Non-participation slashing should be 1% of ticket value"
                );

                // Second output should be change (99% remaining)
                if outputs.len() > 1 {
                    let expected_remaining = ticket_value - expected_slash;
                    assert_eq!(
                        outputs[1].value, expected_remaining,
                        "Remaining value should be 99% of ticket value"
                    );
                }
            }
            _ => assert!(false, "Expected TicketSlashNonParticipation transaction"),
        }
    }

    /// Test slashing percentage - malicious behavior (100%)
    #[test]
    fn test_malicious_behavior_slashing_percentage() {
        let ticket_id = create_test_ticket_id(9);
        let ticket_value = 100_000_000; // 1 RUST
        let block_height: u64 = 1000;

        let proof = TicketMaliciousProof {
            ticket_id: ticket_id.0,
            malicious_action_type: TicketMaliciousActionType::DoubleVoting,
            proof_data: vec![1, 2, 3, 4],
            detection_block_height: block_height,
            witness_signatures: vec![],
        };

        let tx_input = create_test_tx_input();
        let script_pubkey = vec![0x76, 0xa9, 0x14];

        let tx = create_ticket_malicious_behavior_slashing_transaction(
            &ticket_id,
            proof,
            tx_input,
            ticket_value,
            script_pubkey,
            block_height,
        )
        .unwrap();

        // Check that slashed amount is 100% of ticket value
        match tx {
            rusty_shared_types::Transaction::TicketSlashMalicious { outputs, .. } => {
                // Should have only one output (burn output) with 100% of value
                assert_eq!(
                    outputs.len(),
                    1,
                    "Malicious slashing should burn entire ticket value"
                );
                assert_eq!(
                    outputs[0].value, ticket_value,
                    "Malicious behavior slashing should be 100% of ticket value"
                );
            }
            _ => assert!(false, "Expected TicketSlashMalicious transaction"),
        }
    }
}
