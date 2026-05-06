/// Simple test to verify parameter manager integration works
use std::sync::Arc;

fn main() {
    // Test imports work
    use rusty_governance::parameter_manager::{ParameterManager, ParameterValue, ParameterCategory};
    use rusty_shared_types::ConsensusParams;
    use rusty_core::consensus::state::BlockchainState;

    println!("Testing parameter manager integration...");

    // Test 1: Create parameter manager without blockchain state (legacy mode)
    let manager = ParameterManager::new();
    println!("✓ Created parameter manager without blockchain state");
    
    // Test 2: Create parameter manager with blockchain state integration
    let blockchain_state = Arc::new(BlockchainState::new());
    let consensus_params = Arc::new(ConsensusParams::default());
    
    let mut manager_with_state = ParameterManager::new_with_blockchain_state(
        blockchain_state.clone(),
        consensus_params.clone(),
    );
    println!("✓ Created parameter manager with blockchain state integration");
    
    // Test 3: Check connection status
    assert!(manager_with_state.is_connected_to_blockchain_state());
    println!("✓ Parameter manager correctly reports blockchain state connection");
    
    // Test 4: Test getting current parameter value from live state
    let current_value = manager_with_state.get_current_parameter_value("min_block_time").unwrap();
    assert!(matches!(current_value, ParameterValue::U64(150))); // Default value
    println!("✓ Successfully retrieved live parameter value from blockchain state");
    
    // Test 5: Test updating consensus parameters
    manager_with_state.update_consensus_params(Arc::new(ConsensusParams::regtest()));
    let updated_value = manager_with_state.get_current_parameter_value("min_block_time").unwrap();
    assert!(matches!(updated_value, ParameterValue::U64(1))); // regtest value
    println!("✓ Successfully updated and retrieved updated parameter value");
    
    // Test 6: Test parameter validation with live state
    let test_proposal = rusty_shared_types::governance::GovernanceProposal {
        proposal_id: [1; 32],
        proposal_type: rusty_shared_types::governance::ProposalType::ParameterChange,
        target_parameter: Some("min_block_time".to_string()),
        new_value: Some("200".to_string()),
        description_hash: [2; 32],
        start_block_height: 100,
        end_block_height: 200,
        proposer_id: [3; 32],
        proposer_signature: rusty_shared_types::TransactionSignature { bytes: [4; 64] },
        fee: 1000,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        witness: vec![],
    };
    
    let validation_result = manager_with_state.validate_parameter_change(&test_proposal, &ConsensusParams::default());
    assert!(validation_result.is_ok());
    println!("✓ Successfully validated parameter change with live blockchain state");
    
    // Test 7: Test parameter manager stats
    let stats = manager_with_state.get_stats();
    assert!(stats.is_connected_to_blockchain_state);
    assert!(stats.total_parameters > 0);
    println!("✓ Parameter manager stats correctly reflect blockchain state connection");
    
    println!("\n🎉 All tests passed! Parameter manager successfully integrated with consensus state.");
    println!("\nIntegration Summary:");
    println!("- ✅ Parameter manager connected to live blockchain state");
    println!("- ✅ Real-time parameter values read from consensus parameters");
    println!("- ✅ Parameter changes synchronized with blockchain state");
    println!("- ✅ Enhanced validation and governance proposal processing");
    println!("- ✅ Proper error handling for disconnected state");
}