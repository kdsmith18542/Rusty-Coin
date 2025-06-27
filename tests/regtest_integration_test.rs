//! Integration tests for regtest network with mainnet parameters
//! 
//! These tests verify that regtest properly uses mainnet consensus parameters
//! while running in a local environment.

use rusty_shared_types::ConsensusParams;
use rusty_network::protocol::Network;

#[test]
fn test_regtest_uses_mainnet_parameters() {
    let mainnet_params = ConsensusParams::default();
    let regtest_params = ConsensusParams::regtest();
    
    // Verify regtest uses mainnet consensus parameters
    assert_eq!(regtest_params.min_block_time, mainnet_params.min_block_time);
    assert_eq!(regtest_params.difficulty_adjustment_window, mainnet_params.difficulty_adjustment_window);
    assert_eq!(regtest_params.ticket_price, mainnet_params.ticket_price);
    assert_eq!(regtest_params.min_stake, mainnet_params.min_stake);
    assert_eq!(regtest_params.initial_block_reward, mainnet_params.initial_block_reward);
    assert_eq!(regtest_params.pos_reward_ratio, mainnet_params.pos_reward_ratio);
    assert_eq!(regtest_params.voting_period_blocks, mainnet_params.voting_period_blocks);
    assert_eq!(regtest_params.proposal_stake_amount, mainnet_params.proposal_stake_amount);
    
    println!("✅ Regtest uses mainnet consensus parameters");
    println!("   Block time: {} seconds", regtest_params.min_block_time);
    println!("   Difficulty adjustment: {} blocks", regtest_params.difficulty_adjustment_window);
    println!("   Ticket price: {} satoshis", regtest_params.ticket_price);
    println!("   Min stake: {} satoshis", regtest_params.min_stake);
    println!("   Block reward: {} satoshis", regtest_params.initial_block_reward);
}

#[test]
fn test_regtest_network_configuration() {
    // Test that regtest has proper network configuration
    assert_eq!(Network::Regtest.magic(), [0xfa, 0xbf, 0xb5, 0xda]);
    assert_eq!(Network::Regtest.default_port(), 18444);
    
    println!("✅ Regtest network configuration correct");
    println!("   Magic bytes: {:?}", Network::Regtest.magic());
    println!("   Default port: {}", Network::Regtest.default_port());
}

#[test]
fn test_regtest_vs_testnet_differences() {
    let regtest_params = ConsensusParams::regtest();
    let testnet_params = ConsensusParams::testnet();
    
    // Verify regtest is NOT using testnet parameters
    assert_ne!(regtest_params.min_block_time, testnet_params.min_block_time);
    assert_ne!(regtest_params.ticket_price, testnet_params.ticket_price);
    assert_ne!(regtest_params.initial_block_reward, testnet_params.initial_block_reward);
    
    println!("✅ Regtest differs from testnet (uses mainnet params)");
    println!("   Regtest block time: {} vs Testnet: {}", 
             regtest_params.min_block_time, testnet_params.min_block_time);
    println!("   Regtest ticket price: {} vs Testnet: {}", 
             regtest_params.ticket_price, testnet_params.ticket_price);
}

#[cfg(test)]
mod network_tests {
    use super::*;
    
    #[test]
    fn test_production_like_parameters() {
        let params = ConsensusParams::regtest();
        
        // Verify production-like timing
        assert_eq!(params.min_block_time, 150); // 2.5 minutes like mainnet
        assert_eq!(params.difficulty_adjustment_window, 2016); // ~3.5 days like mainnet
        
        // Verify production-like economics
        assert_eq!(params.ticket_price, 100_000_000); // 1 RUST like mainnet
        assert_eq!(params.min_stake, 1_000_000); // 0.01 RUST like mainnet
        assert_eq!(params.initial_block_reward, 50_000_000_000); // 500 RUST like mainnet
        
        // Verify production-like governance
        assert_eq!(params.proposal_stake_amount, 10_000_000_000); // 100 RUST like mainnet
        assert_eq!(params.voting_period_blocks, 144 * 7 * 4); // 4 weeks like mainnet
        
        println!("✅ All production-like parameters verified for regtest");
    }
}
