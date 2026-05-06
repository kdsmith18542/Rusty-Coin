#!/bin/bash
# Comprehensive test error fixing script for Rusty Coin

echo "🔧 Fixing Rusty Coin test compilation errors..."

# Fix 1: Replace enum variants with correct names
echo "Fixing enum variant names..."

# Fix VoteChoice variants
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/VoteChoice::YES/VoteChoice::Yes/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/VoteChoice::NO/VoteChoice::No/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/VoteChoice::ABSTAIN/VoteChoice::Abstain/g' {} \;

# Fix VoterType variants
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/VoterType::POS_TICKET/VoterType::PosTicket/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/VoterType::MASTERNODE/VoterType::Masternode/g' {} \;

# Fix ProposalType variants
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/ProposalType::PROTOCOL_UPGRADE/ProposalType::ProtocolUpgrade/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/ProposalType::PARAMETER_CHANGE/ProposalType::ParameterChange/g' {} \;

# Fix 2: Replace signature arrays with TransactionSignature structs
echo "Fixing signature type mismatches..."
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/dummy_signature(\([0-9]*\))/rusty_shared_types::TransactionSignature { bytes: dummy_signature(\1) }/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/\[0u8; 64\]/rusty_shared_types::TransactionSignature { bytes: [0u8; 64] }/g' {} \;

# Fix 3: Add missing fields to GovernanceProposal
echo "Adding missing fields to GovernanceProposal structs..."
# This is more complex and needs to be done per file, so we'll handle it separately

# Fix 4: Fix import paths
echo "Fixing import paths..."
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/rusty_core::consensus::ConsensusError/rusty_core::consensus::error::ConsensusError/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/rusty_core::script::ScriptEngine/rusty_core::script::script_engine::ScriptEngine/g' {} \;

# Fix 5: Fix constant names
echo "Fixing constant names..."
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/COINBASE_MATURITY/COINBASE_MATURITY_PERIOD_BLOCKS/g' {} \;
find rusty-core/tests/ -name "*.rs" -exec sed -i 's/MAX_BLOCK_SIZE_BYTES/MAX_BLOCK_SIZE/g' {} \;

echo "✅ Basic fixes applied. Manual fixes may still be needed for complex struct initializations."


