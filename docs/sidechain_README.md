# Rusty Coin Sidechain Implementation

A comprehensive sidechain protocol implementation for Rusty Coin, enabling secure cross-chain asset transfers, smart contract execution, and fraud-resistant operations.

## Overview

The Rusty Coin sidechain system provides:

- **Two-way peg operations** for secure asset transfers between mainchain and sidechains
- **Inter-sidechain communication** for asset transfers between different sidechains
- **Fraud proof system** for detecting and preventing malicious behavior
- **Federation-based security** using BLS threshold signatures from masternodes
- **Multi-VM support** for smart contracts (EVM, WASM, custom UTXO-based VM)

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Mainchain     │    │   Sidechain A   │    │   Sidechain B   │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   Assets  │  │◄──►│  │   Assets  │  │◄──►│  │   Assets  │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │Federation │  │    │  │Federation │  │    │  │Federation │  │
│  │Signatures │  │    │  │Signatures │  │    │  │Signatures │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Fraud Proof     │
                    │ System          │
                    └─────────────────┘
```

### Key Features

1. **Two-Way Peg System**
   - Peg-in: Lock assets on mainchain, mint on sidechain
   - Peg-out: Burn assets on sidechain, unlock on mainchain
   - Federation-controlled with BLS threshold signatures

2. **Cross-Chain Transactions**
   - Mainchain ↔ Sidechain transfers
   - Sidechain ↔ Sidechain transfers
   - Cryptographic proof verification

3. **Fraud Detection**
   - Challenge-response system
   - Economic incentives for honest behavior
   - Multiple fraud types supported

4. **Smart Contract Support**
   - EVM compatibility for Ethereum dApps
   - WASM runtime for high-performance contracts
   - Custom UTXO-based VM for Bitcoin-like operations

## Getting Started

### Basic Usage

```rust
use rusty_core::sidechain::*;

// Create sidechain state manager
let mut sidechain_state = SidechainState::new();

// Register a new sidechain
let sidechain_info = SidechainInfo {
    sidechain_id: [1u8; 32],
    name: "My Sidechain".to_string(),
    peg_address: vec![1, 2, 3, 4],
    federation_members: vec![],
    current_epoch: 1,
    vm_type: VMType::EVM,
    genesis_block_hash: [0u8; 32],
    creation_timestamp: 1234567890,
    min_federation_threshold: 2,
};

sidechain_state.register_sidechain(sidechain_info)?;

// Get statistics
let stats = sidechain_state.get_stats();
println!("Registered sidechains: {}", stats.registered_sidechains);
```

### Peg-In Operation

```rust
// Create mainchain transaction that locks funds
let mainchain_tx = create_lock_transaction();

// Initiate peg-in
let peg_id = sidechain_state.initiate_peg_in(
    mainchain_tx,
    sidechain_id,
    recipient_address,
    amount,
    asset_id,
)?;

// Wait for confirmations and federation signatures
sidechain_state.process_peg_confirmations(block_height)?;

// Check peg status
match sidechain_state.get_peg_status(&peg_id) {
    Some(PegStatus::Completed) => println!("Peg-in completed!"),
    Some(status) => println!("Peg-in status: {:?}", status),
    None => println!("Peg-in not found"),
}
```

### Fraud Proof Submission

```rust
// Create fraud proof evidence
let fraud_proof = FraudProof {
    fraud_type: FraudType::InvalidStateTransition,
    fraud_block_height: 100,
    fraud_tx_index: Some(5),
    evidence: create_evidence(),
    challenger_address: vec![1, 2, 3],
    challenge_bond: 2000000,
    response_deadline: 200,
};

// Submit fraud proof
let challenge_id = sidechain_state.submit_fraud_proof(fraud_proof, 2000000)?;

// Process challenges
sidechain_state.process_fraud_proof_challenges(block_height)?;
```

## Configuration

### Two-Way Peg Configuration

```rust
let peg_config = TwoWayPegConfig {
    min_peg_in_confirmations: 6,
    min_peg_out_confirmations: 12,
    federation_threshold: 2,
    min_peg_amount: 100_000,
    max_peg_amount: 1_000_000_000_000,
    peg_timeout_blocks: 1440,
    peg_fee_rate: 1000,
};
```

### Fraud Proof Configuration

```rust
let fraud_config = FraudProofConfig {
    challenge_period_blocks: 1440,
    min_challenge_bond: 1_000_000,
    fraud_proof_reward: 10_000_000,
    false_proof_penalty: 5_000_000,
    max_proof_size: 10_000_000,
    verification_timeout_blocks: 144,
};
```

### Proof Validation Configuration

```rust
let validation_config = ProofValidationConfig {
    min_federation_signatures: 2,
    max_proof_size: 1_000_000,
    strict_validation: true,
    max_merkle_depth: 32,
    verification_timeout_ms: 5000,
};
```

## Security Model

### Federation Control

- **BLS Threshold Signatures**: Masternode federation uses BLS signatures for authorization
- **Epoch-based Rotation**: Federation membership rotates based on epochs
- **Threshold Requirements**: Configurable threshold for signature requirements

### Fraud Prevention

- **Challenge Period**: Time window for submitting fraud proofs
- **Economic Bonds**: Challengers must post bonds to prevent spam
- **Verification Process**: Automated verification of fraud claims
- **Penalties and Rewards**: Economic incentives for honest behavior

### Cross-Chain Security

- **Merkle Proofs**: Cryptographic proofs of transaction inclusion
- **Block Anchoring**: Sidechain blocks anchored to mainchain
- **Confirmation Requirements**: Configurable confirmation thresholds

## VM Support

### Ethereum Virtual Machine (EVM)

- Full Ethereum compatibility
- Support for Solidity smart contracts
- Gas-based execution model

### WebAssembly (WASM)

- High-performance contract execution
- Multiple language support (Rust, C++, AssemblyScript)
- Deterministic execution

### UTXO VM

- Bitcoin-like transaction model
- Script-based programmability
- Efficient for simple operations

## Testing

The implementation includes comprehensive test suites:

```bash
# Run all sidechain tests
cargo test sidechain

# Run specific test modules
cargo test sidechain::tests
cargo test sidechain::two_way_peg::tests
cargo test sidechain::fraud_proofs::tests
cargo test sidechain::proof_validation::tests
cargo test sidechain::integration_tests
```

### Test Coverage

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Fraud detection and prevention
- **Performance Tests**: Validation timing and throughput

## API Documentation

Comprehensive API documentation is available:

- [Sidechain API Reference](api/sidechain_api.md)
- [Two-Way Peg API](api/two_way_peg_api.md)
- [Fraud Proof API](api/fraud_proof_api.md)
- [Proof Validation API](api/proof_validation_api.md)

## Examples

### Complete Peg-In/Peg-Out Cycle

```rust
// 1. Peg-in: Mainchain → Sidechain
let peg_in_id = sidechain_state.initiate_peg_in(
    mainchain_lock_tx,
    sidechain_id,
    sidechain_recipient,
    amount,
    asset_id,
)?;

// Wait for completion
while sidechain_state.get_peg_status(&peg_in_id) != Some(PegStatus::Completed) {
    sidechain_state.process_peg_confirmations(current_height)?;
    current_height += 1;
}

// 2. Use assets on sidechain
let sidechain_tx = create_sidechain_transaction();
process_sidechain_transaction(sidechain_tx)?;

// 3. Peg-out: Sidechain → Mainchain
let burn_tx = create_burn_transaction();
let peg_out_id = sidechain_state.initiate_peg_out(
    burn_tx,
    sidechain_id,
    mainchain_recipient,
    amount,
    asset_id,
)?;

// Wait for completion
while sidechain_state.get_peg_status(&peg_out_id) != Some(PegStatus::Completed) {
    sidechain_state.process_peg_confirmations(current_height)?;
    current_height += 1;
}
```

### Inter-Sidechain Transfer

```rust
// Create inter-sidechain transaction
let inter_tx = CrossChainTxBuilder::build_inter_sidechain(
    source_sidechain_id,
    destination_sidechain_id,
    amount,
    asset_id,
    recipient_address,
)?;

// Add federation signatures
for signature in federation_signatures {
    inter_tx.add_federation_signature(signature)?;
}

// Process on both sidechains
source_sidechain.process_cross_chain_transaction(inter_tx.clone())?;
destination_sidechain.process_cross_chain_transaction(inter_tx)?;
```

## Compliance

This implementation follows the specifications outlined in the Rusty Coin Technical Brief (RCTB):

- **FERR_001**: Two-way peg protocol with peg_in and peg_out transaction types
- **FERR_002**: Sidechain VM integration (EVM-compatible, WASM, custom UTXO-based VM)
- **FERR_003**: Inter-sidechain communication protocols
- **BLS Threshold Signatures**: Federation control using masternode BLS signatures
- **Fraud Proof Mechanisms**: Challenge-response system for security

## Contributing

When contributing to the sidechain implementation:

1. **Follow the API patterns** established in existing code
2. **Add comprehensive tests** for new functionality
3. **Update documentation** for any API changes
4. **Ensure security** considerations are addressed
5. **Maintain compatibility** with RCTB specifications

## License

This implementation is part of the Rusty Coin project and follows the same licensing terms.
