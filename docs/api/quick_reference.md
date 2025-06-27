# Sidechain API Quick Reference

## Core Types

```rust
// Main state manager
let mut state = SidechainState::new();

// Block structures
let block = SidechainBlock::new(header, transactions, cross_chain_txs);
let header = SidechainBlockHeader::new(prev_hash, merkle_root, ...);
let tx = SidechainTransaction { version, inputs, outputs, ... };

// Cross-chain transactions
let cross_tx = CrossChainTransaction::new(tx_type, source, dest, amount, ...);
```

## Quick Operations

### Register Sidechain

```rust
let info = SidechainInfo {
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
state.register_sidechain(info)?;
```

### Peg-In (Mainchain → Sidechain)

```rust
let peg_id = state.initiate_peg_in(
    mainchain_tx,      // Transaction locking funds
    sidechain_id,      // Target sidechain
    recipient_addr,    // Recipient on sidechain
    amount,           // Amount to transfer
    asset_id,         // Asset type
)?;
```

### Peg-Out (Sidechain → Mainchain)

```rust
let peg_id = state.initiate_peg_out(
    burn_tx,          // Transaction burning assets
    sidechain_id,     // Source sidechain
    recipient_addr,   // Recipient on mainchain
    amount,          // Amount to transfer
    asset_id,        // Asset type
)?;
```

### Process Block

```rust
state.process_sidechain_block(block)?;
```

### Submit Fraud Proof

```rust
let challenge_id = state.submit_fraud_proof(fraud_proof, bond_amount)?;
```

### Check Status

```rust
// Peg operation status
let status = state.get_peg_status(&peg_id);

// Fraud proof status
let status = state.get_fraud_proof_status(&challenge_id);

// Overall statistics
let stats = state.get_stats();
```

## Builder Patterns

### Cross-Chain Transaction Builder

```rust
// Peg-in
let peg_in = CrossChainTxBuilder::build_peg_in(
    mainchain_id, sidechain_id, amount, asset_id, recipient
);

// Peg-out
let peg_out = CrossChainTxBuilder::build_peg_out(
    sidechain_id, mainchain_id, amount, asset_id, recipient
);

// Inter-sidechain
let inter = CrossChainTxBuilder::build_inter_sidechain(
    source_id, dest_id, amount, asset_id, recipient
)?;
```

## Configuration

### Two-Way Peg Config

```rust
let config = TwoWayPegConfig {
    min_peg_in_confirmations: 6,
    min_peg_out_confirmations: 12,
    federation_threshold: 2,
    min_peg_amount: 100_000,
    max_peg_amount: 1_000_000_000_000,
    peg_timeout_blocks: 1440,
    peg_fee_rate: 1000,
};
```

### Fraud Proof Config

```rust
let config = FraudProofConfig {
    challenge_period_blocks: 1440,
    min_challenge_bond: 1_000_000,
    fraud_proof_reward: 10_000_000,
    false_proof_penalty: 5_000_000,
    max_proof_size: 10_000_000,
    verification_timeout_blocks: 144,
};
```

### Validation Config

```rust
let config = ProofValidationConfig {
    min_federation_signatures: 2,
    max_proof_size: 1_000_000,
    strict_validation: true,
    max_merkle_depth: 32,
    verification_timeout_ms: 5000,
};
```

## Status Enums

### Peg Status

```rust
pub enum PegStatus {
    Initiated,
    WaitingConfirmations { current: u32, required: u32 },
    WaitingFederationSignatures { received: u32, required: u32 },
    Completed,
    Failed { reason: String },
    TimedOut,
}
```

### Fraud Proof Status

```rust
pub enum FraudProofStatus {
    Pending,
    UnderVerification,
    Proven,
    Disproven,
    TimedOut,
    Withdrawn,
}
```

### Validation Result

```rust
pub enum ProofValidationResult {
    Valid,
    Invalid(String),
    Error(String),
    Timeout,
}
```

## VM Types

```rust
pub enum VMType {
    EVM,      // Ethereum Virtual Machine
    WASM,     // WebAssembly
    UtxoVM,   // Custom UTXO-based VM
    Native,   // Native Rust execution
}
```

## Fraud Types

```rust
pub enum FraudType {
    InvalidStateTransition,
    DoubleSpending,
    InvalidCrossChainTx,
    UnauthorizedSignature,
    InvalidVMExecution,
}
```

## Cross-Chain Transaction Types

```rust
pub enum CrossChainTxType {
    PegIn,                    // Mainchain → Sidechain
    PegOut,                   // Sidechain → Mainchain
    SidechainToSidechain,     // Sidechain → Sidechain
}
```

## Utility Functions

### Cross-Chain Utils

```rust
// Validate batch
CrossChainTxUtils::validate_batch(&transactions)?;

// Calculate total value
let total = CrossChainTxUtils::calculate_batch_value(&txs, &asset_id);

// Group by type
let groups = CrossChainTxUtils::group_by_type(&transactions);

// Filter by chain
let filtered = CrossChainTxUtils::filter_by_chain(&txs, &chain_id);

// Check readiness
let ready = CrossChainTxUtils::is_ready_for_execution(&tx, threshold);
```

## Error Handling

All operations return `Result<T, String>`:

```rust
match state.initiate_peg_in(tx, id, addr, amount, asset) {
    Ok(peg_id) => println!("Peg initiated: {:?}", peg_id),
    Err(error) => eprintln!("Peg failed: {}", error),
}
```

## Common Patterns

### Process Confirmations

```rust
// Process peg confirmations
state.process_peg_confirmations(block_height)?;

// Process fraud proof challenges
state.process_fraud_proof_challenges(block_height)?;
```

### Add Signatures

```rust
// Add federation signature to peg
state.add_peg_federation_signature(peg_id, signature)?;

// Add signature to cross-chain transaction
cross_tx.add_federation_signature(signature)?;
```

### Validation

```rust
// Validate block
let result = validator.validate_sidechain_block(&block);

// Validate transaction
tx.verify()?;

// Validate cross-chain transaction
cross_tx.verify()?;
```

## Testing Helpers

```rust
// Create test hash
fn test_hash(value: u8) -> Hash { [value; 32] }

// Create test masternode ID
fn test_masternode_id(value: u8) -> MasternodeID { MasternodeID([value; 32]) }

// Create test transaction
let tx = SidechainTransaction {
    version: 1,
    inputs: vec![/* ... */],
    outputs: vec![/* ... */],
    lock_time: 0,
    vm_data: None,
    fee: 1000,
};
```

## Statistics

```rust
let stats = state.get_stats();
println!("Sidechains: {}", stats.registered_sidechains);
println!("Active peg-ins: {}", stats.active_peg_ins);
println!("Active peg-outs: {}", stats.active_peg_outs);
println!("Fraud challenges: {}", stats.fraud_challenges);
println!("Proven frauds: {}", stats.proven_frauds);
```

## Federation Management

```rust
// Update federation
let members = vec![masternode_id1, masternode_id2, masternode_id3];
state.update_federation(epoch, members)?;

// Get federation members
let members = state.get_federation_members(epoch);
```

## Block Operations

```rust
// Create block
let block = SidechainBlock::new(header, transactions, cross_chain_txs);

// Calculate hash
let hash = block.hash();

// Verify block
block.verify()?;

// Add fraud proof
block.add_fraud_proof(fraud_proof)?;

// Set federation signature
block.set_federation_signature(signature)?;

// Check if anchored
let anchored = block.is_anchored();
```
