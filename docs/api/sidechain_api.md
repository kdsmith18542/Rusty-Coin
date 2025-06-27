# Sidechain API Documentation

This document provides comprehensive API documentation for the Rusty Coin sidechain implementation.

## Table of Contents

1. [Core Structures](#core-structures)
2. [Two-Way Peg API](#two-way-peg-api)
3. [Fraud Proof API](#fraud-proof-api)
4. [Proof Validation API](#proof-validation-api)
5. [Cross-Chain Transactions](#cross-chain-transactions)
6. [Error Handling](#error-handling)
7. [Examples](#examples)

## Core Structures

### SidechainState

The main state manager for all sidechain operations.

```rust
pub struct SidechainState {
    pub registered_sidechains: HashMap<Hash, SidechainInfo>,
    pub current_blocks: HashMap<Hash, SidechainBlock>,
    pub pending_cross_chain_txs: HashMap<Hash, Vec<CrossChainTransaction>>,
    pub active_fraud_proofs: Vec<FraudProof>,
    pub federation_epochs: HashMap<u64, Vec<MasternodeID>>,
    pub peg_manager: TwoWayPegManager,
    pub proof_validator: SidechainProofValidator,
    pub fraud_proof_manager: FraudProofManager,
}
```

#### Methods

##### `new() -> Self`
Creates a new sidechain state with default configuration.

##### `register_sidechain(info: SidechainInfo) -> Result<(), String>`
Registers a new sidechain with the given information.

**Parameters:**
- `info`: Sidechain configuration and metadata

**Returns:**
- `Ok(())` on success
- `Err(String)` if sidechain already exists or validation fails

##### `process_sidechain_block(block: SidechainBlock) -> Result<(), String>`
Processes and validates a new sidechain block.

**Parameters:**
- `block`: Complete sidechain block to process

**Returns:**
- `Ok(())` if block is valid and processed
- `Err(String)` if validation fails

##### `get_stats() -> SidechainStats`
Returns comprehensive statistics about sidechain operations.

### SidechainBlock

Represents a complete sidechain block.

```rust
pub struct SidechainBlock {
    pub header: SidechainBlockHeader,
    pub transactions: Vec<SidechainTransaction>,
    pub cross_chain_transactions: Vec<CrossChainTransaction>,
    pub fraud_proofs: Vec<FraudProof>,
    pub federation_signature: Option<FederationSignature>,
}
```

#### Methods

##### `new(header: SidechainBlockHeader, transactions: Vec<SidechainTransaction>, cross_chain_transactions: Vec<CrossChainTransaction>) -> Self`
Creates a new sidechain block.

##### `hash() -> Hash`
Calculates the cryptographic hash of the block.

##### `verify() -> Result<(), String>`
Verifies the integrity and validity of the block.

##### `calculate_merkle_root() -> Hash`
Calculates the merkle root of all transactions.

##### `is_anchored() -> bool`
Checks if the block is anchored to the mainchain.

### SidechainTransaction

Represents a transaction within a sidechain.

```rust
pub struct SidechainTransaction {
    pub version: u32,
    pub inputs: Vec<SidechainTxInput>,
    pub outputs: Vec<SidechainTxOutput>,
    pub lock_time: u64,
    pub vm_data: Option<VMExecutionData>,
    pub fee: u64,
}
```

#### Methods

##### `hash() -> Hash`
Calculates the transaction hash.

##### `verify() -> Result<(), String>`
Validates the transaction structure and logic.

##### `txid() -> Hash`
Returns the transaction ID (same as hash).

##### `total_output_value() -> u64`
Calculates the sum of all output values.

## Two-Way Peg API

### TwoWayPegManager

Manages peg-in and peg-out operations between mainchain and sidechains.

#### Configuration

```rust
pub struct TwoWayPegConfig {
    pub min_peg_in_confirmations: u32,
    pub min_peg_out_confirmations: u32,
    pub federation_threshold: u32,
    pub min_peg_amount: u64,
    pub max_peg_amount: u64,
    pub peg_timeout_blocks: u64,
    pub peg_fee_rate: u64,
}
```

#### Methods

##### `new(config: TwoWayPegConfig) -> Self`
Creates a new peg manager with the specified configuration.

##### `initiate_peg_in(mainchain_tx: Transaction, target_sidechain_id: Hash, sidechain_recipient: Vec<u8>, amount: u64, asset_id: Hash) -> Result<Hash, String>`
Initiates a peg-in operation.

**Parameters:**
- `mainchain_tx`: Transaction that locks funds on mainchain
- `target_sidechain_id`: Destination sidechain identifier
- `sidechain_recipient`: Recipient address on sidechain
- `amount`: Amount to peg in
- `asset_id`: Asset type identifier

**Returns:**
- `Ok(Hash)`: Peg operation ID
- `Err(String)`: Error message if validation fails

##### `initiate_peg_out(sidechain_tx: SidechainTransaction, source_sidechain_id: Hash, mainchain_recipient: Vec<u8>, amount: u64, asset_id: Hash) -> Result<Hash, String>`
Initiates a peg-out operation.

##### `process_confirmations(block_height: u64) -> Result<(), String>`
Processes confirmations for pending peg operations.

##### `add_federation_signature(peg_id: Hash, signature: FederationSignature) -> Result<(), String>`
Adds a federation signature to authorize a peg operation.

##### `get_peg_status(peg_id: &Hash) -> Option<PegStatus>`
Returns the current status of a peg operation.

### Peg Status Types

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

## Fraud Proof API

### FraudProofManager

Manages fraud proof challenges and verification.

#### Configuration

```rust
pub struct FraudProofConfig {
    pub challenge_period_blocks: u64,
    pub min_challenge_bond: u64,
    pub fraud_proof_reward: u64,
    pub false_proof_penalty: u64,
    pub max_proof_size: usize,
    pub verification_timeout_blocks: u64,
}
```

#### Methods

##### `new(config: FraudProofConfig) -> Self`
Creates a new fraud proof manager.

##### `submit_fraud_proof(fraud_proof: FraudProof, challenger_bond: u64) -> Result<Hash, String>`
Submits a fraud proof challenge.

**Parameters:**
- `fraud_proof`: The fraud proof evidence
- `challenger_bond`: Bond posted by challenger

**Returns:**
- `Ok(Hash)`: Challenge ID
- `Err(String)`: Error if validation fails

##### `submit_response(challenge_id: Hash, response: FraudProofResponse) -> Result<(), String>`
Submits a response to a fraud proof challenge.

##### `process_challenges(block_height: u64) -> Result<(), String>`
Processes pending fraud proof challenges.

##### `get_challenge_status(challenge_id: &Hash) -> Option<FraudProofStatus>`
Returns the status of a fraud proof challenge.

### Fraud Types

```rust
pub enum FraudType {
    InvalidStateTransition,
    DoubleSpending,
    InvalidCrossChainTx,
    UnauthorizedSignature,
    InvalidVMExecution,
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

## Proof Validation API

### SidechainProofValidator

Validates various types of sidechain proofs.

#### Configuration

```rust
pub struct ProofValidationConfig {
    pub min_federation_signatures: u32,
    pub max_proof_size: usize,
    pub strict_validation: bool,
    pub max_merkle_depth: u32,
    pub verification_timeout_ms: u64,
}
```

#### Methods

##### `new(config: ProofValidationConfig) -> Self`
Creates a new proof validator.

##### `validate_sidechain_block(block: &SidechainBlock) -> ProofValidationResult`
Validates a complete sidechain block.

##### `update_federation_keys(epoch: u64, public_keys: Vec<Vec<u8>>)`
Updates federation public keys for an epoch.

##### `add_trusted_header(header: BlockHeader)`
Adds a trusted mainchain header for validation.

### Validation Results

```rust
pub enum ProofValidationResult {
    Valid,
    Invalid(String),
    Error(String),
    Timeout,
}
```

## Cross-Chain Transactions

### CrossChainTransaction

Represents transactions that span multiple chains.

#### Transaction Types

```rust
pub enum CrossChainTxType {
    PegIn,
    PegOut,
    SidechainToSidechain,
}
```

#### Builder Pattern

```rust
// Create a peg-in transaction
let peg_in = CrossChainTxBuilder::build_peg_in(
    mainchain_id,
    sidechain_id,
    amount,
    asset_id,
    recipient_address,
);

// Create a peg-out transaction
let peg_out = CrossChainTxBuilder::build_peg_out(
    sidechain_id,
    mainchain_id,
    amount,
    asset_id,
    recipient_address,
);

// Create an inter-sidechain transaction
let inter_sidechain = CrossChainTxBuilder::build_inter_sidechain(
    source_sidechain_id,
    destination_sidechain_id,
    amount,
    asset_id,
    recipient_address,
)?;
```

### Utility Functions

#### CrossChainTxUtils

```rust
// Validate a batch of transactions
CrossChainTxUtils::validate_batch(&transactions)?;

// Calculate total value for an asset
let total = CrossChainTxUtils::calculate_batch_value(&transactions, &asset_id);

// Group transactions by type
let groups = CrossChainTxUtils::group_by_type(&transactions);

// Filter transactions by chain
let chain_txs = CrossChainTxUtils::filter_by_chain(&transactions, &chain_id);
```

## Error Handling

All API methods that can fail return `Result<T, String>` where the error string provides detailed information about the failure reason.

### Common Error Types

- **Validation Errors**: Invalid parameters, amounts, or addresses
- **State Errors**: Operations on non-existent or invalid state
- **Signature Errors**: Invalid or insufficient signatures
- **Timeout Errors**: Operations that exceed time limits
- **Configuration Errors**: Invalid configuration parameters

## Examples

### Complete Peg-In Flow

```rust
use rusty_core::sidechain::*;

// Initialize sidechain state
let mut state = SidechainState::new();

// Register sidechain
let sidechain_info = SidechainInfo {
    sidechain_id: [1u8; 32],
    name: "Test Sidechain".to_string(),
    peg_address: vec![1, 2, 3, 4],
    federation_members: vec![],
    current_epoch: 1,
    vm_type: VMType::EVM,
    genesis_block_hash: [0u8; 32],
    creation_timestamp: 1234567890,
    min_federation_threshold: 2,
};

state.register_sidechain(sidechain_info)?;

// Initiate peg-in
let mainchain_tx = create_mainchain_transaction();
let peg_id = state.initiate_peg_in(
    mainchain_tx,
    [1u8; 32], // sidechain_id
    vec![5, 6, 7], // recipient
    5000000, // amount
    [2u8; 32], // asset_id
)?;

// Process confirmations
state.process_peg_confirmations(10)?;

// Add federation signature
let signature = create_federation_signature(&peg_id);
state.add_peg_federation_signature(peg_id, signature)?;

// Check status
let status = state.get_peg_status(&peg_id);
println!("Peg status: {:?}", status);
```

### Fraud Proof Submission

```rust
// Create fraud proof
let fraud_proof = FraudProof {
    fraud_type: FraudType::InvalidStateTransition,
    fraud_block_height: 100,
    fraud_tx_index: Some(5),
    evidence: create_fraud_evidence(),
    challenger_address: vec![1, 2, 3],
    challenge_bond: 2000000,
    response_deadline: 200,
};

// Submit fraud proof
let challenge_id = state.submit_fraud_proof(fraud_proof, 2000000)?;

// Submit response (from accused party)
let response = FraudProofResponse {
    responder_id: masternode_id,
    response_data: vec![4, 5, 6],
    counter_evidence: vec![7, 8, 9],
    signature: vec![10, 11, 12],
    timestamp: 1234567890,
};

state.submit_fraud_proof_response(challenge_id, response)?;

// Process challenges
state.process_fraud_proof_challenges(150)?;
```

For more detailed examples and advanced usage patterns, see the test files in the `tests/` directory.
