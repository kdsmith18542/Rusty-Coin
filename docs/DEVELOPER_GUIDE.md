# Rusty Coin Developer Guide

**Version:** 1.0.0  
**Last Updated:** Based on current implementation status  
**Status:** Draft

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Architecture Overview](#architecture-overview)
4. [Core Concepts](#core-concepts)
5. [Development Setup](#development-setup)
6. [Building Transactions](#building-transactions)
7. [JSON-RPC API](#json-rpc-api)
8. [Testing](#testing)
9. [Contributing](#contributing)

---

## Introduction

Rusty Coin is a blockchain platform implementing a hybrid consensus mechanism combining Proof-of-Work (PoW) and Proof-of-Stake (PoS), with Masternode services and sidechain support.

### Key Features

- **Hybrid Consensus:** OxideHash PoW + OxideSync PoS
- **Masternodes:** Provide OxideSend (instant transactions) and FerrousShield (privacy mixing)
- **FerrisScript:** Custom scripting language for transaction validation
- **Bicameral Governance:** PoS tickets + Masternodes vote on proposals
- **Sidechains:** Two-way peg with BLS threshold signatures
- **Post-Quantum Ready:** Migration path to CRYSTALS-Dilithium

---

## Getting Started

### Prerequisites

- Rust 1.70+ (stable or nightly)
- Cargo package manager
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/rusty-coin/rusty-coin.git
cd rusty-coin

# Build all crates
cargo build --release

# Run tests
cargo test

# Run specific crate tests
cargo test --package rusty-core
```

### Running a Node

```bash
# Build the node binary
cargo build --release --bin rustyd

# Run the node
./target/release/rustyd --datadir ./data --network mainnet
```

---

## Architecture Overview

### Crate Structure

- **`rusty-core`**: Core blockchain logic, consensus, state management
- **`rusty-consensus`**: Consensus rules, validation, PoW/PoS
- **`rusty-crypto`**: Cryptographic primitives (BLAKE3, Ed25519, OxideHash)
- **`rusty-shared-types`**: Shared data structures (Block, Transaction, etc.)
- **`rusty-p2p`**: Peer-to-peer networking (libp2p)
- **`rusty-jsonrpc`**: JSON-RPC API server
- **`rusty-governance`**: Governance protocol implementation
- **`rusty-masternode`**: Masternode protocol (PoSe, OxideSend, FerrousShield)
- **`rusty-node`**: Full node implementation

### Module Organization

```
rusty-core/
├── consensus/        # Blockchain consensus logic
├── script/           # FerrisScript interpreter
├── sidechain/        # Sidechain protocol
├── state/            # State management (UTXO, MPT)
└── governance/       # Governance integration
```

---

## Core Concepts

### Block Structure

A Rusty Coin block contains:
- **Header**: Version, height, hashes, timestamp, difficulty, nonce
- **Transactions**: Standard, Coinbase, and special transaction types
- **Ticket Votes**: PoS votes from selected tickets

### Transaction Types

- **Standard**: Regular value transfer
- **Coinbase**: Block reward transaction
- **MasternodeRegister**: Register a masternode
- **TicketPurchase**: Purchase a PoS ticket
- **GovernanceProposal**: Submit a governance proposal
- **GovernanceVote**: Vote on a proposal
- And more...

### FerrisScript

FerrisScript is a stack-based scripting language for transaction validation:

```rust
// P2PKH script example
// script_sig: <signature> <pubkey>
// script_pubkey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
```

### Consensus Mechanisms

1. **Proof-of-Work (OxideHash)**: Memory-hard PoW algorithm
2. **Proof-of-Stake (OxideSync)**: Ticket-based voting system
3. **Masternode Services**: OxideSend and FerrousShield

---

## Development Setup

### Setting Up Development Environment

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install development tools
cargo install cargo-fuzz      # For fuzz testing
cargo install cargo-tarpaulin # For code coverage
cargo install cargo-audit     # For security auditing
```

### IDE Setup

Recommended: Visual Studio Code with rust-analyzer extension

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test --package rusty-core --test integration_tests

# With output
cargo test -- --nocapture

# Property-based tests
cargo test --package rusty-core --test consensus_proptest
```

---

## Building Transactions

### Creating a Standard Transaction

```rust
use rusty_shared_types::{Transaction, TxInput, TxOutput, OutPoint};

// Create transaction inputs
let input = TxInput::from_outpoint(
    OutPoint {
        txid: [1u8; 32],
        vout: 0,
    },
    vec![], // script_sig (signature + pubkey)
    0xffffffff,
    vec![],
);

// Create transaction outputs
let output = TxOutput {
    value: 1000000, // 0.01 RUST
    script_pubkey: vec![0x76, 0xA9, 0x14, /* pubkeyhash */, 0x88, 0xAC],
    memo: None,
};

// Create transaction
let tx = Transaction::Standard {
    version: 1,
    inputs: vec![input],
    outputs: vec![output],
    lock_time: 0,
    fee: 1000,
    witness: vec![],
};
```

### Creating a Governance Proposal

```rust
use rusty_shared_types::governance::{GovernanceProposal, ProposalType};

let proposal = GovernanceProposal {
    proposal_id: [1u8; 32],
    proposer: [2u8; 32],
    proposal_type: ProposalType::ParameterChange,
    title: "Increase block size".to_string(),
    description_hash: [3u8; 32],
    voting_period: 1000,
    start_block_height: 100,
    collateral_amount: 1000000,
    // ... other fields
};
```

---

## JSON-RPC API

### Connecting to RPC

```bash
# Using curl
curl -X POST http://localhost:8332/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getblockchaininfo",
    "params": [],
    "id": 1
  }'
```

### Common Methods

#### `getblockchaininfo`
Returns information about the blockchain state.

**Response:**
```json
{
  "chain": "mainnet",
  "blocks": 12345,
  "headers": 12345,
  "bestblockhash": "...",
  "difficulty": 1.5,
  "mediantime": 1234567890
}
```

#### `getbalance`
Returns wallet balance.

**Parameters:**
- `minconf` (optional): Minimum confirmations (default: 1)

**Response:**
```json
{
  "confirmed": 1000000000,
  "unconfirmed": 50000000,
  "total": 1050000000
}
```

#### `send_raw_transaction`
Broadcasts a raw transaction to the network.

**Parameters:**
- `hex`: Hex-encoded transaction

**Response:**
```json
{
  "txid": "..."
}
```

### WebSocket Support

Connect to WebSocket endpoint for real-time notifications:

```javascript
const ws = new WebSocket('ws://localhost:8333');

ws.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  console.log('Notification:', notification);
};

// Subscribe to new blocks
ws.send(JSON.stringify({
  jsonrpc: "2.0",
  method: "subscribe_newblock",
  id: 1
}));
```

---

## Testing

### Unit Tests

Located in `*/tests/` directories or `#[cfg(test)]` modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Test implementation
    }
}
```

### Integration Tests

Located in `*/tests/integration_tests.rs`:

```rust
#[test]
fn test_integration() {
    // Multi-component test
}
```

### Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzz target
cargo fuzz run fuzz_ferrisscript
```

### Property-Based Testing

Using `proptest` for invariant testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_property(input in 0u64..1000u64) {
        // Test property holds for all inputs
    }
}
```

---

## Contributing

### Code Style

- Follow Rust standard formatting: `cargo fmt`
- Run clippy: `cargo clippy -- -D warnings`
- All public APIs must have rustdoc comments
- Tests required for new features

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Ensure all tests pass
5. Update documentation
6. Submit pull request

### Specification Compliance

All implementations must match specifications in `docs/specs/`. Run:

```bash
python3 scripts/verify_specs.py
```

---

## Additional Resources

- **Specifications**: `docs/specs/` - Formal protocol specifications
- **API Reference**: Generated rustdoc (run `cargo doc --open`)
- **Examples**: `examples/` directory (when available)

---

## Security Best Practices

1. **Never commit private keys or seeds**
2. **Validate all user input**
3. **Use secure random number generation**
4. **Follow principle of least privilege**
5. **Regular security audits**

---

## Support

- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: See `docs/` directory
- **Specifications**: See `docs/specs/` directory

