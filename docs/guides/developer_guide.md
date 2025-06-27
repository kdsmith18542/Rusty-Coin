# Rusty-Coin Developer Guide

This guide provides a comprehensive overview for developers looking to understand, build, and contribute to the Rusty-Coin project.

## Table of Contents

1.  [Project Setup](#1-project-setup)
    *   [Prerequisites](#prerequisites)
    *   [Cloning the Repository](#cloning-the-repository)
    *   [Building the Project](#building-the-project)
    *   [Running the Node](#running-the-node)
2.  [Core Concepts](#2-core-concepts)
    *   [Blockchain Basics](#blockchain-basics)
    *   [Transaction Types](#transaction-types)
    *   [Consensus Mechanism (PoW/PoS Hybrid)](#consensus-mechanism-powpos-hybrid)
    *   [Masternodes](#masternodes)
    *   [On-Chain Governance (Homestead Accord)](#on-chain-governance-homestead-accord)
3.  [Module Overviews](#3-module-overviews)
    *   [`rusty-core`](#rusty-core)
    *   [`rusty-jsonrpc`](#rusty-jsonrpc)
    *   [`rusty-p2p`](#rusty-p2p)
    *   [`rusty-shared-types`](#rusty-shared-types)
    *   [`rusty-crypto`](#rusty-crypto)
    *   [`rusty-consensus`](#rusty-consensus)
    *   [`rusty-masternode`](#rusty-masternode)
4.  [Contribution Guidelines](#4-contribution-guidelines)
    *   [Code Style](#code-style)
    *   [Testing](#testing)
    *   [Submitting Pull Requests](#submitting-pull-requests)

---

## 1. Project Setup

### Prerequisites

Before you begin, ensure you have the following installed:

*   **Rust**: Install Rust and Cargo using `rustup`:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    Or, for Windows, download from [rustup.rs](https://rustup.rs/).

*   **Git**: For cloning the repository.

### Cloning the Repository

```bash
git clone https://github.com/your-repo/rusty-coin.git
cd rusty-coin
```

### Building the Project

To build all crates in the workspace:

```bash
cargo build --all
```

To build a specific crate (e.g., `rusty-node`):

```bash
cargo build --package rusty-node
```

For optimized release builds:

```bash
cargo build --release --all
```

### Running the Node

To run the Rusty-Coin node with default settings:

```bash
target/release/rusty-node.exe # On Windows
./target/release/rusty-node # On Linux/macOS
```

For more options, use the `--help` flag:

```bash
target/release/rusty-node.exe --help
```

---

## 2. Core Concepts

### Blockchain Basics

Rusty-Coin operates on a decentralized blockchain. Each block contains a header and a list of transactions. Blocks are chained together cryptographically, ensuring immutability and integrity.

### Transaction Types

Rusty-Coin supports various transaction types, including:

*   **Standard Transactions**: For transferring coins between addresses.
*   **Coinbase Transactions**: Special transactions that create new coins as a reward for miners/stakers.
*   **Masternode Register/Update Transactions**: For registering and managing Masternodes.
*   **Ticket Purchase/Redemption Transactions**: For participating in Proof-of-Stake.
*   **Governance Proposal/Vote Transactions**: For on-chain governance.

### Consensus Mechanism (PoW/PoS Hybrid)

Rusty-Coin utilizes a hybrid Proof-of-Work (PoW) and Proof-of-Stake (PoS) consensus mechanism to secure the network and validate transactions. This hybrid approach aims to combine the security of PoW with the efficiency and decentralization benefits of PoS.

### Masternodes

Masternodes are special full nodes that perform various services for the network, such as enhancing privacy (OxideSend), facilitating instant transactions (FerrousShield), and participating in governance. They require a collateral deposit.

### On-Chain Governance (Homestead Accord)

The Homestead Accord is Rusty-Coin's bicameral on-chain governance system, enabling both PoS ticket holders and Masternode operators to vote on protocol upgrades, parameter changes, and treasury spending proposals.

---

## 3. Module Overviews

### `rusty-core`

The `rusty-core` crate is the heart of the Rusty-Coin blockchain. It implements the fundamental consensus rules, block validation, transaction processing, and state management (UTXO set, live tickets pool, active proposals).

### `rusty-jsonrpc`

The `rusty-jsonrpc` crate provides the JSON-RPC API server for the Rusty-Coin node. It exposes methods for querying blockchain data, sending transactions, and interacting with the governance system.

### `rusty-p2p`

The `rusty-p2p` crate handles the peer-to-peer network communication. It manages peer discovery, connection establishment, message exchange, and network synchronization.

### `rusty-shared-types`

The `rusty-shared-types` crate defines common data structures and types used across multiple Rusty-Coin crates, ensuring consistency and interoperability.

### `rusty-crypto`

The `rusty-crypto` crate encapsulates cryptographic primitives used throughout the Rusty-Coin project, including hashing (BLAKE3) and digital signatures (Ed25519).

### `rusty-consensus`

The `rusty-consensus` crate specifically focuses on the Proof-of-Work and Proof-of-Stake consensus algorithms, including difficulty adjustment and voter selection.

### `rusty-masternode`

The `rusty-masternode` crate defines the logic and data structures related to Masternodes, including registration, status management, and participation in network services.

---

## 4. Contribution Guidelines

### Code Style

Rusty-Coin follows standard Rust formatting and clippy lints. Please ensure your code is formatted with `rustfmt` and passes `clippy` checks.

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

### Testing

All new features and bug fixes should be accompanied by appropriate unit and/or integration tests. Run tests with:

```bash
cargo test --all
```

### Submitting Pull Requests

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Implement your changes, adhering to code style and including tests.
4.  Write clear and concise commit messages.
5.  Submit a pull request to the `main` branch, describing your changes in detail. 