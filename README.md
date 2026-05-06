# Rusty-Coin

A high-performance, modular, and secure cryptocurrency implementation written entirely in Rust.

Rusty-Coin is designed with modularity at its core, allowing for easy experimentation with different consensus algorithms, cryptographic primitives, and network protocols. It aims to provide a robust foundation for building next-generation decentralized applications and financial systems.

## Project Structure

The project is organized into several modular crates:

- **[rusty-core](./rusty-core)**: The central hub of the system, coordinating consensus, networking, and state management.
- **[rusty-consensus](./rusty-consensus)**: Pluggable consensus engines (PoW, PoS, etc.).
- **[rusty-crypto](./rusty-crypto)**: High-performance cryptographic primitives and key management.
- **[rusty-p2p](./rusty-p2p)**: Libp2p-based peer-to-peer networking layer.
- **[rusty-governance](./rusty-governance)**: On-chain governance and parameter management.
- **[rusty-masternode](./rusty-masternode)**: Masternode network and specialized services.
- **[rusty-wallet](./rusty-wallet)**: Secure wallet implementation and key storage.
- **[rusty-rpc](./rusty-rpc)**: JSON-RPC interface for interacting with the node.
- **[rusty-types](./rusty-types)** & **[rusty-shared-types](./rusty-shared-types)**: Common data structures used across the ecosystem.

## Key Features

- **Modular Consensus**: Easily switch between Proof-of-Work, Proof-of-Stake, or custom consensus mechanisms.
- **Advanced Networking**: Built on libp2p with custom protocols for efficient block and transaction propagation.
- **Robust Governance**: Built-in mechanisms for protocol upgrades and parameter adjustments.
- **Masternode Support**: High-availability nodes providing additional services and security.
- **Performance Optimized**: Leverages Rust's safety and performance for a high-throughput blockchain.
- **Sidechain Support**: Native support for two-way pegged sidechains and cross-chain communication.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf) (for some components)

### Building

To build the entire workspace:

```bash
cargo build --release
```

### Running a Node

To start a full node on the default network:

```bash
cargo run --release -p rusty-node
```

For detailed instructions, see the **[Build Instructions](./BUILD_INSTRUCTIONS.md)** and **[Developer Guide](./docs/DEVELOPER_GUIDE.md)**.

## Testing

Run the full test suite:

```bash
cargo test
```

We also provide several integration test scripts in the `scripts/` directory for simulating network behavior and validating consensus.

## Documentation

Comprehensive documentation can be found in the `docs/` directory:
- [API Reference](./docs/API_REFERENCE.md)
- [Developer Guide](./docs/DEVELOPER_GUIDE.md)
- [Performance Analysis](./docs/PERFORMANCE.md)

## Contributing

We welcome contributions! Please read our **[Contributing Guidelines](./CONTRIBUTING.md)** before submitting a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
