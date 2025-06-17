# Rusty Coin ($RUST)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A peer-to-peer digital currency engineered for resilience, decentralization, and longevity, built entirely in Rust.

## Key Features

- **Hybrid PoW/PoS Consensus**: Combines Proof-of-Work mining with Proof-of-Stake validation
- **OxideHash Algorithm**: Custom ASIC-resistant hashing algorithm
- **QuantumGuard Ready**: Designed for future post-quantum cryptography
- **Ferrite Sidechains**: Framework for pegged sidechains with advanced functionality
- **Homestead Model**: 100% community-driven with no pre-mine or treasury

## Architecture

- **Language**: Rust (2021 Edition or later)
- **Node Implementation**: Single monolithic binary with modular crates
- **Concurrency**: Tokio runtime for async/await operations
- **Storage**: Custom key-value store optimized for blockchain data

## Getting Started

### Prerequisites

- Rust 1.70+ (stable)
- Clang (for cryptographic libraries)
- Protobuf compiler

### Installation

```sh
git clone https://github.com/your-repo/rusty-coin.git
cd rusty-coin
cargo build --release
```

### Running a Node

```sh
./target/release/rusty-coin-node --network mainnet
```

## Roadmap

| Phase       | Timeline | Milestones |
|-------------|----------|------------|
| Genesis     | Q4 2025  | Testnet launch, security audits |
| Homestead   | Q1 2026  | Mainnet launch, GUI wallet |
| Forge       | Q3 2026  | Masternode activation |
| Metropolis  | 2027     | On-chain governance, sidechains |

## Contributing

Contributions are welcome! Please see our [Contribution Guidelines](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE) for details.