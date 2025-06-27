# Rusty-Coin Formal Protocol Specifications

This document serves as a central index for all formal protocol specifications of the Rusty-Coin blockchain. Each specification details a specific aspect of the protocol, ensuring clarity, consistency, and verifiability.

## Table of Contents

- [00 - Overview](specs/00%20-%20Overview.md)
- [01 - Block Structure](specs/01_block_structure.md)
- [02 - OxideHash (Proof-of-Work) Specification](specs/02_oxidehash_pow_spec.md)
- [03 - OxideSync (Proof-of-Stake) Specification](specs/03_oxidesync_pos_spec.md)
- [04 - FerrisScript Specification](specs/04_ferrisscript_spec.md)
- [05 - UTXO Model Specification](specs/05_utxo_model_spec.md)
- [06 - Masternode Protocol Specification](specs/06_masternode_protocol_spec.md)
- [07 - P2P Protocol Specification](specs/07_p2p_protocol_spec.md)
- [08 - On-Chain Governance (Homestead Accord) Specification](specs/08_json_rpc_spec.md)
- [09 - Governance Protocol Specification](specs/09_governance_protocol_spec.md)
- [10 - Sidechain Protocol Specification](specs/10_sidechain_protocol_spec.md)
- [11 - Post-Quantum Cryptography Migration Specification](specs/11_pq_migration_spec.md)
- [12 - Adaptive Block Size Adjustment Specification](specs/12_adaptive_block_size_spec.md)

---

## Specification Details

### [00 - Overview](specs/00%20-%20Overview.md)

Provides a high-level introduction to the Rusty-Coin project, its goals, and core design principles. It serves as a starting point for understanding the overall architecture.

### [01 - Block Structure](specs/01_block_structure.md)

Details the structure of a Rusty-Coin block, including the block header, transactions, and other components. It specifies the data fields and their serialization format.

### [02 - OxideHash (Proof-of-Work) Specification](specs/02_oxidehash_pow_spec.md)

Outlines the Proof-of-Work algorithm used in Rusty-Coin, including the hashing function (BLAKE3) and difficulty adjustment mechanism.

### [03 - OxideSync (Proof-of-Stake) Specification](specs/03_oxidesync_pos_spec.md)

Describes the Proof-of-Stake consensus mechanism, including ticket lifecycle, staking rewards, and voter selection.

### [04 - FerrisScript Specification](specs/04_ferrisscript_spec.md)

Defines the custom scripting language, FerrisScript, used for transaction validation. It includes opcodes, script execution rules, and security considerations.

### [05 - UTXO Model Specification](specs/05_utxo_model_spec.md)

Explains the Unspent Transaction Output (UTXO) model used in Rusty-Coin for tracking coin ownership and ensuring transaction validity.

### [06 - Masternode Protocol Specification](specs/06_masternode_protocol_spec.md)

Details the Masternode system, covering Masternode registration, collateral requirements, roles, and Proof-of-Service challenges.

### [07 - P2P Protocol Specification](specs/07_p2p_protocol_spec.md)

Describes the peer-to-peer communication protocol, including message types, network synchronization, and peer discovery.

### [08 - On-Chain Governance (Homestead Accord) Specification](specs/08_json_rpc_spec.md)

(Note: This file was previously misnamed as `08_json_rpc_spec.md` but contains governance details.)
Outlines the Homestead Accord, Rusty-Coin's on-chain governance system, specifying proposal submission, voting mechanics, and resolution.

### [09 - Governance Protocol Specification](specs/09_governance_protocol_spec.md)

Provides further details on the governance protocol, complementing the overview in `08_json_rpc_spec.md`.

### [10 - Sidechain Protocol Specification](specs/10_sidechain_protocol_spec.md)

Describes the protocol for interacting with sidechains, enabling cross-chain asset transfers and extended functionalities.

### [11 - Post-Quantum Cryptography Migration Specification](specs/11_pq_migration_spec.md)

Details the planned migration to post-quantum cryptographic algorithms to secure the network against future quantum computing threats.

### [12 - Adaptive Block Size Adjustment Specification](specs/12_adaptive_block_size_spec.md)

Specifies the algorithm for dynamically adjusting the block size limit based on network conditions and demand, aiming to optimize scalability. 