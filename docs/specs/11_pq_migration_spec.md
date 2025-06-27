Rusty Coin Formal Protocol Specifications: 11 - Network Resilience & State Management
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md, 05_utxo_model_spec.md (for UTXO Set definition), 06_masternode_protocol_spec.md (for Masternode List), 07_networking_api_spec.md (for P2P details).

11.1 Overview
Network resilience and efficient state management are critical for Rusty Coin's long-term operational stability, decentralization, and scalability. This document formally specifies the mechanisms and strategies employed to ensure the network can withstand various disruptions, manage its growing blockchain state efficiently, and allow new nodes to synchronize quickly.

11.2 State Management and Pruning
The full state of the Rusty Coin blockchain includes the UTXO_SET, LIVE_TICKETS_POOL, and MASTERNODE_LIST. As the blockchain grows, managing this state efficiently becomes crucial.

11.2.1 Full Node State:

Requirement: All full nodes MUST maintain the entire historical blockchain (all blocks from genesis) and the current, complete UTXO_SET (and other live states like LIVE_TICKETS_POOL, MASTERNODE_LIST). This enables full validation and serving historical data.

Storage: The rusty-consensus module stores this state persistently, typically using a high-performance key-value store (e.g., RocksDB) for fast random access and updates.

11.2.2 Optional Pruning (PRUNED_NODE_MODE):

Purpose: To allow nodes with limited storage capacity to participate in the network without storing the entire blockchain history.

Mechanism: A PRUNED_NODE_MODE MAY be implemented where a node stores only:

The complete UTXO_SET (and other live states).

A minimum recent history of blocks (e.g., PRUNED_BLOCK_HISTORY_DEPTH, typically 2880 blocks or 5 days, or a configurable amount).

The BlockHeader chain from genesis for chain validation.

Limitation: Pruned nodes cannot serve historical block data beyond their stored depth to other syncing nodes and cannot fully re-validate the entire blockchain from scratch without external help (e.g., downloading UTXO set snapshots).

Requirement: The decision to prune MUST be a user configuration option.

11.2.3 State Snapshots and Checkpoints (for Fast IBD):

Purpose: To significantly reduce the time and resources required for new full nodes to perform Initial Block Download (IBD) and catch up to the current network state.

Mechanism:

UTXO Set Snapshots: Periodically (e.g., every SNAPSHOT_INTERVAL_BLOCKS), core developers or trusted community members MAY create and publish cryptographically verifiable snapshots of the UTXO_SET (and other live states).

state_root Verification: Each snapshot is associated with a specific BlockHeight and its corresponding BlockHeader.state_root. New nodes can download such a snapshot and verify its integrity against the state_root included in the canonical blockchain's BlockHeader.

Fast Sync: A new node can:

Download all BlockHeaders from genesis to the current tip.

Download a recent, trusted UTXO_SET snapshot.

Verify the snapshot's integrity using the corresponding state_root.

Then, only download and validate blocks from the snapshot's BlockHeight onwards, processing transactions to incrementally build the UTXO_SET from that point.

Security: Reliance on externally provided snapshots requires trust in the snapshot provider or additional out-of-band verification steps. The core security of this method relies on the state_root being correctly computed and verified by standard IBD from genesis.

11.3 Network Synchronization and Initial Block Download (IBD)
Efficient and secure synchronization of new and offline nodes is vital for network health.

11.3.1 Headers-First Synchronization:

Mechanism: When a new node connects, it first requests BlockHeaders from its peers using the GetHeaders message (/rusty/block-sync/1.0). It builds the longest valid header chain.

Validation: Basic header validation (PoW, timestamps, prev_block_hash) is performed.

11.3.2 Block Body Download:

Mechanism: After synchronizing headers, the node requests full Block bodies for the blocks on the longest chain.

Verification: Full block validation (PoS votes, all transaction rules, merkle_root, state_root derivation) is performed sequentially.

11.3.3 Peer Selection for IBD:

Strategy: Nodes prioritize peers that are able to serve blocks quickly and reliably. Peer scoring (defined in 07_networking_api_spec.md) plays a role here.

Requirement: A node performing IBD MUST concurrently download blocks from multiple peers to optimize speed and redundancy.

11.4 Network Resilience and DoS Mitigation
The network is designed to be resilient against various types of attacks and disruptions.

11.4.1 Peer Scoring and Reputation System:

Mechanism: Nodes maintain a local, dynamic score for each connected peer. This score is adjusted based on peer behavior.

Positive Behavior: Serving valid blocks/transactions promptly, responding to requests, adhering to protocol rules.

Negative Behavior: Sending invalid messages, slow responses, spamming, sending stale blocks, repeatedly dropping connections.

Action: Low-scoring peers are prioritized for disconnection, and future connection attempts may be temporarily or permanently rejected. This helps isolate misbehaving nodes.

11.4.2 Resource Limiting:

Connection Limits: As defined in 07_networking_api_spec.md, strict limits on inbound and outbound connections prevent connection exhaustion attacks.

Mempool Limits: The node's mempool (unconfirmed transactions) has a configurable size limit (in bytes or transaction count) to prevent memory exhaustion by spam. Over-limit transactions are dropped (lowest fee-per-byte first).

Message Rate Limiting: As defined in 07_networking_api_spec.md, incoming P2P messages are rate-limited per peer to prevent flood attacks.

Buffer Sizes: Limits on incoming message buffer sizes prevent large message DoS attacks.

11.4.3 Invalid Message Handling:

Requirement: Any peer sending a syntactically or semantically invalid message (e.g., malformed header, invalid signature, non-conforming protocol message) MUST be immediately disconnected, and its peer score severely penalized. Repeated offenses lead to blacklisting.

11.4.4 Chain Reorganization Handling:

Principle: The rusty-consensus module is designed to gracefully handle chain reorganizations (forks).

Mechanism: When a node discovers a longer, valid alternative chain, it:

Identifies the common ancestor block.

Reverts blocks from the current tip back to the common ancestor, carefully unwinding state changes from the UTXO_SET (as specified in 5.3.2).

Applies blocks from the new, longer chain on top of the common ancestor, atomically updating the UTXO_SET.

Resistance: The combined PoW and PoS finality mechanisms (as specified in 03_oxidesync_pos_spec.md) make deep reorganizations extremely expensive and probabilistically impossible for an attacker to achieve consistently.

11.4.5 Automated Peer Blacklisting:

Mechanism: Nodes automatically blacklist peers that repeatedly exhibit malicious behavior (e.g., repeated invalid messages, consistent DoS attempts, detected malicious PoSe/Masternode actions).

Duration: Blacklisting can be temporary (e.g., 24 hours) or permanent for severe offenses.

11.4.6 Genesis Block and Checkpoints:

Genesis Block: The Genesis Block hash is hardcoded in the client, serving as the immutable starting point of the blockchain.

Checkpoints (Soft): Trusted checkpoints (e.g., hashes of specific past block heights) MAY be optionally included in client releases. These serve as strong, but not absolute, indicators of the correct chain, helping accelerate IBD for very old blocks and providing a reference point for detecting long-range attacks. They do not override consensus rules.