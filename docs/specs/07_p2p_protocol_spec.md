Rusty Coin Formal Protocol Specifications: 07 - Networking & API Layers
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md (for Block, Transaction definitions), rusty_crypto_spec.md (for hash/signature definitions).

7.1 Peer-to-Peer (P2P) Protocol
The Rusty Coin P2P layer is built upon libp2p, a modular networking stack, providing robust, scalable, and secure communication among rustyd full nodes. It facilitates block propagation, transaction gossiping, and peer discovery across the decentralized network.

7.1.1 libp2p Integration and Modules

Swarm Management: Each rustyd instance maintains a libp2p::Swarm instance, which is the central point for managing connections, listeners, and protocol handlers.

Transports: Nodes MUST support the following libp2p transports:

TCP/IP: Standard TCP/IPv4 and IPv6 for reliable stream-based communication.

mDNS (Multicast DNS): For local peer discovery within local area networks (LANs).

WebSockets (WS/WSS): For connecting to browser-based light clients or nodes behind restrictive firewalls/proxies.

Stream Multiplexing: yamux (or mplex) MUST be used for multiplexing multiple logical streams over a single underlying transport connection, improving resource efficiency.

Connection Security: noise (Noise Protocol Framework) MUST be used for authenticated and encrypted end-to-end communication between peers. This ensures message confidentiality and integrity, and peer authentication.

Peer Discovery (Kademlia DHT):

The Kademlia Distributed Hash Table (DHT) is employed for decentralized peer discovery and routing. Each node actively participates in the DHT to find and advertise other peers.

Nodes maintain a routing table (k-buckets) to store information about other peers (PeerId, Multiaddrs).

Bootstrapping: Nodes initially connect to a set of predefined, trusted seed nodes (hardcoded in initial client releases, or dynamically updated via network messages) to join the DHT.

Peer Identification: Each rustyd node MUST generate a unique PeerId using its long-term cryptographic identity key (Ed25519 Operator Key or similar).

7.1.2 Custom P2P Protocols

Rusty Coin defines specific application-level protocols over libp2p streams for efficient data exchange. All messages are serialized using bincode (canonical binary serialization).

/rusty/block-sync/1.0 (Block Synchronization Protocol):

Purpose: Enables efficient retrieval of historical blocks for Initial Block Download (IBD) and for catching up after temporary disconnections.

Message Types:

BlockRequest(start_height: u32, end_height: u32): A peer requests a range of blocks.

BlockResponse(blocks: Vec<Block>): A peer sends requested blocks. Max MAX_BLOCKS_PER_RESPONSE (e.g., 500 blocks).

GetHeaders(locator_hashes: Vec<[u8; 32]>, stop_hash: [u8; 32]): Standard Bitcoin-like getheaders for header synchronization.

Headers(headers: Vec<BlockHeader>): Response to GetHeaders.

Flow:

New nodes initiate GetHeaders to find the longest chain tip.

After headers are synchronized, nodes send BlockRequest for missing block bodies.

Peers prioritize serving BlockRequests from actively syncing nodes.

/rusty/tx-prop/1.0 (Transaction Propagation Protocol):

Purpose: Rapidly gossip new, unconfirmed Transactions across the network to ensure timely inclusion in miners' mempools.

Mechanism: Employs a gossipsub (publish-subscribe) model for efficient fanout.

Nodes subscribe to a common topic (e.g., /rusty/txs/v1).

When a node receives or creates a new valid Transaction (after local mempool validation):

It announces the TxID (using INV message, similar to Bitcoin) to a subset of its peers.

Peers that don't have the TxID in their mempool send a GetData(TxID) request.

The original node (or any peer with the data) sends the full Transaction data in a TxData(Transaction) message.

Security: Implements standard anti-spam measures:

Only relay Transactions that pass basic mempool validation (correct format, sufficient fees, non-duplicate).

Rate limiting on inbound INV and TxData messages per peer.

7.1.3 Connection Management and Peer Scoring

Connection Limits: Each node maintains MAX_OUTBOUND_CONNECTIONS (e.g., 8-16) and allows MAX_INBOUND_CONNECTIONS (e.g., 125).

Peer Scoring: A dynamic peer scoring system tracks the reliability and behavior of connected peers. Metrics include:

Successfully relaying valid blocks/transactions.

Responding to challenges (PoSe, IBD requests).

Latency and bandwidth.

Sending invalid messages or stale blocks.

Scores influence connection priority and potential blacklisting.

DoS Mitigation:

Rate Limiting: Enforce strict rate limits on incoming messages (INV, GetHeaders, BlockRequest) per peer.

Memory Limits: Limit mempool size and temporary buffer allocations for incoming data.

Challenge-Response: (For future, more advanced DoS) Peers that exhibit suspicious behavior might be subjected to cryptographic challenges before further communication.

Gating: New incoming connections might undergo a brief "gating" phase to verify basic protocol adherence before full integration.

7.1.4 Initial Block Download (IBD) Optimizations

Headers-First Sync: Nodes first synchronize all BlockHeaders to quickly identify the longest chain.

UTXO Set Snapshots: For faster IBD, nodes can download authenticated UTXO_SET snapshots (and LIVE_TICKETS_POOL / MASTERNODE_LIST snapshots) from trusted sources.

These snapshots are cryptographically bound by a state_root in a specific BlockHeader on the canonical chain.

Nodes verify the snapshot's integrity against the state_root and then only download and validate blocks after the snapshot height.

Compact Block Relay (Future): For real-time block propagation, a compact block relay protocol (similar to BIP152) can be implemented. This sends only TxIDs of transactions already in mempool, significantly reducing bandwidth.

7.2 JSON-RPC API
The rustyd full node exposes a JSON-RPC 2.0 compliant API for external applications to query blockchain data and interact with the node.

7.2.1 Standard Adherence

JSON-RPC 2.0: All requests and responses MUST strictly conform to the JSON-RPC 2.0 specification, including fields like jsonrpc, method, params, id, result, and error.

Transport Agnostic: The API is primarily exposed over HTTP, but may support WebSocket connections for real-time updates (e.g., mempool changes, new block notifications).

7.2.2 Authentication and Authorization

Authentication: Sensitive RPC methods (e.g., wallet management, node control) require authentication.

API Keys: Nodes can generate API keys (Bearer token in Authorization header) with specific permissions.

Basic Auth (for local/trusted environments): Username/password over HTTPS for basic security.

Authorization: RPC methods are categorized by required permissions:

Public (Read-Only): No authentication required (e.g., getblockcount, getblock).

Wallet Access: Requires wallet authentication (e.g., sendrawtransaction, getbalance).

Admin/Node Control: Requires administrative credentials (e.g., stopnode, setmocktime).

Secure Connection: All HTTP RPC communication MUST be over HTTPS to ensure confidentiality and integrity, especially when authentication is used.

7.2.3 Rate Limiting

Per-IP/Per-Authenticated-User Rate Limiting: To prevent Denial-of-Service attacks, all RPC endpoints are subject to configurable rate limits (e.g., X requests per second).

Burst Limits: Allow for temporary bursts of requests above the sustained rate.

7.2.4 Common RPC Methods (Examples)

This section outlines a subset of common methods. A full specification would list all methods, their parameters (type, required/optional), and detailed response structures.

Method Name

Description

Parameters (Example)

Return Value (Example)

Required Auth

getblockchaininfo

Returns general blockchain and chainstate information.

None

{"chain": "testnet", "blocks": 1234567, ...}

Public

getblockhash

Returns the hash of the block at a given height.

[height: u32]

"[u8; 32]"

Public

getblock

Returns the block data for a given block hash.

[block_hash: [u8; 32], verbosity: u32]

{"hash": "...", "height": 1234, "tx": [...], ...}

Public

getrawtransaction

Returns the raw transaction data.

[txid: [u8; 32], verbose: bool]

{"hex": "...", "vin": [...], "vout": [...], ...}

Public

sendrawtransaction

Broadcasts a raw, hex-encoded transaction to the network.

[hex_tx: String]

[u8; 32] (TxID)

Wallet Access

getmempoolinfo

Returns information about the node's mempool.

None

{"size": 123, "bytes": 45678, ...}

Public

getrawmempool

Returns all transaction IDs in the mempool.

[verbose: bool]

[["txid1", "txid2"], ...]

Public

getbalance

Returns the total balance for owned addresses in the wallet.

None

Decimal (RUST value)

Wallet Access

listunspent

Lists all unspent transaction outputs owned by the wallet.

[min_confirmations: u32, max_confirmations: u32, addresses: Vec<String>]

[{"txid": "...", "vout": 0, "amount": 100.0, ...}, ...]

Wallet Access

dumpprivkey

Reveals the private key for a given address.

[address: String]

String (Base58 encoded private key)

Wallet Access

getnewaddress

Generates a new address for receiving payments.

None

String (Rusty Coin address)

Wallet Access

masternodeinfo

Returns status info about the local masternode.

None

{"status": "ACTIVE", "pose_failures": 0, ...}

Admin/Node Control

stop

Shuts down the node.

None

"node stopping"

Admin/Node Control

- [x] Periodically refresh peer table and drop stale peers <!-- Complete: Implemented in start_with_shutdown loop. -->
- [x] Add NAT traversal (UPnP, hole punching) if required by spec <!-- NOT REQUIRED by current spec (07_p2p_protocol_spec.md) -->
- [x] Document design and update compliance checklist

### P2P: DoS Mitigation (PRIORITY 2)

