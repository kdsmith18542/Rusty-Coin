Rusty Coin Formal Protocol Specifications: 01 - Block Structure
Spec Version: 1.0.1
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, rusty_crypto_spec.md (for hash definitions, Ed25519 signatures), 04_ferrisscript_spec.md (for script definitions).

1.1 Overview
This document formally defines the fundamental data structures that comprise the Rusty Coin blockchain: BlockHeader, Block, Transaction, and their constituent parts (TxInput, TxOutput, TicketVote). These structures are designed for integrity, efficiency, and to support the OxideSync hybrid consensus protocol.

All byte arrays representing cryptographic hashes (e.g., prev_block_hash, merkle_root, state_root, TxID, TicketID) are 32 bytes in length and represent a BLAKE3 hash unless otherwise specified. Ed25519 signatures are 64 bytes.

1.2 BlockHeader Structure
The BlockHeader contains the metadata necessary for Proof-of-Work (PoW) validation and linking blocks in the blockchain. Its hash is the primary identifier of a block.

Binary Representation (Canonical Serialization Order):

Field

Type

Size (Bytes)

Description

Validation Constraints

version

u32

4

Protocol version of the block. Incremented for non-backward-compatible upgrades.

MUST be 1 for initial Mainnet. Future versions MUST be approved by governance.

height

u64

8

The height of this block in the blockchain, with the genesis block at height 0.

MUST be equal to the previous block's height + 1.

prev_block_hash

[u8; 32]

32

BLAKE3 hash of the entire serialized content of the previous block (header + ticket_votes + transactions).

MUST match the hash of the actual previous block in the canonical chain. 0x00...00 for Genesis Block.

merkle_root

[u8; 32]

32

BLAKE3 hash of the Merkle tree root of all transactions included in this block.

MUST be the correct Merkle root of Block.transactions.

state_root

[u8; 32]

32

BLAKE3 hash of the Merkle Patricia Trie root representing the global UTXO set and Ticket Pool state after processing this block.

MUST accurately reflect the state root after applying all transactions and PoS/MN updates.

timestamp

u64

8

Unix epoch timestamp (seconds) when the block was mined.

MUST be strictly greater than prev_block_hash.timestamp. MUST NOT be more than CURRENT_TIME_MAX_DRIFT (e.g., 2 hours) in the future relative to local median network time.

difficulty_target

u32

4

Encoded compact form of the Proof-of-Work difficulty target.

MUST match the network's current calculated difficulty target for this block height.

nonce

u64

8

An arbitrary 64-bit number used by miners to find a valid PoW hash.

When OxideHash(BlockHeader) is computed, the resulting hash MUST be less than the difficulty_target.

Total BlockHeader Size: 98 bytes (excluding variable-length data).

1.3 Block Structure
A Block aggregates the BlockHeader with the PoS votes confirming the previous block and the list of transactions included in this block.

Binary Representation (Canonical Serialization Order):

Field

Type

Description

Validation Constraints

header

BlockHeader

The block header containing metadata and PoW solution.

MUST conform to BlockHeader specifications (Section 1.2).

ticket_votes

Vec<TicketVote>

A vector of PoS TicketVote entries confirming header.prev_block_hash.

MUST contain exactly VOTERS_PER_BLOCK (e.g., 5) entries, including valid and invalid (e.g., non-participating) votes. At least MIN_VALID_VOTES_REQUIRED (e.g., 3) entries MUST be cryptographically valid. All votes MUST be from tickets selected by TICKET_VOTER_SELECTION for header.prev_block_hash.

transactions

Vec<Transaction>

A vector of all validated transactions included in this block.

MUST be less than or equal to MAX_ADAPTIVE_BLOCK_SIZE_BYTES. Each Transaction MUST conform to Transaction specifications (Section 1.5). No duplicate transactions (by TxID) within the block.

1.4 TicketVote Structure
A TicketVote represents a single Proof-of-Stake vote cast by a ticket holder, confirming the validity of the previous block.

Binary Representation (Canonical Serialization Order):

Field

Type

Size (Bytes)

Description

Validation Constraints

ticket_id

[u8; 32]

32

The unique identifier of the locked PoS ticket being used to vote (typically its TxID + VOutIndex hash).

MUST correspond to a LIVE ticket in the LIVE_TICKETS_POOL that was selected by the TICKET_VOTER_SELECTION algorithm for prev_block_hash.

block_hash

[u8; 32]

32

BLAKE3 hash of the block being voted on (typically the previous block).

MUST match the hash of the block the ticket is voting on.

vote

u8

1

The vote choice: 0 for Yes, 1 for No, 2 for Abstain.

MUST be a valid `VoteType` enum value.

signature

[u8; 64]

64

Ed25519 signature of the header.prev_block_hash using the ticket's private key.

MUST be a cryptographically valid Ed25519 signature of the prev_block_hash by the public key associated with ticket_id.

Total TicketVote Size: 129 bytes.

1.5 Transaction Structure
A Transaction represents the transfer of value or modification of state on the Rusty Coin blockchain. It consumes existing Unspent Transaction Outputs (UTXOs) as inputs and creates new UTXOs as outputs.

Binary Representation (Canonical Serialization Order):

Field

Type

Description

Validation Constraints

version

u32

Transaction version.

MUST be 1 for standard transactions. Future versions MUST be approved by governance.

inputs

Vec<TxInput>

A vector of transaction inputs.

MUST contain at least one TxInput. Total value of inputs MUST be greater than or equal to total value of outputs + fees. No duplicate inputs within the same transaction.

outputs

Vec<TxOutput>

A vector of transaction outputs.

MUST contain at least one TxOutput. Total number of outputs + total number of inputs MUST be less than MAX_TX_IO_COUNT (e.g., 250).

lock_time

u32

A block height or Unix timestamp after which this transaction is valid.

0 for immediate validity. If non-zero, transaction is only valid if current block height >= lock_time or current timestamp >= lock_time.

fee

u64

Transaction fee in satoshis (inputs_value - outputs_value).

MUST be greater than or equal to the calculated minimum relay fee based on transaction size.

witness

Vec<Vec<u8>>

Cryptographic witnesses for SegWit-like transactions (e.g., signatures, public keys) for each input.

MUST be valid for unlocking the corresponding TxInput.

1.5.1 Specific Transaction Types
The `Transaction` enum in the codebase defines several specific transaction types beyond a generic transfer, each with its own purpose and payload. These include:

- `Standard`: A basic value transfer transaction.
- `Coinbase`: The first transaction in a block, used to create new coins and collect block rewards.
- `MasternodeRegister`: Registers a new Masternode on the network.
- `MasternodeCollateral`: Designates collateral for a Masternode.
- `GovernanceProposal`: Submits a proposal to the governance system.
- `GovernanceVote`: Casts a vote on an active governance proposal.
- `TicketPurchase`: Used to acquire Proof-of-Stake tickets for voting.
- `TicketRedemption`: Used to redeem expired or mature Proof-of-Stake tickets.
- `MasternodeSlashTx`: A special transaction to penalize Masternodes for non-participation or malicious behavior.

Each of these types has specific validation rules and data structures, which are detailed in their respective protocol specifications (e.g., `03_oxidesync_pos_spec.md`, `06_masternode_protocol_spec.md`, `08_json_rpc_spec.md` for governance, etc.).

1.6 TxInput Structure
A TxInput references an existing UTXO to be spent and provides the script_sig to unlock it. It now also includes a witness field for segregated data.

Binary Representation (Canonical Serialization Order):

Field

Type

Description

Validation Constraints

prev_out_hash

[u8; 32]

BLAKE3 hash of the transaction containing the UTXO being spent.

MUST reference a valid, unspent UTXO in the current UTXO_SET.

prev_out_index

u32

The output index within prev_out_hash (0-indexed).

MUST be a valid index for the referenced transaction's outputs.

script_sig

Vec<u8>

Variable

The unlocking script (scriptSig) that satisfies the script_pubkey of the referenced UTXO.

MUST be a valid FerrisScript that evaluates to true against the script_pubkey. Its length MUST NOT exceed MAX_SCRIPT_BYTES.

witness

Vec<Vec<u8>>

Variable

Cryptographic witnesses for SegWit-like transactions (e.g., signatures, public keys).

If the referenced script_pubkey is a SegWit type, this field MUST contain valid witness data.

Total TxInput Size: 36 bytes (excluding variable-length script_sig and witness).

1.7 TxOutput Structure
An TxOutput defines a new UTXO, specifying a value and a locking script that dictates how the funds can be spent in the future.

Binary Representation (Canonical Serialization Order):

Field

Type

Size (Bytes)

Description

Validation Constraints

value

u64

8

The amount of Rusty Coin in satoshis transferred by this output.

MUST be greater than 0 unless it's an OP_RETURN output. Total value of outputs MUST NOT exceed MAX_MONEY.

script_pubkey

Vec<u8>

Variable

The locking script that defines the conditions for spending this output.

MUST be a valid FerrisScript. Its length MUST NOT exceed MAX_SCRIPT_BYTES. Cannot be a known invalid script pattern.

memo

Option<Vec<u8>>

Variable

Optional memo field for arbitrary data, typically used with OP_RETURN outputs.

If present, data size MUST be within allowed limits for OP_RETURN. This field is ignored for non-OP_RETURN outputs.

Total TxOutput Size: 8 bytes (excluding variable-length script_pubkey and memo).

