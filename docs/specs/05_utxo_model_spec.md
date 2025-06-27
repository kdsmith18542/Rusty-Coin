Rusty Coin Formal Protocol Specifications: 05 - UTXO Model and State Management
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md (for Transaction, TxInput, TxOutput definitions), 04_ferrisscript_spec.md (for script validation).

5.1 Overview
This document formally specifies the Unspent Transaction Output (UTXO) model as implemented in Rusty Coin. It defines the core UTXO_SET state, its management, and the precise rules governing how transactions consume and create UTXOs. The UTXO model is fundamental to Rusty Coin's security, privacy, and parallel validation capabilities.

5.2 The Global UTXO Set (UTXO_SET)
The UTXO_SET represents the current global state of all spendable Rusty Coin. It is a set of all TxOutputs that have been created by valid, confirmed transactions and have not yet been spent as TxInputs.

Identification: Each UTXO is uniquely identified by an OutPoint structure: (TxID, VOutIndex).

TxID: The BLAKE3 hash of the transaction (Transaction structure) that created the TxOutput.

VOutIndex: The zero-based index of the TxOutput within that transaction's outputs vector.

Contents: For each OutPoint in the UTXO_SET, the node stores:

The value of the TxOutput.

The script_pubkey of the TxOutput.

The block height at which the UTXO was created (for lock_time / sequence validation).

A flag indicating if it's a coinbase transaction output (for coinbase maturity rules).

5.3 UTXO Set Management
The UTXO_SET is a mutable state that is updated with each new valid block added to the canonical blockchain. The rusty-consensus module is responsible for atomically updating the UTXO_SET.

5.3.1 Applying a Block to the UTXO_SET

When a new Block is validated and appended to the blockchain, its transactions are applied to the UTXO_SET in a deterministic order:

For each Transaction Tx_i in Block.transactions (in the order they appear in Block.transactions):

Process Inputs: For each TxInput In_j in Tx_i.inputs:

The OutPoint (In_j.prev_out_hash, In_j.prev_out_index) MUST exist in the current UTXO_SET.

The UTXO identified by the OutPoint MUST be removed from the UTXO_SET. This marks it as spent.

Process Outputs: For each TxOutput Out_k in Tx_i.outputs:

A new UTXO is created, identified by (Tx_i.TxID, k).

This new UTXO is added to the UTXO_SET.

5.3.2 Reverting a Block from the UTXO_SET (Blockchain Reorganization)

In the event of a blockchain reorganization (where a previously accepted block is replaced by an alternative chain), the UTXO_SET must be reverted to its state prior to the removed block. This is performed in reverse order of applying a block:

For each Transaction Tx_i in Block.transactions (in reverse order):

Revert Outputs: For each TxOutput Out_k in Tx_i.outputs (in reverse order of creation):

The UTXO (Tx_i.TxID, k) MUST be removed from the UTXO_SET. This effectively "destroys" the UTXOs created by the transaction.

Revert Inputs: For each TxInput In_j in Tx_i.inputs (in reverse order):

The UTXO that was consumed by this input (In_j.prev_out_hash, In_j.prev_out_index) MUST be re-added to the UTXO_SET. This marks it as unspent again.

5.3.3 Data Storage:

The rusty-consensus module maintains the UTXO_SET persistently, typically using a high-performance embedded key-value store like RocksDB. Efficient indexing (e.g., by OutPoint keys) is critical for fast lookups and updates. The state of this UTXO_SET is cryptographically bound into the state_root of each BlockHeader.

5.4 Transaction Validation Rules (Detailed)
Beyond the general structure defined in 01_block_structure.md, the following rules apply specifically to Transaction validation, particularly concerning UTXOs:

Input Existence and Unspent Status:

Each TxInput.prev_out_hash and TxInput.prev_out_index MUST refer to a real TxOutput that currently exists in the UTXO_SET.

The referenced TxOutput MUST NOT have been spent by any other transaction within the same block (for block validation) or within the current mempool (for mempool validation).

Coinbase Maturity:

If a TxInput refers to a TxOutput from a coinbase transaction (the special transaction rewarding the miner of a block), that coinbase UTXO MUST have matured.

A coinbase UTXO is mature if its creation block height is CURRENT_BLOCK_HEIGHT - COINBASE_MATURITY_PERIOD_BLOCKS (e.g., 100 blocks) or earlier.

Value Conservation and Fees:

Let V 
in
​
  be the sum of values of all UTXOs referenced by TxInputs.

Let V 
out
​
  be the sum of values of all TxOutputs in the transaction.

The transaction fee Fee = V_in - V_out.

Fee MUST NOT be negative (V 
in
​
 ≥V 
out
​
 ).

Fee MUST be greater than or equal to MIN_RELAY_FEE_PER_BYTE * TransactionSizeInBytes (where TransactionSizeInBytes is the canonical serialized size of the entire Transaction). This prevents spam and incentivizes miners.

Dust Limit:

Every TxOutput.value MUST be greater than or equal to DUST_LIMIT. Outputs below this limit are generally considered "unspendable" due to transaction fees making their spend uneconomical. The exact DUST_LIMIT value will be defined in core constants (e.g., 500 satoshis).

OP_RETURN outputs are explicitly allowed to be below DUST_LIMIT as they are provably unspendable and do not enter the UTXO_SET.

Script Validation (Refer to 04_ferrisscript_spec.md):

The script_sig of each TxInput, when executed with the corresponding script_pubkey of the referenced UTXO, MUST return TRUE on the stack.

All script_sig and script_pubkey MUST adhere to MAX_SCRIPT_BYTES, MAX_OPCODE_COUNT, and MAX_STACK_DEPTH.

The total number of signature operations (OP_CHECKSIG, OP_CHECKMULTISIG) across all TxInputs in a single transaction MUST NOT exceed MAX_SIG_OPS.

lock_time Validation:

If Transaction.lock_time is non-zero:

If lock_time is less than LOCKTIME_THRESHOLD (e.g., 500,000,000, representing a timestamp), it is interpreted as a block height. The transaction is valid ONLY if the current block height is greater than or equal to lock_time.

If lock_time is greater than or equal to LOCKTIME_THRESHOLD, it is interpreted as a Unix timestamp. The transaction is valid ONLY if the current block's timestamp is greater than or equal to lock_time.

Additionally, all TxInput.sequence values in the transaction MUST NOT be equal to MAX_SEQUENCE (e.g., 0xFFFFFFFF) if lock_time is set.

sequence Validation (for OP_CHECKSEQUENCEVERIFY):

If any TxInput.sequence value is less than MAX_SEQUENCE and OP_CHECKSEQUENCEVERIFY is present in the script_pubkey of the referenced UTXO, then:

The sequence value is interpreted as a relative time lock.

The UTXO must have been created at prev_out_block_height + relative_height_lock or prev_out_timestamp + relative_time_lock_seconds in the past.

Detailed rules for OP_CHECKSEQUENCEVERIFY are in 04_ferrisscript_spec.md.

5.5 State Root (state_root)
The state_root field in the BlockHeader provides a cryptographic commitment to the UTXO_SET and other relevant global states (e.g., the LIVE_TICKETS_POOL, Masternode List).

Structure: The state_root is the BLAKE3 hash of the root of a Merkle Patricia Trie (or similar authenticated data structure like a Merkle B-tree).

Contents of Trie: This trie contains:

All active OutPoints as keys, with their corresponding TxOutput data (value, script_pubkey, coinbase flag, creation_height) as values.

All LIVE TicketIDs and their associated metadata (e.g., owner address, expiration height) from the LIVE_TICKETS_POOL.

All active MasternodeIDs and their associated state (collateral UTXO, public keys, last PoSe check, service status).

Validation: Full nodes MUST be able to derive the identical state_root after applying a block's transactions and state transitions to their local UTXO_SET and other committed states. This ensures that all nodes agree on the exact global state of the blockchain.

Light Client Verification (Future): The state_root enables efficient light client validation (SPV - Simplified Payment Verification) where a light client can verify the existence or non-existence of a UTXO or other state data by requesting Merkle proofs from a full node, without downloading the entire blockchain.