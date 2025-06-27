# Rusty-Coin JSON-RPC API Documentation

This document provides a comprehensive overview and examples for the JSON-RPC API endpoints exposed by the Rusty-Coin node.

All requests should be sent as HTTP POST requests to the RPC server (default: `http://127.0.0.1:8000`) with a `Content-Type: application/json` header.

## Common JSON-RPC Request Structure

```json
{
  "jsonrpc": "2.0",
  "method": "<method_name>",
  "params": [<param1>, <param2>, ...],
  "id": <request_id>
}
```

- `jsonrpc`: Specifies the version of the JSON-RPC protocol. Always "2.0".
- `method`: The name of the RPC method to be invoked.
- `params`: An array of parameters to be passed to the method. Can be empty if no parameters are required.
- `id`: A unique identifier for the request. It can be a string, number, or null. The server must return the same ID in its response.

## Common JSON-RPC Response Structure

### Success Response

```json
{
  "jsonrpc": "2.0",
  "result": <method_result>,
  "id": <request_id>
}
```

- `result`: The data returned by the method. Its type depends on the specific method.

### Error Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": <error_code>,
    "message": "<error_message>",
    "data": <error_data> (optional)
  },
  "id": <request_id>
}
```

- `code`: A number that indicates the error type. (e.g., -32601 for Method not found).
- `message`: A short description of the error.
- `data`: (Optional) Primitive or structured value that contains additional information about the error.

---

## API Endpoints

### 1. `start_sync`

- **Description**: Initiates the network synchronization process.
- **Parameters**: None.
- **Returns**: `String` - A message indicating the synchronization status.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "start_sync",
  "params": [],
  "id": 1
}
```

**Example Response (Success):**

```json
{
  "jsonrpc": "2.0",
  "result": "Network synchronization started.",
  "id": 1
}
```

---

### 2. `get_block_count`

- **Description**: Returns the current block height (number of blocks in the longest chain).
- **Parameters**: None.
- **Returns**: `u64` - The current block height.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_block_count",
  "params": [],
  "id": 2
}
```

**Example Response (Success):**

```json
{
  "jsonrpc": "2.0",
  "result": 12345,
  "id": 2
}
```

---

### 3. `get_block_hash`

- **Description**: Returns the hash of the block at a given height.
- **Parameters**:
  - `height`: `u64` - The block height.
- **Returns**: `Hash` (array of 32 bytes) - The BLAKE3 hash of the block.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_block_hash",
  "params": [100],
  "id": 3
}
```

**Example Response (Success):**

```json
{
  "jsonrpc": "2.0",
  "result": "4b40733a7587d55f4c9c614b8a1f8e1a7b8e1a7b8e1a7b8e1a7b8e1a7b8e1a7b",
  "id": 3
}
```

---

### 4. `get_block`

- **Description**: Returns a full block object given its hash.
- **Parameters**:
  - `hash`: `Hash` (array of 32 bytes) - The BLAKE3 hash of the block.
- **Returns**: `Block` object - The full block data.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_block",
  "params": ["4b40733a7587d55f4c9c614b8a1f8e1a7b8e1a7b8e1a7b8e1a7b8e1a7b8e1a7b"],
  "id": 4
}
```

**Example Response (Success) - Partial `Block` structure shown:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "header": {
      "version": 1,
      "previous_block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "merkle_root": "...",
      "state_root": "...",
      "timestamp": 1678886400,
      "bits": 486604799,
      "nonce": 12345,
      "height": 1
    },
    "transactions": [
      // ... transaction objects ...
    ],
    "ticket_votes": [
      // ... ticket vote objects ...
    ]
  },
  "id": 4
}
```

---

### 5. `get_transaction`

- **Description**: Returns a transaction object given its hash.
- **Parameters**:
  - `txid`: `Hash` (array of 32 bytes) - The BLAKE3 hash of the transaction.
- **Returns**: `Transaction` object - The full transaction data.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_transaction",
  "params": ["5a3e1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"],
  "id": 5
}
```

**Example Response (Error - Method Not Found, as currently implemented placeholder):**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found"
  },
  "id": 5
}
```

---

### 6. `send_raw_transaction`

- **Description**: Broadcasts a raw, hex-encoded transaction to the network.
- **Parameters**:
  - `raw_tx`: `String` - The hex-encoded raw transaction.
- **Returns**: `Hash` (array of 32 bytes) - The transaction ID (hash).

**Example Request (Raw transaction hex is truncated for brevity):**

```json
{
  "jsonrpc": "2.0",
  "method": "send_raw_transaction",
  "params": ["0100000001..."],
  "id": 6
}
```

**Example Response (Success):**

```json
{
  "jsonrpc": "2.0",
  "result": "5a3e1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
  "id": 6
}
```

---

### 7. `get_utxo_set`

- **Description**: Returns a list of all unspent transaction outputs (UTXOs).
- **Parameters**: None.
- **Returns**: `Array<OutPoint>` - A list of `OutPoint` objects, each referencing an unspent transaction output.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_utxo_set",
  "params": [],
  "id": 7
}
```

**Example Response (Success) - Partial `OutPoint` structure shown:**

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      "vout": 0
    },
    {
      "txid": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "vout": 1
    }
  ],
  "id": 7
}
```

---

### 8. `get_governance_proposals`

- **Description**: Returns a list of all active governance proposals.
- **Parameters**: None.
- **Returns**: `Array<GovernanceProposal>` - A list of active governance proposal objects.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_governance_proposals",
  "params": [],
  "id": 8
}
```

**Example Response (Success) - Partial `GovernanceProposal` structure shown:**

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "proposal_id": "d7e6c5b4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6",
      "proposer_address": "...",
      "proposal_type": "PROTOCOL_UPGRADE",
      "start_block_height": 1000,
      "end_block_height": 2000,
      "title": "Example Protocol Upgrade",
      "description_hash": "...",
      "proposer_signature": "...",
      "inputs": [],
      "outputs": [],
      "lock_time": 0
    }
  ],
  "id": 8
}
```

---

### 9. `get_governance_votes`

- **Description**: Returns all votes cast for a specific governance proposal.
- **Parameters**:
  - `proposal_id`: `Hash` (array of 32 bytes) - The ID of the governance proposal.
- **Returns**: `Array<GovernanceVote>` - A list of governance vote objects for the given proposal.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "get_governance_votes",
  "params": ["d7e6c5b4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6"],
  "id": 9
}
```

**Example Response (Success) - Partial `GovernanceVote` structure shown:**

```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "proposal_id": "d7e6c5b4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6",
      "voter_type": "POS_TICKET",
      "voter_id": "...",
      "vote_choice": "YES",
      "voter_signature": "...",
      "inputs": [],
      "outputs": [],
      "lock_time": 0
    },
    {
      "proposal_id": "d7e6c5b4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6",
      "voter_type": "MASTERNODE",
      "voter_id": "...",
      "vote_choice": "NO",
      "voter_signature": "...",
      "inputs": [],
      "outputs": [],
      "lock_time": 0
    }
  ],
  "id": 9
}
``` 