# Rusty Coin JSON-RPC API Reference

**Version:** 1.0.0  
**Base URL:** `http://localhost:8332/rpc` (default)  
**Protocol:** JSON-RPC 2.0

## Authentication

All RPC requests require authentication via API key or Basic Auth:

```bash
# Using API key header
Authorization: Bearer YOUR_API_KEY

# Using Basic Auth
Authorization: Basic base64(username:password)
```

## Permission Levels

- **ReadOnly**: Query methods only (getblock, getbalance, etc.)
- **Standard**: Read + basic write operations
- **Admin**: All operations except critical system changes
- **SuperAdmin**: Full access including system configuration

---

## Core Methods

### `getblockchaininfo`

Returns information about the blockchain state.

**Parameters:** None

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "chain": "mainnet",
    "blocks": 12345,
    "headers": 12345,
    "bestblockhash": "0x...",
    "difficulty": 1.5,
    "mediantime": 1234567890,
    "verificationprogress": 1.0,
    "initialblockdownload": false,
    "chainwork": "0x...",
    "size_on_disk": 1024000
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

### `getblockhash`

Returns the block hash for a given block height.

**Parameters:**
- `height` (number): Block height

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "0x...",
  "id": 1
}
```

**Authorization:** ReadOnly

---

### `getblock`

Returns block information.

**Parameters:**
- `hash` (string): Block hash
- `verbosity` (number, optional): 0 = hex, 1 = JSON, 2 = JSON with transaction details (default: 1)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "hash": "0x...",
    "height": 12345,
    "version": 1,
    "previousblockhash": "0x...",
    "merkleroot": "0x...",
    "stateroot": "0x...",
    "timestamp": 1234567890,
    "difficulty": 1.5,
    "nonce": 0,
    "transactions": [...],
    "ticket_votes": [...]
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

## Wallet Methods

### `getbalance`

Returns wallet balance.

**Parameters:**
- `minconf` (number, optional): Minimum confirmations (default: 1)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "total": 1050000000,
    "confirmed": 1000000000,
    "unconfirmed": 50000000
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

### `listunspent`

Lists unspent transaction outputs.

**Parameters:**
- `minconf` (number, optional): Minimum confirmations (default: 1)
- `maxconf` (number, optional): Maximum confirmations (default: 9999999)
- `addresses` (array, optional): Filter by addresses (not yet implemented)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "txid": "0x...",
      "vout": 0,
      "address": "R...",
      "scriptPubKey": "76a914...88ac",
      "amount": 1000000,
      "confirmations": 6,
      "spendable": true,
      "safe": true
    }
  ],
  "id": 1
}
```

**Authorization:** ReadOnly

---

### `getwalletinfo`

Returns wallet information.

**Parameters:** None

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "walletname": "default",
    "walletversion": 1,
    "balance": 1000000000,
    "unconfirmed_balance": 50000000,
    "immature_balance": 0,
    "txcount": 42,
    "keypoololdest": 1234567890,
    "keypoolsize": 100,
    "unlocked_until": null,
    "paytxfee": 1000,
    "hdmasterkeyid": null
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

## Mining Methods

### `get_mining_info`

Returns mining information.

**Parameters:** None

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "blocks": 12345,
    "currentblocksize": 1000,
    "currentblocktx": 5,
    "difficulty": 1.5,
    "networkhashps": 1000000,
    "pooledtx": 10,
    "chain": "mainnet"
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

### `generate`

Generates blocks (regtest/testnet only).

**Parameters:**
- `nblocks` (number): Number of blocks to generate

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": ["0x...", "0x..."],
  "id": 1
}
```

**Authorization:** Standard

---

## Masternode Methods

### `register_masternode`

Registers a new masternode.

**Parameters:**
- `ip_address` (string): Masternode IP address and port
- `collateral_amount` (number): Collateral amount (must be MASTERNODE_COLLATERAL_AMOUNT)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "masternode_id": "0x...",
    "txid": "0x..."
  },
  "id": 1
}
```

**Authorization:** Standard

---

### `get_masternode_status`

Returns masternode status.

**Parameters:** None

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "masternode_id": "0x...",
    "status": "Active",
    "ip_address": "127.0.0.1:9999",
    "pose_failure_count": 0,
    "last_successful_pose_height": 12340
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

## PoS Ticket Methods

### `purchase_tickets`

Purchases PoS tickets.

**Parameters:**
- `count` (number): Number of tickets to purchase
- `spend_limit` (number): Maximum amount to spend

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "ticket_ids": ["0x...", "0x..."],
    "txid": "0x..."
  },
  "id": 1
}
```

**Authorization:** Standard

---

### `get_ticket_pool_info`

Returns ticket pool information.

**Parameters:** None

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "pool_size": 1000,
    "tickets": 1000,
    "value": 100000000000,
    "average_price": 100000000
  },
  "id": 1
}
```

**Authorization:** ReadOnly

---

## Governance Methods

### `create_governance_proposal`

Creates a governance proposal.

**Parameters:**
- `proposal_type` (string): "ParameterChange" or "ProtocolUpgrade"
- `title` (string): Proposal title
- `description_hash` (string): Hash of proposal description
- `voting_period` (number): Voting period in blocks
- `start_block_height` (number): Block height when voting starts

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "proposal_id": "0x...",
    "txid": "0x..."
  },
  "id": 1
}
```

**Authorization:** Standard

---

### `vote_on_proposal`

Votes on a governance proposal.

**Parameters:**
- `proposal_id` (string): Proposal ID
- `vote_choice` (string): "Yes", "No", or "Abstain"
- `voter_type` (string): "PoSTicket" or "Masternode"

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "txid": "0x..."
  },
  "id": 1
}
```

**Authorization:** Standard

---

## WebSocket Notifications

Connect to WebSocket endpoint for real-time updates:

**Endpoint:** `ws://localhost:8333` (default)

### Subscription Methods

- `subscribe_newblock`: Notifications for new blocks
- `subscribe_newtransaction`: Notifications for new transactions
- `subscribe_mempoolchange`: Notifications for mempool changes
- `subscribe_blockconfirmation`: Notifications for block confirmations
- `subscribe_proposalupdate`: Notifications for governance proposal updates

### Example

```javascript
const ws = new WebSocket('ws://localhost:8333');

// Subscribe to new blocks
ws.send(JSON.stringify({
  jsonrpc: "2.0",
  method: "subscribe_newblock",
  id: 1
}));

// Receive notifications
ws.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  console.log('Notification:', notification);
};
```

---

## Error Codes

- `-32700`: Parse error
- `-32600`: Invalid Request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error
- `-32000`: Server error (custom)
- `-32001`: Unauthorized
- `-32002`: Rate limit exceeded

---

## Rate Limiting

RPC requests are rate-limited per API key:
- **ReadOnly**: 100 requests/minute
- **Standard**: 200 requests/minute
- **Admin**: 500 requests/minute
- **SuperAdmin**: 1000 requests/minute

---

## Examples

### Get Balance

```bash
curl -X POST http://localhost:8332/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getbalance",
    "params": [1],
    "id": 1
  }'
```

### Send Raw Transaction

```bash
curl -X POST http://localhost:8332/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "method": "send_raw_transaction",
    "params": ["0x..."],
    "id": 1
  }'
```

---

## See Also

- [Developer Guide](DEVELOPER_GUIDE.md)
- [Protocol Specifications](../specs/)
- [Rust API Documentation](../target/doc/)

