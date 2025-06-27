# 🧪 Development Testing Guide for Rusty Coin Network

This guide provides comprehensive instructions for testing the Rusty Coin network functionality in a development environment.

## 🎯 **Testing Options Overview**

| Network Type | Best For | Block Time | Port | Status |
|--------------|----------|------------|------|--------|
| **Testnet** | ✅ **Development Testing** | 30 seconds | 18333 | ✅ Fully Implemented |
| **Regtest** | Local Testing | Custom | 18444 | ⚠️ Partially Implemented |
| **Mainnet** | Production | 150 seconds | 8333 | ✅ Production Ready |

## 🚀 **RECOMMENDED: Testnet Development Testing**

**Testnet is perfect for development** because it has:
- ✅ **Fast iterations**: 30-second block times
- ✅ **Low stakes**: Minimal test tokens required
- ✅ **Quick testing**: All timeouts and periods are shorter
- ✅ **Separate network**: Isolated from mainnet
- ✅ **Full features**: All consensus, governance, and masternode features

## 📋 **Setup Instructions**

### **1. Build the Project**

```bash
# Build all components
cargo build --release --all

# Or build specific components
cargo build --release --bin rusty-node
```

### **2. Start a Local Testnet Network**

#### **Option A: Single Node (Basic Testing)**

```bash
# Start a single testnet node
cargo run --bin rusty-node -- \
  --network testnet \
  --node-id "dev-node-1" \
  --port 18333 \
  --log-level debug
```

#### **Option B: Multi-Node Network (Full Testing)**

```bash
# Terminal 1 - Bootstrap Node
cargo run --bin rusty-node -- \
  --network testnet \
  --node-id "testnet-bootstrap" \
  --port 18333 \
  --log-level info

# Terminal 2 - Node 2
cargo run --bin rusty-node -- \
  --network testnet \
  --node-id "testnet-node-2" \
  --port 18334 \
  --bootstrap-nodes "127.0.0.1:18333" \
  --log-level info

# Terminal 3 - Node 3 (Masternode)
cargo run --bin rusty-node -- \
  --network testnet \
  --node-id "testnet-masternode-1" \
  --port 18335 \
  --bootstrap-nodes "127.0.0.1:18333" \
  --log-level info

# Terminal 4 - Node 4 (Miner)
cargo run --bin rusty-node -- \
  --network testnet \
  --node-id "testnet-miner-1" \
  --port 18336 \
  --bootstrap-nodes "127.0.0.1:18333,127.0.0.1:18334" \
  --log-level info
```

### **3. Test Network Functionality**

#### **Basic Network Tests**

```bash
# Test node health
curl http://127.0.0.1:18334/health

# Get block count
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_block_count","params":[],"id":1}'

# Get peer information
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_peer_info","params":[],"id":1}'

# Get network info
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_network_info","params":[],"id":1}'
```

#### **Blockchain Tests**

```bash
# Get best block hash
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_best_block_hash","params":[],"id":1}'

# Get block by height
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_block_by_height","params":[0],"id":1}'

# Get mempool info
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_mempool_info","params":[],"id":1}'
```

#### **Transaction Tests**

```bash
# Create a test transaction (you'll need to modify with actual values)
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"send_raw_transaction",
    "params":["<hex_encoded_transaction>"],
    "id":1
  }'
```

## 🔧 **Advanced Testing Scenarios**

### **1. P2P Network Testing**

```bash
# Test peer discovery
# Start nodes and watch logs for peer connections

# Test message propagation
# Send transactions and observe propagation across nodes

# Test network resilience
# Stop/start nodes and observe network recovery
```

### **2. Consensus Testing**

```bash
# Test PoW mining
# Observe block generation and difficulty adjustment

# Test PoS voting
# Create tickets and observe voting behavior

# Test masternode operations
# Register masternodes and test quorum formation
```

### **3. Governance Testing**

```bash
# Create governance proposals
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"create_governance_proposal",
    "params":[{
      "title": "Test Proposal",
      "description": "Testing governance system",
      "amount": 1000000000
    }],
    "id":1
  }'

# Vote on proposals
curl -X POST http://127.0.0.1:18333 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"vote_on_proposal",
    "params":["<proposal_id>", "yes"],
    "id":1
  }'
```

## 📊 **Testnet Configuration Details**

### **Consensus Parameters**
- **Block Time**: 30 seconds (fast testing)
- **Difficulty Adjustment**: 144 blocks (1 day)
- **Ticket Maturity**: 5 blocks
- **Ticket Expiry**: 1440 blocks (~2.5 days)
- **Voting Period**: 1 week
- **Activation Delay**: 1 day

### **Economic Parameters**
- **Min Stake**: 0.001 TESTRUST
- **Ticket Price**: 0.01 TESTRUST
- **Block Reward**: 100 TESTRUST
- **Proposal Stake**: 10 TESTRUST

### **Network Parameters**
- **Port**: 18333
- **Magic Bytes**: `[0x0b, 0x11, 0x09, 0x07]`
- **Max Block Size**: 8 MB

## 🐛 **Debugging and Monitoring**

### **Log Analysis**

```bash
# Watch logs in real-time
tail -f ~/.config/rusty-coin/logs/node.log

# Filter for specific events
grep "peer_connected" ~/.config/rusty-coin/logs/node.log
grep "block_received" ~/.config/rusty-coin/logs/node.log
grep "transaction_received" ~/.config/rusty-coin/logs/node.log
```

### **Performance Monitoring**

```bash
# Monitor resource usage
htop

# Monitor network connections
netstat -an | grep 18333

# Monitor disk usage
du -sh ~/.config/rusty-coin/
```

## 🧪 **Test Scenarios**

### **Scenario 1: Basic Network Formation**
1. Start bootstrap node
2. Start 2-3 additional nodes
3. Verify peer connections
4. Test message propagation

### **Scenario 2: Block Production and Sync**
1. Start mining on one node
2. Verify blocks are produced
3. Start additional nodes
4. Verify block synchronization

### **Scenario 3: Transaction Processing**
1. Create and send transactions
2. Verify mempool propagation
3. Verify transaction inclusion in blocks
4. Test transaction validation

### **Scenario 4: Masternode Operations**
1. Register masternodes
2. Test quorum formation
3. Test DKG operations
4. Test PoSe challenges

### **Scenario 5: Governance System**
1. Create governance proposals
2. Test voting mechanisms
3. Test proposal activation
4. Test parameter changes

## 🚨 **Troubleshooting**

### **Common Issues**

1. **Nodes not connecting**
   - Check firewall settings
   - Verify bootstrap node addresses
   - Check network configuration

2. **Slow block times**
   - Normal for testnet (30 seconds)
   - Check mining configuration
   - Verify difficulty adjustment

3. **Transaction failures**
   - Check UTXO availability
   - Verify transaction format
   - Check fee calculations

### **Reset Development Environment**

```bash
# Stop all nodes
pkill rusty-node

# Clear data directories
rm -rf ~/.config/rusty-coin/

# Restart with fresh state
cargo run --bin rusty-node -- --network testnet
```

## 🎯 **Next Steps**

After successful testnet testing, you can:
1. **Deploy to public testnet** (when available)
2. **Test with external peers**
3. **Stress test with high transaction volumes**
4. **Test network upgrades and forks**
5. **Prepare for mainnet deployment**

## 📚 **Additional Resources**

- [P2P Protocol Documentation](../p2p/api_reference.md)
- [JSON-RPC API Reference](../api/rpc_methods.md)
- [Consensus Mechanisms Guide](../consensus/overview.md)
- [Governance System Guide](../governance/overview.md)

---

**The testnet provides a complete, fast, and safe environment for testing all Rusty Coin network functionality!** 🚀
