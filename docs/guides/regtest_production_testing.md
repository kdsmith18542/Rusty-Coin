# 🏭 Regtest Production Testing Guide

**Regtest with Mainnet Parameters** - Test locally with production-like conditions

## 🎯 **Overview**

Regtest now uses **mainnet consensus parameters** while running completely locally. This gives you the most realistic testing environment possible without connecting to external networks.

### **Why Regtest for Production Testing?**

✅ **Mainnet Parameters**: Identical consensus rules, timing, and economics  
✅ **Local Control**: Complete control over network conditions  
✅ **Fast Iteration**: No external dependencies or network delays  
✅ **Safe Testing**: No risk to real funds or mainnet  
✅ **Realistic Conditions**: True production behavior simulation  

## 📊 **Regtest Configuration**

### **Network Settings**
- **Network Type**: Regtest
- **Port**: 18444
- **Magic Bytes**: `[0xfa, 0xbf, 0xb5, 0xda]`
- **Isolation**: Completely local network

### **Consensus Parameters (Mainnet Identical)**
- **Block Time**: 150 seconds (2.5 minutes)
- **Difficulty Adjustment**: 2016 blocks (~3.5 days)
- **Ticket Maturity**: 10 blocks
- **Ticket Expiry**: 4096 blocks (~7 days)
- **Voting Period**: 4 weeks
- **Min Stake**: 0.01 RUST
- **Ticket Price**: 1 RUST
- **Block Reward**: 500 RUST

## 🚀 **Quick Start**

### **1. Automated Setup (Recommended)**

```bash
# Start complete regtest network
./scripts/start_regtest_network.sh start

# Start with fresh data
./scripts/start_regtest_network.sh start --clear-data

# Check network status
./scripts/start_regtest_network.sh status

# Test connectivity
./scripts/start_regtest_network.sh test

# Stop network
./scripts/start_regtest_network.sh stop
```

### **2. Manual Setup**

```bash
# Build the project
cargo build --release --bin rusty-node

# Terminal 1 - Bootstrap Node
cargo run --bin rusty-node -- \
  --network regtest \
  --node-id "regtest-bootstrap" \
  --port 18444 \
  --log-level info

# Terminal 2 - Full Node
cargo run --bin rusty-node -- \
  --network regtest \
  --node-id "regtest-node-2" \
  --port 18445 \
  --bootstrap-nodes "127.0.0.1:18444" \
  --log-level info

# Terminal 3 - Masternode
cargo run --bin rusty-node -- \
  --network regtest \
  --node-id "regtest-masternode" \
  --port 18446 \
  --bootstrap-nodes "127.0.0.1:18444" \
  --log-level info

# Terminal 4 - Miner
cargo run --bin rusty-node -- \
  --network regtest \
  --node-id "regtest-miner" \
  --port 18447 \
  --bootstrap-nodes "127.0.0.1:18444,127.0.0.1:18445" \
  --log-level info
```

## 🧪 **Production Testing Scenarios**

### **Scenario 1: Network Formation and P2P**

```bash
# Test peer discovery and connections
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_peer_info","params":[],"id":1}'

# Test network info
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_network_info","params":[],"id":1}'
```

### **Scenario 2: Block Production (Mainnet Timing)**

```bash
# Monitor block production (150-second intervals)
watch -n 10 'curl -s -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_block_count\",\"params\":[],\"id\":1}" | jq'

# Get latest block
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_best_block_hash","params":[],"id":1}'
```

### **Scenario 3: Transaction Processing**

```bash
# Test transaction creation and propagation
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"send_raw_transaction",
    "params":["<hex_transaction>"],
    "id":1
  }'

# Monitor mempool
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_mempool_info","params":[],"id":1}'
```

### **Scenario 4: PoS Ticket System (Mainnet Economics)**

```bash
# Check ticket pool
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_ticket_pool_info","params":[],"id":1}'

# Purchase tickets (1 RUST each)
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"purchase_tickets",
    "params":[{"count":5,"spend_limit":500000000}],
    "id":1
  }'
```

### **Scenario 5: Masternode Operations**

```bash
# Register masternode (requires 1000 RUST collateral)
curl -X POST http://127.0.0.1:18446 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"register_masternode",
    "params":[{
      "collateral_tx": "<tx_hash>",
      "collateral_index": 0,
      "service_address": "127.0.0.1:18446"
    }],
    "id":1
  }'

# Check masternode status
curl -X POST http://127.0.0.1:18446 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_masternode_status","params":[],"id":1}'
```

### **Scenario 6: Governance Testing (Mainnet Parameters)**

```bash
# Create governance proposal (requires 100 RUST stake)
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"create_governance_proposal",
    "params":[{
      "title": "Test Production Proposal",
      "description": "Testing governance with mainnet parameters",
      "amount": 10000000000,
      "payment_address": "<address>"
    }],
    "id":1
  }'

# Vote on proposal
curl -X POST http://127.0.0.1:18444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"vote_on_proposal",
    "params":["<proposal_id>", "yes"],
    "id":1
  }'
```

## 📈 **Performance Testing**

### **Load Testing**

```bash
# Stress test with multiple transactions
for i in {1..100}; do
  curl -X POST http://127.0.0.1:18444 \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"send_raw_transaction\",\"params\":[\"<tx_$i>\"],\"id\":$i}" &
done
wait
```

### **Network Resilience Testing**

```bash
# Test node failures and recovery
./scripts/start_regtest_network.sh stop
sleep 5
./scripts/start_regtest_network.sh start

# Test partial network failures
kill -STOP $(pgrep -f "regtest-node-2")
sleep 30
kill -CONT $(pgrep -f "regtest-node-2")
```

## 🔍 **Monitoring and Debugging**

### **Real-time Monitoring**

```bash
# Monitor all nodes
tail -f ~/.config/rusty-coin-regtest/*/node.log

# Monitor specific node
tail -f ~/.config/rusty-coin-regtest/regtest-node-1/node.log

# Monitor network activity
watch -n 5 './scripts/start_regtest_network.sh status'
```

### **Performance Metrics**

```bash
# Check resource usage
htop

# Monitor network connections
netstat -an | grep 18444

# Check disk usage
du -sh ~/.config/rusty-coin-regtest/
```

## 🎯 **Production Validation Checklist**

### **Network Layer**
- [ ] Peer discovery and connection
- [ ] Message propagation timing
- [ ] Network partition recovery
- [ ] DoS protection mechanisms

### **Consensus Layer**
- [ ] Block production timing (150s)
- [ ] Difficulty adjustment (2016 blocks)
- [ ] PoW validation
- [ ] PoS ticket voting

### **Economic Layer**
- [ ] Transaction fees
- [ ] Block rewards (500 RUST)
- [ ] Ticket pricing (1 RUST)
- [ ] Masternode collateral (1000 RUST)

### **Governance Layer**
- [ ] Proposal creation (100 RUST stake)
- [ ] Voting mechanisms
- [ ] Quorum requirements
- [ ] Activation delays

### **Security Layer**
- [ ] Cryptographic validation
- [ ] Signature verification
- [ ] Fraud proof generation
- [ ] Slashing mechanisms

## 🚨 **Troubleshooting**

### **Common Issues**

1. **Slow block times**
   - Expected: 150 seconds (mainnet timing)
   - Check mining configuration

2. **High resource usage**
   - Expected: Mainnet-level processing
   - Monitor with `htop`

3. **Network connectivity**
   - Check firewall settings
   - Verify port availability

### **Reset Environment**

```bash
# Complete reset
./scripts/start_regtest_network.sh stop
rm -rf ~/.config/rusty-coin-regtest/
./scripts/start_regtest_network.sh start --clear-data
```

## 🎉 **Success Criteria**

Your regtest network is working correctly when:

✅ **All nodes connect and maintain connections**  
✅ **Blocks are produced every ~150 seconds**  
✅ **Transactions propagate across the network**  
✅ **PoS tickets can be purchased and vote**  
✅ **Masternodes can register and participate**  
✅ **Governance proposals can be created and voted on**  
✅ **Network recovers from node failures**  

**You now have a complete local production environment for testing!** 🚀
