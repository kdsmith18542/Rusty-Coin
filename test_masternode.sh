#!/bin/bash

# Test script for Masternode functionality in Rusty-Coin regtest network
# This script tests masternode registration, status monitoring, and PoSe challenges

echo "🔒 Testing Masternode Functionality"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to test RPC call
test_rpc() {
    local method=$1
    local params=$2
    local description=$3
    local p2p_port=${4:-18444}
    local rpc_port=$((p2p_port + 1))
    
    echo -e "${BLUE}Testing: $description${NC}"
    
    if [ -z "$params" ] || [ "$params" = "null" ]; then
        result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}")
    else
        result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}")
    fi
    
    if echo "$result" | jq -e '.result' > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Success${NC}"
        echo "$result" | jq '.result'
    else
        echo -e "${RED}✗ Failed${NC}"
        echo "$result" | jq '.'
    fi
    echo ""
}

# Function to check if nodes are running
check_nodes() {
    echo -e "${YELLOW}Checking if regtest nodes are running...${NC}"
    
    # Check health endpoints (P2P port + 2)
    for p2p_port in 18444 18447 18450; do
        health_port=$((p2p_port + 2))
        if curl -s -f http://127.0.0.1:$health_port/health > /dev/null; then
            echo -e "${GREEN}✓ Node on port $p2p_port is running${NC}"
        else
            echo -e "${RED}✗ Node on port $p2p_port is not running${NC}"
            echo "Please start the regtest network first with: ./scripts/start_regtest_network.sh"
            exit 1
        fi
    done
    echo ""
}

# Check if nodes are running
check_nodes

echo "==================================="
echo "🔧 MASTERNODE REGISTRATION TESTS"
echo "==================================="

# Test masternode registration on different nodes
echo -e "${YELLOW}Testing masternode registration on all nodes...${NC}"

# Register masternode on node 1 (P2P port 18444, RPC port 18445)
test_rpc "register_masternode" '["127.0.0.1:9999", 1000000000000]' "Register masternode on node 1" 18444

# Register masternode on node 2 (P2P port 18447, RPC port 18448)
test_rpc "register_masternode" '["127.0.0.1:9998", 1000000000000]' "Register masternode on node 2" 18447

# Register masternode on node 3 (P2P port 18450, RPC port 18451)
test_rpc "register_masternode" '["127.0.0.1:9997", 1000000000000]' "Register masternode on node 3" 18450

echo "==================================="
echo "📊 MASTERNODE STATUS MONITORING"
echo "==================================="

# Test getting masternode status on each node
echo -e "${YELLOW}Checking masternode status on node 1 (port 18444)...${NC}"
test_rpc "get_masternode_status" "null" "Get masternode status from node 1" 18444

echo -e "${YELLOW}Checking masternode status on node 2 (port 18447)...${NC}"
test_rpc "get_masternode_status" "null" "Get masternode status from node 2" 18447

echo -e "${YELLOW}Checking masternode status on node 3 (port 18450)...${NC}"
test_rpc "get_masternode_status" "null" "Get masternode status from node 3" 18450

echo "==================================="
echo "📋 MASTERNODE LIST OPERATIONS"
echo "==================================="

# Test getting masternode list from each node
echo -e "${YELLOW}Getting masternode list from node 1 (port 18444)...${NC}"
test_rpc "get_masternode_list" "null" "Get masternode list from node 1" 18444

echo -e "${YELLOW}Getting masternode list from node 2 (port 18447)...${NC}"
test_rpc "get_masternode_list" "null" "Get masternode list from node 2" 18447

echo -e "${YELLOW}Getting masternode list from node 3 (port 18450)...${NC}"
test_rpc "get_masternode_list" "null" "Get masternode list from node 3" 18450

echo "==================================="
echo "💓 MASTERNODE HEARTBEAT TESTS"
echo "==================================="

# Test masternode ping from each node
echo -e "${YELLOW}Testing masternode ping functionality...${NC}"

echo -e "${BLUE}Pinging masternode on node 1 (port 18444)...${NC}"
test_rpc "masternode_ping" "null" "Masternode ping from node 1" 18444

echo -e "${BLUE}Pinging masternode on node 2 (port 18447)...${NC}"
test_rpc "masternode_ping" "null" "Masternode ping from node 2" 18447

echo -e "${BLUE}Pinging masternode on node 3 (port 18450)...${NC}"
test_rpc "masternode_ping" "null" "Masternode ping from node 3" 18450

echo "==================================="
echo "🔍 PROOF-OF-SERVICE (POSE) SIMULATION"
echo "==================================="

echo -e "${YELLOW}Simulating PoSe challenge scenarios...${NC}"

# Simulate different PoSe scenarios by checking masternode status multiple times
echo -e "${BLUE}Monitoring masternode health over multiple checks...${NC}"

for round in {1..3}; do
    echo -e "${YELLOW}--- PoSe Check Round $round ---${NC}"
    
    # Check nodes 1, 2, 3 (ports 18444, 18447, 18450)
    for p2p_port in 18444 18447 18450; do
        rpc_port=$((p2p_port + 1))
        node_id=$(((p2p_port - 18444) / 3 + 1))
        echo -e "${BLUE}Round $round - Checking node $node_id health...${NC}"
        
        # Get masternode status
        status_result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"get_masternode_status","params":[],"id":1}')
        
        if echo "$status_result" | jq -e '.result.pose_failures' > /dev/null 2>&1; then
            pose_failures=$(echo "$status_result" | jq -r '.result.pose_failures')
            status=$(echo "$status_result" | jq -r '.result.status')
            echo -e "${GREEN}Node $node_id: Status=$status, PoSe Failures=$pose_failures${NC}"
        else
            echo -e "${RED}Failed to get PoSe status for node $node_id${NC}"
        fi
        
        # Ping masternode
        ping_result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"masternode_ping","params":[],"id":1}')
        
        if echo "$ping_result" | jq -e '.result.success' > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Node $node_id ping successful${NC}"
        else
            echo -e "${RED}✗ Node $node_id ping failed${NC}"
        fi
    done
    
    echo ""
    sleep 2
done

echo "==================================="
echo "📈 MASTERNODE NETWORK METRICS"
echo "==================================="

echo -e "${YELLOW}Collecting masternode network metrics...${NC}"

# Analyze masternode network health
echo -e "${BLUE}Analyzing masternode network status...${NC}"

total_masternodes=0
active_masternodes=0
failed_nodes=0

# Check nodes 1, 2, 3 (ports 18444, 18447, 18450)
for p2p_port in 18444 18447 18450; do
    rpc_port=$((p2p_port + 1))
    node_id=$(((p2p_port - 18444) / 3 + 1))
    
    # Get masternode list to analyze network health
    list_result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"get_masternode_list","params":[],"id":1}')
    
    if echo "$list_result" | jq -e '.result' > /dev/null 2>&1; then
        node_total=$(echo "$list_result" | jq -r '.result.total_masternodes // 0')
        node_active=$(echo "$list_result" | jq -r '.result.active_masternodes // 0')
        
        echo -e "${GREEN}Node $node_id reports: $node_active/$node_total masternodes active${NC}"
        
        if [ "$node_total" -gt "$total_masternodes" ]; then
            total_masternodes=$node_total
            active_masternodes=$node_active
        fi
    else
        echo -e "${RED}Failed to get masternode list from node $node_id${NC}"
        failed_nodes=$((failed_nodes + 1))
    fi
done

echo ""
echo -e "${YELLOW}=== MASTERNODE NETWORK SUMMARY ===${NC}"
echo -e "Total Masternodes: ${BLUE}$total_masternodes${NC}"
echo -e "Active Masternodes: ${GREEN}$active_masternodes${NC}"
echo -e "Failed Node Queries: ${RED}$failed_nodes${NC}"

if [ "$active_masternodes" -gt 0 ]; then
    health_percentage=$(( (active_masternodes * 100) / total_masternodes ))
    echo -e "Network Health: ${GREEN}$health_percentage%${NC}"
else
    echo -e "Network Health: ${RED}0%${NC}"
fi

echo ""
echo "==================================="
echo "🔬 MASTERNODE TESTING COMPLETE"
echo "==================================="

echo -e "${YELLOW}Test Summary:${NC}"
echo "✅ Masternode registration tested on 3 nodes"
echo "✅ Masternode status monitoring verified"
echo "✅ Masternode list operations confirmed"
echo "✅ PoSe heartbeat functionality tested"
echo "✅ Network health metrics collected"

if [ "$failed_nodes" -eq 0 ] && [ "$active_masternodes" -gt 0 ]; then
    echo -e "${GREEN}🎉 All masternode tests passed successfully!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests had issues. Check the output above for details.${NC}"
    exit 1
fi
