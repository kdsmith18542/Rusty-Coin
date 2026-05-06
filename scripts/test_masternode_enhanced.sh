#!/bin/bash
# Protocol-compliant masternode registration and PoSe test

echo "Testing masternode registration with protocol-compliant collateral..."

test_rpc() {
    local method=$1
    local params=$2
    local description=$3
    local p2p_port=${4:-18444}
    local rpc_port=$((p2p_port + 1))
    echo -e "\033[1;34mTesting: $description\033[0m"
    if [ -z "$params" ] || [ "$params" = "null" ]; then
        result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}")
    else
        result=$(curl -s -X POST http://127.0.0.1:$rpc_port/rpc \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}")
    fi
    # Success if .result.success is true, or if .result is a valid object (for info queries)
    if echo "$result" | jq -e '.result.success' | grep -q true; then
        echo -e "\033[0;32m✓ Success\033[0m"
        echo "$result" | jq '.result'
    elif echo "$result" | jq -e '.result' >/dev/null; then
        echo -e "\033[0;32m✓ Success (info)\033[0m"
        echo "$result" | jq '.result'
    else
        echo -e "\033[0;31m✗ Failed\033[0m"
        echo "$result" | jq '.'
    fi
    echo ""
}

test_rpc "register_masternode" '["127.0.0.1:9999", 50000000000]' "Registration with insufficient collateral (500 RUST)" 18444
test_rpc "register_masternode" '["127.0.0.1:9999", 2600000000000]' "Registration with correct collateral (26000 RUST)" 18444
echo "Testing PoSe challenge frequency..."
test_rpc "get_masternode_status" "null" "Check PoSe challenge schedule" 18444
echo "Testing slashing threshold information..."
test_rpc "get_masternode_list" "null" "Check PoSe failure tracking" 18444
