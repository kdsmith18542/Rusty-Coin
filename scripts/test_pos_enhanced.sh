#!/bin/bash
# Protocol-compliant PoS ticket purchasing and pool info test

echo "Testing dynamic ticket pricing based on pool size..."

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

test_rpc "get_ticket_pool_info" "null" "Check current pool size and pricing" 18444
test_rpc "purchase_tickets" '[1, 10000000000]' "Purchase with 100 RUST limit (should succeed)" 18444
test_rpc "purchase_tickets" '[1, 100000000]' "Purchase with 1 RUST limit (should succeed if price is low)" 18444
test_rpc "purchase_tickets" '[1, 50000000]' "Purchase with 0.5 RUST limit (should fail)" 18444
test_rpc "get_ticket_info" '["ticket_id_here"]' "Check ticket state and expiration" 18444
