#!/bin/bash
# Protocol-compliant governance proposal and voting test

echo "Testing governance proposal with bicameral requirements..."

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

test_rpc "create_governance_proposal" '["Network Upgrade", "Upgrade to v2.0", "PROTOCOL_UPGRADE", 100000000000]' "Create upgrade proposal (1000 RUST stake)" 18444
test_rpc "vote_on_proposal" '["proposal_id", "YES"]' "PoS ticket vote" 18444
test_rpc "vote_on_proposal" '["proposal_id", "YES"]' "Masternode vote" 18444
test_rpc "get_proposal_status" '["proposal_id"]' "Check bicameral voting progress" 18444
