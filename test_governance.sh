#!/bin/bash

# Governance Testing Script for Rusty-Coin Regtest Network
# Tests governance proposal lifecycle, voting, and treasury management

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_PORT=18444
NUM_NODES=3
NODES=()
for ((i=0; i<NUM_NODES; i++)); do
    NODES+=($((BASE_PORT + i * 3)))
done

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

error() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
    FAILED_TESTS+=("$1")
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Helper function to make RPC calls
rpc_call() {
    local node_port=$1
    local method=$2
    local params=$3
    local rpc_port=$((node_port + 1))
    
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        http://127.0.0.1:$rpc_port/rpc 2>/dev/null || echo '{"error": "connection_failed"}'
}

# Check if network is running
check_network_status() {
    log "Checking network status..."
    
    for node_port in "${NODES[@]}"; do
        local health_port=$((node_port + 2))
        local response=$(curl -s http://127.0.0.1:$health_port/health 2>/dev/null || echo "FAIL")
        
        if [ "$response" != "OK" ]; then
            error "Node on port $node_port is not responding"
            echo "Please start the regtest network first: ./scripts/start_regtest_network.sh"
            exit 1
        fi
    done
    
    success "All nodes are running and healthy"
}

# Test governance proposal creation
test_create_proposal() {
    log "Testing governance proposal creation..."
    
    local node_port=${NODES[0]}
    
    local response=$(rpc_call $node_port "create_governance_proposal" '["Test Proposal - Network Upgrade", "This is a test proposal for network upgrade funding", "TREASURY_SPEND", 1000]')
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local proposal_id=$(echo "$response" | jq -r '.result.proposal_id // empty')
        if [ -n "$proposal_id" ] && [ "$proposal_id" != "null" ]; then
            success "Created governance proposal with ID: $proposal_id"
            echo "PROPOSAL_ID=$proposal_id" > /tmp/governance_test_state
        else
            error "Failed to extract proposal ID from response: $response"
        fi
    else
        error "Failed to create governance proposal: $error_field"
    fi
}

# Test proposal listing
test_list_proposals() {
    log "Testing governance proposal listing..."
    
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "list_governance_proposals" "[]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local proposals=$(echo "$response" | grep -o '"result":\[[^]]*\]' | cut -d: -f2-)
        if [ -n "$proposals" ] && [ "$proposals" != "[]" ]; then
            success "Retrieved governance proposals list: $proposals"
        else
            warning "No governance proposals found (may be expected if none created)"
        fi
    else
        error "Failed to list governance proposals: $error_field"
    fi
}

# Test proposal details retrieval
test_get_proposal_details() {
    log "Testing proposal details retrieval..."
    
    if [ ! -f /tmp/governance_test_state ]; then
        warning "No proposal ID available, skipping details test"
        return
    fi
    
    source /tmp/governance_test_state
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "get_governance_proposal" "[\"$PROPOSAL_ID\"]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local proposal_details=$(echo "$response" | grep -o '"result":{[^}]*}' | cut -d: -f2-)
        if [ -n "$proposal_details" ] && [ "$proposal_details" != "{}" ]; then
            success "Retrieved proposal details: $proposal_details"
        else
            error "Empty proposal details returned"
        fi
    else
        error "Failed to get proposal details: $error_field"
    fi
}

# Test voting on proposals
test_proposal_voting() {
    log "Testing governance proposal voting..."
    
    if [ ! -f /tmp/governance_test_state ]; then
        warning "No proposal ID available, skipping voting test"
        return
    fi
    
    source /tmp/governance_test_state
    
    # Test voting from multiple nodes
    local votes=("yes" "no" "yes")
    for i in "${!NODES[@]}"; do
        local node_port=${NODES[$i]}
        local vote=${votes[$i]}
        
        local response=$(rpc_call $node_port "vote_on_proposal" "[\"$PROPOSAL_ID\", \"$vote\"]")
        local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
        
        if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
            success "Node $i voted '$vote' on proposal $PROPOSAL_ID"
        else
            error "Node $i failed to vote: $error_field"
        fi
    done
}

# Test vote tallying
test_vote_tally() {
    log "Testing governance vote tallying..."
    
    if [ ! -f /tmp/governance_test_state ]; then
        warning "No proposal ID available, skipping tally test"
        return
    fi
    
    source /tmp/governance_test_state
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "get_proposal_votes" "[\"$PROPOSAL_ID\"]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local vote_results=$(echo "$response" | grep -o '"result":{[^}]*}' | cut -d: -f2-)
        if [ -n "$vote_results" ] && [ "$vote_results" != "{}" ]; then
            success "Retrieved vote tally: $vote_results"
        else
            error "Empty vote tally returned"
        fi
    else
        error "Failed to get vote tally: $error_field"
    fi
}

# Test treasury operations
test_treasury_operations() {
    log "Testing treasury operations..."
    
    # Test treasury balance
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "get_treasury_balance" "[]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local balance=$(echo "$response" | grep -o '"result":[0-9]*' | cut -d: -f2)
        if [ -n "$balance" ]; then
            success "Retrieved treasury balance: $balance"
        else
            error "Failed to parse treasury balance from response: $response"
        fi
    else
        error "Failed to get treasury balance: $error_field"
    fi
    
    # Test treasury history
    local response=$(rpc_call $node_port "get_treasury_history" "[]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local history=$(echo "$response" | grep -o '"result":\[[^]]*\]' | cut -d: -f2-)
        success "Retrieved treasury history: $history"
    else
        error "Failed to get treasury history: $error_field"
    fi
}

# Test proposal finalization
test_proposal_finalization() {
    log "Testing governance proposal finalization..."
    
    if [ ! -f /tmp/governance_test_state ]; then
        warning "No proposal ID available, skipping finalization test"
        return
    fi
    
    source /tmp/governance_test_state
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "finalize_proposal" "[\"$PROPOSAL_ID\"]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local result=$(echo "$response" | grep -o '"result":[^,}]*' | cut -d: -f2 | tr -d '"')
        if [ "$result" = "true" ]; then
            success "Successfully finalized proposal $PROPOSAL_ID"
        else
            warning "Proposal finalization returned: $result"
        fi
    else
        error "Failed to finalize proposal: $error_field"
    fi
}

# Test governance parameters
test_governance_parameters() {
    log "Testing governance parameters retrieval..."
    
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "get_governance_params" "[]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local params=$(echo "$response" | grep -o '"result":{[^}]*}' | cut -d: -f2-)
        if [ -n "$params" ] && [ "$params" != "{}" ]; then
            success "Retrieved governance parameters: $params"
        else
            error "Empty governance parameters returned"
        fi
    else
        error "Failed to get governance parameters: $error_field"
    fi
}

# Test comprehensive governance workflow
test_governance_workflow() {
    log "Testing complete governance workflow..."
    
    # Create multiple proposals
    local proposals=("Network Security Upgrade" "Community Development Fund" "Research Grant Program")
    for proposal_title in "${proposals[@]}"; do
        local proposal_data="{
            \"title\": \"$proposal_title\",
            \"description\": \"Test proposal: $proposal_title\",
            \"amount\": $((RANDOM % 5000 + 1000)),
            \"recipient\": \"recipient_$(echo $proposal_title | tr ' ' '_')\",
            \"voting_period\": 1008
        }"
        
        local node_port=${NODES[0]}
        local response=$(rpc_call $node_port "create_governance_proposal" "[$proposal_data]")
        local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
        
        if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
            success "Created workflow proposal: $proposal_title"
        else
            error "Failed to create workflow proposal '$proposal_title': $error_field"
        fi
    done
    
    # List all proposals to verify creation
    local node_port=${NODES[0]}
    local response=$(rpc_call $node_port "list_governance_proposals" "[]")
    local error_field=$(echo "$response" | grep -o '"error":[^,}]*' | cut -d: -f2 | tr -d '"')
    
    if [ "$error_field" = "null" ] || [ -z "$error_field" ]; then
        local proposal_count=$(echo "$response" | grep -o '"id":"[^"]*"' | wc -l)
        success "Governance workflow created $proposal_count total proposals"
    else
        error "Failed to verify workflow proposals: $error_field"
    fi
}

# Main test execution
main() {
    echo "=========================================="
    echo "Rusty-Coin Governance Testing Suite"
    echo "=========================================="
    echo
    
    check_network_status
    echo
    
    # Core governance functionality tests
    test_governance_parameters
    test_create_proposal
    test_list_proposals
    test_get_proposal_details
    test_proposal_voting
    test_vote_tally
    test_treasury_operations
    test_proposal_finalization
    
    echo
    log "Running comprehensive governance workflow test..."
    test_governance_workflow
    
    echo
    echo "=========================================="
    echo "Governance Test Results Summary"
    echo "=========================================="
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -gt 0 ]; then
        echo
        echo "Failed Tests:"
        for test in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} $test"
        done
        echo
        echo "Check the RPC server logs and ensure all governance features are properly implemented."
    else
        echo
        echo -e "${GREEN}All governance tests passed!${NC}"
        echo "The governance system is working correctly in regtest mode."
    fi
    
    # Cleanup
    rm -f /tmp/governance_test_state
    
    exit $TESTS_FAILED
}

main "$@"
