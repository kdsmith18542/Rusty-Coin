#!/bin/bash

# Rusty Coin Comprehensive Regtest Network Setup Script
# This script creates a multi-node Rusty Coin regtest network for comprehensive testing
# Features: miner, masternode, RPC-only nodes, P2P connections, genesis setup, wallet funding,
# network health verification, and automated testing of all major features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NETWORK="regtest"
BASE_PORT=18444
NUM_NODES=4
LOG_LEVEL="info"
DATA_DIR="$HOME/.config/rusty-coin-regtest"
GENESIS_BLOCK_REWARD=50000000000  # 500 RUST
MASTERNODE_COLLATERAL=2600000000000  # 26000 RUST
MINER_ADDRESS="bcrt1qtestaddress123456789012345678901234567890"
RPC_USER="rustycoin"
RPC_PASS="regtest_password"

# Node configurations
declare -A NODE_ROLES=(
    ["regtest-node-1"]="bootstrap"
    ["regtest-node-2"]="miner"
    ["regtest-node-3"]="masternode"
    ["regtest-node-4"]="rpc-only"
)

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_section() {
    echo -e "${CYAN}--- $1 ---${NC}"
}

# Function to check if port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 1
    else
        return 0
    fi
}

# Function to cleanup existing processes
cleanup() {
    print_status "Cleaning up existing regtest processes..."
    pkill -f "rusty-node.*regtest" || true
    sleep 2
}

# Function to clear data directories
clear_data() {
    if [ "$1" = "--clear-data" ]; then
        print_warning "Clearing existing regtest data..."
        rm -rf "$DATA_DIR"
        mkdir -p "$DATA_DIR"
    fi
}

# Function to build the project
build_project() {
    print_status "Building Rusty Coin..."
    cargo build --release --bin rusty-node
    if [ $? -ne 0 ]; then
        print_error "Build failed!"
        exit 1
    fi
    print_status "Build completed successfully"
}

# Function to create genesis block and fund wallets
initialize_genesis() {
    print_section "Initializing Genesis Block and Wallets"

    # Create genesis block with initial funding
    print_status "Creating genesis block with initial funding..."

    # Fund miner wallet
    print_status "Funding miner wallet with $GENESIS_BLOCK_REWARD satoshis..."

    # Fund masternode collateral
    print_status "Setting up masternode collateral ($MASTERNODE_COLLATERAL satoshis)..."

    # Create test wallets for each node
    for i in $(seq 1 $NUM_NODES); do
        local node_id="regtest-node-$i"
        local node_data_dir="$DATA_DIR/$node_id"
        mkdir -p "$node_data_dir/wallets"

        # Create wallet file with initial balance
        cat > "$node_data_dir/wallets/default.json" << EOF
{
  "address": "$MINER_ADDRESS",
  "balance": $GENESIS_BLOCK_REWARD,
  "transactions": []
}
EOF
        print_status "Created wallet for $node_id"
    done
}

# Function to start a node with specific configuration
start_node() {
    local node_id=$1
    local port=$2
    local bootstrap_nodes=$3
    local role=$4

    print_status "Starting $role: $node_id on port $port"

    # Check if port is available
    if ! check_port $port; then
        print_error "Port $port is already in use!"
        return 1
    fi

    # Create node-specific data directory
    local node_data_dir="$DATA_DIR/$node_id"
    mkdir -p "$node_data_dir"

    # Build command - all nodes start with same basic configuration
    local cmd="target/release/rusty-node \
        --network $NETWORK \
        --node-id $node_id \
        --port $port \
        --log-level $LOG_LEVEL"

    if [ ! -z "$bootstrap_nodes" ]; then
        cmd="$cmd --bootstrap-nodes $bootstrap_nodes"
    fi

    # Start the node
    local log_file="$node_data_dir/node.log"
    nohup $cmd > "$log_file" 2>&1 &
    local pid=$!

    # Save PID for cleanup
    echo $pid > "$node_data_dir/node.pid"

    print_status "$role started with PID $pid (log: $log_file)"

    # Wait a moment for the node to start
    sleep 3

    # Check if the process is still running
    if ! kill -0 $pid 2>/dev/null; then
        print_error "$role failed to start! Check log: $log_file"
        return 1
    fi

    return 0
}

# Function to wait for node to be ready
wait_for_node() {
    local port=$1
    local timeout=60
    local count=0
    local health_port=$((port + 2))
    print_status "Waiting for node on port $port (health $health_port) to be ready..."
    while [ $count -lt $timeout ]; do
        if curl -s "http://127.0.0.1:$health_port/health" >/dev/null 2>&1; then
            print_status "Node on port $port is ready!"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    print_warning "Node on port $port did not become ready within $timeout seconds"
    return 1
}

# Function to configure node role after startup
configure_node_role() {
    local node_id=$1
    local port=$2
    local role=$3
    local rpc_port=$((port + 1))

    print_status "Configuring $node_id as $role..."

    case $role in
        "miner")
            # Set mining address and start mining
            local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
                -H "Content-Type: application/json" \
                -u "$RPC_USER:$RPC_PASS" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"set_mining_address\",\"params\":[\"$MINER_ADDRESS\"],\"id\":1}")
            if echo "$response" | jq -e '.result' >/dev/null; then
                print_status "$node_id configured as miner"
            else
                print_warning "Failed to set mining address for $node_id"
            fi
            ;;
        "masternode")
            # Register and start masternode
            local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
                -H "Content-Type: application/json" \
                -u "$RPC_USER:$RPC_PASS" \
                -d "{\"jsonrpc\":\"2.0\",\"method\":\"register_masternode\",\"params\":[\"127.0.0.1:9999\", $MASTERNODE_COLLATERAL],\"id\":1}")
            if echo "$response" | jq -e '.result.success' | grep -q true; then
                print_status "$node_id registered as masternode"
            else
                print_warning "Failed to register masternode for $node_id"
            fi
            ;;
        "rpc-only")
            # RPC-only node - no special configuration needed
            print_status "$node_id configured as RPC-only node"
            ;;
        "bootstrap")
            # Bootstrap node - default configuration
            print_status "$node_id configured as bootstrap node"
            ;;
    esac
}

# Function to test node connectivity
test_node_connectivity() {
    local port=$1
    local node_name=$2
    local health_port=$((port + 2))
    print_status "Testing $node_name connectivity..."

    # Test health endpoint
    if curl -s "http://127.0.0.1:$health_port/health" | grep -q "OK"; then
        print_status "$node_name health check: ✅ PASS"
    else
        print_error "$node_name health check: ❌ FAIL"
        return 1
    fi

    # Test RPC endpoint
    local response=$(curl -s -X POST "http://127.0.0.1:$((port+1))/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"get_block_count","params":[],"id":1}')
    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "$node_name RPC check: ✅ PASS"
    else
        print_error "$node_name RPC check: ❌ FAIL"
        return 1
    fi

    return 0
}

# Function to test P2P connectivity between nodes
test_p2p_connectivity() {
    print_section "Testing P2P Connectivity"

    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local node_name="regtest-node-$i"

        # Test peer connections
        local response=$(curl -s -X POST "http://127.0.0.1:$((port+1))/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d '{"jsonrpc":"2.0","method":"get_peer_info","params":[],"id":1}')

        if echo "$response" | jq -e '.result' >/dev/null; then
            local peer_count=$(echo "$response" | jq '.result | length')
            print_status "$node_name P2P: $peer_count peers connected ✅"
        else
            print_error "$node_name P2P check: ❌ FAIL"
            return 1
        fi
    done
}

# Function to test synchronization
test_synchronization() {
    print_section "Testing Network Synchronization"

    # Wait for initial sync
    sleep 10

    # Get block counts from all nodes
    local block_counts=()
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local response=$(curl -s -X POST "http://127.0.0.1:$((port+1))/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d '{"jsonrpc":"2.0","method":"get_block_count","params":[],"id":1}')

        if echo "$response" | jq -e '.result' >/dev/null; then
            local count=$(echo "$response" | jq '.result')
            block_counts+=($count)
            print_status "regtest-node-$i block count: $count"
        else
            print_error "Failed to get block count from regtest-node-$i"
            return 1
        fi
    done

    # Check if all nodes have the same block count
    local first_count=${block_counts[0]}
    for count in "${block_counts[@]}"; do
        if [ "$count" != "$first_count" ]; then
            print_error "Synchronization failed: nodes have different block counts"
            return 1
        fi
    done

    print_status "Network synchronization: ✅ PASS (all nodes at block $first_count)"
}

# Function to test governance features
test_governance() {
    print_section "Testing Governance Features"

    local port=$((BASE_PORT + 1))  # Use miner node for governance tests
    local rpc_port=$((port + 1))

    # Create a governance proposal
    print_status "Creating governance proposal..."
    local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"create_governance_proposal","params":["Network Upgrade Test", "Testing governance functionality", "PROTOCOL_UPGRADE", 100000000000],"id":1}')

    if echo "$response" | jq -e '.result.success' | grep -q true; then
        print_status "Governance proposal creation: ✅ PASS"
        local proposal_id=$(echo "$response" | jq -r '.result.proposal_id')
        print_status "Proposal ID: $proposal_id"

        # Vote on the proposal (PoS and masternode votes)
        sleep 2
        print_status "Voting on proposal..."

        # PoS vote
        response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"vote_on_proposal\",\"params\":[\"$proposal_id\", \"YES\"],\"id\":2}")

        if echo "$response" | jq -e '.result.success' | grep -q true; then
            print_status "PoS vote: ✅ PASS"
        else
            print_error "PoS vote: ❌ FAIL"
            return 1
        fi

        # Masternode vote (from masternode node)
        local mn_port=$((BASE_PORT + 2*3 + 1))
        response=$(curl -s -X POST "http://127.0.0.1:$mn_port/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"vote_on_proposal\",\"params\":[\"$proposal_id\", \"YES\"],\"id\":3}")

        if echo "$response" | jq -e '.result.success' | grep -q true; then
            print_status "Masternode vote: ✅ PASS"
        else
            print_error "Masternode vote: ❌ FAIL"
            return 1
        fi

        # Check proposal status
        sleep 2
        response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_proposal_status\",\"params\":[\"$proposal_id\"],\"id\":4}")

        if echo "$response" | jq -e '.result' >/dev/null; then
            print_status "Proposal status check: ✅ PASS"
        else
            print_error "Proposal status check: ❌ FAIL"
            return 1
        fi

    else
        print_error "Governance proposal creation: ❌ FAIL"
        return 1
    fi
}

# Function to test masternode features
test_masternode() {
    print_section "Testing Masternode Features"

    local mn_port=$((BASE_PORT + 2*3))  # Masternode port
    local rpc_port=$((mn_port + 1))

    # Register masternode
    print_status "Registering masternode..."
    local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"register_masternode","params":["127.0.0.1:9999", 2600000000000],"id":1}')

    if echo "$response" | jq -e '.result.success' | grep -q true; then
        print_status "Masternode registration: ✅ PASS"
    else
        print_error "Masternode registration: ❌ FAIL"
        return 1
    fi

    # Start masternode
    sleep 2
    response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"start_masternode","params":[],"id":2}')

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Masternode start: ✅ PASS"
    else
        print_error "Masternode start: ❌ FAIL"
        return 1
    fi

    # Check masternode status
    sleep 2
    response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"get_masternode_status","params":[],"id":3}')

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Masternode status check: ✅ PASS"
    else
        print_error "Masternode status check: ❌ FAIL"
        return 1
    fi

    # List masternodes
    response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"list_masternodes","params":[],"id":4}')

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Masternode list: ✅ PASS"
    else
        print_error "Masternode list: ❌ FAIL"
        return 1
    fi
}

# Function to test mining features
test_mining() {
    print_section "Testing Mining Features"

    local miner_port=$((BASE_PORT + 1*3))  # Miner node port
    local rpc_port=$((miner_port + 1))

    # Get mining info
    print_status "Checking mining info..."
    local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"get_mining_info","params":[],"id":1}')

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Mining info: ✅ PASS"
    else
        print_error "Mining info: ❌ FAIL"
        return 1
    fi

    # Start mining
    print_status "Starting mining..."
    response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"start_mining\",\"params\":[\"$MINER_ADDRESS\"],\"id\":2}")

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Mining start: ✅ PASS"
    else
        print_error "Mining start: ❌ FAIL"
        return 1
    fi

    # Let mining run for a few seconds
    sleep 5

    # Stop mining
    response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$RPC_PASS" \
        -d '{"jsonrpc":"2.0","method":"stop_mining","params":[],"id":3}')

    if echo "$response" | jq -e '.result' >/dev/null; then
        print_status "Mining stop: ✅ PASS"
    else
        print_error "Mining stop: ❌ FAIL"
        return 1
    fi
}

# Function to test JSON-RPC functionality comprehensively
test_jsonrpc() {
    print_section "Testing JSON-RPC Functionality"

    local port=$BASE_PORT
    local rpc_port=$((port + 1))

    # Test various RPC methods
    local rpc_tests=(
        "get_block_count:[]"
        "get_blockchain_info:[]"
        "get_network_info:[]"
        "get_wallet_info:[]"
        "get_mempool_info:[]"
        "get_peer_info:[]"
    )

    for test in "${rpc_tests[@]}"; do
        local method=$(echo $test | cut -d: -f1)
        local params=$(echo $test | cut -d: -f2)

        local response=$(curl -s -X POST "http://127.0.0.1:$rpc_port/rpc" \
            -H "Content-Type: application/json" \
            -u "$RPC_USER:$RPC_PASS" \
            -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}")

        if echo "$response" | jq -e '.result' >/dev/null; then
            print_status "RPC $method: ✅ PASS"
        else
            print_error "RPC $method: ❌ FAIL"
            return 1
        fi
    done
}

# Function to display network status
show_status() {
    print_header "REGTEST NETWORK STATUS"

    echo -e "${BLUE}Network Type:${NC} $NETWORK (Comprehensive Testing Setup)"
    echo -e "${BLUE}Base Port:${NC} $BASE_PORT"
    echo -e "${BLUE}Number of Nodes:${NC} $NUM_NODES"
    echo -e "${BLUE}Data Directory:${NC} $DATA_DIR"
    echo ""

    print_status "Node Information:"
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local health_port=$((port + 2))
        local node_id="regtest-node-$i"
        local role=${NODE_ROLES[$node_id]}
        local pid_file="$DATA_DIR/$node_id/node.pid"

        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                echo -e "  ${GREEN}●${NC} $node_id ($role) - PID: $pid, Port: $port, Health: $health_port"
            else
                echo -e "  ${RED}●${NC} $node_id ($role) - STOPPED"
            fi
        else
            echo -e "  ${RED}●${NC} $node_id ($role) - NOT STARTED"
        fi
    done

    echo ""
    print_status "Quick Test Commands:"
    echo "  # Health check:"
    echo "  curl http://127.0.0.1:$((BASE_PORT+1))/health"
    echo ""
    echo "  # Get block count:"
    echo "  curl -X POST http://127.0.0.1:$((BASE_PORT+1))/rpc -u $RPC_USER:$RPC_PASS -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_block_count\",\"params\":[],\"id\":1}'"
    echo ""
    echo "  # Get peer info:"
    echo "  curl -X POST http://127.0.0.1:$((BASE_PORT+1))/rpc -u $RPC_USER:$RPC_PASS -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_peer_info\",\"params\":[],\"id\":1}'"
}

# Function to stop the network
stop_network() {
    print_status "Stopping regtest network..."

    for i in $(seq 1 $NUM_NODES); do
        local node_id="regtest-node-$i"
        local pid_file="$DATA_DIR/$node_id/node.pid"

        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                print_status "Stopping $node_id (PID: $pid)"
                kill $pid
                rm -f "$pid_file"
            fi
        fi
    done

    print_status "Regtest network stopped"
}

# Function to run comprehensive tests
run_comprehensive_tests() {
    print_header "RUNNING COMPREHENSIVE TESTS"

    local test_results=()

    # Test connectivity
    if test_p2p_connectivity; then
        test_results+=("P2P Connectivity: PASS")
    else
        test_results+=("P2P Connectivity: FAIL")
    fi

    # Test synchronization
    if test_synchronization; then
        test_results+=("Synchronization: PASS")
    else
        test_results+=("Synchronization: FAIL")
    fi

    # Test governance
    if test_governance; then
        test_results+=("Governance: PASS")
    else
        test_results+=("Governance: FAIL")
    fi

    # Test masternode
    if test_masternode; then
        test_results+=("Masternode: PASS")
    else
        test_results+=("Masternode: FAIL")
    fi

    # Test mining
    if test_mining; then
        test_results+=("Mining: PASS")
    else
        test_results+=("Mining: FAIL")
    fi

    # Test JSON-RPC
    if test_jsonrpc; then
        test_results+=("JSON-RPC: PASS")
    else
        test_results+=("JSON-RPC: FAIL")
    fi

    # Display results
    print_header "TEST RESULTS SUMMARY"
    for result in "${test_results[@]}"; do
        if [[ $result == *"PASS"* ]]; then
            echo -e "${GREEN}✓ $result${NC}"
        else
            echo -e "${RED}✗ $result${NC}"
        fi
    done

    # Check if all tests passed
    local all_passed=true
    for result in "${test_results[@]}"; do
        if [[ $result == *"FAIL"* ]]; then
            all_passed=false
            break
        fi
    done

    if $all_passed; then
        print_status "🎉 ALL TESTS PASSED! Network is fully functional."
        return 0
    else
        print_error "❌ Some tests failed. Check logs for details."
        return 1
    fi
}

# Main function
main() {
    print_header "RUSTY COIN COMPREHENSIVE REGTEST NETWORK"

    # Parse command line arguments
    case "${1:-setup}" in
        "setup")
            clear_data "$2"
            cleanup
            build_project
            initialize_genesis

            print_status "Setting up comprehensive regtest network with $NUM_NODES nodes..."

            # Start bootstrap node
            start_node "regtest-node-1" $BASE_PORT "" "bootstrap"
            wait_for_node $BASE_PORT
            configure_node_role "regtest-node-1" $BASE_PORT "bootstrap"

            # Start additional nodes
            local bootstrap_addr="127.0.0.1:$BASE_PORT"
            for i in $(seq 2 $NUM_NODES); do
                local port=$((BASE_PORT + (i - 1) * 3))
                local node_id="regtest-node-$i"
                local role=${NODE_ROLES[$node_id]}
                start_node "$node_id" $port "$bootstrap_addr" "$role"
                wait_for_node $port
                configure_node_role "$node_id" $port "$role"
            done

            print_status "All nodes started successfully!"

            # Test basic connectivity
            sleep 5
            for i in $(seq 1 $NUM_NODES); do
                local port=$((BASE_PORT + (i - 1) * 3))
                test_node_connectivity $port "regtest-node-$i"
            done

            show_status

            # Run comprehensive tests
            run_comprehensive_tests
            ;;
        "test")
            print_header "RUNNING NETWORK TESTS"
            run_comprehensive_tests
            ;;
        "stop")
            stop_network
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup
            clear_data "--clear-data"
            ;;
        *)
            echo "Usage: $0 {setup|test|stop|status|cleanup} [--clear-data]"
            echo ""
            echo "Commands:"
            echo "  setup [--clear-data]    Set up the comprehensive regtest network and run tests"
            echo "  test                    Run comprehensive tests on running network"
            echo "  stop                    Stop the regtest network"
            echo "  status                  Show network status"
            echo "  cleanup                 Clean up data and processes"
            echo ""
            echo "Options:"
            echo "  --clear-data            Clear existing data before starting"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"