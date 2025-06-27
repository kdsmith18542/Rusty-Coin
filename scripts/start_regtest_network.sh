#!/bin/bash

# Rusty Coin Regtest Network Startup Script
# This script starts a local regtest network with mainnet parameters for production testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NETWORK="regtest"
BASE_PORT=18444
NUM_NODES=4
LOG_LEVEL="info"
DATA_DIR="$HOME/.config/rusty-coin-regtest"

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

# Function to start a node
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
    
    # Start the node
    local cmd="target/release/rusty-node \
        --network $NETWORK \
        --node-id $node_id \
        --port $port \
        --log-level $LOG_LEVEL"
    
    if [ ! -z "$bootstrap_nodes" ]; then
        cmd="$cmd --bootstrap-nodes $bootstrap_nodes"
    fi
    
    # Start in background and redirect output to log file
    local log_file="$node_data_dir/node.log"
    nohup $cmd > "$log_file" 2>&1 &
    local pid=$!
    
    # Save PID for cleanup
    echo $pid > "$node_data_dir/node.pid"
    
    print_status "$role started with PID $pid (log: $log_file)"
    
    # Wait a moment for the node to start
    sleep 2
    
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
    local timeout=30
    local count=0
    
    print_status "Waiting for node on port $port to be ready..."
    
    while [ $count -lt $timeout ]; do
        if curl -s "http://127.0.0.1:$((port+1))/health" >/dev/null 2>&1; then
            print_status "Node on port $port is ready!"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    print_warning "Node on port $port did not become ready within $timeout seconds"
    return 1
}

# Function to test node connectivity
test_node() {
    local port=$1
    local node_name=$2
    
    print_status "Testing $node_name connectivity..."
    
    # Test health endpoint
    if curl -s "http://127.0.0.1:$((port+1))/health" | grep -q "OK"; then
        print_status "$node_name health check: ✅ PASS"
    else
        print_error "$node_name health check: ❌ FAIL"
        return 1
    fi
    
    # Test RPC endpoint
    local response=$(curl -s -X POST "http://127.0.0.1:$port" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"get_block_count","params":[],"id":1}')
    
    if echo "$response" | grep -q "result"; then
        print_status "$node_name RPC check: ✅ PASS"
    else
        print_error "$node_name RPC check: ❌ FAIL"
        return 1
    fi
    
    return 0
}

# Function to display network status
show_status() {
    print_header "REGTEST NETWORK STATUS"
    
    echo -e "${BLUE}Network Type:${NC} $NETWORK (Mainnet Parameters)"
    echo -e "${BLUE}Base Port:${NC} $BASE_PORT"
    echo -e "${BLUE}Number of Nodes:${NC} $NUM_NODES"
    echo -e "${BLUE}Data Directory:${NC} $DATA_DIR"
    echo ""
    
    print_status "Node Information:"
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + i - 1))
        local health_port=$((port + 1))
        local node_id="regtest-node-$i"
        local pid_file="$DATA_DIR/$node_id/node.pid"
        
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                echo -e "  ${GREEN}●${NC} $node_id (PID: $pid, Port: $port, Health: $health_port)"
            else
                echo -e "  ${RED}●${NC} $node_id (STOPPED)"
            fi
        else
            echo -e "  ${RED}●${NC} $node_id (NOT STARTED)"
        fi
    done
    
    echo ""
    print_status "Quick Test Commands:"
    echo "  # Health check:"
    echo "  curl http://127.0.0.1:$((BASE_PORT+1))/health"
    echo ""
    echo "  # Get block count:"
    echo "  curl -X POST http://127.0.0.1:$BASE_PORT -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_block_count\",\"params\":[],\"id\":1}'"
    echo ""
    echo "  # Get peer info:"
    echo "  curl -X POST http://127.0.0.1:$BASE_PORT -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_peer_info\",\"params\":[],\"id\":1}'"
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

# Main function
main() {
    print_header "RUSTY COIN REGTEST NETWORK"
    
    # Parse command line arguments
    case "${1:-start}" in
        "start")
            clear_data "$2"
            cleanup
            build_project
            
            print_status "Starting regtest network with $NUM_NODES nodes..."
            
            # Start bootstrap node
            start_node "regtest-node-1" $BASE_PORT "" "Bootstrap Node"
            wait_for_node $BASE_PORT
            
            # Start additional nodes
            local bootstrap_addr="127.0.0.1:$BASE_PORT"
            for i in $(seq 2 $NUM_NODES); do
                local port=$((BASE_PORT + i - 1))
                local node_id="regtest-node-$i"
                local role="Node $i"
                
                if [ $i -eq 3 ]; then
                    role="Masternode"
                elif [ $i -eq 4 ]; then
                    role="Miner"
                fi
                
                start_node "$node_id" $port "$bootstrap_addr" "$role"
                wait_for_node $port
            done
            
            print_status "All nodes started successfully!"
            
            # Test connectivity
            sleep 5
            for i in $(seq 1 $NUM_NODES); do
                local port=$((BASE_PORT + i - 1))
                test_node $port "regtest-node-$i"
            done
            
            show_status
            ;;
        "stop")
            stop_network
            ;;
        "status")
            show_status
            ;;
        "test")
            print_header "TESTING REGTEST NETWORK"
            for i in $(seq 1 $NUM_NODES); do
                local port=$((BASE_PORT + i - 1))
                test_node $port "regtest-node-$i"
            done
            ;;
        *)
            echo "Usage: $0 {start|stop|status|test} [--clear-data]"
            echo ""
            echo "Commands:"
            echo "  start [--clear-data]  Start the regtest network"
            echo "  stop                  Stop the regtest network"
            echo "  status                Show network status"
            echo "  test                  Test network connectivity"
            echo ""
            echo "Options:"
            echo "  --clear-data          Clear existing data before starting"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
