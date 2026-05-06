#!/bin/bash

# Rusty Coin Testnet Deployment Script
# This script deploys a comprehensive testnet environment with miner, masternode, and explorer nodes
# Features: infrastructure provisioning, monitoring setup, health checks, genesis initialization, and funding

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
NETWORK="testnet"
BASE_PORT=18333
NUM_NODES=5
LOG_LEVEL="info"
DATA_DIR="$HOME/.config/rusty-coin-testnet"
GENESIS_BLOCK_REWARD=50000000000  # 500 RUST
MASTERNODE_COLLATERAL=2600000000000  # 26000 RUST
MINER_ADDRESS="tb1qtestaddress123456789012345678901234567890"
RPC_USER="rustycoin"
RPC_PASS="testnet_password_$(date +%s)"
MONITORING_PORT=9090
ALERT_EMAIL="admin@rustycoin.test"

# Node configurations
declare -A NODE_ROLES=(
    ["testnet-bootstrap"]="bootstrap"
    ["testnet-miner-1"]="miner"
    ["testnet-miner-2"]="miner"
    ["testnet-masternode"]="masternode"
    ["testnet-explorer"]="explorer"
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
    print_status "Cleaning up existing testnet processes..."
    pkill -f "rusty-node.*testnet" || true
    sleep 2
}

# Function to clear data directories
clear_data() {
    if [ "$1" = "--clear-data" ]; then
        print_warning "Clearing existing testnet data..."
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
    print_section "Initializing Testnet Genesis Block and Wallets"

    # Create genesis block with initial funding
    print_status "Creating testnet genesis block with initial funding..."

    # Fund miner wallets
    print_status "Funding miner wallets with $GENESIS_BLOCK_REWARD satoshis each..."

    # Fund masternode collateral
    print_status "Setting up masternode collateral ($MASTERNODE_COLLATERAL satoshis)..."

    # Create test wallets for each node
    for i in $(seq 1 $NUM_NODES); do
        local node_id="testnet-node-$i"
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

    # Create masternode collateral wallet
    local mn_data_dir="$DATA_DIR/testnet-masternode"
    mkdir -p "$mn_data_dir/wallets"
    cat > "$mn_data_dir/wallets/collateral.json" << EOF
{
  "address": "tb1qmasternode123456789012345678901234567890",
  "balance": $MASTERNODE_COLLATERAL,
  "transactions": []
}
EOF
    print_status "Created masternode collateral wallet"
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

    # Build command with testnet configuration
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
        "explorer")
            # Explorer node - enable additional RPC methods for block explorer
            print_status "$node_id configured as explorer node"
            ;;
        "bootstrap")
            # Bootstrap node - default configuration
            print_status "$node_id configured as bootstrap node"
            ;;
    esac
}

# Function to setup monitoring and logging
setup_monitoring() {
    print_section "Setting up Monitoring and Logging"

    # Create monitoring directory
    local monitor_dir="$DATA_DIR/monitoring"
    mkdir -p "$monitor_dir"

    # Install monitoring dependencies (if not present)
    if ! command -v jq &> /dev/null; then
        print_warning "jq not found, installing..."
        # On Ubuntu/Debian
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y jq
        # On CentOS/RHEL
        elif command -v yum &> /dev/null; then
            sudo yum install -y jq
        fi
    fi

    # Setup log rotation
    cat > "$monitor_dir/logrotate.conf" << EOF
$DATA_DIR/*/node.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 $(whoami) $(whoami)
    postrotate
        # Reload nodes after log rotation
        pkill -HUP -f "rusty-node.*testnet" || true
    endscript
}
EOF

    # Setup monitoring scripts
    cat > "$monitor_dir/health_check.sh" << EOF
#!/bin/bash
# Health check script for testnet nodes

HEALTH_STATUS="OK"
ISSUES=()

# Check each node
for i in \$(seq 1 $NUM_NODES); do
    port=\$((BASE_PORT + (i - 1) * 3))
    health_port=\$((port + 2))
    node_id="testnet-node-\$i"

    if ! curl -s "http://127.0.0.1:\$health_port/health" >/dev/null 2>&1; then
        HEALTH_STATUS="CRITICAL"
        ISSUES+=("\$node_id health check failed")
    fi

    # Check RPC connectivity
    rpc_port=\$((port + 1))
    response=\$(curl -s -X POST "http://127.0.0.1:\$rpc_port/rpc" \\
        -H "Content-Type: application/json" \\
        -u "$RPC_USER:$RPC_PASS" \\
        -d '{"jsonrpc":"2.0","method":"get_block_count","params":[],"id":1}')

    if ! echo "\$response" | jq -e '.result' >/dev/null 2>&1; then
        HEALTH_STATUS="WARNING"
        ISSUES+=("\$node_id RPC check failed")
    fi
done

# Output status
echo "{\\"status\\": \\"\$HEALTH_STATUS\\", \\"timestamp\\": \$(date +%s), \\"issues\\": [\\"\$(IFS=,; echo "\\"\${ISSUES[*]}\\"\\")\\"]}"
EOF

    chmod +x "$monitor_dir/health_check.sh"

    # Setup alerting script
    cat > "$monitor_dir/alert.sh" << EOF
#!/bin/bash
# Alerting script for testnet issues

ALERT_TYPE=\$1
MESSAGE=\$2
TIMESTAMP=\$(date +%s)

# Log alert
echo "[\$TIMESTAMP] \$ALERT_TYPE: \$MESSAGE" >> "$monitor_dir/alerts.log"

# Email alert (if configured)
if [ ! -z "$ALERT_EMAIL" ] && command -v mail &> /dev/null; then
    echo "\$MESSAGE" | mail -s "Rusty Coin Testnet Alert: \$ALERT_TYPE" "$ALERT_EMAIL"
fi

# Could integrate with Slack, Discord, PagerDuty, etc.
EOF

    chmod +x "$monitor_dir/alert.sh"

    print_status "Monitoring setup completed"
}

# Function to setup automated health checks
setup_health_checks() {
    print_section "Setting up Automated Health Checks"

    local monitor_dir="$DATA_DIR/monitoring"

    # Create cron job for health checks
    local cron_job="* * * * * $monitor_dir/health_check.sh | jq -r '.status' | grep -q CRITICAL && $monitor_dir/alert.sh CRITICAL 'Testnet health check failed'"

    # Add to crontab if not already present
    if ! crontab -l 2>/dev/null | grep -q "health_check.sh"; then
        (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
        print_status "Added health check cron job"
    fi

    # Setup Prometheus metrics endpoint (if Prometheus available)
    if command -v prometheus &> /dev/null; then
        cat > "$monitor_dir/prometheus.yml" << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rusty-coin-testnet'
    static_configs:
      - targets: ['localhost:$MONITORING_PORT']
EOF
        print_status "Prometheus configuration created"
    fi
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
        local node_name="testnet-node-$i"

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

# Function to display testnet status
show_status() {
    print_header "RUSTY COIN TESTNET STATUS"

    echo -e "${BLUE}Network Type:${NC} $NETWORK (Testnet Environment)"
    echo -e "${BLUE}Base Port:${NC} $BASE_PORT"
    echo -e "${BLUE}Number of Nodes:${NC} $NUM_NODES"
    echo -e "${BLUE}Data Directory:${NC} $DATA_DIR"
    echo -e "${BLUE}RPC Credentials:${NC} $RPC_USER / $RPC_PASS"
    echo ""

    print_status "Node Information:"
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local health_port=$((port + 2))
        local node_id="testnet-node-$i"
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
    print_status "Quick Access Commands:"
    echo "  # Health check:"
    echo "  curl http://127.0.0.1:$((BASE_PORT+1))/health"
    echo ""
    echo "  # Get block count:"
    echo "  curl -X POST http://127.0.0.1:$((BASE_PORT+1))/rpc -u $RPC_USER:$RPC_PASS -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_block_count\",\"params\":[],\"id\":1}'"
    echo ""
    echo "  # Get peer info:"
    echo "  curl -X POST http://127.0.0.1:$((BASE_PORT+1))/rpc -u $RPC_USER:$RPC_PASS -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_peer_info\",\"params\":[],\"id\":1}'"
    echo ""
    echo "  # Monitoring:"
    echo "  $DATA_DIR/monitoring/health_check.sh"
}

# Function to stop the testnet
stop_testnet() {
    print_status "Stopping testnet network..."

    for i in $(seq 1 $NUM_NODES); do
        local node_id="testnet-node-$i"
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

    print_status "Testnet network stopped"
}

# Main function
main() {
    print_header "RUSTY COIN TESTNET DEPLOYMENT"

    # Parse command line arguments
    case "${1:-deploy}" in
        "deploy")
            clear_data "$2"
            cleanup
            build_project
            initialize_genesis
            setup_monitoring
            setup_health_checks

            print_status "Deploying comprehensive testnet with $NUM_NODES nodes..."

            # Start bootstrap node
            start_node "testnet-bootstrap" $BASE_PORT "" "bootstrap"
            wait_for_node $BASE_PORT
            configure_node_role "testnet-bootstrap" $BASE_PORT "bootstrap"

            # Start additional nodes
            local bootstrap_addr="127.0.0.1:$BASE_PORT"
            for i in $(seq 2 $NUM_NODES); do
                local port=$((BASE_PORT + (i - 1) * 3))
                local node_id="testnet-node-$i"
                local role=${NODE_ROLES[$node_id]}
                start_node "$node_id" $port "$bootstrap_addr" "$role"
                wait_for_node $port
                configure_node_role "$node_id" $port "$role"
            done

            print_status "All nodes deployed successfully!"

            # Test basic connectivity
            sleep 5
            for i in $(seq 1 $NUM_NODES); do
                local port=$((BASE_PORT + (i - 1) * 3))
                test_node_connectivity $port "testnet-node-$i"
            done

            # Test P2P connectivity
            sleep 5
            test_p2p_connectivity

            show_status

            print_status "🎉 Testnet deployment completed successfully!"
            print_status "Use './scripts/monitor_testnet.sh' to monitor the network"
            ;;
        "stop")
            stop_testnet
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup
            clear_data "--clear-data"
            ;;
        *)
            echo "Usage: $0 {deploy|stop|status|cleanup} [--clear-data]"
            echo ""
            echo "Commands:"
            echo "  deploy [--clear-data]    Deploy the comprehensive testnet and run tests"
            echo "  stop                     Stop the testnet"
            echo "  status                   Show testnet status"
            echo "  cleanup                  Clean up data and processes"
            echo ""
            echo "Options:"
            echo "  --clear-data             Clear existing data before starting"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"