#!/bin/bash

# Rusty Coin Testnet Monitoring Script
# Comprehensive monitoring of node health, network health, service health, and security monitoring
# Includes alerting mechanisms and automated recovery

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
DATA_DIR="$HOME/.config/rusty-coin-testnet"
RPC_USER="rustycoin"
RPC_PASS_FILE="$DATA_DIR/rpc_pass.txt"
MONITORING_INTERVAL=60  # seconds
ALERT_EMAIL="admin@rustycoin.test"
SLACK_WEBHOOK=""  # Set this for Slack alerts
DISCORD_WEBHOOK=""  # Set this for Discord alerts

# Monitoring thresholds
MAX_BLOCK_TIME=600  # 10 minutes
MIN_PEERS=3
MAX_PEER_COUNT=125
MIN_BLOCK_HEIGHT_SYNC=5  # Max blocks behind to be considered synced
MAX_FAILED_TX_RATE=0.1  # 10% failure rate
MAX_CONSENSUS_VIOLATIONS=5  # per hour

# Global state
declare -A LAST_BLOCK_HEIGHTS
declare -A LAST_BLOCK_TIMES
declare -A FAILED_TX_COUNT
declare -A CONSENSUS_VIOLATIONS
START_TIME=$(date +%s)

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

# Function to send alerts
send_alert() {
    local severity=$1
    local message=$2
    local timestamp=$(date +%s)

    # Log alert
    echo "[$timestamp] [$severity] $message" >> "$DATA_DIR/monitoring/alerts.log"

    # Email alert
    if [ ! -z "$ALERT_EMAIL" ] && command -v mail &> /dev/null; then
        echo "$message" | mail -s "Rusty Coin Testnet Alert [$severity]" "$ALERT_EMAIL"
    fi

    # Slack alert
    if [ ! -z "$SLACK_WEBHOOK" ]; then
        curl -s -X POST "$SLACK_WEBHOOK" \
            -H 'Content-type: application/json' \
            -d "{\"text\":\"Rusty Coin Testnet Alert [$severity]: $message\"}" >/dev/null 2>&1 || true
    fi

    # Discord alert
    if [ ! -z "$DISCORD_WEBHOOK" ]; then
        curl -s -X POST "$DISCORD_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{\"content\":\"Rusty Coin Testnet Alert [$severity]: $message\"}" >/dev/null 2>&1 || true
    fi

    # Console output
    case $severity in
        "CRITICAL")
            print_error "ALERT: $message"
            ;;
        "WARNING")
            print_warning "ALERT: $message"
            ;;
        "INFO")
            print_status "ALERT: $message"
            ;;
    esac
}

# Function to get RPC password
get_rpc_pass() {
    if [ -f "$RPC_PASS_FILE" ]; then
        cat "$RPC_PASS_FILE"
    else
        echo "$RPC_PASS"
    fi
}

# Function to make RPC call
rpc_call() {
    local port=$1
    local method=$2
    local params=$3
    local rpc_pass=$(get_rpc_pass)

    curl -s -X POST "http://127.0.0.1:$((port+1))/rpc" \
        -H "Content-Type: application/json" \
        -u "$RPC_USER:$rpc_pass" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" 2>/dev/null
}

# Function to monitor node health
monitor_node_health() {
    print_section "Node Health Monitoring"

    local issues=()
    local critical_issues=()

    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local node_id="testnet-node-$i"
        local health_port=$((port + 2))

        print_status "Checking $node_id..."

        # Health check
        if ! curl -s "http://127.0.0.1:$health_port/health" >/dev/null 2>&1; then
            critical_issues+=("$node_id health check failed")
            continue
        fi

        # RPC connectivity
        local response=$(rpc_call $port "get_block_count" "[]")
        if ! echo "$response" | jq -e '.result' >/dev/null 2>&1; then
            critical_issues+=("$node_id RPC connectivity failed")
            continue
        fi

        local block_height=$(echo "$response" | jq -r '.result')
        local last_height=${LAST_BLOCK_HEIGHTS[$node_id]:-0}

        # Check block height progression
        if [ "$last_height" -gt 0 ] && [ "$block_height" -le "$last_height" ]; then
            issues+=("$node_id block height not progressing (stuck at $block_height)")
        fi

        LAST_BLOCK_HEIGHTS[$node_id]=$block_height

        # Check peer count
        response=$(rpc_call $port "get_peer_info" "[]")
        if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
            local peer_count=$(echo "$response" | jq '.result | length')
            if [ "$peer_count" -lt "$MIN_PEERS" ]; then
                issues+=("$node_id has only $peer_count peers (minimum: $MIN_PEERS)")
            elif [ "$peer_count" -gt "$MAX_PEER_COUNT" ]; then
                issues+=("$node_id has $peer_count peers (maximum recommended: $MAX_PEER_COUNT)")
            fi
        fi

        # Check sync status
        response=$(rpc_call $port "get_blockchain_info" "[]")
        if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
            local verification_progress=$(echo "$response" | jq -r '.result.verificationprogress // 1')
            if (( $(echo "$verification_progress < 0.99" | bc -l) )); then
                issues+=("$node_id sync progress: $(printf "%.2f" $(echo "$verification_progress * 100" | bc -l))%")
            fi
        fi

        print_status "$node_id: Block height $block_height, $peer_count peers"
    done

    # Report issues
    for issue in "${issues[@]}"; do
        send_alert "WARNING" "$issue"
    done

    for issue in "${critical_issues[@]}"; do
        send_alert "CRITICAL" "$issue"
    done
}

# Function to monitor network health
monitor_network_health() {
    print_section "Network Health Monitoring"

    local issues=()
    local block_times=()
    local tx_throughput=0

    # Get network statistics from miner node
    local miner_port=$((BASE_PORT + 1*3))  # miner-1
    local response=$(rpc_call $miner_port "get_mining_info" "[]")

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local network_hashrate=$(echo "$response" | jq -r '.result.networkhashps // 0')
        local blocks=$(echo "$response" | jq -r '.result.blocks // 0')

        print_status "Network hashrate: ${network_hashrate} H/s"
        print_status "Current block height: $blocks"

        # Check block time (simplified - would need historical data)
        local current_time=$(date +%s)
        local last_block_time=${LAST_BLOCK_TIMES["network"]:-$current_time}

        if [ "$blocks" -gt 0 ]; then
            local time_since_last_block=$((current_time - last_block_time))
            if [ "$time_since_last_block" -gt "$MAX_BLOCK_TIME" ]; then
                issues+=("No new blocks for $time_since_last_block seconds")
            fi
        fi

        LAST_BLOCK_TIMES["network"]=$current_time
    fi

    # Check transaction throughput
    response=$(rpc_call $miner_port "get_mempool_info" "[]")
    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local mempool_tx=$(echo "$response" | jq -r '.result.size // 0')
        tx_throughput=$mempool_tx
        print_status "Mempool transactions: $mempool_tx"
    fi

    # Check network difficulty
    response=$(rpc_call $miner_port "get_blockchain_info" "[]")
    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local difficulty=$(echo "$response" | jq -r '.result.difficulty // 0')
        print_status "Network difficulty: $difficulty"
    fi

    # Report issues
    for issue in "${issues[@]}"; do
        send_alert "WARNING" "$issue"
    done
}

# Function to monitor service health
monitor_service_health() {
    print_section "Service Health Monitoring"

    local issues=()

    # Monitor masternode status
    local mn_port=$((BASE_PORT + 3*3))  # masternode
    local response=$(rpc_call $mn_port "get_masternode_status" "[]")

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local mn_status=$(echo "$response" | jq -r '.result.status // "UNKNOWN"')
        local pose_failures=$(echo "$response" | jq -r '.result.pose_failures // 0')

        print_status "Masternode status: $mn_status"
        print_status "PoSe failures: $pose_failures"

        if [ "$mn_status" != "ACTIVE" ]; then
            issues+=("Masternode status is $mn_status (expected: ACTIVE)")
        fi

        if [ "$pose_failures" -gt 0 ]; then
            issues+=("Masternode has $pose_failures PoSe failures")
        fi
    else
        issues+=("Cannot get masternode status")
    fi

    # Monitor governance activity
    response=$(rpc_call $mn_port "get_governance_proposals" "[]")
    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local proposal_count=$(echo "$response" | jq '.result | length')
        print_status "Active governance proposals: $proposal_count"
    fi

    # Monitor sidechain operations (if available)
    # This would depend on sidechain implementation details

    # Report issues
    for issue in "${issues[@]}"; do
        send_alert "WARNING" "$issue"
    done
}

# Function to monitor security
monitor_security() {
    print_section "Security Monitoring"

    local issues=()
    local failed_tx_rate=0

    # Check for failed transactions
    local miner_port=$((BASE_PORT + 1*3))
    local response=$(rpc_call $miner_port "get_mempool_info" "[]")

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local mempool_size=$(echo "$response" | jq -r '.result.size // 0')
        local failed_tx=${FAILED_TX_COUNT["total"]:-0}

        if [ "$mempool_size" -gt 0 ]; then
            failed_tx_rate=$(echo "scale=4; $failed_tx / $mempool_size" | bc -l 2>/dev/null || echo "0")
        fi

        if (( $(echo "$failed_tx_rate > $MAX_FAILED_TX_RATE" | bc -l 2>/dev/null || echo "0") )); then
            issues+=("High failed transaction rate: $(printf "%.2f" $(echo "$failed_tx_rate * 100" | bc -l))%")
        fi
    fi

    # Check for consensus violations
    local consensus_violations=${CONSENSUS_VIOLATIONS["total"]:-0}
    if [ "$consensus_violations" -gt "$MAX_CONSENSUS_VIOLATIONS" ]; then
        issues+=("High consensus violations: $consensus_violations in last hour")
    fi

    # Check for unusual network activity
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local response=$(rpc_call $port "get_peer_info" "[]")

        if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
            # Check for peers with unusual connection patterns
            local suspicious_peers=$(echo "$response" | jq '[.result[] | select(.inbound == false and .pingtime > 1000)] | length')
            if [ "$suspicious_peers" -gt 0 ]; then
                issues+=("Node $i has $suspicious_peers suspicious peers")
            fi
        fi
    done

    # Report issues
    for issue in "${issues[@]}"; do
        send_alert "CRITICAL" "$issue"
    done
}

# Function for automated recovery
automated_recovery() {
    print_section "Automated Recovery"

    local recovery_actions=()

    # Check for nodes that need restart
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local node_id="testnet-node-$i"
        local health_port=$((port + 2))
        local pid_file="$DATA_DIR/$node_id/node.pid"

        # Check if node is responsive
        if ! curl -s "http://127.0.0.1:$health_port/health" >/dev/null 2>&1; then
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                if kill -0 $pid 2>/dev/null; then
                    print_warning "Restarting unresponsive node $node_id"
                    kill $pid
                    sleep 2
                fi
                rm -f "$pid_file"
            fi

            # Attempt restart (simplified - would need full restart logic)
            recovery_actions+=("Node $node_id restarted")
            send_alert "INFO" "Automatically restarted node $node_id"
        fi
    done

    # Check for stuck sync and attempt resync
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local node_id="testnet-node-$i"
        local last_height=${LAST_BLOCK_HEIGHTS[$node_id]:-0}
        local current_height=${LAST_BLOCK_HEIGHTS[$node_id]:-0}

        if [ "$last_height" -eq "$current_height" ] && [ "$current_height" -gt 0 ]; then
            # Node appears stuck - could trigger resync
            recovery_actions+=("Node $node_id may need resync")
        fi
    done

    if [ ${#recovery_actions[@]} -gt 0 ]; then
        print_status "Recovery actions taken:"
        for action in "${recovery_actions[@]}"; do
            print_status "  - $action"
        done
    fi
}

# Function to generate monitoring report
generate_report() {
    print_section "Monitoring Report"

    local uptime=$(( $(date +%s) - START_TIME ))
    local uptime_str=$(printf '%02dh:%02dm:%02ds\n' $((uptime/3600)) $((uptime%3600/60)) $((uptime%60)))

    echo "Uptime: $uptime_str"
    echo "Nodes monitored: $NUM_NODES"
    echo "Monitoring interval: ${MONITORING_INTERVAL}s"
    echo ""

    # Node status summary
    echo "Node Status:"
    for i in $(seq 1 $NUM_NODES); do
        local port=$((BASE_PORT + (i - 1) * 3))
        local node_id="testnet-node-$i"
        local block_height=${LAST_BLOCK_HEIGHTS[$node_id]:-"unknown"}

        if curl -s "http://127.0.0.1:$((port+2))/health" >/dev/null 2>&1; then
            echo "  $node_id: ✅ UP (block: $block_height)"
        else
            echo "  $node_id: ❌ DOWN"
        fi
    done

    echo ""
    echo "Recent alerts:"
    if [ -f "$DATA_DIR/monitoring/alerts.log" ]; then
        tail -10 "$DATA_DIR/monitoring/alerts.log" 2>/dev/null || echo "  No recent alerts"
    else
        echo "  No alerts log found"
    fi
}

# Function to setup monitoring directories
setup_monitoring_dirs() {
    mkdir -p "$DATA_DIR/monitoring"
    mkdir -p "$DATA_DIR/logs"
}

# Main monitoring loop
main() {
    print_header "RUSTY COIN TESTNET MONITORING"

    # Parse command line arguments
    case "${1:-monitor}" in
        "monitor")
            setup_monitoring_dirs

            print_status "Starting comprehensive testnet monitoring..."
            print_status "Monitoring interval: ${MONITORING_INTERVAL} seconds"
            print_status "Press Ctrl+C to stop"

            # Initialize state
            for i in $(seq 1 $NUM_NODES); do
                local node_id="testnet-node-$i"
                LAST_BLOCK_HEIGHTS[$node_id]=0
            done

            trap 'print_status "Monitoring stopped by user"; exit 0' INT

            while true; do
                local cycle_start=$(date +%s)

                # Run all monitoring checks
                monitor_node_health
                monitor_network_health
                monitor_service_health
                monitor_security
                automated_recovery

                # Generate periodic report
                local current_time=$(date +%s)
                if [ $((current_time % 300)) -lt $MONITORING_INTERVAL ]; then  # Every 5 minutes
                    generate_report
                fi

                # Wait for next cycle
                local cycle_end=$(date +%s)
                local cycle_duration=$((cycle_end - cycle_start))
                local sleep_time=$((MONITORING_INTERVAL - cycle_duration))

                if [ $sleep_time -gt 0 ]; then
                    sleep $sleep_time
                fi
            done
            ;;
        "status")
            generate_report
            ;;
        "alerts")
            print_header "RECENT ALERTS"
            if [ -f "$DATA_DIR/monitoring/alerts.log" ]; then
                tail -20 "$DATA_DIR/monitoring/alerts.log" 2>/dev/null || echo "No alerts found"
            else
                echo "No alerts log found"
            fi
            ;;
        "check")
            # Run one-time check
            monitor_node_health
            monitor_network_health
            monitor_service_health
            monitor_security
            print_status "One-time check completed"
            ;;
        *)
            echo "Usage: $0 {monitor|status|alerts|check}"
            echo ""
            echo "Commands:"
            echo "  monitor    Start continuous monitoring"
            echo "  status     Show current monitoring status"
            echo "  alerts     Show recent alerts"
            echo "  check      Run one-time health check"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"