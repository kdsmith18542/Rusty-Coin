#!/bin/bash
# Quick Specification Compliance Check for Rusty Coin
# This script performs basic checks to verify the project meets the specifications

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPECS_DIR="$PROJECT_ROOT/docs/specs"
RESULTS_FILE="$PROJECT_ROOT/spec_compliance_results.txt"

echo "🔍 Rusty Coin Specification Compliance Check"
echo "=============================================="
echo "Project Root: $PROJECT_ROOT"
echo "Specs Directory: $SPECS_DIR"
echo ""

# Initialize results
PASSED=0
FAILED=0
TOTAL=0

check_spec() {
    local spec_name="$1"
    local spec_file="$2"
    local check_function="$3"
    
    echo "📋 Checking $spec_name..."
    TOTAL=$((TOTAL + 1))
    
    if [ -f "$spec_file" ]; then
        if $check_function; then
            echo "   ✅ PASS - $spec_name"
            PASSED=$((PASSED + 1))
        else
            echo "   ❌ FAIL - $spec_name"
            FAILED=$((FAILED + 1))
        fi
    else
        echo "   ⚠️  SKIP - $spec_file not found"
    fi
    echo ""
}

# Check 01 - Block Structure
check_block_structure() {
    # Check for BlockHeader struct
    if grep -r "struct BlockHeader" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for required fields
        if grep -r "version:" "$PROJECT_ROOT" --include="*.rs" | grep -q "u32" && \
           grep -r "height:" "$PROJECT_ROOT" --include="*.rs" | grep -q "u64" && \
           grep -r "previous_block_hash:" "$PROJECT_ROOT" --include="*.rs" | grep -q "\[u8; 32\]"; then
            return 0
        fi
    fi
    return 1
}

# Check 02 - OxideHash PoW
check_oxidehash_pow() {
    # Check for OxideHash implementation
    if grep -r "OxideHash\|oxide_hash" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for required constants
        if grep -r "SCRATCHPAD_SIZE" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1 && \
           grep -r "ITERATIONS_PER_HASH" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 03 - OxideSync PoS
check_oxidesync_pos() {
    # Check for PoS-related structures
    if grep -r "TicketVote\|ticket_vote" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for PoS states
        if grep -r "LIVE\|PENDING\|EXPIRED" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 04 - FerrisScript
check_ferrisscript() {
    # Check for script engine
    if [ -f "$PROJECT_ROOT/rusty-core/src/script/script_engine.rs" ] || \
       [ -f "$PROJECT_ROOT/rusty-core/src/script/opcode.rs" ]; then
        # Check for required opcodes
        if grep -r "OP_CHECKSIG\|OP_DUP\|OP_HASH160" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 05 - UTXO Model
check_utxo_model() {
    # Check for UTXO structures
    if grep -r "struct.*Utxo\|struct.*UTXO" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for UTXO set management
        if grep -r "utxo_set\|UTXO_SET" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 06 - Masternode Protocol
check_masternode_protocol() {
    # Check for masternode implementation
    if [ -d "$PROJECT_ROOT/rusty-masternode" ] || \
       grep -r "Masternode\|masternode" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for PoSe (Proof of Service)
        if grep -r "PoSe\|POSE" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 07 - P2P Protocol
check_p2p_protocol() {
    # Check for P2P implementation
    if [ -d "$PROJECT_ROOT/rusty-p2p" ] || [ -d "$PROJECT_ROOT/rusty-network" ]; then
        # Check for network message types
        if grep -r "GetHeaders\|GetBlock\|Transaction" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 08 - JSON-RPC
check_json_rpc() {
    # Check for RPC implementation
    if [ -d "$PROJECT_ROOT/rusty-rpc" ] || [ -d "$PROJECT_ROOT/rusty-jsonrpc" ]; then
        # Check for RPC methods
        if grep -r "rpc\|RPC" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 09 - Governance Protocol
check_governance_protocol() {
    # Check for governance implementation
    if [ -d "$PROJECT_ROOT/rusty-governance" ] || \
       grep -r "governance\|Governance" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        # Check for governance structures
        if grep -r "Proposal\|Vote" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 10 - Sidechain Protocol
check_sidechain_protocol() {
    # Check for sidechain implementation
    if [ -d "$PROJECT_ROOT/rusty-core/src/sidechain" ] || \
       grep -r "sidechain\|Sidechain" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Check 11 - Post-Quantum Migration
check_pq_migration() {
    # Check for PQ crypto implementation
    if [ -d "$PROJECT_ROOT/rusty-crypto" ]; then
        # Check for PQ algorithms
        if grep -r "post.*quantum\|quantum.*resistant" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Check 12 - Adaptive Block Size
check_adaptive_block_size() {
    # Check for adaptive block size implementation
    if grep -r "adaptive.*block.*size\|block.*size.*adaptive" "$PROJECT_ROOT" --include="*.rs" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Run all checks
echo "Starting specification compliance checks..."
echo ""

check_spec "01 - Block Structure" "$SPECS_DIR/01_block_structure.md" check_block_structure
check_spec "02 - OxideHash PoW" "$SPECS_DIR/02_oxidehash_pow_spec.md" check_oxidehash_pow
check_spec "03 - OxideSync PoS" "$SPECS_DIR/03_oxidesync_pos_spec.md" check_oxidesync_pos
check_spec "04 - FerrisScript" "$SPECS_DIR/04_ferrisscript_spec.md" check_ferrisscript
check_spec "05 - UTXO Model" "$SPECS_DIR/05_utxo_model_spec.md" check_utxo_model
check_spec "06 - Masternode Protocol" "$SPECS_DIR/06_masternode_protocol_spec.md" check_masternode_protocol
check_spec "07 - P2P Protocol" "$SPECS_DIR/07_p2p_protocol_spec.md" check_p2p_protocol
check_spec "08 - JSON-RPC" "$SPECS_DIR/08_json_rpc_spec.md" check_json_rpc
check_spec "09 - Governance Protocol" "$SPECS_DIR/09_governance_protocol_spec.md" check_governance_protocol
check_spec "10 - Sidechain Protocol" "$SPECS_DIR/10_sidechain_protocol_spec.md" check_sidechain_protocol
check_spec "11 - Post-Quantum Migration" "$SPECS_DIR/11_pq_migration_spec.md" check_pq_migration
check_spec "12 - Adaptive Block Size" "$SPECS_DIR/12_adaptive_block_size_spec.md" check_adaptive_block_size

# Generate summary report
echo "=============================================="
echo "📊 COMPLIANCE SUMMARY"
echo "=============================================="
echo "Total Specifications: $TOTAL"
echo "Passed: $PASSED ✅"
echo "Failed: $FAILED ❌"
echo "Compliance Rate: $(( (PASSED * 100) / TOTAL ))%"
echo ""

# Save results to file
{
    echo "Rusty Coin Specification Compliance Results"
    echo "Generated: $(date)"
    echo "=============================================="
    echo "Total Specifications: $TOTAL"
    echo "Passed: $PASSED ✅"
    echo "Failed: $FAILED ❌"
    echo "Compliance Rate: $(( (PASSED * 100) / TOTAL ))%"
    echo ""
    echo "For detailed analysis, run: python3 scripts/verify_specs.py --verbose"
} > "$RESULTS_FILE"

echo "📄 Results saved to: $RESULTS_FILE"
echo ""
echo "💡 For detailed analysis, run:"
echo "   python3 scripts/verify_specs.py --verbose"
echo "   python3 scripts/verify_specs.py --output detailed_report.md"


