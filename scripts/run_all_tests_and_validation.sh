#!/bin/bash

# Rusty Coin Comprehensive Test and Validation Automation Script
# This script executes all Rusty Coin project components including unit tests,
# integration tests, specification compliance, performance benchmarks, security tests,
# and CI/CD pipeline simulation with comprehensive logging and error handling.

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
REPORT_DIR="$PROJECT_ROOT/reports"
TEMP_DIR="$PROJECT_ROOT/temp"
MAX_RETRIES=3
RETRY_DELAY=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test results tracking
declare -A TEST_RESULTS
declare -a FAILURE_REASONS
START_TIME=$(date +%s)
LOG_FILE=""
REPORT_FILE=""

# Function to get timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Function to log with timestamp
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(get_timestamp)
    local colored_message

    case "$level" in
        "INFO")
            colored_message="${GREEN}[INFO]${NC} $timestamp - $message"
            ;;
        "WARN")
            colored_message="${YELLOW}[WARN]${NC} $timestamp - $message"
            ;;
        "ERROR")
            colored_message="${RED}[ERROR]${NC} $timestamp - $message"
            ;;
        "DEBUG")
            colored_message="${BLUE}[DEBUG]${NC} $timestamp - $message"
            ;;
        *)
            colored_message="${NC}$timestamp - $message"
            ;;
    esac

    echo -e "$colored_message"
    echo "$timestamp [$level] $message" >> "$LOG_FILE"
}

# Function to print section header
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to print subsection
print_section() {
    echo -e "${CYAN}--- $1 ---${NC}"
}

# Function to record test result
record_result() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"

    TEST_RESULTS["$test_name"]="$result"
    if [ "$result" = "FAIL" ]; then
        FAILURE_REASONS+=("$test_name: $details")
    fi

    log "INFO" "Test '$test_name': $result${details:+ - $details}"
}

# Function to retry command with exponential backoff
retry_command() {
    local cmd="$1"
    local test_name="$2"
    local attempt=1
    local max_attempts=$MAX_RETRIES

    while [ $attempt -le $max_attempts ]; do
        log "INFO" "Attempting $test_name (attempt $attempt/$max_attempts)"

        if eval "$cmd" >> "$LOG_FILE" 2>&1; then
            log "INFO" "$test_name succeeded on attempt $attempt"
            return 0
        else
            log "WARN" "$test_name failed on attempt $attempt"
            if [ $attempt -lt $max_attempts ]; then
                local delay=$((RETRY_DELAY * attempt))
                log "INFO" "Retrying in $delay seconds..."
                sleep $delay
            fi
        fi
        ((attempt++))
    done

    log "ERROR" "$test_name failed after $max_attempts attempts"
    return 1
}

# Function to check command existence
check_command() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to setup directories
setup_directories() {
    print_section "Setting up directories"

    mkdir -p "$LOG_DIR"
    mkdir -p "$REPORT_DIR"
    mkdir -p "$TEMP_DIR"

    # Generate unique log and report files
    local timestamp=$(date +%Y%m%d_%H%M%S)
    LOG_FILE="$LOG_DIR/validation_run_$timestamp.log"
    REPORT_FILE="$REPORT_DIR/validation_report_$timestamp.md"

    touch "$LOG_FILE"
    touch "$REPORT_FILE"

    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "Report file: $REPORT_FILE"
}

# Function to check dependencies
check_dependencies() {
    print_section "Checking Dependencies"

    local deps=("rustc" "cargo" "jq" "curl")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if check_command "$dep"; then
            log "INFO" "✓ $dep found"
        else
            log "ERROR" "✗ $dep not found"
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        record_result "dependency_check" "FAIL" "Missing: ${missing_deps[*]}"
        return 1
    fi

    # Check Rust version
    local rust_version=$(rustc --version | grep -oP '\d+\.\d+\.\d+')
    log "INFO" "Rust version: $rust_version"

    record_result "dependency_check" "PASS"
    return 0
}

# Function to validate compilation
validate_compilation() {
    print_section "Compilation Validation"

    cd "$PROJECT_ROOT"

    # Run cargo check
    log "INFO" "Running cargo check..."
    if retry_command "cargo check --workspace" "cargo_check"; then
        log "INFO" "✓ cargo check passed"
    else
        record_result "compilation_check" "FAIL" "cargo check failed"
        return 1
    fi

    # Run cargo build --release
    log "INFO" "Running cargo build --release..."
    if retry_command "cargo build --workspace --release" "cargo_build_release"; then
        log "INFO" "✓ cargo build --release passed"
    else
        record_result "compilation_build" "FAIL" "cargo build --release failed"
        return 1
    fi

    record_result "compilation_validation" "PASS"
    return 0
}

# Function to run unit tests
run_unit_tests() {
    print_section "Unit Test Execution"

    cd "$PROJECT_ROOT"

    # Get list of crates from Cargo.toml
    local crates=$(cargo metadata --format-version 1 | jq -r '.packages[].name' | grep '^rusty-')

    local failed_crates=()
    for crate in $crates; do
        log "INFO" "Running unit tests for $crate..."
        if retry_command "cargo test --lib --package $crate" "unit_tests_$crate"; then
            log "INFO" "✓ Unit tests passed for $crate"
        else
            log "ERROR" "✗ Unit tests failed for $crate"
            failed_crates+=("$crate")
        fi
    done

    if [ ${#failed_crates[@]} -gt 0 ]; then
        record_result "unit_tests" "FAIL" "Failed crates: ${failed_crates[*]}"
        return 1
    fi

    record_result "unit_tests" "PASS"
    return 0
}

# Function to run integration tests
run_integration_tests() {
    print_section "Integration Test Execution"

    cd "$PROJECT_ROOT"

    log "INFO" "Running integration tests..."
    if retry_command "cargo test --test '*integration*'" "integration_tests"; then
        log "INFO" "✓ Integration tests passed"
        record_result "integration_tests" "PASS"
        return 0
    else
        record_result "integration_tests" "FAIL" "Integration tests failed"
        return 1
    fi
}

# Function to run specification compliance tests
run_spec_compliance_tests() {
    print_section "Specification Compliance Tests"

    cd "$PROJECT_ROOT"

    local spec_tests=(
        "governance_parameter_tests.rs:spec_09_governance"
        "jsonrpc_api_tests.rs:spec_08_jsonrpc"
        "masternode_spec06_tests.rs:spec_06_masternode"
        "sidechain_spec10_tests.rs:spec_10_sidechain"
        "cross_chain_processing_tests.rs:cross_chain_processing"
    )

    local failed_specs=()
    for spec_test in "${spec_tests[@]}"; do
        local test_file=$(echo "$spec_test" | cut -d: -f1)
        local test_name=$(echo "$spec_test" | cut -d: -f2)

        log "INFO" "Running spec compliance test: $test_name..."
        if retry_command "cargo test --test $test_file" "spec_test_$test_name"; then
            log "INFO" "✓ Spec test passed: $test_name"
        else
            log "ERROR" "✗ Spec test failed: $test_name"
            failed_specs+=("$test_name")
        fi
    done

    if [ ${#failed_specs[@]} -gt 0 ]; then
        record_result "spec_compliance_tests" "FAIL" "Failed specs: ${failed_specs[*]}"
        return 1
    fi

    record_result "spec_compliance_tests" "PASS"
    return 0
}

# Function to run performance benchmarks
run_performance_benchmarks() {
    print_section "Performance Benchmarks"

    cd "$PROJECT_ROOT"

    # Check if cargo-criterion is available
    if ! check_command "cargo-criterion"; then
        log "WARN" "cargo-criterion not found, installing..."
        if ! retry_command "cargo install cargo-criterion" "install_cargo_criterion"; then
            record_result "performance_benchmarks" "FAIL" "Failed to install cargo-criterion"
            return 1
        fi
    fi

    log "INFO" "Running performance benchmarks..."
    if retry_command "cargo criterion --message-format=json > $REPORT_DIR/benchmark_results.json" "performance_benchmarks"; then
        log "INFO" "✓ Performance benchmarks completed"
        record_result "performance_benchmarks" "PASS"
        return 0
    else
        record_result "performance_benchmarks" "FAIL" "Performance benchmarks failed"
        return 1
    fi
}

# Function to run security tests
run_security_tests() {
    print_section "Security Tests"

    cd "$PROJECT_ROOT"

    # Run fuzzing tests
    log "INFO" "Running security fuzzing tests..."
    local fuzz_targets=(
        "fuzz_block_parsing"
        "fuzz_consensus_validation"
        "fuzz_cross_chain_tx"
        "fuzz_ferrisscript"
        "fuzz_fraud_proofs"
        "fuzz_governance_proposals"
        "fuzz_merkle_proofs"
        "fuzz_sidechain_validation"
        "fuzz_transaction_parsing"
    )

    # Check if cargo-fuzz is available
    if ! check_command "cargo-fuzz"; then
        log "WARN" "cargo-fuzz not found, installing..."
        if ! retry_command "cargo install cargo-fuzz" "install_cargo_fuzz"; then
            record_result "security_fuzzing" "FAIL" "Failed to install cargo-fuzz"
            return 1
        fi
    fi

    local failed_fuzz=()
    for target in "${fuzz_targets[@]}"; do
        log "INFO" "Running fuzz test: $target..."
        if cd rusty-core && retry_command "cargo fuzz run $target -- -max_total_time=10" "fuzz_$target"; then
            log "INFO" "✓ Fuzz test passed: $target"
        else
            log "ERROR" "✗ Fuzz test failed: $target"
            failed_fuzz+=("$target")
        fi
        cd "$PROJECT_ROOT"
    done

    # Run security audit
    log "INFO" "Running security audit..."
    if ! check_command "cargo-audit"; then
        log "WARN" "cargo-audit not found, installing..."
        retry_command "cargo install cargo-audit" "install_cargo_audit" || true
    fi

    if check_command "cargo-audit"; then
        if retry_command "cargo audit --format json > $REPORT_DIR/audit_results.json" "security_audit"; then
            # Check for critical vulnerabilities
            local critical_count=$(jq '.vulnerabilities.critical | length' "$REPORT_DIR/audit_results.json" 2>/dev/null || echo "0")
            if [ "$critical_count" -gt 0 ]; then
                log "ERROR" "Found $critical_count critical security vulnerabilities"
                record_result "security_audit" "FAIL" "$critical_count critical vulnerabilities found"
            else
                log "INFO" "✓ No critical security vulnerabilities found"
                record_result "security_audit" "PASS"
            fi
        else
            record_result "security_audit" "FAIL" "Security audit failed"
        fi
    else
        log "WARN" "cargo-audit not available, skipping security audit"
        record_result "security_audit" "SKIP" "cargo-audit not available"
    fi

    # Run edge case tests
    log "INFO" "Running security edge case tests..."
    if retry_command "cargo test --test security_edge_case_tests" "security_edge_cases"; then
        log "INFO" "✓ Security edge case tests passed"
    else
        log "ERROR" "✗ Security edge case tests failed"
        failed_fuzz+=("edge_cases")
    fi

    if [ ${#failed_fuzz[@]} -gt 0 ]; then
        record_result "security_fuzzing" "FAIL" "Failed: ${failed_fuzz[*]}"
        return 1
    fi

    record_result "security_tests" "PASS"
    return 0
}

# Function to validate scripts
validate_scripts() {
    print_section "Script Validation"

    cd "$PROJECT_ROOT"

    local scripts=(
        "setup_regtest_network.sh:test"
        "deploy_testnet.sh:status"
        "monitor_testnet.sh:--help"
    )

    local failed_scripts=()
    for script_info in "${scripts[@]}"; do
        local script=$(echo "$script_info" | cut -d: -f1)
        local arg=$(echo "$script_info" | cut -d: -f2)

        if [ -f "scripts/$script" ]; then
            log "INFO" "Validating script: $script..."
            if retry_command "./scripts/$script $arg" "script_validation_$script"; then
                log "INFO" "✓ Script validation passed: $script"
            else
                log "ERROR" "✗ Script validation failed: $script"
                failed_scripts+=("$script")
            fi
        else
            log "WARN" "Script not found: $script"
            failed_scripts+=("$script")
        fi
    done

    if [ ${#failed_scripts[@]} -gt 0 ]; then
        record_result "script_validation" "FAIL" "Failed scripts: ${failed_scripts[*]}"
        return 1
    fi

    record_result "script_validation" "PASS"
    return 0
}

# Function to simulate CI/CD pipeline
simulate_ci_pipeline() {
    print_section "CI/CD Pipeline Simulation"

    cd "$PROJECT_ROOT"

    log "INFO" "Simulating CI/CD pipeline locally..."

    # Simulate build job
    log "INFO" "Simulating build job..."
    if retry_command "cargo build --workspace --release" "ci_build"; then
        log "INFO" "✓ CI build simulation passed"
    else
        record_result "ci_pipeline_build" "FAIL" "Build simulation failed"
        return 1
    fi

    # Simulate test jobs
    log "INFO" "Simulating test jobs..."
    if retry_command "cargo test --workspace" "ci_tests"; then
        log "INFO" "✓ CI test simulation passed"
    else
        record_result "ci_pipeline_tests" "FAIL" "Test simulation failed"
        return 1
    fi

    # Simulate quality checks
    log "INFO" "Simulating quality checks..."
    if retry_command "cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings" "ci_quality"; then
        log "INFO" "✓ CI quality checks passed"
    else
        record_result "ci_pipeline_quality" "FAIL" "Quality checks failed"
        return 1
    fi

    record_result "ci_pipeline_simulation" "PASS"
    return 0
}

# Function to analyze failures
analyze_failures() {
    print_section "Failure Analysis"

    if [ ${#FAILURE_REASONS[@]} -eq 0 ]; then
        log "INFO" "No failures to analyze"
        return 0
    fi

    log "INFO" "Analyzing ${#FAILURE_REASONS[@]} failures..."

    # Analyze log file for common error patterns
    local error_patterns=(
        "panic!:.*"
        "thread.*panicked"
        "error\\[.*\\]"
        "FAILED"
        "Compilation failed"
        "Test failed"
    )

    echo "# Failure Analysis Report" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    for reason in "${FAILURE_REASONS[@]}"; do
        echo "## $reason" >> "$REPORT_FILE"

        # Extract relevant log lines
        local test_name=$(echo "$reason" | cut -d: -f1)
        grep -A 10 -B 5 "$test_name" "$LOG_FILE" | head -20 >> "$REPORT_FILE" 2>/dev/null || true
        echo "" >> "$REPORT_FILE"
    done

    # Suggest fixes based on common patterns
    echo "## Suggested Fixes" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    if grep -q "cargo check" "$LOG_FILE" && grep -q "error" "$LOG_FILE"; then
        echo "- **Compilation Errors**: Check for missing dependencies or syntax errors in source code" >> "$REPORT_FILE"
    fi

    if grep -q "test.*failed" "$LOG_FILE"; then
        echo "- **Test Failures**: Review test logic, check for race conditions, or environment-specific issues" >> "$REPORT_FILE"
    fi

    if grep -q "panic!" "$LOG_FILE"; then
        echo "- **Panics**: Check for null pointer dereferences, array bounds issues, or assertion failures" >> "$REPORT_FILE"
    fi

    if grep -q "timeout" "$LOG_FILE"; then
        echo "- **Timeouts**: Consider increasing timeouts or optimizing performance" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"
}

# Function to generate comprehensive report
generate_report() {
    print_section "Generating Comprehensive Report"

    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))

    {
        echo "# Rusty Coin Validation Report"
        echo "Generated: $(get_timestamp)"
        echo "Duration: ${duration}s"
        echo ""

        echo "## Test Results Summary"
        echo ""

        local total_tests=0
        local passed_tests=0
        local failed_tests=0
        local skipped_tests=0

        for test in "${!TEST_RESULTS[@]}"; do
            ((total_tests++))
            case "${TEST_RESULTS[$test]}" in
                "PASS")
                    ((passed_tests++))
                    echo "- ✅ **$test**: PASSED"
                    ;;
                "FAIL")
                    ((failed_tests++))
                    echo "- ❌ **$test**: FAILED"
                    ;;
                "SKIP")
                    ((skipped_tests++))
                    echo "- ⏭️ **$test**: SKIPPED"
                    ;;
            esac
        done

        echo ""
        echo "## Statistics"
        echo "- **Total Tests**: $total_tests"
        echo "- **Passed**: $passed_tests"
        echo "- **Failed**: $failed_tests"
        echo "- **Skipped**: $skipped_tests"
        echo "- **Success Rate**: $((passed_tests * 100 / total_tests))%"
        echo ""

        if [ ${#FAILURE_REASONS[@]} -gt 0 ]; then
            echo "## Failure Details"
            echo ""
            for reason in "${FAILURE_REASONS[@]}"; do
                echo "- $reason"
            done
            echo ""
        fi

        echo "## System Information"
        echo "- **OS**: $(uname -s) $(uname -r)"
        echo "- **Rust**: $(rustc --version)"
        echo "- **Cargo**: $(cargo --version)"
        echo "- **Working Directory**: $PROJECT_ROOT"
        echo ""

        echo "## Log Files"
        echo "- **Main Log**: $LOG_FILE"
        echo "- **Reports Directory**: $REPORT_DIR"
        echo ""

    } > "$REPORT_FILE"

    log "INFO" "Report generated: $REPORT_FILE"
}

# Function to cleanup
cleanup() {
    print_section "Cleanup"

    log "INFO" "Performing cleanup..."

    # Stop any background processes
    pkill -f "rusty-node.*regtest" || true
    pkill -f "monitor_testnet" || true

    # Clean temporary files
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        log "INFO" "Cleaned temporary directory: $TEMP_DIR"
    fi

    # Keep logs and reports for analysis
    log "INFO" "Preserved logs and reports for analysis"
}

# Function to display final status
display_final_status() {
    print_header "VALIDATION COMPLETE"

    local total_tests=${#TEST_RESULTS[@]}
    local passed=0
    local failed=0

    for result in "${TEST_RESULTS[@]}"; do
        case "$result" in
            "PASS") ((passed++)) ;;
            "FAIL") ((failed++)) ;;
        esac
    done

    echo -e "${BLUE}Total Tests Run:${NC} $total_tests"
    echo -e "${GREEN}Passed:${NC} $passed"
    echo -e "${RED}Failed:${NC} $failed"
    echo -e "${BLUE}Success Rate:${NC} $((passed * 100 / total_tests))%"
    echo ""
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo ""

    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL VALIDATION CHECKS PASSED!${NC}"
        echo "The Rusty Coin project is ready for deployment."
        return 0
    else
        echo -e "${RED}❌ VALIDATION FAILED${NC}"
        echo "Please review the log and report files for details."
        echo ""
        echo "Failure Summary:"
        for reason in "${FAILURE_REASONS[@]}"; do
            echo -e "${RED}  - $reason${NC}"
        done
        return 1
    fi
}

# Main function
main() {
    print_header "RUSTY COIN COMPREHENSIVE VALIDATION"

    # Setup
    setup_directories

    # Run all validation steps
    local steps=(
        "check_dependencies"
        "validate_compilation"
        "run_unit_tests"
        "run_integration_tests"
        "run_spec_compliance_tests"
        "run_performance_benchmarks"
        "run_security_tests"
        "validate_scripts"
        "simulate_ci_pipeline"
    )

    local failed_steps=()

    for step in "${steps[@]}"; do
        log "INFO" "Starting step: $step"
        if ! $step; then
            failed_steps+=("$step")
            log "ERROR" "Step failed: $step"
            # Continue with other steps for comprehensive reporting
        fi
    done

    # Analysis and reporting
    analyze_failures
    generate_report
    cleanup
    display_final_status

    # Exit with failure if any step failed
    if [ ${#failed_steps[@]} -gt 0 ]; then
        log "ERROR" "Validation failed with ${#failed_steps[@]} failed steps: ${failed_steps[*]}"
        exit 1
    else
        log "INFO" "All validation steps completed successfully"
        exit 0
    fi
}

# Handle command line arguments
case "${1:-run}" in
    "run")
        main
        ;;
    "clean")
        cleanup
        echo "Cleanup completed"
        ;;
    "report")
        if [ -n "${2:-}" ]; then
            REPORT_FILE="$2"
        fi
        generate_report
        echo "Report generated: $REPORT_FILE"
        ;;
    *)
        echo "Usage: $0 {run|clean|report [report_file]}"
        echo ""
        echo "Commands:"
        echo "  run              Run all validation tests"
        echo "  clean            Clean up temporary files and processes"
        echo "  report [file]    Generate validation report"
        exit 1
        ;;
esac