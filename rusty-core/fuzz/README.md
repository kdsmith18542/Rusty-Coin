# Fuzz Testing for Rusty Coin Core

This directory contains comprehensive fuzz testing targets for the Rusty Coin core components. Fuzz testing helps discover security vulnerabilities, edge cases, and robustness issues by feeding random or semi-random data to the system.

## Overview

The fuzz testing suite covers all critical components of the Rusty Coin system:

- **Block Parsing** - Tests block and transaction parsing robustness
- **Transaction Validation** - Tests transaction validation and edge cases
- **Sidechain Operations** - Tests sidechain block validation and cross-chain transactions
- **Governance Proposals** - Tests governance proposal parsing and voting mechanisms
- **Cross-Chain Transactions** - Tests cross-chain transaction validation and proofs
- **Fraud Proofs** - Tests fraud detection and proof validation
- **Merkle Proofs** - Tests Merkle tree operations and proof validation
- **Consensus Validation** - Tests consensus rules and block acceptance

## Fuzz Targets

### 1. Block Parsing (`fuzz_block_parsing`)
Tests the robustness of block and transaction parsing against malformed input.

**Coverage:**
- Raw binary parsing of blocks and transactions
- Structured fuzzing with well-formed but potentially malicious data
- Serialization round-trip testing
- Validation edge cases with extreme values

**Key Areas:**
- Block header validation
- Transaction input/output parsing
- Merkle root calculation
- Block hash computation

### 2. Transaction Parsing (`fuzz_transaction_parsing`)
Focuses on transaction-specific parsing and validation vulnerabilities.

**Coverage:**
- Transaction structure validation
- Input/output value arithmetic (overflow/underflow testing)
- Script parsing and validation
- Lock time and sequence number handling

**Key Areas:**
- Value overflow protection
- Script size limits
- Input/output bounds checking
- Fee calculation accuracy

### 3. Sidechain Validation (`fuzz_sidechain_validation`)
Tests sidechain block validation and cross-chain operations.

**Coverage:**
- Sidechain block structure validation
- VM execution data parsing
- Cross-chain transaction validation
- Fraud proof parsing

**Key Areas:**
- Multi-VM support (EVM, WASM, UtxoVM, Native)
- Cross-chain proof verification
- Federation signature validation
- State root calculation

### 4. Governance Proposals (`fuzz_governance_proposals`)
Tests governance proposal parsing, validation, and execution.

**Coverage:**
- Proposal structure validation
- Voting mechanism testing
- Parameter change validation
- Proposal execution logic

**Key Areas:**
- Stake-based voting power
- Proposal type handling
- Deadline enforcement
- Parameter validation

### 5. Cross-Chain Transactions (`fuzz_cross_chain_tx`)
Tests cross-chain transaction validation and utilities.

**Coverage:**
- Cross-chain transaction types (PegIn, PegOut, SidechainToSidechain)
- Merkle proof validation
- Federation signature verification
- Batch transaction processing

**Key Areas:**
- Proof verification algorithms
- Signature threshold validation
- Amount and fee calculations
- Chain ID validation

### 6. Fraud Proofs (`fuzz_fraud_proofs`)
Tests fraud detection and proof validation mechanisms.

**Coverage:**
- Fraud proof structure validation
- Evidence parsing and verification
- Challenge-response mechanisms
- Penalty and reward calculations

**Key Areas:**
- Multiple fraud types
- Evidence validation
- Timeout handling
- Economic incentive calculations

### 7. Merkle Proofs (`fuzz_merkle_proofs`)
Tests Merkle tree operations and proof validation.

**Coverage:**
- Merkle tree construction
- Proof generation and verification
- Edge cases (empty trees, single leaves)
- Block Merkle root validation

**Key Areas:**
- Proof verification algorithms
- Tree size validation
- Index bounds checking
- Hash calculation accuracy

### 8. Consensus Validation (`fuzz_consensus_validation`)
Tests consensus rule validation and chain state management.

**Coverage:**
- Block validation rules
- Difficulty adjustment algorithms
- Chain state management
- Memory pool operations

**Key Areas:**
- Difficulty target validation
- Timestamp verification
- Chain reorganization
- Work calculation

## Running Fuzz Tests

### Prerequisites

1. Install `cargo-fuzz`:
```bash
cargo install cargo-fuzz
```

2. Ensure you have the nightly Rust toolchain:
```bash
rustup install nightly
rustup default nightly
```

### Running Individual Targets

Run a specific fuzz target:
```bash
cd rusty-core
cargo fuzz run fuzz_block_parsing
```

Run with specific options:
```bash
# Run for 60 seconds
cargo fuzz run fuzz_block_parsing -- -max_total_time=60

# Run with specific number of iterations
cargo fuzz run fuzz_transaction_parsing -- -runs=10000

# Run with custom timeout per input
cargo fuzz run fuzz_sidechain_validation -- -timeout=30
```

### Running All Targets

Run all fuzz targets sequentially:
```bash
#!/bin/bash
TARGETS=(
    "fuzz_block_parsing"
    "fuzz_transaction_parsing"
    "fuzz_sidechain_validation"
    "fuzz_governance_proposals"
    "fuzz_cross_chain_tx"
    "fuzz_fraud_proofs"
    "fuzz_merkle_proofs"
    "fuzz_consensus_validation"
)

for target in "${TARGETS[@]}"; do
    echo "Running $target..."
    cargo fuzz run $target -- -max_total_time=300  # 5 minutes each
done
```

### Continuous Fuzzing

For continuous integration or long-running fuzzing:
```bash
# Run indefinitely until crash found
cargo fuzz run fuzz_block_parsing -- -max_total_time=0

# Run with memory limit
cargo fuzz run fuzz_transaction_parsing -- -rss_limit_mb=2048

# Run with artifact generation
cargo fuzz run fuzz_sidechain_validation -- -artifact_prefix=sidechain_
```

## Analyzing Results

### Crash Investigation

When a fuzz target finds a crash, it saves the input that caused it:
```bash
# Reproduce a crash
cargo fuzz run fuzz_block_parsing fuzz/artifacts/fuzz_block_parsing/crash-<hash>

# Debug with more verbose output
RUST_LOG=debug cargo fuzz run fuzz_block_parsing fuzz/artifacts/fuzz_block_parsing/crash-<hash>
```

### Coverage Analysis

Generate coverage reports:
```bash
# Install coverage tools
cargo install cargo-cov

# Run with coverage
cargo fuzz coverage fuzz_block_parsing

# Generate HTML report
cargo cov report --html
```

### Performance Profiling

Profile fuzz target performance:
```bash
# Run with profiling
cargo fuzz run fuzz_transaction_parsing -- -print_stats=1

# Memory usage profiling
cargo fuzz run fuzz_sidechain_validation -- -malloc_limit_mb=1024 -print_stats=1
```

## Configuration

### Fuzz Target Configuration

Each fuzz target can be configured through command-line options:

```bash
# Common useful options
-max_total_time=N     # Run for N seconds
-runs=N              # Run N iterations
-timeout=N           # Timeout per input (seconds)
-rss_limit_mb=N      # Memory limit in MB
-artifact_prefix=X   # Prefix for saved artifacts
-print_stats=1       # Print execution statistics
-verbosity=N         # Verbosity level (0-3)
```

### Custom Dictionaries

Create custom dictionaries for better fuzzing:
```bash
# Create dictionary file
echo -e '"rusty"\n"coin"\n"sidechain"\n"governance"' > fuzz/dict.txt

# Use dictionary
cargo fuzz run fuzz_governance_proposals -- -dict=fuzz/dict.txt
```

## Best Practices

### 1. Regular Fuzzing
- Run fuzz tests regularly as part of CI/CD
- Allocate dedicated fuzzing time for each release
- Monitor for new crash patterns

### 2. Seed Corpus Management
- Maintain good seed inputs for each target
- Add interesting test cases to seed corpus
- Share corpus between similar targets

### 3. Crash Triage
- Investigate all crashes promptly
- Categorize crashes by severity
- Create regression tests for fixed issues

### 4. Performance Monitoring
- Monitor fuzzing performance over time
- Optimize slow fuzz targets
- Balance coverage vs. speed

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Fuzz Testing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - fuzz_block_parsing
          - fuzz_transaction_parsing
          - fuzz_sidechain_validation
          - fuzz_governance_proposals
          - fuzz_cross_chain_tx
          - fuzz_fraud_proofs
          - fuzz_merkle_proofs
          - fuzz_consensus_validation
    
    steps:
    - uses: actions/checkout@v3
    - uses: actions-rs/toolchain@v1
      with:
        toolchain: nightly
        override: true
    
    - name: Install cargo-fuzz
      run: cargo install cargo-fuzz
    
    - name: Run fuzz target
      run: |
        cd rusty-core
        timeout 1800 cargo fuzz run ${{ matrix.target }} || true
    
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: fuzz-artifacts-${{ matrix.target }}
        path: rusty-core/fuzz/artifacts/
```

## Security Considerations

### 1. Input Validation
- All fuzz targets test input validation robustness
- Focus on boundary conditions and edge cases
- Test with malformed and malicious inputs

### 2. Memory Safety
- Fuzz targets help detect memory safety issues
- Monitor for buffer overflows and use-after-free
- Test with various memory limits

### 3. Denial of Service
- Test for algorithmic complexity attacks
- Monitor resource usage during fuzzing
- Validate timeout and limit enforcement

### 4. Cryptographic Operations
- Fuzz cryptographic parsing and validation
- Test signature verification edge cases
- Validate hash function inputs

## Troubleshooting

### Common Issues

1. **Out of Memory**
   - Reduce input size limits
   - Use `-rss_limit_mb` option
   - Optimize data structures

2. **Slow Fuzzing**
   - Profile target performance
   - Reduce validation complexity
   - Use faster hash functions for fuzzing

3. **False Positives**
   - Review crash conditions
   - Add proper error handling
   - Distinguish expected vs. unexpected failures

4. **Coverage Gaps**
   - Analyze coverage reports
   - Add targeted test cases
   - Improve input generation

## Contributing

When adding new fuzz targets:

1. Follow existing naming conventions
2. Include comprehensive documentation
3. Test with various input sizes
4. Add appropriate error handling
5. Update this README with new targets

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [Fuzzing best practices](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
