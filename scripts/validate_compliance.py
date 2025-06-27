#!/usr/bin/env python3
"""
Compliance validation script for Rusty Coin consensus structures.

This script validates that the implementation matches the formal specifications
without requiring Rust compilation.
"""

import os
import re
import sys
from pathlib import Path

def check_file_exists(path):
    """Check if a file exists and return its content."""
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return f.read()

def validate_block_header_structure():
    """Validate BlockHeader structure compliance."""
    print("🔍 Validating BlockHeader structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for BlockHeader struct
    block_header_pattern = r'pub struct BlockHeader\s*\{([^}]+)\}'
    match = re.search(block_header_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ BlockHeader struct not found")
        return False
    
    fields = match.group(1)
    required_fields = [
        'version: u32',
        'previous_block_hash: \[u8; 32\]',
        'merkle_root: \[u8; 32\]',
        'timestamp: u64',
        'nonce: u64',
        'difficulty_target: u32',
        'height: u64',
        'state_root: \[u8; 32\]'
    ]
    
    missing_fields = []
    for field in required_fields:
        if not re.search(field.replace('[', r'\[').replace(']', r'\]'), fields):
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing BlockHeader fields: {missing_fields}")
        return False
    
    print("✅ BlockHeader structure is compliant")
    return True

def validate_block_structure():
    """Validate Block structure compliance."""
    print("🔍 Validating Block structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for Block struct
    block_pattern = r'pub struct Block\s*\{([^}]+)\}'
    match = re.search(block_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ Block struct not found")
        return False
    
    fields = match.group(1)
    required_fields = [
        'header: BlockHeader',
        'ticket_votes: Vec<TicketVote>',
        'transactions: Vec<Transaction>'
    ]
    
    missing_fields = []
    for field in required_fields:
        if field not in fields:
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing Block fields: {missing_fields}")
        return False
    
    print("✅ Block structure is compliant")
    return True

def validate_ticket_vote_structure():
    """Validate TicketVote structure compliance."""
    print("🔍 Validating TicketVote structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for TicketVote struct
    ticket_vote_pattern = r'pub struct TicketVote\s*\{([^}]+)\}'
    match = re.search(ticket_vote_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ TicketVote struct not found")
        return False
    
    fields = match.group(1)
    required_fields = [
        'ticket_id: \[u8; 32\]',
        'block_hash: \[u8; 32\]',
        'vote: VoteType',
        'signature: TransactionSignature'
    ]
    
    missing_fields = []
    for field in required_fields:
        if not re.search(field.replace('[', r'\[').replace(']', r'\]'), fields):
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing TicketVote fields: {missing_fields}")
        return False
    
    # Check VoteType enum
    vote_type_pattern = r'pub enum VoteType\s*\{([^}]+)\}'
    vote_match = re.search(vote_type_pattern, content, re.DOTALL)
    
    if not vote_match:
        print("❌ VoteType enum not found")
        return False
    
    vote_fields = vote_match.group(1)
    required_vote_types = ['Yes = 0', 'No = 1', 'Abstain = 2']
    
    for vote_type in required_vote_types:
        if vote_type not in vote_fields:
            print(f"❌ Missing VoteType: {vote_type}")
            return False
    
    print("✅ TicketVote structure is compliant")
    return True

def validate_transaction_structure():
    """Validate Transaction structure compliance."""
    print("🔍 Validating Transaction structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for Transaction enum
    transaction_pattern = r'pub enum Transaction\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
    match = re.search(transaction_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ Transaction enum not found")
        return False
    
    transaction_content = match.group(1)
    
    # Check for Standard transaction variant
    if 'Standard {' not in transaction_content:
        print("❌ Standard transaction variant not found")
        return False
    
    # Extract Standard variant fields
    standard_pattern = r'Standard\s*\{([^}]+)\}'
    standard_match = re.search(standard_pattern, transaction_content, re.DOTALL)
    
    if not standard_match:
        print("❌ Standard transaction fields not found")
        return False
    
    standard_fields = standard_match.group(1)
    required_fields = [
        'version: u32',
        'inputs: Vec<TxInput>',
        'outputs: Vec<TxOutput>',
        'lock_time: u32',
        'fee: u64',
        'witness: Vec<Vec<u8>>'
    ]
    
    missing_fields = []
    for field in required_fields:
        if field not in standard_fields:
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing Standard transaction fields: {missing_fields}")
        return False
    
    print("✅ Transaction structure is compliant")
    return True

def validate_tx_output_structure():
    """Validate TxOutput structure compliance."""
    print("🔍 Validating TxOutput structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for TxOutput struct
    tx_output_pattern = r'pub struct TxOutput\s*\{([^}]+)\}'
    match = re.search(tx_output_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ TxOutput struct not found")
        return False
    
    fields = match.group(1)
    required_fields = [
        'value: u64',
        'script_pubkey: Vec<u8>',
        'memo: Option<Vec<u8>>'
    ]
    
    missing_fields = []
    for field in required_fields:
        if field not in fields:
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing TxOutput fields: {missing_fields}")
        return False
    
    # Check for constructor methods
    if 'pub fn new(' not in content:
        print("❌ TxOutput::new() constructor not found")
        return False
    
    if 'pub fn new_with_memo(' not in content:
        print("❌ TxOutput::new_with_memo() constructor not found")
        return False
    
    print("✅ TxOutput structure is compliant")
    return True

def validate_tx_input_structure():
    """Validate TxInput structure compliance."""
    print("🔍 Validating TxInput structure...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for TxInput struct
    tx_input_pattern = r'pub struct TxInput\s*\{([^}]+)\}'
    match = re.search(tx_input_pattern, content, re.DOTALL)
    
    if not match:
        print("❌ TxInput struct not found")
        return False
    
    fields = match.group(1)
    required_fields = [
        'previous_output: OutPoint',
        'script_sig: Vec<u8>',
        'sequence: u32'
    ]
    
    missing_fields = []
    for field in required_fields:
        if field not in fields:
            missing_fields.append(field)
    
    if missing_fields:
        print(f"❌ Missing TxInput fields: {missing_fields}")
        return False
    
    # Check for OutPoint struct
    outpoint_pattern = r'pub struct OutPoint\s*\{([^}]+)\}'
    outpoint_match = re.search(outpoint_pattern, content, re.DOTALL)
    
    if not outpoint_match:
        print("❌ OutPoint struct not found")
        return False
    
    outpoint_fields = outpoint_match.group(1)
    required_outpoint_fields = [
        'txid: \[u8; 32\]',
        'vout: u32'
    ]
    
    for field in required_outpoint_fields:
        if not re.search(field.replace('[', r'\[').replace(']', r'\]'), outpoint_fields):
            print(f"❌ Missing OutPoint field: {field}")
            return False
    
    print("✅ TxInput structure is compliant")
    return True

def validate_serialization_support():
    """Validate serialization support."""
    print("🔍 Validating serialization support...")
    
    shared_types_path = "rusty-shared-types/src/lib.rs"
    content = check_file_exists(shared_types_path)
    
    if not content:
        print("❌ Could not find rusty-shared-types/src/lib.rs")
        return False
    
    # Check for required derive macros
    required_derives = [
        'Serialize',
        'Deserialize',
        'Encode',
        'Decode'
    ]
    
    structures = ['BlockHeader', 'Block', 'TicketVote', 'Transaction', 'TxOutput', 'TxInput']
    
    for structure in structures:
        struct_pattern = rf'#\[derive\([^\]]*\)\]\s*pub (?:struct|enum) {structure}'
        match = re.search(struct_pattern, content, re.DOTALL)
        
        if not match:
            print(f"❌ {structure} derive macros not found")
            return False
        
        derive_content = match.group(0)
        
        for derive in required_derives:
            if derive not in derive_content:
                print(f"❌ {structure} missing {derive} derive")
                return False
    
    print("✅ Serialization support is compliant")
    return True

def validate_documentation():
    """Validate documentation compliance."""
    print("🔍 Validating documentation...")
    
    # Check for compliance documentation
    compliance_doc = "docs/compliance/consensus_structures_audit.md"
    if not os.path.exists(compliance_doc):
        print("❌ Compliance audit documentation not found")
        return False
    
    # Check for P2P documentation
    p2p_docs = [
        "docs/p2p/protocol_design.md",
        "docs/p2p/compliance_checklist.md",
        "docs/p2p/api_reference.md",
        "docs/p2p/README.md"
    ]
    
    for doc in p2p_docs:
        if not os.path.exists(doc):
            print(f"❌ P2P documentation not found: {doc}")
            return False
    
    print("✅ Documentation is compliant")
    return True

def main():
    """Main validation function."""
    print("🚀 Starting Rusty Coin Compliance Validation")
    print("=" * 50)
    
    validations = [
        validate_block_header_structure,
        validate_block_structure,
        validate_ticket_vote_structure,
        validate_transaction_structure,
        validate_tx_output_structure,
        validate_tx_input_structure,
        validate_serialization_support,
        validate_documentation,
    ]
    
    passed = 0
    total = len(validations)
    
    for validation in validations:
        try:
            if validation():
                passed += 1
            print()
        except Exception as e:
            print(f"❌ Validation failed with error: {e}")
            print()
    
    print("=" * 50)
    print(f"📊 Compliance Results: {passed}/{total} validations passed")
    
    if passed == total:
        print("🎉 FULL COMPLIANCE ACHIEVED! 🎉")
        print("All consensus structures meet specification requirements.")
        return 0
    else:
        compliance_percentage = (passed / total) * 100
        print(f"📈 Compliance: {compliance_percentage:.1f}%")
        print("Some validations failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
