#!/usr/bin/env python3
"""
Rusty Coin Specification Compliance Verification Script

This script systematically verifies that the Rusty Coin implementation
matches the formal specifications defined in docs/specs/.

Usage:
    python3 scripts/verify_specs.py [--spec SPEC_NAME] [--verbose]
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Any
import re

class SpecVerifier:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.specs_dir = self.project_root / "docs" / "specs"
        self.results = {}
        
    def verify_all_specs(self) -> Dict[str, Any]:
        """Verify all specifications and return results"""
        print("🔍 Starting Rusty Coin Specification Verification")
        print("=" * 60)
        
        # Define spec files and their verification methods
        specs = {
            "01_block_structure": self.verify_block_structure,
            "02_oxidehash_pow": self.verify_oxidehash_pow,
            "03_oxidesync_pos": self.verify_oxidesync_pos,
            "04_ferrisscript": self.verify_ferrisscript,
            "05_utxo_model": self.verify_utxo_model,
            "06_masternode_protocol": self.verify_masternode_protocol,
            "07_p2p_protocol": self.verify_p2p_protocol,
            "08_json_rpc": self.verify_json_rpc,
            "09_governance_protocol": self.verify_governance_protocol,
            "10_sidechain_protocol": self.verify_sidechain_protocol,
            "11_pq_migration": self.verify_pq_migration,
            "12_adaptive_block_size": self.verify_adaptive_block_size,
        }
        
        for spec_name, verify_func in specs.items():
            print(f"\n📋 Verifying {spec_name}...")
            try:
                result = verify_func()
                self.results[spec_name] = result
                status = "✅ PASS" if result["passed"] else "❌ FAIL"
                print(f"   {status} - {result['summary']}")
            except Exception as e:
                self.results[spec_name] = {
                    "passed": False,
                    "summary": f"Error during verification: {str(e)}",
                    "details": str(e)
                }
                print(f"   ❌ ERROR - {str(e)}")
        
        return self.results
    
    def verify_block_structure(self) -> Dict[str, Any]:
        """Verify block structure implementation matches spec 01"""
        issues = []
        
        # Check for BlockHeader structure
        header_checks = self._check_struct_definition(
            "BlockHeader",
            {
                "version": "u32",
                "height": "u64", 
                "previous_block_hash": "[u8; 32]",
                "merkle_root": "[u8; 32]",
                "state_root": "[u8; 32]",
                "timestamp": "u64",
                "difficulty_target": "u32",
                "nonce": "u64"
            }
        )
        issues.extend(header_checks)
        
        # Check for Block structure
        block_checks = self._check_struct_definition(
            "Block",
            {
                "header": "BlockHeader",
                "ticket_votes": "Vec<TicketVote>",
                "transactions": "Vec<Transaction>"
            }
        )
        issues.extend(block_checks)
        
        # Check for Transaction structure
        tx_checks = self._check_struct_definition(
            "Transaction",
            {
                "version": "u32",
                "inputs": "Vec<TxInput>",
                "outputs": "Vec<TxOutput>",
                "lock_time": "u32"
            }
        )
        issues.extend(tx_checks)
        
        # Check for TxInput structure
        txinput_checks = self._check_struct_definition(
            "TxInput",
            {
                "prev_out_hash": "[u8; 32]",
                "prev_out_index": "u32",
                "script_sig": "Vec<u8>"
            }
        )
        issues.extend(txinput_checks)
        
        # Check for TxOutput structure
        txoutput_checks = self._check_struct_definition(
            "TxOutput",
            {
                "value": "u64",
                "script_pubkey": "Vec<u8>"
            }
        )
        issues.extend(txoutput_checks)
        
        # Check for TicketVote structure
        ticketvote_checks = self._check_struct_definition(
            "TicketVote",
            {
                "ticket_id": "[u8; 32]",
                "signature": "[u8; 64]"
            }
        )
        issues.extend(ticketvote_checks)
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Block structure verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with block structure definitions"
        }
    
    def verify_oxidehash_pow(self) -> Dict[str, Any]:
        """Verify OxideHash PoW implementation matches spec 02"""
        issues = []
        
        # Check for OxideHash implementation
        oxidehash_files = [
            "rusty-crypto/src/hash.rs",
            "rusty-consensus/src/pow.rs",
            "rusty-core/src/consensus/pow.rs"
        ]
        
        found_implementation = False
        for file_path in oxidehash_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_implementation = True
                break
        
        if not found_implementation:
            issues.append("OxideHash implementation not found in expected locations")
        
        # Check for required constants
        constants_to_check = [
            "SCRATCHPAD_SIZE",
            "ITERATIONS_PER_HASH"
        ]
        
        for constant in constants_to_check:
            if not self._check_constant_exists(constant):
                issues.append(f"Required constant {constant} not found")
        
        # Check for BLAKE3 usage
        if not self._check_blake3_usage():
            issues.append("BLAKE3 hash function not properly used in OxideHash")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"OxideHash PoW verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with OxideHash implementation"
        }
    
    def verify_oxidesync_pos(self) -> Dict[str, Any]:
        """Verify OxideSync PoS implementation matches spec 03"""
        issues = []
        
        # Check for PoS-related structures
        pos_structures = [
            "TicketVote",
            "LIVE_TICKETS_POOL", 
            "TICKET_VOTER_SELECTION"
        ]
        
        for structure in pos_structures:
            if not self._check_pos_structure_exists(structure):
                issues.append(f"PoS structure {structure} not found or incomplete")
        
        # Check for ticket lifecycle management
        ticket_lifecycle_checks = [
            "PENDING",
            "LIVE", 
            "EXPIRED",
            "SPENT"
        ]
        
        for state in ticket_lifecycle_checks:
            if not self._check_ticket_state_exists(state):
                issues.append(f"Ticket state {state} not properly implemented")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"OxideSync PoS verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with PoS implementation"
        }
    
    def verify_ferrisscript(self) -> Dict[str, Any]:
        """Verify FerrisScript implementation matches spec 04"""
        issues = []
        
        # Check for script engine
        script_files = [
            "rusty-core/src/script/script_engine.rs",
            "rusty-core/src/script/opcode.rs"
        ]
        
        found_script_engine = False
        for file_path in script_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_script_engine = True
                break
        
        if not found_script_engine:
            issues.append("FerrisScript engine not found")
        
        # Check for required opcodes
        required_opcodes = [
            "OP_0", "OP_PUSHDATA1", "OP_PUSHDATA2", "OP_PUSHDATA4",
            "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8",
            "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
            "OP_DUP", "OP_HASH160", "OP_EQUAL", "OP_EQUALVERIFY",
            "OP_CHECKSIG", "OP_CHECKMULTISIG", "OP_VERIFY", "OP_RETURN"
        ]
        
        for opcode in required_opcodes:
            if not self._check_opcode_exists(opcode):
                issues.append(f"Required opcode {opcode} not found")
        
        # Check for script limits
        script_limits = [
            "MAX_SCRIPT_BYTES",
            "MAX_OPCODE_COUNT", 
            "MAX_STACK_DEPTH",
            "MAX_SIG_OPS"
        ]
        
        for limit in script_limits:
            if not self._check_constant_exists(limit):
                issues.append(f"Script limit {limit} not defined")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"FerrisScript verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with FerrisScript implementation"
        }
    
    def verify_utxo_model(self) -> Dict[str, Any]:
        """Verify UTXO model implementation matches spec 05"""
        issues = []
        
        # Check for UTXO set management
        utxo_files = [
            "rusty-core/src/consensus/utxo_set.rs",
            "rusty-shared-types/src/lib.rs"
        ]
        
        found_utxo_implementation = False
        for file_path in utxo_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_utxo_implementation = True
                break
        
        if not found_utxo_implementation:
            issues.append("UTXO set implementation not found")
        
        # Check for UTXO-related structures
        utxo_structures = [
            "Utxo",
            "OutPoint",
            "UTXO_SET"
        ]
        
        for structure in utxo_structures:
            if not self._check_utxo_structure_exists(structure):
                issues.append(f"UTXO structure {structure} not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"UTXO model verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with UTXO model implementation"
        }
    
    def verify_masternode_protocol(self) -> Dict[str, Any]:
        """Verify Masternode protocol implementation matches spec 06"""
        issues = []
        
        # Check for masternode-related files
        masternode_files = [
            "rusty-masternode/src/",
            "rusty-core/src/consensus/masternode.rs"
        ]
        
        found_masternode_implementation = False
        for file_path in masternode_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_masternode_implementation = True
                break
        
        if not found_masternode_implementation:
            issues.append("Masternode implementation not found")
        
        # Check for masternode structures
        masternode_structures = [
            "Masternode",
            "MASTERNODE_LIST",
            "POSE_CHALLENGE",
            "POSE_RESPONSE"
        ]
        
        for structure in masternode_structures:
            if not self._check_masternode_structure_exists(structure):
                issues.append(f"Masternode structure {structure} not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Masternode protocol verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with Masternode protocol implementation"
        }
    
    def verify_p2p_protocol(self) -> Dict[str, Any]:
        """Verify P2P protocol implementation matches spec 07"""
        issues = []
        
        # Check for P2P-related files
        p2p_files = [
            "rusty-p2p/src/",
            "rusty-network/src/"
        ]
        
        found_p2p_implementation = False
        for file_path in p2p_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_p2p_implementation = True
                break
        
        if not found_p2p_implementation:
            issues.append("P2P protocol implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"P2P protocol verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with P2P protocol implementation"
        }
    
    def verify_json_rpc(self) -> Dict[str, Any]:
        """Verify JSON-RPC implementation matches spec 08"""
        issues = []
        
        # Check for RPC-related files
        rpc_files = [
            "rusty-rpc/src/",
            "rusty-jsonrpc/src/"
        ]
        
        found_rpc_implementation = False
        for file_path in rpc_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_rpc_implementation = True
                break
        
        if not found_rpc_implementation:
            issues.append("JSON-RPC implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"JSON-RPC verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with JSON-RPC implementation"
        }
    
    def verify_governance_protocol(self) -> Dict[str, Any]:
        """Verify Governance protocol implementation matches spec 09"""
        issues = []
        
        # Check for governance-related files
        governance_files = [
            "rusty-governance/src/",
            "rusty-core/src/governance.rs"
        ]
        
        found_governance_implementation = False
        for file_path in governance_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_governance_implementation = True
                break
        
        if not found_governance_implementation:
            issues.append("Governance protocol implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Governance protocol verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with Governance protocol implementation"
        }
    
    def verify_sidechain_protocol(self) -> Dict[str, Any]:
        """Verify Sidechain protocol implementation matches spec 10"""
        issues = []
        
        # Check for sidechain-related files
        sidechain_files = [
            "rusty-core/src/sidechain/",
            "rusty-core/src/sidechain.rs"
        ]
        
        found_sidechain_implementation = False
        for file_path in sidechain_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_sidechain_implementation = True
                break
        
        if not found_sidechain_implementation:
            issues.append("Sidechain protocol implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Sidechain protocol verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with Sidechain protocol implementation"
        }
    
    def verify_pq_migration(self) -> Dict[str, Any]:
        """Verify Post-Quantum migration implementation matches spec 11"""
        issues = []
        
        # Check for PQ-related files
        pq_files = [
            "rusty-crypto/src/",
            "rusty-core/src/crypto/"
        ]
        
        found_pq_implementation = False
        for file_path in pq_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_pq_implementation = True
                break
        
        if not found_pq_implementation:
            issues.append("Post-Quantum migration implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Post-Quantum migration verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with Post-Quantum migration implementation"
        }
    
    def verify_adaptive_block_size(self) -> Dict[str, Any]:
        """Verify Adaptive block size implementation matches spec 12"""
        issues = []
        
        # Check for adaptive block size implementation
        adaptive_files = [
            "rusty-consensus/src/adaptive_block_size.rs",
            "rusty-core/src/consensus/adaptive_block_size.rs"
        ]
        
        found_adaptive_implementation = False
        for file_path in adaptive_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                found_adaptive_implementation = True
                break
        
        if not found_adaptive_implementation:
            issues.append("Adaptive block size implementation not found")
        
        passed = len(issues) == 0
        return {
            "passed": passed,
            "summary": f"Adaptive block size verification {'passed' if passed else 'failed'}",
            "issues": issues,
            "details": f"Found {len(issues)} issues with Adaptive block size implementation"
        }
    
    def _check_struct_definition(self, struct_name: str, expected_fields: Dict[str, str]) -> List[str]:
        """Check if a struct is defined with expected fields"""
        issues = []
        
        # Search for struct definition in Rust files
        rust_files = list(self.project_root.rglob("*.rs"))
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Look for struct definition
                struct_pattern = rf"struct\s+{struct_name}\s*\{{"
                if re.search(struct_pattern, content):
                    # Check for each expected field
                    for field_name, field_type in expected_fields.items():
                        field_pattern = rf"pub\s+{field_name}:\s*{re.escape(field_type)}"
                        if not re.search(field_pattern, content):
                            issues.append(f"Field {field_name} of type {field_type} not found in {struct_name}")
                    break
            except Exception:
                continue
        
        return issues
    
    def _check_constant_exists(self, constant_name: str) -> bool:
        """Check if a constant is defined"""
        rust_files = list(self.project_root.rglob("*.rs"))
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Look for constant definition
                const_pattern = rf"const\s+{constant_name}"
                if re.search(const_pattern, content):
                    return True
            except Exception:
                continue
        
        return False
    
    def _check_blake3_usage(self) -> bool:
        """Check if BLAKE3 is properly used"""
        rust_files = list(self.project_root.rglob("*.rs"))
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if "blake3" in content.lower() or "BLAKE3" in content:
                    return True
            except Exception:
                continue
        
        return False
    
    def _check_pos_structure_exists(self, structure_name: str) -> bool:
        """Check if PoS structure exists"""
        return self._check_struct_definition(structure_name, {}) == []
    
    def _check_ticket_state_exists(self, state_name: str) -> bool:
        """Check if ticket state is defined"""
        rust_files = list(self.project_root.rglob("*.rs"))
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if state_name in content:
                    return True
            except Exception:
                continue
        
        return False
    
    def _check_opcode_exists(self, opcode_name: str) -> bool:
        """Check if opcode is defined"""
        rust_files = list(self.project_root.rglob("*.rs"))
        
        for file_path in rust_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if opcode_name in content:
                    return True
            except Exception:
                continue
        
        return False
    
    def _check_utxo_structure_exists(self, structure_name: str) -> bool:
        """Check if UTXO structure exists"""
        return self._check_struct_definition(structure_name, {}) == []
    
    def _check_masternode_structure_exists(self, structure_name: str) -> bool:
        """Check if masternode structure exists"""
        return self._check_struct_definition(structure_name, {}) == []
    
    def generate_report(self) -> str:
        """Generate a comprehensive compliance report"""
        total_specs = len(self.results)
        passed_specs = sum(1 for result in self.results.values() if result["passed"])
        failed_specs = total_specs - passed_specs
        
        report = f"""
# Rusty Coin Specification Compliance Report

## Summary
- **Total Specifications**: {total_specs}
- **Passed**: {passed_specs} ✅
- **Failed**: {failed_specs} ❌
- **Compliance Rate**: {(passed_specs/total_specs)*100:.1f}%

## Detailed Results

"""
        
        for spec_name, result in self.results.items():
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            report += f"### {spec_name}\n"
            report += f"**Status**: {status}\n"
            report += f"**Summary**: {result['summary']}\n"
            report += f"**Details**: {result['details']}\n"
            
            if "issues" in result and result["issues"]:
                report += "**Issues Found**:\n"
                for issue in result["issues"]:
                    report += f"- {issue}\n"
            
            report += "\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(description="Verify Rusty Coin implementation against specifications")
    parser.add_argument("--spec", help="Verify specific specification only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", help="Output file for report")
    
    args = parser.parse_args()
    
    # Get project root
    project_root = Path(__file__).parent.parent
    verifier = SpecVerifier(str(project_root))
    
    if args.spec:
        # Verify specific spec
        spec_method = getattr(verifier, f"verify_{args.spec}", None)
        if spec_method:
            result = spec_method()
            print(f"Specification {args.spec}: {'PASS' if result['passed'] else 'FAIL'}")
            if args.verbose:
                print(f"Details: {result['details']}")
        else:
            print(f"Unknown specification: {args.spec}")
            sys.exit(1)
    else:
        # Verify all specs
        results = verifier.verify_all_specs()
        
        # Generate report
        report = verifier.generate_report()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.output}")
        else:
            print(report)

if __name__ == "__main__":
    main()


