Rusty Coin Formal Protocol Specifications: 02 - OxideHash Proof-of-Work
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md, rusty_crypto_spec.md (for BLAKE3 definition).

2.1 Overview
OxideHash is the custom, memory-hard Proof-of-Work (PoW) hashing algorithm employed by Rusty Coin. Its primary purpose is to provide initial block creation and robust Sybil resistance. It is designed to be GPU-friendly and ASIC-resistant by requiring significant memory and exhibiting unpredictable memory access patterns.

2.2 Algorithm Parameters
SCRATCHPAD_SIZE: 2 
30
  bytes (1 GiB)

ITERATIONS_PER_HASH: 2 
20
  (1,048,576) memory read/compute operations

INITIAL_SEED_HASH_ALGORITHM: BLAKE3

INNER_HASH_FUNCTION: BLAKE3 (for deriving memory addresses and intermediate states)

COMPUTE_OPERATION: Bitwise XOR (^) and 64-bit addition (+) with wrap-around.

ASIC_RESISTANCE_TARGET: Maximize cost differential between general-purpose hardware (GPUs) and specialized hardware (ASICs).

2.3 OxideHash Procedure (OxideHash(BlockHeader) -> [u8; 32])
The OxideHash function takes a BlockHeader (with a candidate nonce) as input and produces a 32-byte BLAKE3 hash. Miners must find a nonce such that this resulting hash is less than the current difficulty_target.

Steps:

Serialization & Initial Seed:

Serialize the entire BlockHeader (excluding only the nonce field, which is the variable being iterated by miners) into a canonical byte array H_bytes.

Compute the initial 32-byte seed S = BLAKE3(H_bytes).

Scratchpad Initialization:

Allocate a mutable SCRATCHPAD of SCRATCHPAD_SIZE bytes (1 GiB) in system RAM.

Initialize the SCRATCHPAD content. A pseudo-random stream derived from S should be used to fill the entire SCRATCHPAD. This can be achieved by iteratively hashing S concatenated with a counter, and using the output to fill sections of the scratchpad.

SCRATCHPAD[0...31] = BLAKE3(S | 0)

SCRATCHPAD[32...63] = BLAKE3(S | 1)

... and so on, until the entire 1 GiB is filled.

Iterative Read/Compute Operations:

Initialize a 32-byte current_state_hash = S.

Perform ITERATIONS_PER_HASH rounds of memory access and computation:

For i from 0 to ITERATIONS_PER_HASH - 1:

Address Derivation:

Derive a 64-bit read_address_offset: read_address_offset = BLAKE3(current_state_hash | i)[0..7] (first 8 bytes of hash).

Normalize read_address_offset to read_address = read_address_offset % (SCRATCHPAD_SIZE - 32) to ensure it's a valid 32-byte aligned starting offset within the SCRATCHPAD.

Read Data:

Read 32 bytes read_data from SCRATCHPAD[read_address .. read_address + 31].

Compute current_state_hash:

current_state_hash = BLAKE3(current_state_hash XOR read_data). (The XOR here is a byte-wise XOR of the two 32-byte arrays, followed by BLAKE3 hash).

Write Data (Update Scratchpad):

Derive a 64-bit write_address_offset: write_address_offset = BLAKE3(current_state_hash | (i XOR 0xFFFFFFFF))[0..7].

Normalize write_address_offset to write_address = write_address_offset % (SCRATCHPAD_SIZE - 32).

Write current_state_hash into SCRATCHPAD[write_address .. write_address + 31]. This ensures the scratchpad's content is constantly evolving and unpredictable.

Final Hash Computation:

After ITERATIONS_PER_HASH rounds, compute the final 32-byte output hash F = BLAKE3(SCRATCHPAD[0..31] | current_state_hash | SCRATCHPAD[32..SCRATCHPAD_SIZE-1]). (A simplified final hash would take the first/last few blocks of the scratchpad content along with the final current_state_hash).

The result F is the OxideHash(BlockHeader).

2.4 Difficulty Target
The difficulty_target field in the BlockHeader represents a 256-bit unsigned integer in a compact, packed format. A block is valid if and only if its OxideHash(BlockHeader) (interpreted as a 256-bit unsigned integer) is numerically less than the difficulty_target.

2.5 ASIC-Resistance and GPU-Friendliness
Memory-Hardness: The large SCRATCHPAD_SIZE (1 GiB) makes it infeasible to implement OxideHash efficiently without significant amounts of high-bandwidth memory. This drives up the cost of specialized hardware (ASICs) which would need to integrate large DRAM on-die or near-die, unlike general-purpose CPUs/GPUs that already possess such memory.

Pseudo-Random Access: The unpredictable read/write patterns within the scratchpad prevent the use of traditional caching techniques effectively. This further reduces the efficiency advantage of ASICs over GPUs.

GPU-Friendliness: GPUs are inherently optimized for parallel memory access and arithmetic operations, making them well-suited for the iterative read/compute phases of OxideHash, ensuring broad miner participation.

Dynamic Nature: The scratchpad's content continuously changes with each iteration, making it difficult for ASICs to exploit fixed-pattern optimizations.

2.6 Validation Constraints
A full node MUST re-execute OxideHash(BlockHeader) using the provided BlockHeader and nonce.

The resulting hash MUST be less than the difficulty_target specified in the BlockHeader.

The SCRATCHPAD MUST be allocated entirely in RAM; disk-based caching or virtual memory paging for SCRATCHPAD invalidates the memory-hardness property and may be detected by performance profiling.

The difficulty_target itself MUST conform to the rules defined in rusty_consensus_spec.md (specifically, the difficulty adjustment algorithm).