Rusty Coin Formal Protocol Specifications: 02a - Proof-of-Work Difficulty Adjustment
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md (for BlockHeader and timestamp), 02_oxidehash_pow_spec.md (for OxideHash and difficulty_target).

2a.1 Overview
The Proof-of-Work (PoW) Difficulty Adjustment Algorithm is a fundamental component of the Rusty Coin consensus protocol. Its primary purpose is to dynamically adjust the difficulty_target for OxideHash computations, ensuring that the average time between blocks remains consistently close to TARGET_BLOCK_TIME, regardless of fluctuations in the network's total mining hashrate. This stability is crucial for predictable emission, transaction finality, and network operation.

2a.2 Algorithm Parameters
TARGET_BLOCK_TIME_SECONDS: 150 seconds (2.5 minutes). This is the desired average time for a miner to find a new block.

DIFFICULTY_ADJUSTMENT_PERIOD_BLOCKS: 2016 blocks. This is the number of blocks over which the average block time is measured to calculate the new difficulty. This period aligns with the TICKET_PRICE_ADJUSTMENT_PERIOD for consistency.

MAX_DIFFICULTY_ADJUSTMENT_FACTOR: 4. This factor limits how much the difficulty can increase or decrease in a single adjustment. It prevents extreme volatility in difficulty targets.

MIN_DIFFICULTY_TARGET: A predefined minimum difficulty_target value, ensuring that block finding never becomes trivially easy, even with very low hashrate. This translates to a maximum possible numerical hash value.

INITIAL_DIFFICULTY_TARGET: The difficulty_target for the Genesis Block, hardcoded in the client software.

2a.3 Difficulty Adjustment Procedure
The difficulty_target is re-calculated and applies to all blocks mined from the beginning of each new DIFFICULTY_ADJUSTMENT_PERIOD.

Steps:

Identify Adjustment Block: The difficulty adjustment occurs for the first block (let's call its height H 
current
​
 ) after every DIFFICULTY_ADJUSTMENT_PERIOD_BLOCKS. That is, if (H_{current} - 1) % DIFFICULTY_ADJUSTMENT_PERIOD_BLOCKS == 0, then the current block (H 
current
​
 ) is the first block of a new adjustment period.

Special Case: Genesis Block:

For the Genesis Block (H 
current
​
 =0), its difficulty_target is INITIAL_DIFFICULTY_TARGET.

Special Case: Non-Adjustment Period Blocks:

If the current block H 
current
​
  is NOT the first block of a new adjustment period, its difficulty_target MUST be the same as the difficulty_target of the immediately preceding block, Block(H_{current}-1).

Difficulty Calculation for Adjustment Blocks:

If the current block H 
current
​
  IS the first block of a new adjustment period:
a.  Identify Reference Blocks:
* FirstBlockInPeriod = Block(H_{current} - DIFFICULTY_ADJUSTMENT_PERIOD_BLOCKS)
* LastBlockInPeriod = Block(H_{current} - 1)
b.  Calculate Actual Elapsed Time:
* ActualTimeSpan = LastBlockInPeriod.header.timestamp - FirstBlockInPeriod.header.timestamp
c.  Calculate Expected Elapsed Time:
* ExpectedTimeSpan = DIFFICULTY_ADJUSTMENT_PERIOD_BLOCKS * TARGET_BLOCK_TIME_SECONDS
d.  Calculate Time Ratio:
* TimeRatio = ActualTimeSpan / ExpectedTimeSpan
e.  Clamp Time Ratio: To prevent extreme difficulty jumps, TimeRatio MUST be clamped between 1 / MAX_DIFFICULTY_ADJUSTMENT_FACTOR and MAX_DIFFICULTY_ADJUSTMENT_FACTOR.
* ClampedTimeRatio = max(1 / MAX_DIFFICULTY_ADJUSTMENT_FACTOR, min(MAX_DIFFICULTY_ADJUSTMENT_FACTOR, TimeRatio))
f.  Calculate New Difficulty Target (Inverse Relationship):
* OldDifficultyTarget = LastBlockInPeriod.header.difficulty_target (interpreted as a 256-bit integer).
* NewDifficultyTarget = OldDifficultyTarget * ClampedTimeRatio (interpreted as a 256-bit integer, ensuring correct integer arithmetic and truncation if needed).
* Note on Inverse Relationship: If ActualTimeSpan is longer than ExpectedTimeSpan, TimeRatio > 1, meaning blocks were found too slowly, so NewDifficultyTarget increases (difficulty decreases). If ActualTimeSpan is shorter, TimeRatio < 1, blocks were found too fast, so NewDifficultyTarget decreases (difficulty increases).
g.  Clamp NewDifficultyTarget to Minimum:
* NewDifficultyTarget MUST NOT be greater than MIN_DIFFICULTY_TARGET. If the calculated NewDifficultyTarget is greater, it MUST be set to MIN_DIFFICULTY_TARGET. This enforces a floor on difficulty.
h.  Set difficulty_target for Block(H_{current}):
* The calculated NewDifficultyTarget (in compact form) is set as Block(H_{current}).header.difficulty_target.

2a.4 Compact Difficulty Target Representation
The difficulty_target is stored in BlockHeader as a u32 (4 bytes) in a compact, floating-point-like format to represent a 256-bit target.

The first byte represents the "exponent" (number of bytes the target occupies).

The following three bytes represent the "mantissa" (the significant digits of the target).

The actual 256-bit target is calculated by taking the mantissa and shifting it left by (exponent - 3) * 8 bits.

Example:

A compact target 0x1d00ffff means:

exponent = 0x1d (29)

mantissa = 0x00ffff

Actual target = 0x00ffff * 2^(8 * (29 - 3)) = 0x00ffff * 2^(8 * 26) = 0x00ffff0000...00 (26 zero bytes).

2a.5 Validation Constraints
Full nodes MUST calculate the expected difficulty_target for each block.

The BlockHeader.difficulty_target value in an incoming block MUST exactly match the calculated expected value for that block height.

Any block with a mismatched difficulty_target MUST be rejected as invalid.

The timestamp of the FirstBlockInPeriod MUST be used in the ActualTimeSpan calculation; any timestamp manipulation within the period does not affect the calculation for previous periods.