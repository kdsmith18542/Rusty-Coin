Rusty Coin Formal Protocol Specifications: 12 - Adaptive Block Size
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md (for BlockHeader), 05_utxo_model_spec.md (for transaction validation context).

12.1 Overview
The Adaptive Block Size algorithm is a core protocol mechanism designed to allow Rusty Coin's network capacity to grow organically with actual demand, without requiring contentious hard forks for block size increases. It dynamically adjusts the maximum allowed block size based on the observed median block size of previous periods, balancing scalability with the imperative of maintaining decentralization and node accessibility.

12.2 Purpose and Rationale
Organic Scalability: Unlike fixed block size limits that can lead to network congestion or require disruptive hard forks for expansion, the adaptive mechanism allows throughput to increase naturally as network usage dictates.

Decentralization Preservation: By setting limits on growth and basing adjustments on medians (which are less susceptible to manipulation than averages), the algorithm aims to prevent sudden, rapid increases in block size that could centralize the network by pricing out nodes with limited bandwidth or storage.

Responsiveness to Demand: Ensures the network can accommodate bursts of transaction volume more efficiently than a static limit.

Reduced Governance Overhead: Automates a historically contentious parameter, freeing up governance resources for more complex protocol evolutions.

12.3 Algorithm Parameters
The following parameters govern the Adaptive Block Size algorithm:

INITIAL_MAX_BLOCK_SIZE_BYTES: The maximum allowed block size at network genesis (e.g., 2,000,000 bytes / 2 MB).

MEDIAN_CALCULATION_PERIOD_BLOCKS: The number of past blocks used to calculate the median block size (e.g., 2016 blocks, approximately 3.5 days). This period aligns with difficulty adjustment for consistency.

BLOCK_SIZE_GROWTH_FACTOR_PERCENTAGE: The maximum percentage by which the ADAPTIVE_MAX_BLOCK_SIZE_BYTES can increase per MEDIAN_CALCULATION_PERIOD (e.g., 10%).

BLOCK_SIZE_SHRINK_FACTOR_PERCENTAGE: The maximum percentage by which the ADAPTIVE_MAX_BLOCK_SIZE_BYTES can decrease per MEDIAN_CALCULATION_PERIOD (e.g., 5%).

ABSOLUTE_HARD_MAX_BLOCK_SIZE_BYTES: A fixed, hard-coded upper limit for the maximum allowed block size, regardless of demand or median calculations (e.g., 64,000,000 bytes / 64 MB). This acts as a final safeguard against runaway growth.

MIN_MAX_BLOCK_SIZE_BYTES: A fixed, hard-coded lower limit for the maximum allowed block size (e.g., 1,000,000 bytes / 1 MB).

12.4 Calculation of ADAPTIVE_MAX_BLOCK_SIZE_BYTES
The ADAPTIVE_MAX_BLOCK_SIZE_BYTES is re-calculated and applies to all blocks mined from the beginning of each new MEDIAN_CALCULATION_PERIOD.

Steps:

Determine Reference Period: At the beginning of a new MEDIAN_CALCULATION_PERIOD (i.e., for block height H where H(modMEDIAN_CALCULATION_PERIOD_BLOCKS)==0), collect the actual sizes (in bytes) of the previous MEDIAN_CALCULATION_PERIOD_BLOCKS blocks (from H−MEDIAN_CALCULATION_PERIOD_BLOCKS to H−1).

Calculate Median Block Size (MedianActualSize):

Sort the collected block sizes in ascending order.

The MedianActualSize is the middle value of the sorted list. If the number of blocks is even, it is the average of the two middle values.

For periods shorter than MEDIAN_CALCULATION_PERIOD_BLOCKS (e.g., at the very start of the chain), MedianActualSize defaults to INITIAL_MAX_BLOCK_SIZE_BYTES.

Calculate Potential New Limit (PotentialLimit):

PotentialLimit = MedianActualSize * (1 + BLOCK_SIZE_GROWTH_FACTOR_PERCENTAGE) if MedianActualSize is greater than the previous ADAPTIVE_MAX_BLOCK_SIZE_BYTES.

PotentialLimit = MedianActualSize * (1 - BLOCK_SIZE_SHRINK_FACTOR_PERCENTAGE) if MedianActualSize is less than the previous ADAPTIVE_MAX_BLOCK_SIZE_BYTES.

If MedianActualSize is equal to the previous ADAPTIVE_MAX_BLOCK_SIZE_BYTES, PotentialLimit remains unchanged.

Apply Hard Limits:

The ADAPTIVE_MAX_BLOCK_SIZE_BYTES for the current period is the PotentialLimit clamped between MIN_MAX_BLOCK_SIZE_BYTES and ABSOLUTE_HARD_MAX_BLOCK_SIZE_BYTES.

ADAPTIVE_MAX_BLOCK_SIZE_BYTES = clamp(PotentialLimit, MIN_MAX_BLOCK_SIZE_BYTES, ABSOLUTE_HARD_MAX_BLOCK_SIZE_BYTES)

12.5 Impact on Other Consensus Parameters
The ADAPTIVE_MAX_BLOCK_SIZE_BYTES directly influences other resource limits within a block to ensure proportional scaling and prevent specific types of DoS attacks.

MAX_SIG_OPS_PER_BLOCK: The maximum number of signature operations (e.g., OP_CHECKSIG, OP_CHECKMULTISIG) allowed within a block is directly proportional to ADAPTIVE_MAX_BLOCK_SIZE_BYTES.

MAX_SIG_OPS_PER_BLOCK = ADAPTIVE_MAX_BLOCK_SIZE_BYTES / SIG_OPS_BYTE_COST (e.g., 20 bytes/sigop).

This prevents attackers from creating very small blocks with an extremely high number of computationally expensive signature verifications.

Transaction Validation Cost: The overall complexity of transaction validation (e.g., FerrisScript execution cost) within a block implicitly scales with the ADAPTIVE_MAX_BLOCK_SIZE_BYTES.

12.6 Security Considerations and Anti-Gaming Measures
Median vs. Average: Using the median block size is a crucial anti-gaming measure. A malicious actor attempting to inflate the block size cannot do so effectively by mining a few exceptionally large blocks, as the median value is robust to outliers. They would need to consistently fill a significant portion of blocks over the entire MEDIAN_CALCULATION_PERIOD.

Growth/Shrink Factors: The asymmetric BLOCK_SIZE_GROWTH_FACTOR_PERCENTAGE and BLOCK_SIZE_SHRINK_FACTOR_PERCENTAGE prevent rapid, uncontrolled expansion while allowing for quicker contraction if demand drops.

ABSOLUTE_HARD_MAX_BLOCK_SIZE_BYTES: This hard limit is a final safety mechanism, preventing the block size from ever growing beyond a point deemed safe for network decentralization and hardware requirements, even if the adaptive algorithm were somehow gamed. This limit can only be changed via on-chain governance (Homestead Accord).

Transaction Fee Market: A dynamic transaction fee market (where higher fees incentivize miners to include transactions) works in conjunction with adaptive block size to ensure blocks are filled only when there is actual demand, preventing artificial inflation of MedianActualSize. Transactions below MIN_RELAY_FEE_PER_BYTE are not relayed, further controlling growth.

P2P Network Load: Nodes MUST implement robust peer scoring and message rate limiting (as defined in 07_networking_api_spec.md) to prevent DoS attacks that attempt to exploit increased block size limits by overwhelming network bandwidth.

12.7 Validation Requirements
Miners proposing a new Block MUST ensure that the total serialized size of the Block (header + ticket_votes + transactions) does not exceed the ADAPTIVE_MAX_BLOCK_SIZE_BYTES for that BlockHeight.

Full nodes validating an incoming Block MUST:

Calculate the correct ADAPTIVE_MAX_BLOCK_SIZE_BYTES for the BlockHeight.

Verify that the Block's serialized size does not exceed this calculated limit.

Verify that MAX_SIG_OPS_PER_BLOCK is not exceeded.

Any block violating these rules MUST be rejected.