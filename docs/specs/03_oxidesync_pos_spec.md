Rusty Coin Formal Protocol Specifications: 03 - OxideSync Proof-of-Stake (Ticket Voting)
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md, rusty_crypto_spec.md (for Ed25519 signatures, BLAKE3 hashes).

3.1 Overview
The OxideSync Proof-of-Stake (PoS) layer, utilizing a "Ticket Voting" mechanism, serves as a crucial component of Rusty Coin's hybrid consensus. It ensures strong transaction finality and enhances network security against 51% attacks by providing a cryptographic attestation layer for Proof-of-Work (PoW) mined blocks. This dual-layer approach aims to combine the fair distribution of PoW with the efficiency and finality guarantees of PoS.

3.2 Ticket Definition and Lifecycle
A Ticket in Rusty Coin represents a cryptographic right to participate in PoS block validation. It is created by locking a specific amount of $RUST in a dedicated Unspent Transaction Output (UTXO).

3.2.1 Ticket Structure and Identification

Identification: A Ticket is uniquely identified by the (TxID, VOutIndex) pair of the TxOutput that locks the required $RUST collateral. This TxID is the BLAKE3 hash of the transaction that purchased the ticket.

Collateral: Each ticket MUST lock TICKET_LOCKED_AMOUNT of RUST (in satoshis). This amount is determined by the Ticket Price Adjustment mechanism.

Locking Script: The script_pubkey of a Ticket UTXO MUST be designed such that it can only be spent by the ticket owner AFTER the ticket has expired or by a valid slashing transaction. It explicitly designates the output as a TICKET_TYPE transaction. For detailed scripting requirements, refer to 04_ferrisscript_spec.md.

Associated Key: Each ticket is associated with a public key (derived from the script_pubkey for P2PKH/P2SH tickets), which is used for signing votes.

3.2.2 Ticket States

A Ticket transitions through the following states, managed by the rusty-consensus state:

PENDING: A ticket is in PENDING state from the moment its purchase transaction is broadcast to the network until the block containing its purchase transaction is fully validated and PoS-finalized. During this state, the ticket is not eligible for voting.

LIVE (Active): A ticket transitions to LIVE when the block containing its purchase transaction reaches POS_FINALITY_DEPTH (e.g., 1 block after inclusion). LIVE tickets are eligible for selection in TICKET_VOTER_SELECTION.

EXPIRED: A LIVE ticket becomes EXPIRED if its block height exceeds PurchaseBlockHeight + TICKET_EXPIRATION_PERIOD_BLOCKS (e.g., 4096 blocks, approximately 7 days at 2.5 min/block). EXPIRED tickets are no longer eligible for voting but can be spent by their owner.

SPENT: A ticket is SPENT when its underlying UTXO is consumed by a valid transaction. This can occur after expiration, or due to a slashing event. A spent ticket is permanently removed from the LIVE_TICKETS_POOL.

3.2.3 Live Tickets Pool (LIVE_TICKETS_POOL)

The LIVE_TICKETS_POOL is a dynamic data structure maintained by each full node within the rusty-consensus crate. It contains the TicketIDs and associated public keys of all currently LIVE tickets. The pool's state is cryptographically committed to in the state_root of each BlockHeader.

3.3 Ticket Price Adjustment
The price of a new ticket (TICKET_LOCKED_AMOUNT) is dynamically adjusted to ensure a healthy and stable number of LIVE tickets, promoting decentralization and consistent PoS security.

Frequency: Adjustment occurs every TICKET_PRICE_ADJUSTMENT_PERIOD blocks (e.g., 2016 blocks, approximately 3.5 days). The adjustment is calculated at the beginning of the block directly following an adjustment period boundary.

Target: TARGET_LIVE_TICKETS (e.g., 20,000 tickets).

Algorithm:

Let P 
old
​
  be the TICKET_LOCKED_AMOUNT from the previous adjustment period.

Let N 
L
​
  be the observed count of LIVE tickets averaged over the preceding TICKET_PRICE_ADJUSTMENT_PERIOD.

Let T 
G
​
  be the TARGET_LIVE_TICKETS.

The new ticket price P 
new
​
  is calculated using a proportional feedback mechanism:
P_new = P_old * (1 + (K_P * (N_L - T_G) / T_G))

Where K 
P
​
  is a proportionality constant (e.g., 0.05) to control the speed of adjustment. A smaller K 
P
​
  results in slower, more stable adjustments.

Constraints: P_new MUST be capped at MAX_TICKET_PRICE and floored at MIN_TICKET_PRICE to prevent extreme price fluctuations.

Initial Price: The very first TICKET_LOCKED_AMOUNT is a fixed INITIAL_TICKET_PRICE defined in the Genesis Block parameters.

Impact: The newly calculated TICKET_LOCKED_AMOUNT applies to all Ticket purchase transactions included in blocks from the adjustment block onwards.

3.4 Voter Selection (TICKET_VOTER_SELECTION)
For each block H proposed by a PoW miner, a fixed number of tickets (VOTERS_PER_BLOCK, e.g., 5) are deterministically selected from the LIVE_TICKETS_POOL to cast votes on the validity of block H−1.

Input for Selection: The selection process is seeded by the BLAKE3 hash of BlockH-1 (the block directly preceding the current PoW block).

Algorithm Steps:

Snapshot: Take a snapshot of the LIVE_TICKETS_POOL as it was definitively known and PoS-finalized at the end of BlockH-1.

Deterministic Pseudo-Random Function (DPRF): Use a predefined DPRF, DPRF(seed, ticket_id), which generates a pseudo-random 256-bit number for each ticket.

Seed: The seed for the DPRF is BLAKE3(BlockH-1.hash).

Ticket ID: Each TicketID from the LIVE_TICKETS_POOL_SNAPSHOT is an input to the DPRF.

Lottery: Each ticket T_i in the LIVE_TICKETS_POOL_SNAPSHOT is assigned a "lottery score" equal to DPRF(seed, T_i.ticket_id).

Selection: The VOTERS_PER_BLOCK tickets with the numerically lowest lottery_score are selected. If multiple tickets have the same score, their TicketID (as a byte array) is used as a tie-breaker.

Unpredictability: The design of the DPRF ensures that the selection of voters is unpredictable until BlockH-1.hash is finalized and known to all nodes. This prevents pre-computation of future voters and mitigates collusion attempts.

Output: An ordered list of VOTERS_PER_BLOCK unique TicketIDs. This list is canonical and verifiable by all honest full nodes.

3.5 Block Validation (POS_BLOCK_VALIDATION)
The rusty-consensus module performs the following validation checks on BlockH from the perspective of the PoS layer, in addition to standard PoW and transaction validation:

3.5.1 ticket_votes Structure Validation:

BlockH.ticket_votes MUST contain exactly VOTERS_PER_BLOCK (e.g., 5) TicketVote entries. If fewer entries are present, the block is considered malformed and invalid. (Note: This assumes placeholders for non-participating voters, or a specific convention for omitted votes, which must be clearly defined).

3.5.2 Individual TicketVote Entry Validation:

For each TicketVote entry V_j within BlockH.ticket_votes:

V_j.ticket_id MUST be one of the TicketIDs generated by TICKET_VOTER_SELECTION for BlockH-1. Any vote from an unselected ticket renders BlockH invalid.

The ticket identified by V_j.ticket_id MUST have been LIVE in the LIVE_TICKETS_POOL at the height of BlockH-1.

V_j.signature MUST be a cryptographically valid Ed25519 signature of BlockH-1.hash using the public key associated with V_j.ticket_id.

3.5.3 Quorum Check:

The total count of cryptographically valid TicketVote entries in BlockH.ticket_votes MUST be greater than or equal to MIN_VALID_VOTES_REQUIRED (e.g., 3).

If MIN_VALID_VOTES_REQUIRED is not met, BlockH is considered invalid and MUST be rejected by honest full nodes. The PoW miner must find a new PoW solution for block height H.

3.6 Finality Guarantees
The OxideSync PoS layer provides strong probabilistic finality, enhancing the security of the chain beyond a simple PoW confirmation depth.

Mechanism: When a block N is referenced by the prev_block_hash of block N+1, and block N+1 successfully passes all POS_BLOCK_VALIDATION checks (including the MIN_VALID_VOTES_REQUIRED quorum), then block N is considered PoS-finalized.

Reorganization Resistance: Reorganizations that replace a PoS-finalized block (i.e., changing block N after N+1 is finalized) become computationally infeasible. Such an attack would require:

Re-mining block N (PoW effort).

Finding a new PoW solution for block N+1 AND assembling a new ticket_votes quorum (or manipulating the original quorum) that re-confirms the new block N. This implies a simultaneous 51% attack on both the PoW hashrate AND the PoS ticket pool at the precise moment of finalization.

Confirmation Time: For users, a transaction included in block N can be considered highly secure after block N+1 is seen and validated by the network, providing significantly faster practical finality than deep PoW confirmations alone.

3.7 Slashing for Non-Participation and Malice
To incentivize continuous participation and honest behavior, penalties for misbehaving ticket holders are implemented.

3.7.1 Non-Participation Slashing:

Condition: A LIVE ticket is selected for voting by TICKET_VOTER_SELECTION but fails to submit a cryptographically valid TicketVote in its designated block H.

Detection: Any honest node can detect non-participation by verifying the BlockH.ticket_votes against the TICKET_VOTER_SELECTION output.

Mechanism: After a GRACE_PERIOD_BLOCKS (e.g., 10 blocks from H), any node can submit a SLASH_TICKET_NON_PARTICIPATION transaction, including a cryptographic proof of the ticket's selection and absence of a valid vote.

Penalty: Upon successful validation of the SLASH_TICKET_NON_PARTICIPATION transaction, NON_PARTICIPATION_SLASH_PERCENTAGE (e.g., 1%) of the ticket's TICKET_LOCKED_AMOUNT is burned. Repeated non-participation by the same ticket within a SLASH_FORGIVENESS_PERIOD (e.g., 100 blocks) may result in an increased penalty or temporary exclusion from the LIVE_TICKETS_POOL.

3.7.2 Malicious Slashing (Double-Voting / Invalid Vote):

Condition: A LIVE ticket attempts to double-vote (signs two conflicting prev_block_hashes for the same block height, or signs a vote for an invalid block).

Detection: Any honest node can detect malicious behavior by observing conflicting TicketVotes on the network or by verifying a signed vote against an invalid block.

Mechanism: Any node can submit a SLASH_TICKET_MALICIOUS_BEHAVIOR transaction, including cryptographic proof of the malicious action (e.g., two conflicting signatures for the same TicketID).

Penalty: Upon successful validation of the SLASH_TICKET_MALICIOUS_BEHAVIOR transaction, MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE (e.g., 100%) of the ticket's TICKET_LOCKED_AMOUNT is burned, and the ticket is permanently blacklisted from ever re-entering the LIVE_TICKETS_POOL.