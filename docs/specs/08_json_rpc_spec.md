Rusty Coin Formal Protocol Specifications: 08 - On-Chain Governance (Homestead Accord)
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md (for Transaction definitions), 03_oxidesync_pos_spec.md (for PoS Ticket context), 06_masternode_protocol_spec.md (for Masternode context), rusty_crypto_spec.md (for signatures).

8.1 Overview
The Homestead Accord defines Rusty Coin's on-chain governance system. It is a bicameral voting mechanism that empowers both Proof-of-Stake (PoS) ticket holders and active Masternode operators to collectively approve or reject proposals for protocol changes. This system ensures decentralized decision-making, reduces the likelihood of contentious forks, and provides a formal, auditable process for network evolution.

8.2 Governance Actors and Voting Power
The Homestead Accord recognizes two primary classes of governance actors, each with distinct voting power:

PoS Ticket Holders (Stakers):

Eligibility: Any LIVE PoS ticket (as defined in 03_oxidesync_pos_spec.md) is eligible to vote.

Voting Power: Each LIVE PoS ticket represents one vote.

Incentive: Participation in governance voting may be considered a component of good staking behavior, potentially influencing future reward mechanisms (defined by governance).

Masternode Operators:

Eligibility: Any ACTIVE Masternode (as defined in 06_masternode_protocol_spec.md) is eligible to vote.

Voting Power: Each ACTIVE Masternode represents one vote.

Incentive: Participation in governance voting is a core service of Masternodes, contributing to their overall eligibility for block rewards.

8.3 Proposal Lifecycle
A proposal undergoes a defined lifecycle from submission to resolution.

8.3.1 Proposal Submission (GOVERNANCE_PROPOSAL_TX)

Any network participant meeting a minimum PROPOSAL_STAKE_AMOUNT (e.g., 1000 RUST) may submit a formal proposal to the network.

Transaction Type: A special GOVERNANCE_PROPOSAL_TX MUST be used.

Inputs: Must include at least one TxInput spending the PROPOSAL_STAKE_AMOUNT to a temporary escrow address controlled by the protocol. This stake is burned if the proposal is rejected due to insufficient quorum or if it is malicious/spam.

Payload: The GOVERNANCE_PROPOSAL_TX payload MUST contain:

ProposalID: A unique BLAKE3 hash of the canonical serialized proposal content.

ProposerAddress: The Rusty Coin address of the proposer.

ProposalType: An enumerated type (e.g., PROTOCOL_UPGRADE, PARAMETER_CHANGE, TREASURY_SPEND (future)).

StartBlockHeight: The block height at which voting officially begins.

EndBlockHeight: The block height at which voting officially ends. (EndBlockHeight - StartBlockHeight + 1) defines the VOTING_PERIOD_BLOCKS.

Title: A short, descriptive title (max 128 characters).

DescriptionHash: BLAKE3 hash of a markdown document hosted off-chain (e.g., IPFS or a designated governance repository) providing a detailed description of the proposal.

CodeChangeHash (Optional): For PROTOCOL_UPGRADE proposals, a BLAKE3 hash of the proposed code changes (e.g., a Git commit hash or a patch file hash).

TargetParameter (Optional): For PARAMETER_CHANGE proposals, the name of the parameter to change (e.g., TICKET_PRICE_ADJUSTMENT_PERIOD).

NewValue (Optional): For PARAMETER_CHANGE proposals, the proposed new value.

ProposerSignature: Ed25519 signature by the ProposerAddress over the entire GOVERNANCE_PROPOSAL_TX payload.

Validation: rusty-consensus MUST validate:

Correct PROPOSAL_STAKE_AMOUNT locked.

Valid ProposalType, StartBlockHeight, EndBlockHeight (e.g., VOTING_PERIOD_BLOCKS within limits).

Syntactic correctness of the payload.

Valid ProposerSignature.

8.3.2 Voting Phase (GOVERNANCE_VOTE_TX)

During the VOTING_PERIOD_BLOCKS, eligible governance actors can cast their votes.

Transaction Type: A special GOVERNANCE_VOTE_TX MUST be used.

Inputs: MUST include an input spending a small transaction fee.

Payload: The GOVERNANCE_VOTE_TX payload MUST contain:

ProposalID: The ProposalID being voted on.

VoterType: POS_TICKET or MASTERNODE.

VoterID:

For POS_TICKET: The TicketID (TxID + VOutIndex) of the LIVE ticket casting the vote.

For MASTERNODE: The MasternodeID (TxID of collateral UTXO) of the ACTIVE Masternode casting the vote.

VoteChoice: YES, NO, or ABSTAIN.

VoterSignature: Ed25519 signature by the Operator Key (for Masternode) or the key associated with the TicketID (for PoS) over the GOVERNANCE_VOTE_TX payload.

Validation: rusty-consensus MUST validate:

The GOVERNANCE_PROPOSAL_TX exists and its VOTING_PERIOD_BLOCKS is active.

VoterID corresponds to a LIVE PoS ticket or an ACTIVE Masternode at the block height the vote is included.

The VoterID has not already voted on this ProposalID.

Valid VoterSignature.

8.3.3 Proposal Resolution

At EndBlockHeight, the rusty-consensus module evaluates the votes to determine the proposal's outcome.

Vote Aggregation: All valid GOVERNANCE_VOTE_TX transactions included in blocks during VOTING_PERIOD_BLOCKS are counted for each ProposalID, aggregated separately for PoS votes and Masternode votes.

Quorum Check (Bicameral):

PoS Quorum: The total number of YES + NO votes from PoS tickets MUST be greater than or equal to POS_VOTING_QUORUM_PERCENTAGE (e.g., 20%) of the theoretical maximum LIVE tickets that could have voted during the period.

Masternode Quorum: The total number of YES + NO votes from Masternodes MUST be greater than or equal to MN_VOTING_QUORUM_PERCENTAGE (e.g., 50%) of ACTIVE Masternodes at EndBlockHeight.

If EITHER quorum fails, the proposal is REJECTED.

Supermajority Check (Bicameral):

If both quorums are met:

PoS Approval: The percentage of YES votes among (YES + NO) votes from PoS tickets MUST be greater than or equal to POS_APPROVAL_PERCENTAGE (e.g., 75%).

Masternode Approval: The percentage of YES votes among (YES + NO) votes from Masternodes MUST be greater than or equal to MN_APPROVAL_PERCENTAGE (e.g., 66%).

If BOTH approval percentages are met, the proposal is PASSED.

Otherwise, the proposal is REJECTED.

Expiration: If a proposal does not reach either quorum or supermajority by EndBlockHeight, it is automatically EXPIRED (rejected).

8.3.4 Proposal Activation

PASSED Proposals:

PARAMETER_CHANGE: The specified parameter is atomically updated by the protocol at EndBlockHeight + ACTIVATION_DELAY_BLOCKS.

PROTOCOL_UPGRADE: A software upgrade is signaled. Nodes running the new software will activate the new protocol rules at EndBlockHeight + ACTIVATION_DELAY_BLOCKS. Nodes not updated will fork off.

TREASURY_SPEND (Future): Funds are released from a protocol-controlled address (future feature).

REJECTED/EXPIRED Proposals: Have no effect on the protocol. The PROPOSAL_STAKE_AMOUNT is typically burned if the proposal failed to meet quorum, or returned to the proposer if it met quorum but failed supermajority (details subject to final governance rule specification).

8.4 Governance Data Management
The state of all active proposals and their aggregated votes is implicitly committed within the state_root of the BlockHeader. This ensures transparency and verifiability of the entire governance process. rusty-consensus maintains a PROPOSALS_STATE data structure for this purpose.

8.5 Fork Minimization Strategy
The bicameral on-chain governance model aims to minimize contentious hard forks by providing a formalized, transparent, and economically incentivized process for protocol evolution. By requiring a supermajority from two distinct economic stakeholders (stakers and masternodes), it encourages broader consensus and discourages unilateral changes.