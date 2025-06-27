Rusty Coin Formal Protocol Specifications: 06 - Masternode Protocol
Spec Version: 1.0.0
Status: Draft
Last Updated: June 18, 2025
Author(s): Rusty Coin Core Team

Dependencies: 00_overview.md, 01_block_structure.md, 03_oxidesync_pos_spec.md (for LIVE_TICKETS_POOL context), 04_ferrisscript_spec.md, 05_utxo_model_spec.md, rusty_crypto_spec.md (for Ed25519, BLAKE3).

6.1 Overview
The Rusty Coin Masternode Network constitutes a vital second-layer infrastructure, providing advanced network services and participating in critical security mechanisms. Masternodes are full nodes that lock a significant amount of $RUST collateral and must continuously prove their availability and service provision to earn a portion of the block rewards.

6.2 Masternode Identity and Registration
A Masternode's identity is cryptographically secured and registered on the blockchain.

6.2.1 Masternode Collateral

Amount: Each Masternode MUST lock MASTERNODE_COLLATERAL_AMOUNT of RUST (in satoshis) in a dedicated UTXO on the mainchain. This amount is a fixed constant defined at network genesis.

Identification: The Masternode collateral UTXO is identified by its (TxID, VOutIndex) pair, similar to a PoS ticket.

Locking Script: The script_pubkey of the collateral UTXO MUST be designed such that it can only be spent by the masternode owner AFTER an explicit deregistration (e.g., via a special transaction type) or due to a slashing event.

6.2.2 Masternode Public Keys

Each Masternode MUST be associated with at least two distinct Ed25519 public key pairs:

Operator Key: Used for signing Proof-of-Service (PoSe) challenges and participating in Masternode-specific quorums (OxideSend, FerrousShield). This key MUST be kept online and responsive.

Voting Key (Optional, Future): If Masternodes participate directly in on-chain governance (Homestead Accord) without also being PoS ticket holders, a separate voting key may be specified. For now, it's assumed PoS ticket voting handles governance.

Collateral Ownership Key: The public key associated with the script_pubkey of the collateral UTXO, used to spend/deregister the collateral. This key should ideally be kept offline (cold storage).

6.2.3 Masternode Registration (MN_REGISTER_TX)

To register a Masternode, the owner MUST broadcast a special MN_REGISTER_TX transaction:

Inputs: MUST include at least one TxInput spending exactly MASTERNODE_COLLATERAL_AMOUNT to a new TxOutput specifically designed to lock the collateral (see 6.2.1).

Outputs: The transaction MUST create a new TxOutput locking MASTERNODE_COLLATERAL_AMOUNT with a script designating it as Masternode collateral. It MUST also include a small transaction fee.

Payload: The MN_REGISTER_TX MUST include an additional payload containing:

The Operator Key (public key).

The network address (IP:Port) of the Masternode.

A signature by the Collateral Ownership Key over the entire transaction (including the payload).

Validation: Full nodes verify:

Correct collateral amount locked.

Valid Operator Key and network address.

Valid signature by the Collateral Ownership Key.

The Masternode is not already registered.

6.2.4 Masternode List (MASTERNODE_LIST)

The MASTERNODE_LIST is a dynamic data structure maintained by each full node, containing metadata for all currently registered Masternodes. Its state is cryptographically committed to in the state_root of each BlockHeader.

Contents: For each MasternodeID (typically the TxID of the collateral UTXO), the MASTERNODE_LIST stores:

Collateral OutPoint.

Operator Key (public key).

Network address.

Current status (e.g., REGISTERED, ACTIVE, OFFLINE, PROBATION, BANNED).

Last successful PoSe check timestamp/block height.

PoSe failure count.

6.3 Proof-of-Service (PoSe) Protocol
PoSe is a challenge-response mechanism that requires Masternodes to continuously prove their active presence and responsiveness to the network to remain eligible for rewards.

6.3.1 PoSe Challenge Generation (POSE_CHALLENGE)

Frequency: PoSe challenges are generated deterministically by the network every POSE_CHALLENGE_PERIOD_BLOCKS (e.g., 60 blocks, ~2.5 hours).

Challenger Selection:

At the start of a POSE_CHALLENGE_PERIOD, a deterministic pseudo-random function (DPRF), DPRF_CHALLENGER(BlockH.hash, MASTERNODE_LIST_SNAPSHOT), is used to select NUM_CHALLENGERS (e.g., 3) Masternodes from the MASTERNODE_LIST to act as challengers.

The BlockH.hash is the hash of the last block finalized before the start of the current POSE_CHALLENGE_PERIOD.

Target Selection: For each POSE_CHALLENGE_PERIOD, NUM_TARGETS_PER_PERIOD (e.g., 10% of active Masternodes, or a fixed number) Masternodes are selected as targets to be challenged. This selection also uses a DPRF: DPRF_TARGET(BlockH.hash, MASTERNODE_LIST_SNAPSHOT).

Challenge Content: Each challenger sends a POSE_CHALLENGE message to its assigned targets. The challenge payload includes:

ChallengeNonce: A unique random number generated by the challenger.

ChallengeBlockhash: The BLAKE3 hash of BlockH.hash (the most recently finalized block at challenge generation).

ChallengerMasternodeID: The TxID of the challenger's collateral UTXO.

Signature: Ed25519 signature by the ChallengerMasternodeID.Operator Key over the ChallengeNonce and ChallengeBlockhash.

6.3.2 PoSe Response Verification (POSE_RESPONSE_VERIFICATION)

Response Content: A challenged Masternode MUST send a POSE_RESPONSE message to its challenger(s) within POSE_RESPONSE_TIMEOUT_SECONDS (e.g., 60 seconds). The response payload includes:

ChallengeNonce: Copied from the received challenge.

SignedBlockhash: Ed25519 signature by the TargetMasternodeID.Operator Key over the ChallengeBlockhash.

TargetMasternodeID: The TxID of the challenged Masternode's collateral UTXO.

Verification Steps (by Challenger and Network):

Timeliness: The response MUST be received within POSE_RESPONSE_TIMEOUT_SECONDS.

Challenge Match: Response.ChallengeNonce MUST match the original Challenge.ChallengeNonce.

Signature Validity: Response.SignedBlockhash MUST be a valid Ed25519 signature of Challenge.ChallengeBlockhash using the TargetMasternodeID.Operator Key recorded in the MASTERNODE_LIST.

Broadcast: Upon successful verification, the challenger broadcasts a POSE_PROOF_OF_VALID_RESPONSE message to the network.

Status Update: If a Masternode successfully responds to all challenges within a POSE_CHALLENGE_PERIOD, its LastSuccessfulPoSe timestamp/height in the MASTERNODE_LIST is updated, and its PoSe failure count is reset.

6.4 Masternode Slashing (MASTERNODE_SLASHING)
To maintain the integrity and reliability of the Masternode network, penalties are imposed for non-performance or malicious behavior.

6.4.1 Non-Participation Slashing:

Condition: A Masternode fails to submit a valid POSE_RESPONSE to a challenge within POSE_RESPONSE_TIMEOUT_SECONDS, or its POSE_PROOF_OF_VALID_RESPONSE is not broadcast/validated within the POSE_CHALLENGE_PERIOD.

Detection: Any honest full node can detect non-participation by comparing selected targets to validated responses.

Penalty:

Warning/Probation: Upon the first (or Nth) detected failure in a POSE_CHALLENGE_PERIOD, the Masternode's status in MASTERNODE_LIST is set to PROBATION, and its PoSe failure count increments.

Reward Suspension: A Masternode on PROBATION MAY have its block reward allocation temporarily suspended for SUSPENSION_PERIOD_BLOCKS.

Slashing: If PoSe failure count exceeds MAX_POSE_FAILURES (e.g., 3) within a RESET_FAILURES_PERIOD (e.g., 100 blocks), NON_PARTICIPATION_SLASH_PERCENTAGE (e.g., 5%) of its MASTERNODE_COLLATERAL_AMOUNT is burned.

Proof Mechanism: A special MN_SLASH_NON_PARTICIPATION_TX can be broadcast by any node, providing cryptographic proof of the Masternode's non-responsiveness (e.g., challenge data, absence of valid response within a block range).

6.4.2 Malicious Behavior Slashing:

Condition: A Masternode is proven to have engaged in malicious behavior:

Double-Signing: Signing two conflicting SignedBlockhashes for the same ChallengeBlockhash with the same Operator Key.

Invalid Service Provision: Provably failing to uphold commitments for OxideSend or FerrousShield (details in 6.5).

Detection: Requires cryptographic evidence of the malicious act.

Penalty: MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE (e.g., 100%) of the MASTERNODE_COLLATERAL_AMOUNT is burned immediately.

Proof Mechanism: A special MN_SLASH_MALICIOUS_TX MUST be broadcast, containing cryptographic proof (e.g., conflicting signatures). This transaction is validated by rusty-consensus.

Blacklisting: A Masternode whose collateral is slashed for malicious behavior is permanently blacklisted by its Operator Key and Collateral TxID, preventing future registration.

6.5 Network Services
Masternodes collectively provide advanced services to the Rusty Coin network, enhancing usability and privacy.

6.5.1 OxideSend (Instant Transaction Service)

Purpose: To provide near-instantaneous transaction confirmation, significantly reducing waiting times compared to traditional block confirmations.

Mechanism:

Initiation: A user's wallet (e.g., rusty-wallet) signals an OxideSend request for a transaction.

Quorum Selection: A deterministic Masternode quorum of OXIDESEND_QUORUM_SIZE (e.g., 10-15 Masternodes) is selected using a DPRF seeded by the latest BlockH.hash from the ACTIVE MASTERNODE_LIST. This quorum is responsible for locking the transaction inputs.

Input Locking Protocol:

The sender's wallet broadcasts the OxideSend transaction to the selected quorum.

Each Masternode in the quorum verifies the transaction (input existence, validity, no double-spend in its mempool).

If valid, each Masternode signs a TX_INPUT_LOCK message, committing not to allow the transaction's inputs to be spent by any other transaction in its mempool for OXIDESEND_LOCK_DURATION_BLOCKS (e.g., 5 blocks). This signature is made with the Masternode's Operator Key.

The signed TX_INPUT_LOCK messages are gossiped throughout the network.

Instant Confirmation: Once the recipient's wallet (or any node) observes OXIDESEND_MIN_QUORUM_SIGS_REQUIRED (e.g., 80% of OXIDESEND_QUORUM_SIZE) valid TX_INPUT_LOCK signatures for the transaction, the transaction can be considered "instantly confirmed" and highly reliable, awaiting inclusion in a block.

Block Inclusion: Miners (who also track TX_INPUT_LOCKs) prioritize OxideSend transactions for inclusion in the next block.

Security: OxideSend's security relies on the economic collateral of the Masternode quorum. Any Masternode that participates in an OxideSend lock and then allows a double-spend of those inputs (e.g., by including a conflicting transaction in its own mined block) is subject to MALICIOUS_BEHAVIOR_SLASH_PERCENTAGE slashing.

6.5.2 FerrousShield (Trust-Minimized Privacy)

Purpose: To enhance transaction privacy by obscuring the linkage between transaction inputs and outputs through a CoinJoin implementation.

Mechanism:

User Request: A user's wallet initiates a FerrousShield request, specifying the amount of RUST to mix.

Masternode Coordination: A FerrousShield Coordinator Quorum of FERROUSSHIELD_QUORUM_SIZE (e.g., 5-7 Masternodes) is selected using a DPRF. This quorum coordinates the CoinJoin process.

Multi-Round CoinJoin: The process involves multiple rounds to maximize anonymity and prevent coordinator deanonymization:

Input Collection: Participating users submit their inputs (UTXOs) to the coordinator.

Output Submission: Users submit their desired output addresses (fresh, newly generated addresses) to receive mixed coins.

Transaction Construction: The coordinator constructs a single, large transaction with all participants' inputs and outputs.

Blinded Signatures / Secure MPC (Multi-Party Computation): To ensure the coordinator does not learn the input-output mapping, participants may use cryptographic techniques like blinded signatures or collaborate through Secure Multi-Party Computation where each participant signs only their portion of the transaction without revealing their full linkage. The exact secure MPC protocol used will be formally defined in a sub-specification.

Signature Collection: Each participant signs their allocated inputs and outputs in the aggregated transaction.

Broadcast & Inclusion: Once all participants have signed the aggregated CoinJoin transaction, it is broadcast to the network and included in a block.

Trust Minimization: The design goal is to minimize trust in the coordinating Masternodes. They should only be able to aggregate and coordinate, not steal funds or deanonymize participants.

Anonymity Set: The anonymity set is defined by the number of participants in a successful FerrousShield CoinJoin round. Larger rounds provide stronger privacy.

Fees: A small fee MAY be charged for FerrousShield services (e.g., a percentage of the mixed amount), distributed among the coordinating Masternodes.

Security: Masternodes involved in FerrousShield are subject to slashing if they attempt to maliciously deanonymize users or disrupt the mixing process. Evidence of such behavior (e.g., leaking participant data, intentionally failing to cooperate) would trigger MN_SLASH_MALICIOUS_TX.