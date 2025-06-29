//! Data structures for Rusty Coin's on-chain governance (Homestead Accord).

use serde::{Serialize, Deserialize};
use crate::{Hash, PublicKey, TransactionSignature};

/// Enumerates the types of governance proposals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalType {
    /// A proposal to upgrade the protocol rules.
    ProtocolUpgrade,
    /// A proposal to change a protocol parameter (e.g., difficulty adjustment, fee rates).
    ParameterChange,
    /// A proposal to spend funds from the treasury (future feature).
    TreasurySpend,
    /// A proposal to fix a bug in the protocol.
    BugFix,
    /// A proposal to allocate funds for community initiatives.
    CommunityFund,
}

/// Represents a formal proposal submitted to the governance system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GovernanceProposal {
    /// A unique BLAKE3 hash of the canonical serialized proposal content.
    pub proposal_id: Hash,
    /// The Rusty Coin address of the proposer.
    pub proposer_address: PublicKey,
    /// The type of the proposal.
    pub proposal_type: ProposalType,
    /// The block height at which voting officially begins.
    pub start_block_height: u64,
    /// The block height at which voting officially ends.
    pub end_block_height: u64,
    /// A short, descriptive title (max 128 characters).
    pub title: String,
    /// BLAKE3 hash of a markdown document hosted off-chain providing a detailed description.
    pub description_hash: Hash,
    /// For ProtocolUpgrade proposals, a BLAKE3 hash of the proposed code changes (Optional).
    pub code_change_hash: Option<Hash>,
    /// For ParameterChange proposals, the name of the parameter to change (Optional).
    pub target_parameter: Option<String>,
    /// For ParameterChange proposals, the proposed new value (Optional).
    pub new_value: Option<String>,
    /// For BugFix proposals, a description of the bug being fixed.
    pub bug_description: Option<String>,
    /// For CommunityFund proposals, the recipient address.
    pub recipient_address: Option<PublicKey>,
    /// For CommunityFund proposals, the amount to be allocated.
    pub amount: Option<u64>,
    /// For CommunityFund proposals, a description of the project.
    pub project_description: Option<String>,
    /// Ed25519 signature by the ProposerAddress over the entire GOVERNANCE_PROPOSAL_TX payload.
    pub proposer_signature: TransactionSignature,
    pub inputs: Vec<crate::TxInput>,
    pub outputs: Vec<crate::TxOutput>,
    pub lock_time: u32,
    pub witness: Vec<Vec<u8>>,
    pub fee: u64,
}

impl GovernanceProposal {
    /// Calculate the hash of the proposal
    pub fn hash(&self) -> Hash {
        match bincode::serialize(self) {
            Ok(bytes) => blake3::hash(&bytes).into(),
            Err(_) => [0u8; 32], // Should never happen for valid proposals
        }
    }
}

/// Proof that a proposal was approved by governance vote
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalProof {
    /// Total voting power that participated
    pub total_voting_power: u64,
    /// Yes votes received
    pub yes_votes: u64,
    /// No votes received
    pub no_votes: u64,
    /// Abstain votes received
    pub abstain_votes: u64,
    /// Approval percentage achieved (in basis points, 10000 = 100%)
    pub approval_percentage_bp: u64,
    /// Required approval threshold (in basis points, 10000 = 100%)
    pub required_threshold_bp: u64,
    /// Block height when voting ended
    pub voting_end_height: u64,
    /// Hash of the voting state at end of voting period
    pub voting_state_hash: Hash,
}

/// Enumerates the type of voter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VoterType {
    /// Proof-of-Stake ticket holder.
    PosTicket,
    /// Masternode operator.
    Masternode,
}

/// Enumerates the possible choices for a vote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

/// Represents a vote cast on a governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GovernanceVote {
    /// The ProposalID being voted on.
    pub proposal_id: Hash,
    /// The type of voter (PoS ticket or Masternode).
    pub voter_type: VoterType,
    /// The ID of the voter (TicketID for PoS, MasternodeID for Masternode).
    pub voter_id: PublicKey, // Using PublicKey as MasternodeID is OutPoint, not compatible with Hash
    /// The choice of the vote (Yes, No, Abstain).
    pub vote_choice: VoteChoice,
    /// Ed25519 signature by the Operator Key (for Masternode) or the key associated with the TicketID (for PoS) over the GOVERNANCE_VOTE_TX payload.
    pub voter_signature: TransactionSignature,
    pub inputs: Vec<crate::TxInput>,
    pub outputs: Vec<crate::TxOutput>,
    pub lock_time: u32,
    pub witness: Vec<Vec<u8>>,
    pub fee: u64,
} 