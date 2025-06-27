//! Audit logging functionalities for the Rusty-Coin blockchain.

use tracing::{event, Level};
use rusty_shared_types::Hash;
use rusty_shared_types::Transaction;
use rusty_shared_types::BlockHeader;
use rusty_shared_types::governance::{GovernanceProposal, GovernanceVote};
use crate::consensus::error::ConsensusError;
use rusty_shared_types::masternode::{MasternodeIdentity, MasternodeID};
use crate::consensus::governance_state::ProposalOutcome;
use std::net::SocketAddr;

/// Logs when the node starts up.
#[tracing::instrument(level = "info", skip(node_id, listen_port))]
pub fn log_node_startup(node_id: &str, listen_port: u16) {
    event!(Level::INFO, "Node started with ID: {}, listening on port {}", node_id, listen_port);
}

/// Logs when the node shuts down gracefully.
#[tracing::instrument(level = "info", skip(node_id))]
pub fn log_node_shutdown(node_id: &str) {
    event!(Level::INFO, "Node with ID: {} is shutting down.", node_id);
}

/// Logs when a new block is successfully received and added to the blockchain.
#[tracing::instrument(level = "info", skip(block))]
pub fn log_block_added(block: &BlockHeader) {
    event!(Level::INFO, "New block added: height={}, hash={:?}", block.height, block.hash());
}

/// Logs when a block fails validation.
#[tracing::instrument(level = "warn", skip(block, error))]
pub fn log_block_validation_failed(block: &BlockHeader, error: &ConsensusError) {
    event!(Level::WARN, "Block validation failed for block height={}, hash={:?}: {}", block.height, block.hash(), error);
}

/// Logs when a transaction is received by the node (e.g., from P2P or RPC).
#[tracing::instrument(level = "info", skip(tx))]
pub fn log_transaction_received(tx: &Transaction) {
    event!(Level::INFO, "New transaction added to mempool: txid={:?}", tx.txid());
}

/// Logs when a transaction successfully passes validation.
#[tracing::instrument(level = "info", skip(tx))]
pub fn log_transaction_validated(tx: &Transaction) {
    event!(Level::INFO, "Transaction validated: tx_id={}", hex::encode(tx.txid()));
}

/// Logs when a transaction fails validation.
#[tracing::instrument(level = "warn", skip(tx, error))]
pub fn log_transaction_validation_failed(tx: &Transaction, error: &ConsensusError) {
    event!(Level::WARN, "Transaction validation failed for txid={:?}: {}", tx.txid(), error);
}

/// Logs when a Masternode is successfully registered.
#[tracing::instrument(level = "info", skip(identity))]
pub fn log_masternode_registered(identity: &MasternodeIdentity) {
    event!(Level::INFO, "Masternode registered: id={:?}, address={}", identity.collateral_outpoint, identity.network_address);
}

/// Logs when a Masternode is slashed.
#[tracing::instrument(level = "warn", skip(slash_tx))]
pub fn log_masternode_slashed(slash_tx: &rusty_shared_types::masternode::MasternodeSlashTx) {
    event!(Level::WARN, "Masternode slashed: masternode_id={:?}, reason={:?}", slash_tx.masternode_id, slash_tx.reason);
}

/// Logs when a Masternode registration fails.
#[tracing::instrument(level = "warn", skip(identity, error))]
pub fn log_masternode_registration_failed(identity: &MasternodeIdentity, error: &ConsensusError) {
    event!(Level::WARN, "Masternode registration failed for id={:?}: {}", identity.collateral_outpoint, error);
}

/// Logs when an RPC call is received.
#[tracing::instrument(level = "debug", skip(method_name))]
pub fn log_rpc_request(method_name: &str, client_ip: SocketAddr) {
    event!(Level::DEBUG, "RPC Request: method={}, from={}", method_name, client_ip);
}

/// Logs when an RPC call fails due to an authentication error.
#[tracing::instrument(level = "warn", skip(method_name, client_ip))]
pub fn log_rpc_error(method_name: &str, client_ip: SocketAddr, error: &str) {
    event!(Level::WARN, "RPC Error: method={}, from={}, error={}", method_name, client_ip, error);
}

/// Logs when a governance proposal is successfully submitted.
#[tracing::instrument(level = "info", skip(proposal))]
pub fn log_governance_proposal_submitted(proposal: &GovernanceProposal) {
    event!(Level::INFO, "Governance proposal submitted: id={:?}, type={:?}, title={}", proposal.proposal_id, proposal.proposal_type, proposal.title);
}

/// Logs when a governance vote is successfully cast.
#[tracing::instrument(level = "info", skip(vote))]
pub fn log_governance_vote_cast(vote: &GovernanceVote) {
    event!(Level::INFO, "Governance vote cast: proposal_id={:?}, voter_id={:?}, choice={:?}", vote.proposal_id, vote.voter_id, vote.vote_choice);
}

/// Logs when a governance proposal is evaluated.
#[tracing::instrument(level = "info", skip(proposal_id, outcome_reason))]
pub fn log_governance_proposal_evaluated(
    proposal_id: &Hash,
    outcome: &str,
    outcome_reason: Option<&str>,
) {
    event!(Level::INFO, "Governance proposal evaluated: proposal_id={}, outcome={:?}, outcome_reason={:?}", hex::encode(proposal_id), outcome, outcome_reason);
}

/// Logs when a governance proposal is resolved.
#[tracing::instrument(level = "info", skip(proposal_id, outcome_reason))]
pub fn log_governance_proposal_resolved(
    proposal_id: &Hash,
    outcome_reason: &str,
) {
    event!(Level::INFO, "Governance proposal resolved: id={:?}, outcome={}", proposal_id, outcome_reason);
}

/// Logs when a PoSe challenge is generated.
#[tracing::instrument(level = "info", skip(challenge))]
pub fn log_pose_challenge_generated(challenge: &rusty_shared_types::PoSeChallenge) {
    event!(
        Level::INFO,
        "PoSe challenge generated: masternode_id={:?}, block_height={}, nonce={}",
        challenge.challenger_masternode_id,
        challenge.challenge_generation_block_height,
        challenge.challenge_nonce
    );
}

/// Logs when a PoSe response is received.
#[tracing::instrument(level = "info", skip(response))]
pub fn log_pose_response_received(response: &rusty_shared_types::PoSeResponse) {
    event!(
        Level::INFO,
        "PoSe response received: masternode_id={:?}, challenge_nonce={}",
        response.target_masternode_id,
        response.challenge_nonce
    );
}

/// Logs when a PoSe response is valid.
#[tracing::instrument(level = "info", skip(response))]
pub fn log_pose_response_valid(response: &rusty_shared_types::PoSeResponse) {
    event!(
        Level::INFO,
        "PoSe response valid: masternode_id={:?}, challenge_nonce={}",
        response.target_masternode_id,
        response.challenge_nonce
    );
}

/// Logs when a PoSe response is invalid.
#[tracing::instrument(level = "warn", skip(response, error))]
pub fn log_pose_response_invalid(response: &rusty_shared_types::PoSeResponse, error: &str) {
    event!(
        Level::WARN,
        "PoSe response invalid: masternode_id={:?}, challenge_nonce={}, error={}",
        response.target_masternode_id,
        response.challenge_nonce,
        error
    );
}

/// Logs when a masternode is penalized for failing a PoSe challenge.
#[tracing::instrument(level = "warn", skip(masternode_id, penalty_amount))]
pub fn log_masternode_penalized(masternode_id: &MasternodeID, penalty_amount: u64) {
    event!(
        Level::WARN,
        "Masternode penalized: id={:?}, penalty_amount={}",
        masternode_id,
        penalty_amount
    );
}

/// Logs when a governance proposal is evaluated with a specific outcome.
#[tracing::instrument(level = "info", skip(proposal_id, outcome))]
pub fn log_governance_proposal_outcome(
    proposal_id: &Hash,
    outcome: &ProposalOutcome,
    details: &str,
) {
    event!(
        Level::INFO,
        "Governance proposal outcome: id={:?}, outcome={:?}, details={}",
        proposal_id,
        outcome,
        details
    );
}