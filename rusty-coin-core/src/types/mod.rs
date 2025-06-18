//! Core types for Rusty Coin blockchain

pub mod prelude {
    pub use super::BlockchainState;
}

use serde::{Deserialize, Serialize};
use crate::crypto::{
    Hash,
    PublicKey,
};
use std::time::{SystemTime, UNIX_EPOCH};
use bincode;

/// Identifies a specific transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct OutPoint {
    pub tx_hash: Hash,
    pub output_index: u32,
}

/// A transaction input references an output from a previous transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct TxInput {
    /// Reference to the transaction output being spent
    pub outpoint: OutPoint,
    /// Signature that proves ownership of the output being spent
    pub signature: Vec<u8>,
    /// Public key of the output being spent
    pub public_key: PublicKey,
}

impl TxInput {
    /// Returns true if this is a coinbase input.
    pub fn is_coinbase(&self) -> bool {
        self.outpoint.tx_hash == Hash::zero() && self.outpoint.output_index == u32::MAX
    }
}

/// A transaction output specifies an amount and a locking script.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct TxOutput {
    /// Amount in satoshis (1 RUST = 100,000,000 satoshis)
    pub value: u64,
    /// Public key hash of the recipient (20 bytes)
    pub pubkey_hash: [u8; 20],
    /// Optional data for a staking ticket purchase
    #[bincode(with_serde)]
    pub ticket_data: Option<VotingTicketPayload>,
    /// Optional data for a ticket revocation (redemption)
    #[bincode(with_serde)]
    pub revocation_data: Option<TicketRevocationPayload>,
    /// Optional data for a masternode registration
    #[bincode(with_serde)]
    pub masternode_data: Option<MasternodeRegistrationPayload>,
    /// Optional data for a governance proposal
    #[bincode(with_serde)]
    pub proposal_data: Option<GovernanceProposalPayload>,
    /// Optional data for a governance vote
    #[bincode(with_serde)]
    pub vote_data: Option<GovernanceVotePayload>,
    /// Indicates if this transaction requests an instant lock (OxideSend)
    pub is_instant_send: bool,
}

/// Payload for a governance proposal, included in a transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct GovernanceProposalPayload {
    pub proposal_id: Hash,
    pub title: String,
    pub description: String,
    pub proposal_type: ProposalType,
    pub start_height: u64,
    pub end_height: u64,
    pub voting_threshold: f64, // e.g., 0.75 for 75%
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum ProposalType {
    ProtocolUpgrade,
    ParameterChange,
    TreasuryRequest,
    Other,
}

/// Payload for a masternode registration, included in a transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct MasternodeRegistrationPayload {
    /// Public key of the masternode operator (for signing PoSe and other messages).
    pub public_key: PublicKey,
    /// Public key for payouts (where rewards are sent).
    pub payout_address: [u8; 20],
    /// IP address of the masternode.
    pub ip_address: String,
    /// Port of the masternode.
    pub port: u16,
}

/// Payload for a ticket revocation, included in a transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct TicketRevocationPayload {
    /// The hash of the ticket being revoked.
    pub ticket_hash: Hash,
}

/// Payload for a staking ticket, included in a transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct VotingTicketPayload {
    /// The public key of the staker, derived from the UTXO's script_pubkey being spent.
    /// This public key will be used for signing blocks.
    pub staker_public_key: PublicKey,
    /// The block height at which this ticket was created.
    pub creation_height: u64,
}

/// Payload for a governance vote, included in a transaction output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct GovernanceVotePayload {
    pub proposal_id: Hash,
    pub voter_type: VoterType,
    pub voter_id: Hash, // Hash of masternode registration tx or voting ticket
    pub vote: bool, // true for yes, false for no
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum VoterType {
    Masternode,
    Staker,
}

/// A transaction is a transfer of value between wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// List of inputs
    pub inputs: Vec<TxInput>,
    /// List of outputs
    pub outputs: Vec<TxOutput>,
    /// Lock time or block number after which this transaction is valid
    pub lock_time: u32,
    /// Block creation timestamp (seconds since Unix epoch)
    pub timestamp: u64,
}

impl Transaction {
    /// Creates a new coinbase transaction (mining reward)
    pub fn new_coinbase(to: [u8; 20], value: u64, height: u64) -> Self {
        // Coinbase transactions have a single input with special data
        let mut signature = vec![0; 32];
        signature[..8].copy_from_slice(&height.to_le_bytes());

        let input = TxInput {
            outpoint: OutPoint {
                tx_hash: Hash::zero(),
                output_index: u32::MAX,
            },
            signature,
            public_key: PublicKey::zero(),
        };

        let output = TxOutput {
            value,
            pubkey_hash: to,
            ticket_data: None,
            revocation_data: None,
            masternode_data: None,
            proposal_data: None,
            vote_data: None,
            is_instant_send: false,
        };

        Transaction {
            version: 1,
            inputs: vec![input],
            outputs: vec![output],
            lock_time: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Computes the transaction hash (used as the transaction ID)
    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let tx_data = bincode::encode_to_vec(&self, config).expect("Failed to serialize transaction");
        Hash::blake3(&tx_data)
    }

    /// Computes the hash of the transaction for signing purposes (excludes signatures).
    pub fn hash_for_signature(&self) -> Hash {
        let mut tx_copy = self.clone();
        for input in &mut tx_copy.inputs {
            input.signature = vec![]; // Clear signatures for hashing
        }
        let config = bincode::config::standard();
        let tx_data = bincode::encode_to_vec(&tx_copy, config).expect("Failed to serialize transaction for signing");
        Hash::blake3(&tx_data)
    }

    /// Returns true if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 
            && self.inputs[0].outpoint.tx_hash == Hash::zero() 
            && self.inputs[0].outpoint.output_index == u32::MAX
    }

    /// Creates a new regular transaction (non-coinbase).
    /// This function assumes `utxos` are valid and belong to the `sender_keypair`.
    pub fn new_regular_transaction(
        sender_keypair: &crate::crypto::KeyPair,
        utxos_to_spend: Vec<UTXO>,
        recipient_address: [u8; 20],
        amount: u64,
        change_address: [u8; 20],
        fee: u64,
        is_instant_send: bool,
    ) -> Result<Self, crate::error::Error> {
        let mut inputs = Vec::new();
        let mut total_input_value = 0;

        for utxo in utxos_to_spend {
            total_input_value += utxo.value;
            let input = TxInput {
                outpoint: OutPoint {
                    tx_hash: utxo.tx_hash,
                    output_index: utxo.output_index,
                },
                signature: vec![], // Placeholder, will be signed later
                public_key: sender_keypair.public_key.clone(),
            };
            inputs.push(input);
        }

        if total_input_value < amount + fee {
            return Err(crate::error::Error::TxError("Insufficient funds".to_string()));
        }

        let mut outputs = Vec::new();
        // Recipient output
        outputs.push(TxOutput {
            value: amount,
            pubkey_hash: recipient_address,
            ticket_data: None,
            revocation_data: None,
            masternode_data: None,
            proposal_data: None,
            vote_data: None,
            is_instant_send,
        });

        // Change output, if any
        let change_value = total_input_value - amount - fee;
        if change_value > 0 {
            outputs.push(TxOutput {
                value: change_value,
                pubkey_hash: change_address,
                ticket_data: None,
                revocation_data: None,
                masternode_data: None,
                proposal_data: None,
                vote_data: None,
                is_instant_send: false,
            });
        }

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Sign each input
        let tx_hash_for_signing = tx.hash_for_signature(); // Use hash for signature
        for input in &mut tx.inputs {
            let signature = crate::crypto::sign(sender_keypair, tx_hash_for_signing.as_bytes())?;
            input.signature = signature.0.to_vec();
        }

        Ok(tx)
    }

    /// Returns true if this transaction is a ticket purchase.
    pub fn is_ticket_purchase(&self) -> bool {
        // A transaction is a ticket purchase if it has exactly one output with ticket_data present.
        self.outputs.len() == 1 && self.outputs[0].ticket_data.is_some() && self.outputs[0].revocation_data.is_none()
    }

    /// Returns true if this transaction is a ticket revocation (redemption).
    pub fn is_ticket_revocation(&self) -> bool {
        // A transaction is a ticket revocation if it has exactly one output with revocation_data present.
        self.outputs.len() == 1 && self.outputs[0].revocation_data.is_some() && self.outputs[0].ticket_data.is_none()
    }

    /// Returns true if this transaction is a masternode registration.
    pub fn is_masternode_registration(&self) -> bool {
        self.outputs.len() == 1 && self.outputs[0].masternode_data.is_some() && self.outputs[0].ticket_data.is_none()
    }

    /// Returns true if this transaction is a governance proposal.
    pub fn is_governance_proposal(&self) -> bool {
        self.outputs.len() == 1 && self.outputs[0].proposal_data.is_some()
    }

    /// Returns true if this transaction is a governance vote.
    pub fn is_governance_vote(&self) -> bool {
        self.outputs.len() == 1 && self.outputs[0].vote_data.is_some()
    }

    /// Returns true if this transaction is a masternode update.
    pub fn is_masternode_update(&self) -> bool {
        // A transaction is a masternode update if it has a special marker in the first output's script
        // or a specific output that indicates it's an update transaction.
        // For now, we'll check for a specific pattern in the first output's script.
        // This is a simplified version and should be enhanced based on your protocol.
        self.outputs.first().map_or(false, |output| {
            // Check for a specific pattern in the script that indicates an update
            // This is a placeholder - adjust based on your actual protocol
            output.pubkey_hash.starts_with(b"MN_UPDATE_")
        })
    }

    /// Returns true if this transaction is a masternode revocation.
    pub fn is_masternode_revocation(&self) -> bool {
        // A transaction is a masternode revocation if it spends a masternode collateral
        // and has a special marker output.
        // For now, we'll check for a specific pattern in the first output's script.
        // This is a simplified version and should be enhanced based on your protocol.
        self.outputs.first().map_or(false, |output| {
            // Check for a specific pattern in the script that indicates a revocation
            // This is a placeholder - adjust based on your actual protocol
            output.pubkey_hash.starts_with(b"MN_REVOKE_")
        })
    }

    /// Creates a new masternode registration transaction.
    pub fn new_masternode_registration(
        sender_keypair: &crate::crypto::KeyPair,
        collateral_utxo: UTXO,
        collateral_amount: u64,
        public_key: PublicKey,
        payout_address: [u8; 20],
        ip_address: String,
        port: u16,
        fee: u64,
    ) -> Result<Self, crate::error::Error> {
        let mut inputs = Vec::new();
        inputs.push(TxInput {
            outpoint: OutPoint {
                tx_hash: collateral_utxo.tx_hash,
                output_index: collateral_utxo.output_index,
            },
            signature: vec![], // Will be signed later
            public_key: sender_keypair.public_key.clone(),
        });

        if collateral_utxo.value < collateral_amount + fee {
            return Err(crate::error::Error::TxError("Insufficient collateral for masternode registration".to_string()));
        }

        let mut outputs = Vec::new();
        // Masternode registration output
        outputs.push(TxOutput {
            value: collateral_amount,
            pubkey_hash: payout_address, // Payout address is typically the masternode owner's address
            ticket_data: None,
            revocation_data: None,
            masternode_data: Some(MasternodeRegistrationPayload {
                public_key,
                payout_address,
                ip_address,
                port,
            }),
            proposal_data: None,
            vote_data: None,
            is_instant_send: false,
        });

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Sign each input
        let tx_hash_for_signing = tx.hash_for_signature();
        for input in &mut tx.inputs {
            let signature = crate::crypto::sign(sender_keypair, tx_hash_for_signing.as_bytes())?;
            input.signature = signature.0.to_vec();
        }

        Ok(tx)
    }

    /// Creates a new ticket revocation transaction.
    pub fn new_ticket_revocation(
        sender_keypair: &crate::crypto::KeyPair,
        ticket_to_revoke: OutPoint,
        ticket_hash: Hash,
        recipient_address: [u8; 20],
        amount: u64,
        fee: u64,
    ) -> Result<Self, crate::error::Error> {
        let mut inputs = Vec::new();
        inputs.push(TxInput {
            outpoint: ticket_to_revoke,
            signature: vec![], // Will be signed later
            public_key: sender_keypair.public_key.clone(),
        });

        let mut outputs = Vec::new();
        outputs.push(TxOutput {
            value: amount,
            pubkey_hash: recipient_address,
            ticket_data: None,
            revocation_data: Some(TicketRevocationPayload { ticket_hash }),
            masternode_data: None,
            proposal_data: None,
            vote_data: None,
            is_instant_send: false,
        });

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs: outputs.clone(),
            lock_time: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Sign each input
        let tx_hash_for_signing = tx.hash_for_signature(); // Use hash for signature
        for input in &mut tx.inputs {
            let signature = crate::crypto::sign(sender_keypair, tx_hash_for_signing.as_bytes())?;
            input.signature = signature.0.to_vec();
        }

        // For simplicity, fee is assumed to be covered by the difference between ticket value and `amount`.
        // In a real system, the `amount` might be the full ticket value, and a separate input would cover the fee.
        // For now, we'll just ensure there's enough value to cover the `amount`.
        let _total_output_value = outputs.iter().map(|o| o.value).sum::<u64>();
        if amount + fee > amount { // Simplified check for now
             // This condition is always true if fee > 0. It's meant to be a placeholder.
        }

        Ok(tx)
    }

    /// Creates a new governance proposal transaction.
    pub fn new_governance_proposal_transaction(
        sender_keypair: &crate::crypto::KeyPair,
        utxos_to_spend: Vec<UTXO>,
        fee: u64,
        proposal_payload: GovernanceProposalPayload,
    ) -> Result<Self, crate::error::Error> {
        let mut inputs = Vec::new();
        let mut total_input_value = 0;

        for utxo in utxos_to_spend {
            total_input_value += utxo.value;
            let input = TxInput {
                outpoint: OutPoint {
                    tx_hash: utxo.tx_hash,
                    output_index: utxo.output_index,
                },
                signature: vec![], // Placeholder, will be signed later
                public_key: sender_keypair.public_key.clone(),
            };
            inputs.push(input);
        }

        if total_input_value < fee {
            return Err(crate::error::Error::TxError("Insufficient funds for proposal fee".to_string()));
        }

        let mut outputs = Vec::new();
        // The output for a governance proposal is special; it contains the proposal data.
        // The value of this output could be a small fee or zero, depending on protocol design.
        // For now, let's assume a small fee is paid.
        outputs.push(TxOutput {
            value: 0, // No value transferred for the proposal itself, just for the fee
            pubkey_hash: [0; 20], // Dummy address, or a burn address
            ticket_data: None,
            revocation_data: None,
            masternode_data: None,
            proposal_data: Some(proposal_payload),
            vote_data: None,
            is_instant_send: false,
        });

        let mut tx = Transaction {
            version: 1, // Or a new version for governance transactions
            inputs,
            outputs,
            lock_time: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Sign each input
        let tx_hash_for_signing = tx.hash_for_signature(); // Use hash for signature
        for input in &mut tx.inputs {
            let signature = crate::crypto::sign(sender_keypair, tx_hash_for_signing.as_bytes())?;
            input.signature = signature.0.to_vec();
        }

        Ok(tx)
    }

    /// Creates a new governance vote transaction.
    pub fn new_governance_vote_transaction(
        sender_keypair: &crate::crypto::KeyPair,
        utxos_to_spend: Vec<UTXO>,
        fee: u64,
        vote_payload: GovernanceVotePayload,
    ) -> Result<Self, crate::error::Error> {
        let mut inputs = Vec::new();
        let mut total_input_value = 0;

        for utxo in utxos_to_spend {
            total_input_value += utxo.value;
            let input = TxInput {
                outpoint: OutPoint {
                    tx_hash: utxo.tx_hash,
                    output_index: utxo.output_index,
                },
                signature: vec![], // Placeholder, will be signed later
                public_key: sender_keypair.public_key.clone(),
            };
            inputs.push(input);
        }

        if total_input_value < fee {
            return Err(crate::error::Error::TxError("Insufficient funds for vote fee".to_string()));
        }

        let mut outputs = Vec::new();
        outputs.push(TxOutput {
            value: 0, // No value transferred for the vote itself, just for the fee
            pubkey_hash: [0; 20], // Dummy address, or a burn address
            ticket_data: None,
            revocation_data: None,
            masternode_data: None,
            proposal_data: None,
            vote_data: Some(vote_payload),
            is_instant_send: false,
        });

        let mut tx = Transaction {
            version: 1, // Or a new version for governance transactions
            inputs,
            outputs,
            lock_time: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Sign each input
        let tx_hash_for_signing = tx.hash_for_signature(); // Use hash for signature
        for input in &mut tx.inputs {
            let signature = crate::crypto::sign(sender_keypair, tx_hash_for_signing.as_bytes())?;
            input.signature = signature.0.to_vec();
        }

        Ok(tx)
    }

    /// Extracts a VotingTicket from the transaction's outputs if it's a ticket purchase.
    pub fn extract_ticket_from_outputs(&self, tx_hash: &Hash, block_height: u64) -> Option<crate::consensus::pos::VotingTicket> {
        if let Some(output) = self.outputs.first() {
            if let Some(payload) = &output.ticket_data {
                // The ticket hash is derived from the transaction hash itself and the output index.
                // For a ticket purchase, there should be only one output for the ticket.
                let ticket_hash_data = format!("{}{}", tx_hash.to_string(), 0);
                let ticket_hash = Hash::blake3(ticket_hash_data.as_bytes());

                Some(crate::consensus::pos::VotingTicket {
                    hash: ticket_hash,
                    staker_public_key: payload.staker_public_key.clone(),
                    stake_amount: output.value,
                    creation_height: block_height,
                    signature: crate::crypto::Signature([0u8; 64]), // This signature will be for block signing, not tx signing.
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Extracts a governance proposal payload from the transaction outputs.
    pub fn extract_governance_proposal_from_outputs(&self) -> Option<GovernanceProposalPayload> {
        self.outputs.iter().find_map(|output| output.proposal_data.clone())
    }

    /// Extracts a governance vote payload from the transaction outputs.
    pub fn extract_vote_from_outputs(&self, _tx_hash: &Hash) -> Option<GovernanceVotePayload> {
        // The _tx_hash argument is kept for compatibility with the trait, but not used here
        self.outputs.iter().find_map(|output| output.vote_data.clone())
    }
}

/// A Merkle tree is a binary tree of hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleTree {
    /// The root hash of the Merkle tree.
    pub root: Hash,
}

impl MerkleTree {
    /// Creates a new Merkle tree from a list of hashes.
    pub fn from_hashes(hashes: Vec<Hash>) -> Self {
        if hashes.is_empty() {
            return Self { root: Hash::zero() };
        }
        
        let mut current_level = hashes;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for pair in current_level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                
                let mut combined = Vec::new();
                combined.extend_from_slice(left.as_bytes());
                combined.extend_from_slice(right.as_bytes());
                next_level.push(blake3::hash(&combined).into());
            }
            
            current_level = next_level;
        }
        
        Self { root: current_level[0] }
    }
}

/// Block header contains metadata about a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    /// Protocol version
    pub version: u32,
    /// Hash of the previous block
    pub prev_block_hash: Hash,
    /// Root hash of the Merkle tree of transactions
    pub merkle_root: Hash,
    /// Block creation timestamp (seconds since Unix epoch)
    pub timestamp: u64,
    /// Current target in compact format
    pub bits: u32,
    /// Nonce value used for mining
    pub nonce: u32,
    /// Hash of the voting tickets used for PoS validation
    pub ticket_hash: Hash,
    /// Cumulative work of this block and all its ancestors
    pub cumulative_work: u128,
    /// Block height (number of blocks since genesis)
    pub height: u64,
    /// Hash of cryptographic commitments from pegged sidechains.
    pub sidechain_commitment_hash: Hash,
    /// Proof-of-Stake votes for the previous block
    pub pos_votes: Vec<PoSVote>,
}

impl BlockHeader {
    /// Creates a new block header
    pub fn new(
        version: u32,
        prev_block_hash: Hash,
        merkle_root: Hash,
        timestamp: u64,
        bits: u32,
        nonce: u32,
        ticket_hash: Hash,
        cumulative_work: u128,
        height: u64,
        sidechain_commitment_hash: Hash,
        pos_votes: Vec<PoSVote>,
    ) -> Self {
        BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
            ticket_hash,
            cumulative_work,
            height,
            sidechain_commitment_hash,
            pos_votes,
        }
    }

    /// Computes the block header hash (used for mining)
    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let header_data = bincode::encode_to_vec(&self, config).expect("Failed to serialize block header");
        Hash::blake3(&header_data)
    }
}

/// A block contains a header and a list of transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Creates a new block
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }

    /// Computes the block hash (same as the header hash)
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Computes the Merkle root of the block's transactions.
    pub fn compute_merkle_root(&self) -> Hash {
        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        MerkleTree::from_hashes(tx_hashes).root
    }

    /// Returns a list of all UTXOs created by transactions in this block.
    pub fn get_utxos(&self) -> Vec<UTXO> {
        let mut utxos = Vec::new();
        for tx in &self.transactions {
            let txid = tx.hash();
            for (output_index, output) in tx.outputs.iter().enumerate() {
                utxos.push(UTXO {
                    tx_hash: txid,
                    output_index: output_index as u32,
                    value: output.value,
                    script_pubkey: output.pubkey_hash,
                });
            }
        }
        utxos
    }

    /// Creates a new genesis block.
    pub fn create_genesis_block(
        coinbase_tx: Transaction,
        _staker_keypair: &crate::crypto::KeyPair, // Renamed to _staker_keypair since it's not directly used in header signing here
        initial_difficulty_bits: u32,
    ) -> Result<Self, crate::error::Error> {
        let genesis_merkle_root = coinbase_tx.hash(); // Merkle root of the single coinbase transaction
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let genesis_header = BlockHeader::new(
            1, // Version
            Hash::zero(), // Previous block hash (genesis)
            genesis_merkle_root,
            timestamp, // Timestamp
            initial_difficulty_bits,
            0, // Nonce (for PoW in hybrid, or 0 for PoS)
            Hash::zero(), // Ticket hash (no tickets yet in genesis)
            0, // Cumulative work
            0, // Height (genesis is height 0)
            Hash::zero(), // Sidechain commitment hash (no sidechains yet)
            vec![], // No PoS votes in genesis
        );

        let genesis_block = Block::new(
            genesis_header,
            vec![coinbase_tx],
        );

        Ok(genesis_block)
    }
}

/// An unspent transaction output (UTXO).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct UTXO {
    /// The transaction ID that this output belongs to.
    pub tx_hash: Hash,
    /// The index of the output in that transaction.
    pub output_index: u32,
    /// The value of the output.
    pub value: u64,
    /// The locking script (public key hash) of the output.
    pub script_pubkey: [u8; 20],
}

/// Trait representing blockchain state needed for validation
pub trait BlockchainState {
    /// Get block header by hash
    fn get_header(&self, hash: &crate::crypto::Hash) -> Option<BlockHeader>;
    
    /// Get full block by hash
    fn get_block(&self, hash: &crate::crypto::Hash) -> Option<Block>;

    /// Get transaction by hash
    fn get_transaction(&self, txid: &crate::crypto::Hash) -> Option<Transaction>;

    /// Get a specific UTXO by its outpoint.
    fn get_utxo(&self, txid: &crate::crypto::Hash, output_index: u32) -> Option<UTXO>;

    /// Add a UTXO to the set.
    fn add_utxo(&self, utxo: UTXO) -> Result<(), crate::error::Error>;

    /// Remove a UTXO from the set (when it's spent).
    fn remove_utxo(&self, txid: &crate::crypto::Hash, output_index: u32) -> Result<(), crate::error::Error>;
    
    /// Get current chain height
    fn height(&self) -> u64;
    
    /// Check if transaction exists
    fn contains_tx(&self, txid: &crate::crypto::Hash) -> bool;
    
    /// Add a block header to the state
    fn put_header(&self, header: &BlockHeader) -> Result<(), crate::error::Error>;

    /// Add a block to the state
    fn put_block(&self, block: &Block) -> Result<(), crate::error::Error>;

    /// Add a transaction to the state
    fn put_transaction(&self, tx: &Transaction) -> Result<(), crate::error::Error>;

    /// Get active staking tickets
    fn active_tickets(&self) -> Vec<crate::consensus::pos::VotingTicket>;

    /// Get all registered masternodes
    fn masternodes(&self) -> Vec<Masternode>;
    
    /// Add an active voting ticket to the state
    fn add_active_ticket(&self, ticket: crate::consensus::pos::VotingTicket) -> Result<(), crate::error::Error>;
    
    /// Remove an active voting ticket by its hash
    fn remove_active_ticket(&self, ticket_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Add a masternode to the set.
    fn add_masternode(&self, masternode: Masternode) -> Result<(), crate::error::Error>;

    /// Update a masternode's status or other information.
    fn update_masternode(&self, masternode: Masternode) -> Result<(), crate::error::Error>;

    /// Remove a masternode from the set (e.g., on de-registration or ban).
    fn remove_masternode(&self, pro_reg_tx_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Add a PoS vote to the state
    fn add_pos_vote(&self, vote: PoSVote) -> Result<(), crate::error::Error>;

    /// Get PoS votes for a given block hash
    fn get_pos_votes(&self, block_hash: &Hash) -> Vec<PoSVote>;

    /// Update a masternode's last seen timestamp.
    fn update_masternode_last_seen(&self, pro_reg_tx_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Remove a governance proposal.
    fn remove_governance_proposal(&self, proposal_tx_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Remove a governance vote.
    fn remove_governance_vote(&self, vote_tx_hash: &Hash, proposal_id: &Hash) -> Result<(), crate::error::Error>;

    /// Store the size of a block.
    fn put_block_size(&self, height: u64, size: u64) -> Result<(), crate::error::Error>;

    /// Get block sizes within a specified height range.
    fn get_block_sizes_in_range(&self, start_height: u64, end_height: u64) -> Vec<u64>;

    /// Increment a masternode's failed PoSe challenges count.
    fn increment_masternode_pose_failures(&self, pro_reg_tx_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Deactivate a masternode (e.g., set its status to PoSeFailed or Banned).
    fn deactivate_masternode(&self, pro_reg_tx_hash: &Hash) -> Result<(), crate::error::Error>;

    /// Store a governance proposal.
    fn put_governance_proposal(&self, proposal_tx_hash: &Hash, proposal_payload: &GovernanceProposalPayload) -> Result<(), crate::error::Error>;

    /// Get a governance proposal by its transaction hash.
    fn get_governance_proposal(&self, proposal_tx_hash: &Hash) -> Option<GovernanceProposalPayload>;

    /// Get all stored governance proposals.
    fn get_all_governance_proposals(&self) -> Vec<GovernanceProposalPayload>;

    /// Store a governance vote.
    fn put_governance_vote(&self, vote_tx_hash: &Hash, vote_payload: &GovernanceVotePayload) -> Result<(), crate::error::Error>;

    /// Get all governance votes for a specific proposal.
    fn get_governance_votes_for_proposal(&self, proposal_id: &Hash) -> Vec<GovernanceVotePayload>;

    /// Update the current chain height.
    fn update_height(&self, height: u64) -> Result<(), crate::error::Error>;

    /// Get the hash of the block at a specific height.
    fn get_block_hash_at_height(&self, height: u64) -> Result<Hash, crate::error::Error>;

    /// Get the last N block headers, ordered from oldest to newest.
    fn get_last_n_headers(&self, n: u32) -> Result<Vec<BlockHeader>, crate::error::Error>;
}

/// Represents the status of a Masternode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum MasternodeStatus {
    Active,
    PoSeFailed,
    Banned,
    // Add other statuses as needed, e.g., PreEnabled, Updating
}

/// Represents a Masternode in the Rusty Coin network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct Masternode {
    /// Hash of the ProReg (Masternode Registration) transaction.
    pub pro_reg_tx_hash: Hash,
    /// Hash of the collateral UTXO that locks the funds.
    pub collateral_tx_hash: Hash,
    /// Index of the collateral output in the collateral transaction.
    pub collateral_output_index: u32,
    /// Public key of the masternode operator (for signing PoSe and other messages).
    pub public_key: PublicKey,
    /// Public key for payouts (where rewards are sent).
    pub payout_address: [u8; 20],
    /// IP address of the masternode.
    pub ip_address: String,
    /// Port of the masternode.
    pub port: u16,
    /// Timestamp of the last successful Proof-of-Service ping.
    pub last_seen: u64,
    /// Number of consecutive failed PoSe challenges.
    pub failed_pose_challenges: u32,
    /// Current status of the masternode.
    pub status: MasternodeStatus,
    /// Block height at which this masternode was registered.
    pub registration_height: u64,
}

impl Masternode {
    pub fn new(
        pro_reg_tx_hash: Hash,
        collateral_tx_hash: Hash,
        collateral_output_index: u32,
        public_key: PublicKey,
        payout_address: [u8; 20],
        ip_address: String,
        port: u16,
        registration_height: u64,
    ) -> Self {
        Self {
            pro_reg_tx_hash,
            collateral_tx_hash,
            collateral_output_index,
            public_key,
            payout_address,
            ip_address,
            port,
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), // Initial last seen
            failed_pose_challenges: 0,
            status: MasternodeStatus::Active,
            registration_height,
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let mn_data = bincode::encode_to_vec(self, config).expect("Failed to serialize masternode");
        Hash::blake3(&mn_data)
    }
}

// New struct for Proof-of-Stake votes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct PoSVote {
    pub ticket_hash: Hash,
    pub block_hash: Hash,
    pub signature: Vec<u8>,
}

impl PoSVote {
    pub fn new(ticket_hash: Hash, block_hash: Hash, signature: Vec<u8>) -> Self {
        PoSVote {
            ticket_hash,
            block_hash,
            signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct VotingTicket {
    pub hash: Hash,
    pub staker_public_key: PublicKey,
    pub stake_amount: u64,
    pub creation_height: u64,
    pub signature: Vec<u8>,
}

impl VotingTicket {
    pub fn new(
        hash: Hash,
        staker_public_key: PublicKey,
        stake_amount: u64,
        creation_height: u64,
        signature: Vec<u8>,
    ) -> Self {
        VotingTicket {
            hash,
            staker_public_key,
            stake_amount,
            creation_height,
            signature,
        }
    }
}
