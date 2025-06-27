use serde::{Deserialize, Serialize};
use bincode;
use rusty_shared_types::{
    governance, TxInput, TxOutput,
    TransactionSignature, MasternodeIdentity,
    masternode::MasternodeSlashTx
};

/// Represents the different types of transactions supported by the blockchain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Transaction {
    Standard {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        fee: u64,
        witness: Vec<Vec<u8>>,
    },
    Coinbase {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    MasternodeRegister {
        masternode_identity: MasternodeIdentity,
        signature: TransactionSignature,
        lock_time: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        witness: Vec<Vec<u8>>,
    },
    MasternodeCollateral {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        masternode_identity: MasternodeIdentity,
        collateral_amount: u64,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    GovernanceProposal(governance::GovernanceProposal),
    GovernanceVote(governance::GovernanceVote),
    /// Activation transaction for approved governance proposals
    ActivateProposal {
        version: u32,
        proposal_id: [u8; 32],
        activation_block_height: u64,
        approval_proof: governance::ApprovalProof,
        activator_signature: TransactionSignature,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
        witness: Vec<Vec<u8>>,
    },
    TicketPurchase {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        ticket_id: [u8; 32],
        locked_amount: u64,
        lock_time: u32,
        fee: u64,
        ticket_address: Vec<u8>,
        witness: Vec<Vec<u8>>,
    },
    TicketRedemption {
        version: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        ticket_id: [u8; 32],
        lock_time: u32,
        fee: u64,
        witness: Vec<Vec<u8>>,
    },
    MasternodeSlashTx(MasternodeSlashTx),
}

impl Transaction {
    /// Returns a slice of `TxInput`s for the transaction.
    ///
    /// This method provides a unified way to access the inputs regardless of the transaction type.
    pub fn get_inputs(&self) -> &[TxInput] {
        match self {
            Self::Standard { inputs, .. } => inputs,
            Self::Coinbase { inputs, .. } => inputs,
            Self::MasternodeRegister { inputs, .. } => inputs,
            Self::MasternodeCollateral { inputs, .. } => inputs,
            Self::GovernanceProposal(proposal) => proposal.inputs.as_slice(),
            Self::GovernanceVote(vote) => vote.inputs.as_slice(),
            Self::ActivateProposal { inputs, .. } => inputs,
            Self::TicketPurchase { inputs, .. } => inputs,
            Self::TicketRedemption { inputs, .. } => inputs,
            Self::MasternodeSlashTx(tx) => tx.inputs.as_slice(),
        }
    }

    /// Returns the transaction fee.
    pub fn get_fee(&self) -> u64 {
        match self {
            Self::Standard { fee, .. } => *fee,
            Self::TicketPurchase { fee, .. } => *fee,
            Self::TicketRedemption { fee, .. } => *fee,
            Self::GovernanceProposal(_) => 0, // Governance proposals have a stake, not a fee
            Self::GovernanceVote(_) => 0, // Governance votes have a small fee handled elsewhere
            Self::ActivateProposal { .. } => 0, // Activation fee handled in inputs/outputs
            Self::MasternodeSlashTx(tx) => tx.fee,
            _ => 0, // Other transaction types might not have an explicit fee field
        }
    }

    /// Returns a slice of `TxOutput`s for the transaction.
    ///
    /// This method provides a unified way to access the outputs regardless of the transaction type.
    pub fn get_outputs(&self) -> &[TxOutput] {
        match self {
            Self::Standard { outputs, .. } => outputs,
            Self::Coinbase { outputs, .. } => outputs,
            Self::MasternodeRegister { outputs, .. } => outputs,
            Self::MasternodeCollateral { outputs, .. } => outputs,
            Self::GovernanceProposal(proposal) => proposal.outputs.as_slice(),
            Self::GovernanceVote(vote) => vote.outputs.as_slice(),
            Self::ActivateProposal { outputs, .. } => outputs,
            Self::TicketPurchase { outputs, .. } => outputs,
            Self::TicketRedemption { outputs, .. } => outputs,
            Self::MasternodeSlashTx(tx) => tx.outputs.as_slice(),
        }
    }

    pub fn get_outputs_mut(&mut self) -> &mut Vec<TxOutput> {
        match self {
            Self::Standard { outputs, .. } => outputs,
            Self::Coinbase { outputs, .. } => outputs,
            Self::MasternodeRegister { outputs, .. } => outputs,
            Self::MasternodeCollateral { outputs, .. } => outputs,
            Self::GovernanceProposal(proposal) => proposal.outputs.as_mut(),
            Self::GovernanceVote(vote) => vote.outputs.as_mut(),
            Self::ActivateProposal { outputs, .. } => outputs,
            Self::TicketPurchase { outputs, .. } => outputs,
            Self::TicketRedemption { outputs, .. } => outputs,
            Self::MasternodeSlashTx(tx) => tx.outputs.as_mut(),
        }
    }

    pub fn get_lock_time(&self) -> u32 {
        match self {
            Self::Standard { lock_time, .. } => *lock_time,
            Self::Coinbase { lock_time, .. } => *lock_time,
            Self::MasternodeRegister { lock_time, .. } => *lock_time,
            Self::MasternodeCollateral { lock_time, .. } => *lock_time,
            Self::GovernanceProposal(proposal) => proposal.lock_time,
            Self::GovernanceVote(vote) => vote.lock_time,
            Self::ActivateProposal { lock_time, .. } => *lock_time,
            Self::TicketPurchase { lock_time, .. } => *lock_time,
            Self::TicketRedemption { lock_time, .. } => *lock_time,
            Self::MasternodeSlashTx(tx) => tx.lock_time,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(self)
    }

    pub fn txid(&self) -> [u8; 32] {
        use blake3::hash;
        *hash(&self.to_bytes().unwrap()).as_bytes()
    }

    pub fn is_coinbase(&self) -> bool {
        matches!(self, Transaction::Coinbase { .. })
    }

    pub fn input_count(&self) -> usize {
        self.get_inputs().len()
    }

    pub fn output_count(&self) -> usize {
        self.get_outputs().len()
    }

    pub fn get_witnesses(&self) -> &[Vec<u8>] {
        match self {
            Self::Standard { witness, .. } => witness,
            Self::Coinbase { witness, .. } => witness,
            Self::MasternodeRegister { witness, .. } => witness,
            Self::MasternodeCollateral { witness, .. } => witness,
            Self::ActivateProposal { witness, .. } => witness,
            Self::TicketPurchase { witness, .. } => witness,
            Self::TicketRedemption { witness, .. } => witness,
            _ => &[], // Other transaction types might not have an explicit witness field
        }
    }

    pub fn get_witnesses_mut(&mut self) -> &mut Vec<Vec<u8>> {
        match self {
            Self::Standard { witness, .. } => witness,
            Self::Coinbase { witness, .. } => witness,
            Self::MasternodeRegister { witness, .. } => witness,
            Self::MasternodeCollateral { witness, .. } => witness,
            Self::ActivateProposal { witness, .. } => witness,
            Self::TicketPurchase { witness, .. } => witness,
            Self::TicketRedemption { witness, .. } => witness,
            _ => panic!("Attempted to get mutable witnesses from a transaction type that does not support them"), // This should be handled more gracefully, e.g., by returning Option<&mut Vec<Vec<u8>>>
        }
    }

    pub fn set_witnesses(&mut self, witnesses: Vec<Vec<u8>>) {
        match self {
            Self::Standard { witness, .. } => *witness = witnesses,
            Self::Coinbase { witness, .. } => *witness = witnesses,
            Self::MasternodeRegister { witness, .. } => *witness = witnesses,
            Self::MasternodeCollateral { witness, .. } => *witness = witnesses,
            Self::ActivateProposal { witness, .. } => *witness = witnesses,
            Self::TicketPurchase { witness, .. } => *witness = witnesses,
            Self::TicketRedemption { witness, .. } => *witness = witnesses,
            _ => panic!("Attempted to set witnesses on a transaction type that does not support them"), // This should be handled more gracefully
        }
    }
}
