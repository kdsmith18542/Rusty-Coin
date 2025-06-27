use serde::{Deserialize, Serialize};
use bincode;

/// Represents a reference to a specific transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// The transaction ID (hash) of the transaction containing the output.
    pub txid: [u8; 32],
    /// The index of the output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        bincode::serialize(self)
    }
}

impl From<[u8; 32]> for OutPoint {
    fn from(txid: [u8; 32]) -> Self {
        OutPoint {
            txid,
            vout: 0, // Default vout to 0 when converting from a raw txid
        }
    }
}

/// Represents a transaction output, specifying a value and a locking script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// The value of the output in satoshis.
    pub value: u64,
    /// The locking script (scriptPubKey) that defines the conditions for spending this output.
    pub script_pubkey: Vec<u8>,
    /// Optional memo field for arbitrary data, typically for OP_RETURN outputs.
    pub memo: Option<Vec<u8>>,
}

impl TxOutput {
    /// Creates a new `TxOutput` without a memo.
    ///
    /// # Arguments
    /// * `value` - The value of the output in satoshis
    /// * `script_pubkey` - The locking script that defines spending conditions
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        TxOutput { value, script_pubkey, memo: None }
    }

    /// Creates a new `TxOutput` with a memo field.
    ///
    /// # Arguments
    /// * `value` - The value of the output in satoshis
    /// * `script_pubkey` - The locking script that defines spending conditions
    /// * `memo` - Optional memo data for OP_RETURN outputs
    pub fn new_with_memo(value: u64, script_pubkey: Vec<u8>, memo: Option<Vec<u8>>) -> Self {
        TxOutput { value, script_pubkey, memo }
    }
}

/// Represents a transaction input, referencing a previous transaction's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    /// The `OutPoint` referencing the output being spent.
    pub previous_output: OutPoint,
    /// The script signature, providing proof of ownership.
    pub script_sig: Vec<u8>,
    /// A sequence number, typically used for replace-by-fee or relative lock-times.
    pub sequence: u32,
    /// Cryptographic witnesses for SegWit-like transactions (e.g., signatures, public keys).
    pub witness: Vec<Vec<u8>>,
}
