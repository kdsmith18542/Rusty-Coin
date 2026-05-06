//! Script engine interface for use by consensus and core logic.

use crate::{Transaction, TxOutput};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Script verification failed")]
    VerificationFailed,
    #[error("Script execution error: {0}")]
    ExecutionError(String),
}

pub trait ScriptEngine {
    fn verify_script(
        &mut self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        tx: &Transaction,
        input_index: usize,
        utxo_output: &TxOutput,
    ) -> Result<(), ScriptError>;
}
