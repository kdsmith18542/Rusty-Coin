//! UTXO set management for the Rusty Coin consensus engine.
//!
//! This module provides the `UtxoSet` structure responsible for managing the
//! Unspent Transaction Output (UTXO) set using RocksDB for persistent storage.

use crate::error::ConsensusError;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use rusty_shared_types::{BlockHeader, OutPoint, Ticket, TxOutput};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

pub struct UtxoSet {
    db: Arc<DB>,
    pub tickets: HashMap<[u8; 32], Ticket>,
}

impl UtxoSet {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Create column family descriptors
        let cf_opts = Options::default();
        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("utxos", cf_opts.clone()),
            ColumnFamilyDescriptor::new("tickets", cf_opts.clone()),
            ColumnFamilyDescriptor::new("block_metadata", cf_opts.clone()),
        ];

        let db = Arc::new(
            DB::open_cf_descriptors(&opts, path, cf_descriptors)
                .map_err(|e| ConsensusError::DatabaseError(e.to_string()))?,
        );

        Ok(Self {
            db,
            tickets: HashMap::new(),
        })
    }

    /// Retrieves a UTXO by its OutPoint.
    pub fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<(TxOutput, u64, bool)>, ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        let cf_utxos = self
            .db
            .cf_handle("utxos")
            .ok_or(ConsensusError::DatabaseError(
                "utxos column family not found".to_string(),
            ))?;
        let db = self.db.clone();
        db.get_cf(cf_utxos, &key)?
            .map(|data| bincode::deserialize(&data))
            .transpose()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
            .map(|opt| opt.map(|(output, height, is_coinbase)| (output, height, is_coinbase)))
    }

    /// Applies a batch of UTXO and state changes atomically.
    pub fn apply_batch(&self, batch: WriteBatch) -> Result<(), ConsensusError> {
        self.db.write(batch)?;
        Ok(())
    }

    /// Creates a WriteBatch for UTXO insertions, deletions, and state updates.
    pub fn create_batch() -> WriteBatch {
        WriteBatch::default()
    }

    /// Puts a UTXO into the batch with height and coinbase flag per UTXO spec.
    pub fn put_utxo_in_batch(
        &self,
        batch: &mut WriteBatch,
        outpoint: &OutPoint,
        output: &TxOutput,
        height: u64,
        is_coinbase: bool,
    ) -> Result<(), ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        let value = bincode::serialize(&(output, height, is_coinbase))?;
        let cf_utxos = self
            .db
            .cf_handle("utxos")
            .ok_or(ConsensusError::DatabaseError(
                "utxos column family not found".to_string(),
            ))?;
        batch.put_cf(cf_utxos, &key, &value);
        Ok(())
    }

    /// Deletes a UTXO from the batch.
    pub fn delete_utxo_in_batch(
        &self,
        batch: &mut WriteBatch,
        outpoint: &OutPoint,
    ) -> Result<(), ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        let cf_utxos = self
            .db
            .cf_handle("utxos")
            .ok_or(ConsensusError::DatabaseError(
                "utxos column family not found".to_string(),
            ))?;
        batch.delete_cf(cf_utxos, &key);
        Ok(())
    }

    /// Puts a ticket into the batch.
    pub fn put_ticket_in_batch(
        batch: &mut WriteBatch,
        cf: &ColumnFamily,
        ticket_id: &[u8; 32],
        ticket_vote: &Ticket,
    ) -> Result<(), ConsensusError> {
        let key = ticket_id;
        let value = bincode::serialize(ticket_vote)?;
        batch.put_cf(cf, key, &value);
        Ok(())
    }

    /// Deletes a ticket from the batch.
    pub fn delete_ticket_in_batch(
        batch: &mut WriteBatch,
        cf: &ColumnFamily,
        ticket_id: &[u8; 32],
    ) -> Result<(), ConsensusError> {
        let key = ticket_id;
        batch.delete_cf(cf, key);
        Ok(())
    }

    /// Retrieves a ticket by its ID.
    pub fn get_ticket(&self, ticket_id: &[u8; 32]) -> Result<Option<Ticket>, ConsensusError> {
        let cf_tickets = self
            .db
            .cf_handle("tickets")
            .ok_or(ConsensusError::DatabaseError(
                "tickets column family not found".to_string(),
            ))?;
        let db = self.db.clone();
        db.get_cf(cf_tickets, ticket_id)?
            .map(|data| bincode::deserialize(&data))
            .transpose()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    /// Puts block metadata into the batch.
    pub fn put_block_metadata_in_batch(
        batch: &mut WriteBatch,
        cf: &ColumnFamily,
        block_hash: &[u8; 32],
        header: &BlockHeader,
    ) -> Result<(), ConsensusError> {
        let key = block_hash;
        let value = bincode::serialize(header)?;
        batch.put_cf(cf, key, &value);
        Ok(())
    }
}
