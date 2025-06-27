//! UTXO set management for the Rusty Coin consensus engine.
//!
//! This module provides the `UtxoSet` structure responsible for managing the
//! Unspent Transaction Output (UTXO) set using RocksDB for persistent storage.

use rocksdb::{DB, ColumnFamily, Options, WriteBatch};
use rusty_types::transaction::{OutPoint, TxOutput};
use rusty_types::block::{BlockHeader, TicketVote};
use std::sync::Arc;
use crate::error::ConsensusError;
use tracing::{info, debug, error};

use std::collections::HashMap;
use crate::pos::Ticket;

pub struct UtxoSet {
    db: Arc<DB>,
    cf_utxos: Arc<ColumnFamily>,
    cf_tickets: Arc<ColumnFamily>,
    cf_block_metadata: Arc<ColumnFamily>,
    pub tickets: HashMap<[u8; 32], Ticket>,
}

impl UtxoSet {
    pub fn new(path: &str) -> Result<Self, ConsensusError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db = Arc::new(DB::open_cf_descriptors(
            &opts,
            path,
            vec![
                ColumnFamilyDescriptor::new("utxos", Options::default()),
                ColumnFamilyDescriptor::new("tickets", Options::default()),
                ColumnFamilyDescriptor::new("block_metadata", Options::default()),
            ],
        )?);

        let cf_utxos = Arc::new(db.cf_handle("utxos").ok_or(ConsensusError::DatabaseError("utxos column family not found".to_string()))?);
        let cf_tickets = Arc::new(db.cf_handle("tickets").ok_or(ConsensusError::DatabaseError("tickets column family not found".to_string()))?);
        let cf_block_metadata = Arc::new(db.cf_handle("block_metadata").ok_or(ConsensusError::DatabaseError("block_metadata column family not found".to_string()))?);

        info!("UTXO set initialized with RocksDB at: {}", path);

        Ok(Self {
            db,
            cf_utxos,
            cf_tickets,
            cf_block_metadata,
            tickets: HashMap::new(),
        })
    }

    /// Retrieves a UTXO by its OutPoint.
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOutput>, ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        let cf_utxos = self.cf_utxos.clone();
        let db = self.db.clone();
        db.get_cf(cf_utxos.as_ref(), &key)?
            .map(|data| bincode::deserialize(&data))
            .transpose()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
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

    /// Puts a UTXO into the batch.
    pub fn put_utxo_in_batch(batch: &mut WriteBatch, cf: &ColumnFamily, outpoint: &OutPoint, output: &TxOutput) -> Result<(), ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        let value = bincode::serialize(output)?;
        batch.put_cf(cf, &key, &value);
        Ok(())
    }

    /// Deletes a UTXO from the batch.
    pub fn delete_utxo_in_batch(batch: &mut WriteBatch, cf: &ColumnFamily, outpoint: &OutPoint) -> Result<(), ConsensusError> {
        let key = bincode::serialize(outpoint)?;
        batch.delete_cf(cf, &key);
        Ok(())
    }

    /// Puts a ticket into the batch.
    pub fn put_ticket_in_batch(batch: &mut WriteBatch, cf: &ColumnFamily, ticket_id: &[u8; 32], ticket_vote: &TicketVote) -> Result<(), ConsensusError> {
        let key = ticket_id;
        let value = bincode::serialize(ticket_vote)?;
        batch.put_cf(cf, key, &value);
        Ok(())
    }

    /// Deletes a ticket from the batch.
    pub fn delete_ticket_in_batch(batch: &mut WriteBatch, cf: &ColumnFamily, ticket_id: &[u8; 32]) -> Result<(), ConsensusError> {
        let key = ticket_id;
        batch.delete_cf(cf, key);
        Ok(())
    }

    /// Retrieves a ticket by its ID.
    pub fn get_ticket(&self, ticket_id: &[u8; 32]) -> Result<Option<TicketVote>, ConsensusError> {
        let cf_tickets = self.cf_tickets.clone();
        let db = self.db.clone();
        db.get_cf(cf_tickets.as_ref(), ticket_id)?
            .map(|data| bincode::deserialize(&data))
            .transpose()
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }

    /// Puts block metadata into the batch.
    pub fn put_block_metadata_in_batch(batch: &mut WriteBatch, cf: &ColumnFamily, block_hash: &[u8; 32], header: &BlockHeader) -> Result<(), ConsensusError> {
        let key = block_hash;
        let value = bincode::serialize(header)?;
        batch.put_cf(cf, key, &value);
        Ok(())
    }

    /// Gets a reference to the UTXOs column family.
    pub fn cf_utxos(&self) -> &ColumnFamily {
        &self.cf_utxos
    }

    /// Gets a reference to the tickets column family.
    pub fn cf_tickets(&self) -> &ColumnFamily {
        &self.cf_tickets
    }

    /// Gets a reference to the block metadata column family.
    pub fn cf_block_metadata(&self) -> &ColumnFamily {
        &self.cf_block_metadata
    }
}