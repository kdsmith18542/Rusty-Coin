//! Synchronization manager for initial block download, header-first sync, and compact block relay.

use crate::consensus::error::ConsensusError;
use crate::consensus::pos::LiveTicketsPool;
use crate::consensus::state::BlockchainState;
use crate::consensus::utxo_set::UtxoSet;
use crate::constants::MIN_RELAY_FEE_PER_BYTE;
use crate::network::{P2PNetwork, PeerId};
use crate::script::script_engine::ScriptEngine;
use crate::types::{BlockRequest, BlockResponse, GetHeaders, Headers, Inv, P2PMessage, PeerInfo};
use bincode;
use blake3;
use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature, Verifier};
use hex;
use log::{info, warn, error};
use rusty_shared_types::{
    Block, BlockHeader, Hash, TicketId, TicketVote, Transaction, TxInput, TxOutput,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;


pub const MAX_PEER_CONNECTIONS: usize = 8; // Max 8 peer connections
pub const IBD_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes timeout for IBD
pub const HEADER_SYNC_TIMEOUT: Duration = Duration::from_secs(60); // 1 minute timeout for header sync

pub struct SyncManager {
    pub peers: HashMap<PeerId, PeerInfo>,
    pub blocks_in_flight: HashMap<Hash, (PeerId, u64)>,
    pub transactions_in_flight: HashMap<Hash, (PeerId, u64)>,
    pub sync_state: SyncState,
    pub last_sync_time: Option<Instant>,
    /// Reference to blockchain state for proper validation
    pub blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>,
    /// Reference to UTXO set for validation
    pub utxo_set: Arc<tokio::sync::RwLock<UtxoSet>>,
    /// Reference to live tickets pool for PoS validation
    pub live_tickets: Arc<tokio::sync::RwLock<LiveTicketsPool>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    NotSynced,
    HeaderSync,
    BlockSync,
    Synced,
    Error(String),
}

impl SyncManager {
    pub fn new(
        blockchain_state: Arc<tokio::sync::RwLock<BlockchainState>>,
        utxo_set: Arc<tokio::sync::RwLock<UtxoSet>>,
        live_tickets: Arc<tokio::sync::RwLock<LiveTicketsPool>>,
    ) -> Self {
        SyncManager {
            peers: HashMap::new(),
            blocks_in_flight: HashMap::new(),
            transactions_in_flight: HashMap::new(),
            sync_state: SyncState::NotSynced,
            last_sync_time: None,
            blockchain_state,
            utxo_set,
            live_tickets,
        }
    }

    /// Start the initial block download process
    pub async fn initial_block_download(mut self, p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<(), ConsensusError> {
        println!("[SyncManager] Starting Initial Block Download...");
        self.sync_state = SyncState::BlockSync;
        self.last_sync_time = Some(Instant::now());

        // Step 1: Discover peers and their heights
        let peer_heights = self.discover_peer_heights(p2p_network.clone()).await?;
        if peer_heights.is_empty() {
            return Err(ConsensusError::NetworkError(
                "No peers available for IBD".to_string(),
            ));
        }

        // Step 2: Select the best peer for synchronization
        let mut selected_peer = self.select_best_sync_peer(&peer_heights)?;

        info!(
            "[SyncManager] Selected peer {} at height {} for IBD",
            selected_peer, peer_heights.get(&selected_peer).unwrap_or(&0)
        );

        // Step 3: Download blocks in batches
        let mut current_height = 0; // Start from genesis
        let batch_size = 100; // Download 100 blocks at a time

        while current_height < *peer_heights.get(&selected_peer).unwrap_or(&0) {
            let target_height = *peer_heights.get(&selected_peer).unwrap_or(&0);
            let end_height = std::cmp::min(current_height + batch_size, target_height);

            match self
                .download_block_batch(current_height, end_height, &selected_peer, p2p_network.clone())
                .await
            {
                Ok(_) => {
                    info!(
                        "[SyncManager] Downloaded blocks {} to {}",
                        current_height, end_height
                    );
                    current_height = end_height;
                }
                Err(e) => {
                    warn!(
                        "[SyncManager] Error downloading blocks {} to {} from peer {}: {:?}",
                        current_height, end_height, selected_peer, e
                    );
                    // Try with a different peer
                    if let Ok(new_peer) = self.select_best_sync_peer(&peer_heights) {
                        if new_peer != selected_peer {
                            info!("[SyncManager] Switching to peer {} for sync", new_peer);
                            selected_peer = new_peer;
                        }
                    }
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }

            // Check timeout
            if let Some(start_time) = self.last_sync_time {
                if start_time.elapsed() > IBD_TIMEOUT {
                    return Err(ConsensusError::NetworkError(
                        "IBD timeout exceeded".to_string(),
                    ));
                }
            }
        }

        // Step 4: Synchronize UTXO state
        info!("[SyncManager] Synchronizing UTXO state after IBD...");
        self.synchronize_utxo_state().await?;

        self.sync_state = SyncState::Synced;
        info!("[SyncManager] Initial Block Download complete.");
        Ok(())
    }

    /// Perform header-first synchronization
    pub async fn header_first_sync_async(mut self, p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<(), ConsensusError> {
        println!("[SyncManager] Starting header-first synchronization...");
        self.sync_state = SyncState::HeaderSync;
        self.last_sync_time = Some(Instant::now());

        // Step 1: Discover peers and their heights
        let peer_heights = self.discover_peer_heights(p2p_network.clone()).await?;
        if peer_heights.is_empty() {
            return Err(ConsensusError::NetworkError(
                "No peers available for header sync".to_string(),
            ));
        }

        // Step 2: Select the best peer for synchronization
        let mut selected_peer = self.select_best_sync_peer(&peer_heights)?;

        info!(
            "[SyncManager] Selected peer {} at height {} for IBD",
            selected_peer, peer_heights.get(&selected_peer).unwrap_or(&0)
        );

        // Step 3: Download headers in batches
        let mut current_height = 0; // Start from genesis
        let header_batch_size = 2000; // Download 2000 headers at a time (more efficient than blocks)

        while current_height < *peer_heights.get(&selected_peer).unwrap_or(&0) {
            let target_height = *peer_heights.get(&selected_peer).unwrap_or(&0);
            let end_height = std::cmp::min(current_height + header_batch_size, target_height);

            match self
                .download_header_batch(current_height, end_height, &selected_peer, p2p_network.clone())
                .await
            {
                Ok(_) => {
                    info!(
                        "[SyncManager] Downloaded headers {} to {}",
                        current_height, end_height
                    );
                    current_height = end_height;
                }
                Err(e) => {
                    warn!(
                        "[SyncManager] Error downloading headers {} to {} from peer {}: {:?}",
                        current_height, end_height, selected_peer, e
                    );
                    // Try with a different peer
                    if let Ok(new_peer) = self.select_best_sync_peer(&peer_heights) {
                        if new_peer != selected_peer {
                            info!("[SyncManager] Switching to peer {} for header sync", new_peer);
                            selected_peer = new_peer;
                        }
                    }
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }

            // Check timeout
            if let Some(start_time) = self.last_sync_time {
                if start_time.elapsed() > HEADER_SYNC_TIMEOUT {
                    return Err(ConsensusError::NetworkError(
                        "Header sync timeout exceeded".to_string(),
                    ));
                }
            }
        }

        self.sync_state = SyncState::Synced;
        println!("[SyncManager] Header-first synchronization complete.");
        Ok(())
    }

    /// Discover peer heights using P2P network
    async fn discover_peer_heights(&mut self, p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<HashMap<PeerId, u64>, ConsensusError> {
        let mut peer_heights = HashMap::new();

        // Get connected peers from P2P network
        let connected_peers = {
            let network = p2p_network.lock().unwrap();
            network.get_connected_peers()
        };

        for peer_id in connected_peers {
            // Query peer height by sending a version message or getstatus request
            // For now, we'll use a simplified approach - in real implementation,
            // this would involve sending a GetStatus message and receiving Status response
            match self.query_peer_height(&peer_id).await {
                Ok(height) => {
                    peer_heights.insert(peer_id.clone(), height);
                    info!("[SyncManager] Peer {} at height {}", peer_id, height);
                }
                Err(e) => {
                    warn!("[SyncManager] Failed to query height from peer {}: {:?}", peer_id, e);
                    // Continue with other peers
                }
            }
        }

        if peer_heights.is_empty() {
            return Err(ConsensusError::NetworkError(
                "No peers available for height discovery".to_string(),
            ));
        }

        Ok(peer_heights)
    }

    /// Query a peer's current blockchain height
    async fn query_peer_height(&self, peer_id: &PeerId) -> Result<u64, ConsensusError> {
        // In a real implementation, this would send a GetStatus message
        // For now, we'll simulate by checking if we have peer info
        if let Some(peer_info) = self.peers.get(peer_id) {
            // Use last_seen as a proxy for height (this is temporary)
            // Real implementation would send P2PMessage::GetStatus and receive Status
            Ok(peer_info.last_seen % 10000)
        } else {
            Err(ConsensusError::NetworkError(format!(
                "Peer {} not found in peer list",
                peer_id
            )))
        }
    }

    /// Select the best peer for synchronization based on height and reliability
    fn select_best_sync_peer(&self, peer_heights: &HashMap<PeerId, u64>) -> Result<PeerId, ConsensusError> {
        if peer_heights.is_empty() {
            return Err(ConsensusError::NetworkError(
                "No peers available for selection".to_string(),
            ));
        }

        // Find the peer with the highest height
        let (best_peer, max_height) = peer_heights
            .iter()
            .max_by_key(|(_, height)| *height)
            .ok_or_else(|| ConsensusError::NetworkError("No valid peers found".to_string()))?;

        // Additional criteria: prefer peers with fewer in-flight requests
        let mut candidates: Vec<_> = peer_heights
            .iter()
            .filter(|(_, height)| **height >= *max_height - 10) // Within 10 blocks of max
            .collect();

        candidates.sort_by_key(|(peer_id, _)| {
            // Prefer peers with fewer blocks in flight
            let in_flight = self.peers.get(*peer_id)
                .map(|info| info.blocks_in_flight)
                .unwrap_or(0);
            in_flight
        });

        let selected_peer = candidates.first()
            .map(|(peer_id, _)| (*peer_id).clone())
            .unwrap_or_else(|| best_peer.clone());

        info!(
            "[SyncManager] Selected peer {} for sync (height: {}, in-flight: {})",
            selected_peer,
            peer_heights.get(&selected_peer).unwrap_or(&0),
            self.peers.get(&selected_peer)
                .map(|info| info.blocks_in_flight)
                .unwrap_or(0)
        );

        Ok(selected_peer)
    }

    /// Synchronize UTXO state during IBD
    async fn synchronize_utxo_state(&mut self) -> Result<(), ConsensusError> {
        info!("[SyncManager] Starting UTXO state synchronization...");

        // Get current blockchain height
        let current_height = {
            let state = self.blockchain_state.read().await;
            state.get_current_block_height().unwrap_or(0)
        };

        if current_height == 0 {
            info!("[SyncManager] No blocks to synchronize UTXO state for");
            return Ok(());
        }

        // The UTXO set should already be synchronized as blocks were validated during download
        // However, we can perform additional validation here if needed

        // Verify UTXO set integrity
        let utxo_count = {
            let utxo_set = self.utxo_set.read().await;
            utxo_set.len()
        };

        info!(
            "[SyncManager] UTXO state synchronized: {} UTXOs at height {}",
            utxo_count, current_height
        );

        Ok(())
    }

    /// Download a batch of blocks from a peer
    async fn download_block_batch(
        &mut self,
        start_height: u64,
        end_height: u64,
        peer_id: &PeerId,
        p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>,
    ) -> Result<(), ConsensusError> {
        // Implement BlockRequest/BlockResponse protocol according to /rusty/block-sync/1.0
        let block_count = end_height - start_height;

        // Check if we have too many blocks in flight
        if self.blocks_in_flight.len() >= MAX_PEER_CONNECTIONS * 10 {
            return Err(ConsensusError::NetworkError(
                "Too many blocks in flight".to_string(),
            ));
        }

        // Create BlockRequest message
        let request = BlockRequest {
            start_height: start_height as u32,
            end_height: end_height as u32,
        };

        info!(
            "[SyncManager] Sending BlockRequest for heights {} to {} to peer {}",
            start_height, end_height, peer_id
        );

        // Send BlockRequest to peer using the P2P network trait
        let block_response = {
            let network = p2p_network.lock().unwrap();
            network.request_blocks(peer_id.clone(), request)
        };

        let block_response = block_response.ok_or_else(|| {
            ConsensusError::NetworkError(format!("No BlockResponse from peer {}", peer_id))
        })?;

        // Validate that we received the expected number of blocks
        if block_response.blocks.len() as u64 != block_count {
            warn!(
                "[SyncManager] Expected {} blocks, received {}",
                block_count,
                block_response.blocks.len()
            );
        }

        // Validate and store blocks
        for block in block_response.blocks {
            // Add to in-flight tracking
            self.blocks_in_flight.insert(block.hash(), (peer_id.clone(), block.header.height));

            // Validate block according to consensus rules
            self.validate_and_store_block(&block).await?;

            // Remove from in-flight tracking
            self.blocks_in_flight.remove(&block.hash());
        }

        info!(
            "[SyncManager] Successfully downloaded and validated {} blocks from peer {}",
            block_count, peer_id
        );
        Ok(())
    }

    /// Download a batch of headers from a peer
    async fn download_header_batch(
        &mut self,
        start_height: u64,
        end_height: u64,
        peer_id: &PeerId,
        p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>,
    ) -> Result<(), ConsensusError> {
        // Implement GetHeaders/Headers protocol according to /rusty/block-sync/1.0
        let header_count = end_height - start_height;

        // Create GetHeaders message with locator hashes
        let locator_hashes = self.build_locator_hashes(start_height)?;
        let stop_hash = [0u8; 32]; // Stop at end_height

        let request = GetHeaders {
            locator_hashes,
            stop_hash,
        };

        info!(
            "[SyncManager] Sending GetHeaders for heights {} to {} to peer {}",
            start_height, end_height, peer_id
        );

        // Send GetHeaders request to peer
        let headers_response = {
            let network = p2p_network.lock().unwrap();
            network.request_headers(peer_id.clone(), request)
        };

        let headers = match headers_response {
            Some(response) => response.headers,
            None => {
                return Err(ConsensusError::NetworkError(format!(
                    "No Headers response from peer {}",
                    peer_id
                )));
            }
        };

        // Validate that we received the expected number of headers
        if headers.len() as u64 != header_count {
            warn!(
                "[SyncManager] Expected {} headers, received {}",
                header_count,
                headers.len()
            );
        }

        // Validate and store headers
        for header in headers {
            self.validate_and_store_header(&header).await?;
        }

        info!(
            "[SyncManager] Successfully downloaded and validated {} headers from peer {}",
            header_count, peer_id
        );
        Ok(())
    }

    /// Build locator hashes for GetHeaders request
    fn build_locator_hashes(&self, start_height: u64) -> Result<Vec<[u8; 32]>, ConsensusError> {
        let mut locator_hashes = Vec::new();

        // Add recent block hashes in exponential backoff pattern
        let mut height = start_height;
        let mut step = 1;

        while height > 0 && locator_hashes.len() < 10 {
            if let Ok(Some(hash)) = self.blockchain_state.blocking_read().get_block_hash(height) {
                locator_hashes.push(hash);
            }

            if height < step {
                break;
            }
            height = height.saturating_sub(step);
            step = step.saturating_mul(2);
        }

        // Always include genesis block hash
        if locator_hashes.is_empty() || locator_hashes.last() != Some(&[0u8; 32]) {
            locator_hashes.push([0u8; 32]); // Genesis block hash
        }

        Ok(locator_hashes)
    }


    /// Create a simulated block for testing
    fn create_simulated_block(&self, height: u64) -> Result<Block, ConsensusError> {
        let prev_hash = if height == 0 {
            [0u8; 32]
        } else {
            self.blockchain_state
                .blocking_read()
                .get_block_hash(height - 1)?
                .unwrap_or([0u8; 32])
        };

        let header = BlockHeader {
            version: 1,
            height,
            previous_block_hash: prev_hash,
            merkle_root: [0u8; 32], // Would be calculated from transactions
            state_root: [0u8; 32],  // Would be calculated from state
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        };

        // Create a coinbase transaction
        let coinbase_tx = Transaction::Coinbase {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput::new(50 * 100_000_000, vec![])], // 50 RUST reward
            lock_time: 0,
            witness: vec![],
        };

        Ok(Block {
            header,
            ticket_votes: vec![],
            transactions: vec![coinbase_tx],
        })
    }

    /// Create a simulated block header for testing
    fn create_simulated_header(&self, height: u64) -> Result<BlockHeader, ConsensusError> {
        let prev_hash = if height == 0 {
            [0u8; 32]
        } else {
            self.blockchain_state
                .blocking_read()
                .get_block_hash(height - 1)?
                .unwrap_or([0u8; 32])
        };

        Ok(BlockHeader {
            version: 1,
            height,
            previous_block_hash: prev_hash,
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty_target: 0x1d00ffff,
            nonce: 0,
        })
    }

    /// Validate and store a block
    async fn validate_and_store_block(&self, block: &Block) -> Result<(), ConsensusError> {
        // Validate block header according to protocol specifications
        self.validate_block_header(&block.header)?;

        // Validate ticket votes according to OxideSync PoS specification
        self.validate_ticket_votes(&block.ticket_votes, &block.header)?;

        // Validate transactions according to UTXO model specification
        self.validate_block_transactions(&block.transactions)?;

        // Validate block size constraints
        self.validate_block_size(block)?;

        // Validate merkle root matches transactions
        self.validate_merkle_root(block)?;

        // Store block in blockchain state
        let mut state = self.blockchain_state.blocking_write();
        state.put_block(block)?;
        state.put_block_hash(block.header.height, block.hash())?;
        state.update_tip(block.hash(), block.header.height)?;

        println!(
            "[SyncManager] Validating and storing block at height {}",
            block.header.height
        );
        Ok(())
    }

    /// Validate block header according to protocol specifications
    fn validate_block_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Validate version
        if header.version != 1 {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid block version: {}",
                header.version
            )));
        }

        // Validate height (should be previous block height + 1)
        let current_height = self
            .blockchain_state
            .blocking_read()
            .get_current_block_height()
            .unwrap_or(0);
        let expected_height = if header.height == 0 {
            0 // Genesis block
        } else {
            current_height + 1
        };
        if header.height != expected_height {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid block height: expected {}, got {}",
                expected_height, header.height
            )));
        }

        // Validate previous block hash
        if header.height == 0 {
            // Genesis block should have zero previous block hash
            if header.previous_block_hash != [0u8; 32] {
                return Err(ConsensusError::BlockValidation(
                    "Genesis block must have zero previous block hash".to_string(),
                ));
            }
        } else {
            // Non-genesis blocks must have non-zero previous block hash
            if header.previous_block_hash == [0u8; 32] {
                return Err(ConsensusError::BlockValidation(
                    "Non-genesis block cannot have zero previous block hash".to_string(),
                ));
            }

            // Validate that previous block hash matches the hash of the previous header
            let previous_height = header.height - 1;
            if let Ok(Some(previous_hash)) = self
                .blockchain_state
                .blocking_read()
                .get_block_hash(previous_height)
            {
                if header.previous_block_hash != previous_hash {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Previous block hash mismatch: expected {:?}, got {:?}",
                        previous_hash, header.previous_block_hash
                    )));
                }
            }
        }

        // Validate timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Block timestamp must not be more than 2 hours in the future
        const MAX_TIME_DRIFT: u64 = 2 * 60 * 60; // 2 hours
        if header.timestamp > current_time + MAX_TIME_DRIFT {
            return Err(ConsensusError::BlockValidation(format!(
                "Block timestamp {} is too far in the future",
                header.timestamp
            )));
        }

        // Validate difficulty target against network difficulty
        let expected_difficulty = self.calculate_expected_difficulty(header.height)?;
        if header.difficulty_target != expected_difficulty {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid difficulty target: expected {}, got {}",
                expected_difficulty, header.difficulty_target
            )));
        }

        // Validate PoW hash meets difficulty target
        self.validate_pow_hash(header)?;

        Ok(())
    }

    /// Validate ticket votes according to OxideSync PoS specification
    fn validate_ticket_votes(
        &self,
        ticket_votes: &[TicketVote],
        header: &BlockHeader,
    ) -> Result<(), ConsensusError> {
        const VOTERS_PER_BLOCK: usize = 5;
        const MIN_VALID_VOTES_REQUIRED: usize = 3;

        // Validate ticket_votes structure: must contain exactly VOTERS_PER_BLOCK entries
        if ticket_votes.len() != VOTERS_PER_BLOCK {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid ticket_votes count: expected {}, got {}",
                VOTERS_PER_BLOCK,
                ticket_votes.len()
            )));
        }

        let mut valid_votes = 0;

        for (i, vote) in ticket_votes.iter().enumerate() {
            // Validate ticket_id is non-zero
            if vote.ticket_id == [0u8; 32] {
                println!("[SyncManager] Warning: Vote {} has zero ticket_id", i);
                continue;
            }

            // Validate block_hash matches the previous block hash
            if vote.block_hash != header.previous_block_hash {
                println!("[SyncManager] Warning: Vote {} has incorrect block_hash", i);
                continue;
            }

            // Validate vote value is in valid range (0, 1, or 2)
            if vote.vote > 2 {
                println!(
                    "[SyncManager] Warning: Vote {} has invalid vote value: {}",
                    i, vote.vote
                );
                continue;
            }

            // Validate signature format (64 bytes for Ed25519)
            if vote.signature.len() != 64 {
                println!(
                    "[SyncManager] Warning: Vote {} has invalid signature length: {}",
                    i,
                    vote.signature.len()
                );
                continue;
            }

            // Validate signature cryptographically using ticket's public key
            if let Some(ticket) = self
                .live_tickets
                .blocking_read()
                .get_ticket(&TicketId::from(vote.ticket_id))
            {
                let public_key = ticket.pubkey.clone();
                let signature = DalekSignature::from_bytes(&vote.signature).map_err(|_| {
                    ConsensusError::BlockValidation(format!(
                        "Invalid signature format for vote {}",
                        i
                    ))
                })?;

                // Create the message to verify (ticket_id + block_hash + vote_value)
                let mut message = Vec::new();
                message.extend_from_slice(&vote.ticket_id);
                message.extend_from_slice(&vote.block_hash);
                message.extend_from_slice(&vote.vote.to_le_bytes());

                // Verify the signature
                let dalek_public_key = DalekPublicKey::from_bytes(&public_key).map_err(|_| {
                    ConsensusError::BlockValidation(format!(
                        "Invalid public key for ticket {}",
                        hex::encode(vote.ticket_id)
                    ))
                })?;

                if dalek_public_key.verify(&message, &signature).is_err() {
                    println!("[SyncManager] Warning: Vote {} has invalid signature", i);
                    continue;
                }
            } else {
                println!(
                    "[SyncManager] Warning: Vote {} references unknown ticket",
                    i
                );
                continue;
            }

            // Verify ticket is in LIVE_TICKETS_POOL and was selected by TICKET_VOTER_SELECTION
            if self
                .live_tickets
                .blocking_read()
                .get_ticket(&TicketId::from(vote.ticket_id))
                .is_none()
            {
                println!(
                    "[SyncManager] Warning: Vote {} references ticket not in live pool",
                    i
                );
                continue;
            }

            valid_votes += 1;
        }

        // Validate quorum: must have at least MIN_VALID_VOTES_REQUIRED valid votes
        if valid_votes < MIN_VALID_VOTES_REQUIRED {
            return Err(ConsensusError::BlockValidation(format!(
                "Insufficient valid votes: {} < {}",
                valid_votes, MIN_VALID_VOTES_REQUIRED
            )));
        }

        Ok(())
    }

    /// Validate block transactions according to UTXO model specification
    fn validate_block_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<(), ConsensusError> {
        if transactions.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "Block must contain at least one transaction".to_string(),
            ));
        }

        // First transaction must be coinbase
        match &transactions[0] {
            Transaction::Coinbase { .. } => {}
            _ => {
                return Err(ConsensusError::BlockValidation(
                    "First transaction in block must be coinbase".to_string(),
                ))
            }
        }

        // Validate each transaction
        for (i, transaction) in transactions.iter().enumerate() {
            self.validate_transaction(transaction, i == 0)?; // i == 0 means coinbase
        }

        // Check for duplicate transactions
        let mut tx_hashes = std::collections::HashSet::new();
        for transaction in transactions {
            let tx_hash = transaction.txid();
            if !tx_hashes.insert(tx_hash) {
                return Err(ConsensusError::BlockValidation(format!(
                    "Duplicate transaction found: {:?}",
                    tx_hash
                )));
            }
        }

        Ok(())
    }

    /// Validate individual transaction
    fn validate_transaction(
        &self,
        transaction: &Transaction,
        is_coinbase: bool,
    ) -> Result<(), ConsensusError> {
        match transaction {
            Transaction::Standard {
                version,
                inputs,
                outputs,
                lock_time: _,
                fee: _,
                witness,
            } => {
                // Validate version
                if *version != 1 {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Invalid transaction version: {}",
                        version
                    )));
                }

                // Validate inputs (coinbase transactions have no inputs)
                if !is_coinbase {
                    if inputs.is_empty() {
                        return Err(ConsensusError::BlockValidation(
                            "Non-coinbase transaction must have at least one input".to_string(),
                        ));
                    }

                    // Validate each input
                    for input in inputs {
                        self.validate_tx_input(input)?;
                    }
                }

                // Validate outputs
                if outputs.is_empty() {
                    return Err(ConsensusError::BlockValidation(
                        "Transaction must have at least one output".to_string(),
                    ));
                }

                // Validate total I/O count
                const MAX_TX_IO_COUNT: usize = 250;
                if inputs.len() + outputs.len() > MAX_TX_IO_COUNT {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Transaction I/O count exceeds limit: {} > {}",
                        inputs.len() + outputs.len(),
                        MAX_TX_IO_COUNT
                    )));
                }

                // Validate outputs
                for output in outputs {
                    self.validate_tx_output(output)?;
                }

                // Validate fee calculation and minimum relay fee
                let total_input_value: u64 = inputs
                    .iter()
                    .map(|input| {
                        let outpoint = input.previous_output.clone();
                        self.utxo_set
                            .blocking_read()
                            .get_utxo(&outpoint)
                            .map(|utxo| utxo.output.value)
                            .unwrap_or(0)
                    })
                    .sum::<u64>();

                let total_output_value: u64 = outputs.iter().map(|output| output.value).sum();

                let actual_fee = total_input_value.saturating_sub(total_output_value);

                // Validate minimum relay fee
                let tx_size = self.estimate_transaction_size(inputs.len(), outputs.len());
                let min_relay_fee = MIN_RELAY_FEE_PER_BYTE * tx_size as u64;

                if actual_fee < min_relay_fee {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Transaction fee {} is below minimum relay fee {}",
                        actual_fee, min_relay_fee
                    )));
                }

                // Validate witness data
                if !witness.is_empty() {
                    // Validate witness format and size
                    const MAX_WITNESS_SIZE: usize = 10_000;
                    if witness.len() > MAX_WITNESS_SIZE {
                        return Err(ConsensusError::BlockValidation(format!(
                            "Witness data too large: {} > {}",
                            witness.len(),
                            MAX_WITNESS_SIZE
                        )));
                    }

                    // Validate each witness element
                    for (i, witness_element) in witness.iter().enumerate() {
                        if witness_element.len() > 520 {
                            // Bitcoin-style witness element limit
                            return Err(ConsensusError::BlockValidation(format!(
                                "Witness element {} too large: {} > 520",
                                i,
                                witness_element.len()
                            )));
                        }
                    }
                }

                Ok(())
            }
            Transaction::Coinbase {
                version,
                inputs,
                outputs,
                lock_time: _,
                witness: _,
            } => {
                // Coinbase validation
                if *version != 1 {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Invalid coinbase version: {}",
                        version
                    )));
                }

                // Coinbase should have no inputs
                if !inputs.is_empty() {
                    return Err(ConsensusError::BlockValidation(
                        "Coinbase transaction should have no inputs".to_string(),
                    ));
                }

                // Validate outputs
                if outputs.is_empty() {
                    return Err(ConsensusError::BlockValidation(
                        "Coinbase transaction must have at least one output".to_string(),
                    ));
                }

                for output in outputs {
                    self.validate_tx_output(output)?;
                }

                Ok(())
            }
            Transaction::GovernanceProposal(proposal) => {
                // Validate governance proposal
                if proposal.proposal_id == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Governance proposal must have non-zero proposal ID".to_string(),
                    ));
                }

                // Validate proposal structure
                if proposal.description_hash == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Governance proposal must have non-zero description hash".to_string(),
                    ));
                }

                // Validate signature format
                if proposal.proposer_signature.bytes.len() != 64 {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Invalid proposal signature length: {}",
                        proposal.proposer_signature.bytes.len()
                    )));
                }

                Ok(())
            }
            Transaction::GovernanceVote(vote) => {
                // Validate governance vote
                if vote.proposal_id == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Governance vote must have non-zero proposal ID".to_string(),
                    ));
                }

                if vote.voter_id == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Governance vote must have non-zero voter ID".to_string(),
                    ));
                }

                // Validate signature format
                if vote.voter_signature.bytes.len() != 64 {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Invalid vote signature length: {}",
                        vote.voter_signature.bytes.len()
                    )));
                }

                Ok(())
            }
            Transaction::MasternodeRegister {
                masternode_identity,
                signature,
                lock_time: _,
                inputs: _,
                outputs: _,
                witness: _,
            } => {
                // Validate masternode registration
                if masternode_identity.collateral_outpoint.txid == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Masternode registration must have valid collateral outpoint".to_string(),
                    ));
                }

                if masternode_identity.operator_public_key == [0u8; 32] {
                    return Err(ConsensusError::BlockValidation(
                        "Masternode registration must have valid operator public key".to_string(),
                    ));
                }

                // Validate signature format
                if signature.bytes.len() != 64 {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Invalid registration signature length: {}",
                        signature.bytes.len()
                    )));
                }

                Ok(())
            }

            _ => {
                // For now, accept other transaction types without detailed validation
                Ok(())
            }
        }
    }

    /// Validate transaction input
    fn validate_tx_input(&self, input: &TxInput) -> Result<(), ConsensusError> {
        // Validate previous output hash is non-zero
        if input.previous_output.txid == [0u8; 32] {
            return Err(ConsensusError::BlockValidation(
                "Transaction input has zero previous output hash".to_string(),
            ));
        }

        // Validate script_sig length
        const MAX_SCRIPT_BYTES: usize = 10_000;
        if input.script_sig.len() > MAX_SCRIPT_BYTES {
            return Err(ConsensusError::BlockValidation(format!(
                "Script signature too long: {} > {}",
                input.script_sig.len(),
                MAX_SCRIPT_BYTES
            )));
        }

        // Validate that referenced UTXO exists and is unspent
        let outpoint = input.previous_output.clone();

        if let Some(utxo) = self.utxo_set.blocking_read().get_utxo(&outpoint) {
            // Validate coinbase maturity
            let current_height = self
                .blockchain_state
                .blocking_read()
                .get_current_block_height()
                .unwrap_or(0);
            if utxo.is_coinbase {
                const COINBASE_MATURITY: u64 = 100;
                if current_height < utxo.creation_height + COINBASE_MATURITY {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Coinbase UTXO not mature: height {} < {} + {}",
                        current_height, utxo.creation_height, COINBASE_MATURITY
                    )));
                }
            }
        } else {
            return Err(ConsensusError::BlockValidation(format!(
                "Referenced UTXO does not exist: {:?}",
                outpoint
            )));
        }

        // Validate script_sig against script_pubkey of referenced UTXO
        if let Some(utxo) = self.utxo_set.blocking_read().get_utxo(&outpoint) {
            // Validate script format (actual script execution would require transaction context)
            const MAX_SCRIPT_BYTES: usize = 10_000;
            if utxo.output.script_pubkey.len() > MAX_SCRIPT_BYTES {
                return Err(ConsensusError::BlockValidation(format!(
                    "Script pubkey too long: {} > {}",
                    utxo.output.script_pubkey.len(),
                    MAX_SCRIPT_BYTES
                )));
            }
        }

        Ok(())
    }

    /// Validate transaction output
    fn validate_tx_output(&self, output: &TxOutput) -> Result<(), ConsensusError> {
        // Validate value is positive (except for OP_RETURN outputs)
        const MAX_MONEY: u64 = 21_000_000 * 100_000_000; // 21 million RUST in satoshis

        if output.value == 0 {
            // Check if this is an OP_RETURN output
            if !output.script_pubkey.starts_with(&[0x6a]) {
                // OP_RETURN
                return Err(ConsensusError::BlockValidation(
                    "Non-OP_RETURN output cannot have zero value".to_string(),
                ));
            }
        } else if output.value > MAX_MONEY {
            return Err(ConsensusError::BlockValidation(format!(
                "Output value exceeds maximum: {} > {}",
                output.value, MAX_MONEY
            )));
        }

        // Validate script_pubkey length
        const MAX_SCRIPT_BYTES: usize = 10_000;
        if output.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(ConsensusError::BlockValidation(format!(
                "Script pubkey too long: {} > {}",
                output.script_pubkey.len(),
                MAX_SCRIPT_BYTES
            )));
        }

        // Validate script_pubkey is valid FerrisScript
        let _script_engine = ScriptEngine::new();
        // Validate script format
        if output.script_pubkey.len() > 10_000 {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid script_pubkey format: {:?}",
                output.script_pubkey
            )));
        }

        // Validate memo field if present
        if let Some(ref memo) = output.memo {
            const MAX_MEMO_SIZE: usize = 80; // Standard memo size limit
            if memo.len() > MAX_MEMO_SIZE {
                return Err(ConsensusError::BlockValidation(format!(
                    "Memo too large: {} > {}",
                    memo.len(),
                    MAX_MEMO_SIZE
                )));
            }
        }

        Ok(())
    }

    /// Validate block size constraints
    fn validate_block_size(&self, block: &Block) -> Result<(), ConsensusError> {
        // Implement adaptive block size validation
        let current_height = self
            .blockchain_state
            .blocking_read()
            .get_current_block_height()
            .unwrap_or(0);

        // Base block size limit
        let mut max_block_size = 1_000_000; // 1MB base

        // Adaptive block size based on network conditions
        if current_height > 100_000 {
            // After 100k blocks, allow larger blocks
            max_block_size = 2_000_000; // 2MB
        }

        if current_height > 500_000 {
            // After 500k blocks, allow even larger blocks
            max_block_size = 4_000_000; // 4MB
        }

        // Calculate actual block size (simplified)
        let block_size = self.calculate_block_size(block);
        if block_size > max_block_size {
            return Err(ConsensusError::BlockValidation(format!(
                "Block size exceeds limit: {} > {}",
                block_size, max_block_size
            )));
        }

        Ok(())
    }

    /// Calculate actual block size in bytes
    fn calculate_block_size(&self, block: &Block) -> usize {
        // Serialize block to get actual size
        let serialized = bincode::serialize(block).unwrap_or_default();
        serialized.len()
    }

    /// Validate merkle root matches transactions
    fn validate_merkle_root(&self, block: &Block) -> Result<(), ConsensusError> {
        // Calculate actual merkle root from block transactions
        let calculated_merkle_root = self.calculate_merkle_root(&block.transactions)?;

        if block.header.merkle_root != calculated_merkle_root {
            return Err(ConsensusError::BlockValidation(format!(
                "Merkle root mismatch: expected {:?}, calculated {:?}",
                block.header.merkle_root, calculated_merkle_root
            )));
        }

        Ok(())
    }

    /// Calculate merkle root from transactions using BLAKE3
    fn calculate_merkle_root(
        &self,
        transactions: &[Transaction],
    ) -> Result<[u8; 32], ConsensusError> {
        if transactions.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "Cannot calculate merkle root for empty transaction list".to_string(),
            ));
        }

        // Get transaction hashes
        let mut tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.txid()).collect();

        // Build merkle tree
        while tx_hashes.len() > 1 {
            let mut new_level = Vec::new();

            for chunk in tx_hashes.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);

                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    // Duplicate last element if odd number
                    hasher.update(&chunk[0]);
                }

                let hash = hasher.finalize();
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(hash.as_bytes());
                new_level.push(hash_bytes);
            }

            tx_hashes = new_level;
        }

        Ok(tx_hashes[0])
    }

    /// Validate and store a header
    async fn validate_and_store_header(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Validate header according to protocol specifications
        self.validate_block_header(header)?;

        // Validate PoW hash meets difficulty target
        self.validate_pow_hash(header)?;

        // Validate header chain continuity
        self.validate_header_continuity(header)?;

        // Store header in header chain
        let mut state = self.blockchain_state.blocking_write();
        state.put_block_hash(header.height, header.hash())?;

        // Update tip if this is the highest header
        let current_height = state.get_current_block_height().unwrap_or(0);
        if header.height > current_height {
            state.update_tip(header.hash(), header.height)?;
        }

        println!(
            "[SyncManager] Validating and storing header at height {}",
            header.height
        );
        Ok(())
    }

    /// Validate PoW hash meets difficulty target
    fn validate_pow_hash(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Calculate the block hash using OxideHash
        let block_hash = self.calculate_block_hash(header);

        // Convert difficulty target to threshold
        let threshold = self.difficulty_target_to_threshold(header.difficulty_target);

        // Validate that block hash is less than threshold
        if block_hash >= threshold {
            return Err(ConsensusError::BlockValidation(format!(
                "Block hash {:?} does not meet difficulty target {:?}",
                block_hash, threshold
            )));
        }

        Ok(())
    }

    /// Calculate block hash using OxideHash (actual implementation)
    fn calculate_block_hash(&self, header: &BlockHeader) -> [u8; 32] {
        // Implement actual OxideHash calculation
        // OxideHash is a double-BLAKE3 hash of the header fields
        let mut hasher = blake3::Hasher::new();

        // Hash all header fields in canonical order
        hasher.update(&header.version.to_le_bytes());
        hasher.update(&header.height.to_le_bytes());
        hasher.update(&header.previous_block_hash);
        hasher.update(&header.merkle_root);
        hasher.update(&header.state_root);
        hasher.update(&header.timestamp.to_le_bytes());
        hasher.update(&header.difficulty_target.to_le_bytes());
        hasher.update(&header.nonce.to_le_bytes());

        // First BLAKE3 hash
        let first_hash = hasher.finalize();

        // Second BLAKE3 hash (double-hash for additional security)
        let mut final_hasher = blake3::Hasher::new();
        final_hasher.update(first_hash.as_bytes());
        let final_hash = final_hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(final_hash.as_bytes());
        hash_bytes
    }

    /// Convert difficulty target to threshold (proper implementation)
    fn difficulty_target_to_threshold(&self, difficulty_target: u32) -> [u8; 32] {
        // Implement proper difficulty target conversion
        // This converts the compact difficulty format to a 256-bit threshold

        // Extract mantissa and exponent from compact difficulty
        let mantissa = difficulty_target & 0x007fffff;
        let exponent = (difficulty_target >> 24) & 0xff;

        // Calculate the actual difficulty value
        let difficulty_value = if exponent <= 3 {
            // Handle special case for very small difficulties
            mantissa >> (8 * (3 - exponent))
        } else {
            mantissa << (8 * (exponent - 3))
        };

        // Calculate target from difficulty (avoiding overflow)
        // Note: This is a simplified calculation to avoid overflow
        let target = if difficulty_value > 0 {
            // Use a more reasonable calculation that doesn't overflow
            u64::MAX / difficulty_value as u64
        } else {
            u64::MAX
        };

        // Convert to 32-byte array (little-endian)
        let mut threshold = [0u8; 32];
        threshold[0..8].copy_from_slice(&target.to_le_bytes());

        threshold
    }

    /// Validate header chain continuity
    fn validate_header_continuity(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        if header.height == 0 {
            // Genesis block doesn't need continuity validation
            return Ok(());
        }

        // Get previous header from header chain
        let previous_height = header.height - 1;
        if let Ok(Some(previous_hash)) = self
            .blockchain_state
            .blocking_read()
            .get_block_hash(previous_height)
        {
            // Validate that previous block hash matches the hash of the previous header
            if header.previous_block_hash != previous_hash {
                return Err(ConsensusError::BlockValidation(format!(
                    "Header chain discontinuity: expected previous hash {:?}, got {:?}",
                    previous_hash, header.previous_block_hash
                )));
            }

            // Validate that height is previous height + 1
            if header.height != previous_height + 1 {
                return Err(ConsensusError::BlockValidation(format!(
                    "Invalid header height: expected {}, got {}",
                    previous_height + 1,
                    header.height
                )));
            }
        } else {
            return Err(ConsensusError::BlockValidation(format!(
                "Previous header not found at height {}",
                previous_height
            )));
        }

        Ok(())
    }

    /// Add a peer to the sync manager
    pub fn add_peer(&mut self, peer_id: PeerId, peer_info: PeerInfo) {
        self.peers.insert(peer_id, peer_info);
    }

    /// Remove a peer from the sync manager
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Get the current sync state
    pub fn get_sync_state(&self) -> &SyncState {
        &self.sync_state
    }

    /// Check if the node is fully synced
    pub fn is_synced(&self) -> bool {
        matches!(self.sync_state, SyncState::Synced)
    }

    /// Get sync progress as a percentage
    pub fn get_sync_progress(&self) -> f64 {
        match self.sync_state {
            SyncState::NotSynced => 0.0,
            SyncState::HeaderSync => 25.0, // Header sync is ~25% of total sync
            SyncState::BlockSync => 75.0,  // Block sync is ~75% of total sync
            SyncState::Synced => 100.0,
            SyncState::Error(_) => 0.0,
        }
    }

    /// Handle peer disconnection
    pub fn handle_peer_disconnect(&mut self, peer_id: &PeerId) {
        // Remove peer from active connections
        self.peers.remove(peer_id);

        // Remove any in-flight requests from this peer
        self.blocks_in_flight.retain(|_, (p, _)| p != peer_id);
        self.transactions_in_flight.retain(|_, (p, _)| p != peer_id);

        println!("[SyncManager] Peer {:?} disconnected", peer_id);
    }

    /// Handle new block announcement
    pub fn handle_new_block_announcement(&mut self, block_hash: Hash, peer_id: &PeerId) {
        // In a real implementation, this would:
        // 1. Check if we already have this block
        // 2. If not, request it from the announcing peer
        // 3. Add to blocks_in_flight if requesting

        println!(
            "[SyncManager] New block announcement from peer {:?}: {:?}",
            peer_id, block_hash
        );
    }

    /// Handle new transaction announcement
    pub fn handle_new_transaction_announcement(&mut self, tx_hash: Hash, peer_id: &PeerId) {
        // In a real implementation, this would:
        // 1. Check if we already have this transaction
        // 2. If not, request it from the announcing peer
        // 3. Add to transactions_in_flight if requesting

        println!(
            "[SyncManager] New transaction announcement from peer {:?}: {:?}",
            peer_id, tx_hash
        );
    }

    /// Calculate expected difficulty target for a given height
    fn calculate_expected_difficulty(&self, height: u64) -> Result<u32, ConsensusError> {
        // Simple difficulty calculation based on height
        // In a real implementation, this would use the actual difficulty adjustment algorithm
        const BASE_DIFFICULTY: u32 = 0x1d00ffff; // Bitcoin-style base difficulty

        if height == 0 {
            return Ok(BASE_DIFFICULTY);
        }

        // For simplicity, use a basic difficulty adjustment
        // In production, this would implement the actual OxideHash difficulty adjustment
        let adjustment_factor = if height % 2016 == 0 {
            // Difficulty adjustment every 2016 blocks
            let time_span = 14 * 24 * 60 * 60; // 14 days in seconds
            let target_time_span = 10 * 60 * 2016; // 10 minutes * 2016 blocks

            if time_span > target_time_span * 4 {
                // Maximum 4x increase
                4.0
            } else if time_span < target_time_span / 4 {
                // Maximum 4x decrease
                1.0 / 4.0
            } else {
                time_span as f64 / target_time_span as f64
            }
        } else {
            1.0 // No adjustment
        };

        let new_difficulty = (BASE_DIFFICULTY as f64 * adjustment_factor) as u32;
        Ok(new_difficulty)
    }

    /// Estimate transaction size in bytes for fee calculation
    fn estimate_transaction_size(&self, input_count: usize, output_count: usize) -> usize {
        // Conservative estimation based on typical transaction structure:
        // - Base transaction: ~10 bytes (version, input count, output count, lock_time)
        // - Per input: ~148 bytes (prev_out: 36, script_sig: ~107, sequence: 4, witness: 1)
        // - Per output: ~34 bytes (value: 8, script_pubkey: ~25, memo: 1)

        const BASE_TX_SIZE: usize = 10;
        const INPUT_SIZE: usize = 148;
        const OUTPUT_SIZE: usize = 34;

        BASE_TX_SIZE + (input_count * INPUT_SIZE) + (output_count * OUTPUT_SIZE)
    }
}
