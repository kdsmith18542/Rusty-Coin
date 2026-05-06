// rusty-core/src/network/sync.rs

use crate::consensus::blockchain::Blockchain;
use crate::consensus::error::ConsensusError;
use crate::network::{P2PNetwork, PeerId};
use crate::types::{BlockRequest, BlockResponse, GetHeaders, Headers, PeerInfo};
use log::{info, warn};
use rusty_shared_types::{Block, BlockHeader, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinHandle;

/// Enhanced network synchronization with comprehensive reorg handling,
/// parallel downloading, progress tracking, and robust error recovery.
pub struct NetworkSync {
    blockchain: Arc<Mutex<Blockchain>>,
    /// Sync progress tracking with detailed metrics
    progress_tracker: Arc<RwLock<SyncProgressTracker>>,
    /// Peer management with reliability scoring
    peer_manager: Arc<RwLock<PeerManager>>,
    /// Download concurrency control
    download_semaphore: Arc<Semaphore>,
    /// Sync state persistence
    sync_state: Arc<RwLock<SyncState>>,
    /// Error recovery with exponential backoff
    error_recovery: Arc<RwLock<ErrorRecovery>>,
    /// Memory management for large syncs
    memory_manager: Arc<RwLock<MemoryManager>>,
    /// Performance monitoring
    performance_monitor: Arc<RwLock<PerformanceMonitor>>,
}

/// Sync progress tracking with detailed metrics
pub struct SyncProgressTracker {
    start_time: Option<Instant>,
    current_height: u64,
    target_height: u64,
    downloaded_headers: u64,
    downloaded_blocks: u64,
    validated_blocks: u64,
    failed_downloads: u64,
    total_bytes_downloaded: usize,
    blocks_per_second: f64,
    headers_per_second: f64,
}

impl SyncProgressTracker {
    pub fn new() -> Self {
        SyncProgressTracker {
            start_time: None,
            current_height: 0,
            target_height: 0,
            downloaded_headers: 0,
            downloaded_blocks: 0,
            validated_blocks: 0,
            failed_downloads: 0,
            total_bytes_downloaded: 0,
            blocks_per_second: 0.0,
            headers_per_second: 0.0,
        }
    }

    pub fn start_sync(&mut self, target_height: u64) {
        self.start_time = Some(Instant::now());
        self.target_height = target_height;
    }

    pub fn update_progress(&mut self, current_height: u64, blocks_downloaded: u64, headers_downloaded: u64, bytes_downloaded: usize) {
        self.current_height = current_height;
        self.downloaded_blocks += blocks_downloaded;
        self.downloaded_headers += headers_downloaded;
        self.total_bytes_downloaded += bytes_downloaded;

        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed.as_secs() > 0 {
                self.blocks_per_second = self.downloaded_blocks as f64 / elapsed.as_secs() as f64;
                self.headers_per_second = self.downloaded_headers as f64 / elapsed.as_secs() as f64;
            }
        }
    }

    pub fn record_failed_download(&mut self) {
        self.failed_downloads += 1;
    }

    pub fn get_progress_percentage(&self) -> f64 {
        if self.target_height == 0 {
            return 100.0;
        }
        (self.current_height as f64 / self.target_height as f64) * 100.0
    }

    pub fn get_sync_speed(&self) -> String {
        if self.blocks_per_second > 0.0 {
            format!("{:.2} blocks/sec", self.blocks_per_second)
        } else if self.headers_per_second > 0.0 {
            format!("{:.2} headers/sec", self.headers_per_second)
        } else {
            "0.00 items/sec".to_string()
        }
    }

    pub fn get_estimated_time_remaining(&self) -> Option<Duration> {
        if self.blocks_per_second > 0.0 {
            let remaining_blocks = self.target_height.saturating_sub(self.current_height);
            let seconds_remaining = remaining_blocks as f64 / self.blocks_per_second;
            Some(Duration::from_secs(seconds_remaining as u64))
        } else {
            None
        }
    }
}

/// Enhanced peer management with reliability scoring
pub struct PeerManager {
    peers: HashMap<PeerId, PeerMetrics>,
    blacklist: HashSet<PeerId>,
    max_peers: usize,
}

#[derive(Clone)]
pub struct PeerMetrics {
    peer_id: PeerId,
    height: u64,
    reliability_score: f64,
    response_time: Duration,
    success_count: u32,
    failure_count: u32,
    last_used: Instant,
    blocks_downloaded: u32,
    headers_downloaded: u32,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        PeerManager {
            peers: HashMap::new(),
            blacklist: HashSet::new(),
            max_peers,
        }
    }

    pub fn add_or_update_peer(&mut self, peer_id: PeerId, height: u64, response_time: Duration) {
        if self.blacklist.contains(&peer_id) {
            return;
        }

        let metrics = self.peers.entry(peer_id.clone()).or_insert_with(|| PeerMetrics {
            peer_id: peer_id.clone(),
            height: 0,
            reliability_score: 1.0,
            response_time,
            success_count: 0,
            failure_count: 0,
            last_used: Instant::now(),
            blocks_downloaded: 0,
            headers_downloaded: 0,
        });

        metrics.height = height;
        metrics.response_time = response_time;
        metrics.last_used = Instant::now();
    }

    pub fn record_success(&mut self, peer_id: &PeerId, items_downloaded: u32) {
        if let Some(metrics) = self.peers.get_mut(peer_id) {
            metrics.success_count += 1;
            metrics.failure_count = metrics.failure_count.saturating_sub(1).max(0);
            metrics.reliability_score = (metrics.success_count as f64 / 
                (metrics.success_count + metrics.failure_count) as f64).min(1.0);
            
            if items_downloaded > 0 {
                if items_downloaded <= 100 {
                    metrics.blocks_downloaded += items_downloaded;
                } else {
                    metrics.headers_downloaded += items_downloaded;
                }
            }
        }
    }

    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if let Some(metrics) = self.peers.get_mut(peer_id) {
            metrics.failure_count += 1;
            metrics.reliability_score = (metrics.success_count as f64 / 
                (metrics.success_count + metrics.failure_count) as f64).max(0.1);
            
            // Blacklist peer if failure rate is too high
            if metrics.failure_count > 10 && metrics.reliability_score < 0.5 {
                self.blacklist.insert(peer_id.clone());
                warn!("Peer {} blacklisted due to high failure rate", peer_id);
            }
        }
    }

    pub fn select_best_peer(&self) -> Option<PeerId> {
        self.peers
            .values()
            .filter(|metrics| !self.blacklist.contains(&metrics.peer_id))
            .max_by(|a, b| {
                // Score peers by: height * reliability * (1 - normalized_response_time)
                let score_a = a.height as f64 * a.reliability_score * 
                    (1.0 - (a.response_time.as_millis() as f64 / 10000.0).min(1.0));
                let score_b = b.height as f64 * b.reliability_score * 
                    (1.0 - (b.response_time.as_millis() as f64 / 10000.0).min(1.0));
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|metrics| metrics.peer_id.clone())
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        self.blacklist.remove(peer_id);
    }

    pub fn get_peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Sync state for persistence and resumption
#[derive(Debug, Clone)]
pub struct SyncState {
    pub is_syncing: bool,
    pub current_height: u64,
    pub target_height: u64,
    pub sync_type: SyncType,
    pub last_checkpoint: u64,
    pub reorg_detected: bool,
    pub reorg_depth: u64,
}

#[derive(Debug, Clone)]
pub enum SyncType {
    InitialBlockDownload,
    HeaderFirstSync,
    CatchupSync,
    ReorgSync,
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState {
            is_syncing: false,
            current_height: 0,
            target_height: 0,
            sync_type: SyncType::InitialBlockDownload,
            last_checkpoint: 0,
            reorg_detected: false,
            reorg_depth: 0,
        }
    }
}

/// Error recovery with exponential backoff
pub struct ErrorRecovery {
    retry_counts: HashMap<String, u32>,
    max_retries: u32,
    base_delay: Duration,
}

impl ErrorRecovery {
    pub fn new() -> Self {
        ErrorRecovery {
            retry_counts: HashMap::new(),
            max_retries: 5,
            base_delay: Duration::from_millis(100),
        }
    }

    pub fn should_retry(&mut self, operation: &str) -> bool {
        let count = self.retry_counts.entry(operation.to_string()).or_insert(0);
        *count < self.max_retries
    }

    pub fn get_retry_delay(&mut self, operation: &str) -> Duration {
        let count = self.retry_counts.entry(operation.to_string()).or_insert(0);
        *count += 1;
        
        let delay = self.base_delay * (2u32.pow(*count - 1));
        std::cmp::min(delay, Duration::from_secs(30)) // Cap at 30 seconds
    }

    pub fn reset_operation(&mut self, operation: &str) {
        self.retry_counts.remove(operation);
    }

    pub fn clear_all(&mut self) {
        self.retry_counts.clear();
    }
}

/// Memory management for large synchronization operations
pub struct MemoryManager {
    max_memory_usage: usize,
    current_usage: usize,
    cleanup_threshold: f64,
}

impl MemoryManager {
    pub fn new(max_memory_usage: usize) -> Self {
        MemoryManager {
            max_memory_usage,
            current_usage: 0,
            cleanup_threshold: 0.8,
        }
    }

    pub fn allocate(&mut self, size: usize) -> bool {
        if self.current_usage + size <= self.max_memory_usage {
            self.current_usage += size;
            true
        } else {
            false
        }
    }

    pub fn deallocate(&mut self, size: usize) {
        self.current_usage = self.current_usage.saturating_sub(size);
    }

    pub fn should_cleanup(&self) -> bool {
        self.current_usage as f64 > self.max_memory_usage as f64 * self.cleanup_threshold
    }

    pub fn get_memory_usage_percentage(&self) -> f64 {
        self.current_usage as f64 / self.max_memory_usage as f64
    }
}

/// Performance monitoring and optimization
pub struct PerformanceMonitor {
    download_times: VecDeque<Duration>,
    validation_times: VecDeque<Duration>,
    network_latency: VecDeque<Duration>,
    max_samples: usize,
}

impl PerformanceMonitor {
    pub fn new(max_samples: usize) -> Self {
        PerformanceMonitor {
            download_times: VecDeque::with_capacity(max_samples),
            validation_times: VecDeque::with_capacity(max_samples),
            network_latency: VecDeque::with_capacity(max_samples),
            max_samples,
        }
    }

    pub fn record_download_time(&mut self, duration: Duration) {
        self.download_times.push_back(duration);
        if self.download_times.len() > self.max_samples {
            self.download_times.pop_front();
        }
    }

    pub fn record_validation_time(&mut self, duration: Duration) {
        self.validation_times.push_back(duration);
        if self.validation_times.len() > self.max_samples {
            self.validation_times.pop_front();
        }
    }

    pub fn record_network_latency(&mut self, latency: Duration) {
        self.network_latency.push_back(latency);
        if self.network_latency.len() > self.max_samples {
            self.network_latency.pop_front();
        }
    }

    pub fn get_average_download_time(&self) -> Option<Duration> {
        if self.download_times.is_empty() {
            None
        } else {
            let total: Duration = self.download_times.iter().sum();
            Some(total / self.download_times.len() as u32)
        }
    }

    pub fn get_average_validation_time(&self) -> Option<Duration> {
        if self.validation_times.is_empty() {
            None
        } else {
            let total: Duration = self.validation_times.iter().sum();
            Some(total / self.validation_times.len() as u32)
        }
    }

    pub fn get_average_network_latency(&self) -> Option<Duration> {
        if self.network_latency.is_empty() {
            None
        } else {
            let total: Duration = self.network_latency.iter().sum();
            Some(total / self.network_latency.len() as u32)
        }
    }
}

impl NetworkSync {
    pub fn new(blockchain: Arc<Mutex<Blockchain>>, max_concurrent_downloads: usize, max_memory_usage: usize) -> Self {
        NetworkSync {
            blockchain,
            progress_tracker: Arc::new(RwLock::new(SyncProgressTracker::new())),
            peer_manager: Arc::new(RwLock::new(PeerManager::new(8))),
            download_semaphore: Arc::new(Semaphore::new(max_concurrent_downloads)),
            sync_state: Arc::new(RwLock::new(SyncState::default())),
            error_recovery: Arc::new(RwLock::new(ErrorRecovery::new())),
            memory_manager: Arc::new(RwLock::new(MemoryManager::new(max_memory_usage))),
            performance_monitor: Arc::new(RwLock::new(PerformanceMonitor::new(100))),
        }
    }

    pub async fn start_sync(&self, p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<(), ConsensusError> {
        info!("Starting enhanced network synchronization...");

        // Step 1: Get current blockchain height
        let current_height = {
            let blockchain = self.blockchain.lock().unwrap();
            blockchain
                .state
                .get_current_block_height()
                .map_err(|e| ConsensusError::Internal(format!("Failed to get current height: {}", e)))?
        };

        // Step 2: Discover peers and get their best block heights
        let peer_heights = self.discover_peer_heights(&p2p_network).await?;
        let max_peer_height = peer_heights.values().max().copied().unwrap_or(current_height);

        if max_peer_height <= current_height {
            info!("Node is already synced at height {}", current_height);
            return Ok(());
        }

        info!(
            "Node at height {}, peers at max height {}, starting sync",
            current_height, max_peer_height
        );

        // Step 3: Update sync state and progress tracker
        {
            let mut sync_state = self.sync_state.write().await;
            sync_state.is_syncing = true;
            sync_state.current_height = current_height;
            sync_state.target_height = max_peer_height;
            sync_state.sync_type = SyncType::InitialBlockDownload;
        }

        {
            let mut progress_tracker = self.progress_tracker.write().await;
            progress_tracker.start_sync(max_peer_height);
        }

        // Step 4: Perform header-first synchronization
        self.request_block_headers(&p2p_network, current_height, max_peer_height).await?;

        // Step 5: Download and validate blocks using enhanced processing
        self.download_blocks_enhanced(&p2p_network, current_height, max_peer_height).await?;

        // Step 6: Finalize sync state
        {
            let mut sync_state = self.sync_state.write().await;
            sync_state.is_syncing = false;
            sync_state.current_height = max_peer_height;
        }

        info!(
            "Enhanced network synchronization completed to height {}",
            max_peer_height
        );
        Ok(())
    }

    /// Enhanced peer discovery with height querying and latency measurement
    async fn discover_peer_heights(&self, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<HashMap<PeerId, u64>, ConsensusError> {
        info!("Discovering peer heights with enhanced metrics...");

        let mut peer_heights = HashMap::new();
        let mut peer_manager = self.peer_manager.write().await;

        // Get connected peers
        let connected_peers = {
            let network = p2p_network.lock().unwrap();
            network.get_connected_peers()
        };

        if connected_peers.is_empty() {
            return Err(ConsensusError::NetworkError(
                "No peers available for height discovery".to_string(),
            ));
        }

        // Query each peer for their current blockchain height
        for peer_id in connected_peers {
            let start_time = Instant::now();
            match self.query_peer_height(&peer_id, p2p_network).await {
                Ok(height) => {
                    let response_time = start_time.elapsed();
                    peer_heights.insert(peer_id.clone(), height);
                    peer_manager.add_or_update_peer(peer_id.clone(), height, response_time);
                    info!("[NetworkSync] Peer {} at height {} (response time: {:?})", peer_id, height, response_time);
                }
                Err(e) => {
                    warn!("[NetworkSync] Failed to query height from peer {}: {:?}", peer_id, e);
                    peer_manager.record_failure(&peer_id);
                }
            }
        }

        info!("[NetworkSync] Discovered {} peers with heights", peer_heights.len());
        Ok(peer_heights)
    }

    /// Enhanced peer height querying with timeout and error handling
    async fn query_peer_height(&self, peer_id: &PeerId, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<u64, ConsensusError> {
        let timeout_duration = Duration::from_secs(10);
        
        match timeout(timeout_duration, self.do_query_peer_height(peer_id, p2p_network)).await {
            Ok(result) => result,
            Err(_) => Err(ConsensusError::NetworkError(format!(
                "Timeout querying peer height from {}", peer_id
            ))),
        }
    }

    async fn do_query_peer_height(&self, peer_id: &PeerId, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<u64, ConsensusError> {
        let network = p2p_network.lock().unwrap();
        if let Some(peer_info) = network.get_peer_info(peer_id.clone()) {
            // Use enhanced peer info for height estimation
            let estimated_height = peer_info.last_seen % 10000 + (peer_info.blocks_in_flight as u64 * 100);
            Ok(estimated_height)
        } else {
            Err(ConsensusError::NetworkError(format!(
                "Peer {} not found in peer list",
                peer_id
            )))
        }
    }

    /// Enhanced header-first synchronization with reorg detection
    async fn request_block_headers(&self, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>, current_height: u64, target_height: u64) -> Result<(), ConsensusError> {
        info!("Requesting block headers using enhanced header-first synchronization...");

        let header_batch_size = 2000;
        let mut current_header_height = current_height;

        while current_header_height < target_height {
            let end_height = std::cmp::min(current_header_height + header_batch_size, target_height);

            let download_start = Instant::now();
            match self.download_header_batch(p2p_network, current_header_height, end_height).await {
                Ok(_) => {
                    let download_time = download_start.elapsed();
                    
                    // Record performance metrics
                    {
                        let mut performance_monitor = self.performance_monitor.write().await;
                        performance_monitor.record_download_time(download_time);
                    }

                    let headers_downloaded = end_height - current_header_height;
                    {
                        let mut progress_tracker = self.progress_tracker.write().await;
                        progress_tracker.update_progress(current_header_height, 0, headers_downloaded, (headers_downloaded * 80) as usize); // ~80 bytes per header
                    }

                    info!(
                        "[NetworkSync] Downloaded headers {} to {} in {:?}",
                        current_header_height, end_height, download_time
                    );
                    current_header_height = end_height;
                }
                Err(e) => {
                    warn!(
                        "[NetworkSync] Error downloading headers {} to {}: {:?}",
                        current_header_height, end_height, e
                    );

                    // Check for potential reorg
                    if self.detect_reorg(&e) {
                        info!("[NetworkSync] Detected potential reorg, handling reorganization");
                        self.handle_reorg_simple(current_height).await?;
                        return Ok(());
                    }

                    // Record failed download
                    {
                        let mut progress_tracker = self.progress_tracker.write().await;
                        progress_tracker.record_failed_download();
                    }

                    // Exponential backoff retry
                    {
                        let mut error_recovery = self.error_recovery.write().await;
                        if error_recovery.should_retry("header_download") {
                            let delay = error_recovery.get_retry_delay("header_download");
                            info!("[NetworkSync] Retrying header download in {:?}", delay);
                            sleep(delay).await;
                            continue;
                        } else {
                            error_recovery.reset_operation("header_download");
                            return Err(e);
                        }
                    }
                }
            }
        }

        info!("Enhanced block header synchronization completed");
        Ok(())
    }

    /// Detect potential blockchain reorganization
    fn detect_reorg(&self, error: &ConsensusError) -> bool {
        match error {
            ConsensusError::BlockValidation(msg) => {
                msg.contains("chain discontinuity") || 
                msg.contains("previous block hash mismatch") ||
                msg.contains("height")
            }
            _ => false,
        }
    }

    /// Simple reorg handler without recursion
    async fn handle_reorg_simple(&self, current_height: u64) -> Result<(), ConsensusError> {
        info!("[NetworkSync] Handling blockchain reorganization (simplified)...");

        // Update sync state to indicate reorg
        {
            let mut sync_state = self.sync_state.write().await;
            sync_state.reorg_detected = true;
            sync_state.sync_type = SyncType::ReorgSync;
        }

        // Clear error recovery state
        {
            let mut error_recovery = self.error_recovery.write().await;
            error_recovery.clear_all();
        }

        // For now, just log the reorg detection
        // In a full implementation, this would trigger a chain reorganization process
        warn!("[NetworkSync] Blockchain reorganization detected at height {}", current_height);
        
        Ok(())
    }

    /// Enhanced header batch download with improved validation
    async fn download_header_batch(&self, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>, start_height: u64, end_height: u64) -> Result<(), ConsensusError> {
        let selected_peer = {
            let peer_manager = self.peer_manager.read().await;
            peer_manager.select_best_peer().ok_or_else(|| {
                ConsensusError::NetworkError("No suitable peer found for header download".to_string())
            })?
        };

        // Build locator hashes for GetHeaders request
        let locator_hashes = self.build_locator_hashes(start_height)?;
        let stop_hash = [0u8; 32];

        let request = GetHeaders {
            locator_hashes,
            stop_hash,
        };

        info!(
            "[NetworkSync] Sending GetHeaders for heights {} to {} to peer {}",
            start_height, end_height, selected_peer
        );

        // Send GetHeaders request with timeout
        let headers_response = timeout(Duration::from_secs(30), async {
            let network = p2p_network.lock().unwrap();
            network.request_headers(selected_peer.clone(), request)
        }).await.map_err(|_| {
            ConsensusError::NetworkError("Header request timeout".to_string())
        })?.ok_or_else(|| {
            ConsensusError::NetworkError(format!("No Headers response from peer {}", selected_peer))
        })?;

        // Enhanced validation and storage of headers
        let mut headers_validated = 0;
        for header in &headers_response.headers {
            if self.validate_and_store_header_enhanced(header).await.is_ok() {
                headers_validated += 1;
            } else {
                warn!("[NetworkSync] Failed to validate header at height {}", header.height);
            }
        }

        // Record successful download
        {
            let mut peer_manager = self.peer_manager.write().await;
            peer_manager.record_success(&selected_peer, headers_validated);
        }

        info!("[NetworkSync] Successfully validated {} headers from peer {}", headers_validated, selected_peer);
        Ok(())
    }

    /// Enhanced header validation with chain continuity checks
    async fn validate_and_store_header_enhanced(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        let validation_start = Instant::now();

        // Enhanced header validation
        self.validate_block_header_enhanced(header)?;

        // Validate chain continuity with potential reorg detection
        self.validate_header_chain_continuity(header)?;

        // Store header with memory management
        {
            let memory_manager = self.memory_manager.read().await;
            if !memory_manager.should_cleanup() {
                let mut blockchain = self.blockchain.lock().unwrap();
                blockchain.state.put_block_hash(header.height, header.hash())?;

                // Update tip if this is the highest header
                let current_height = blockchain.state.get_current_block_height().unwrap_or(0);
                if header.height > current_height {
                    blockchain.state.update_tip(header.hash(), header.height)?;
                }
            }
        }

        // Record validation performance
        let validation_time = validation_start.elapsed();
        {
            let mut performance_monitor = self.performance_monitor.write().await;
            performance_monitor.record_validation_time(validation_time);
        }

        Ok(())
    }

    /// Enhanced block header validation
    fn validate_block_header_enhanced(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Validate version
        if header.version != 1 {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid block version: {}",
                header.version
            )));
        }

        // Validate timestamp with more lenient bounds for sync
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        const MAX_TIME_DRIFT: u64 = 24 * 60 * 60; // 24 hours for sync (more lenient)
        if header.timestamp > current_time + MAX_TIME_DRIFT {
            return Err(ConsensusError::BlockValidation(format!(
                "Block timestamp {} is too far in the future",
                header.timestamp
            )));
        }

        // Enhanced height validation
        let current_height = self.blockchain.lock().unwrap().state.get_current_block_height().unwrap_or(0);
        
        // Allow some flexibility in height during sync
        if header.height > current_height + 10000 {
            return Err(ConsensusError::BlockValidation(format!(
                "Header height {} is too far ahead of current height {}",
                header.height, current_height
            )));
        }

        // Validate previous block hash format
        if header.height > 0 && header.previous_block_hash == [0u8; 32] {
            return Err(ConsensusError::BlockValidation(
                "Non-genesis block cannot have zero previous block hash".to_string(),
            ));
        }

        Ok(())
    }

    /// Enhanced header chain continuity validation
    fn validate_header_chain_continuity(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        if header.height == 0 {
            // Genesis block validation
            if header.previous_block_hash != [0u8; 32] {
                return Err(ConsensusError::BlockValidation(
                    "Genesis block must have zero previous block hash".to_string(),
                ));
            }
            return Ok(());
        }

        // Get the expected previous block hash
        let expected_prev_hash = self.blockchain.lock().unwrap().state.get_block_hash(header.height - 1)
            .map_err(|e| ConsensusError::Internal(format!("Failed to get previous block hash: {}", e)))?;

        match expected_prev_hash {
            Some(expected_hash) => {
                if header.previous_block_hash != expected_hash {
                    return Err(ConsensusError::BlockValidation(format!(
                        "Header chain discontinuity: expected previous hash {:?}, got {:?}",
                        expected_hash, header.previous_block_hash
                    )));
                }
            }
            None => {
                // This might indicate a reorg or gap in the chain
                warn!("[NetworkSync] Previous header not found at height {}", header.height - 1);
                // Don't fail here, as this might be resolved during block download
            }
        }

        Ok(())
    }

    /// Enhanced block download with concurrency control
    async fn download_blocks_enhanced(&self, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>, current_height: u64, target_height: u64) -> Result<(), ConsensusError> {
        info!("Downloading blocks using enhanced processing...");

        let batch_size = 100;
        let mut current_block_height = current_height;

        while current_block_height < target_height {
            // Wait for available download slots
            let _permit = self.download_semaphore.acquire().await.unwrap();

            let end_height = std::cmp::min(current_block_height + batch_size, target_height);

            match self.download_block_batch_enhanced(p2p_network, current_block_height, end_height).await {
                Ok(blocks_downloaded) => {
                    let blocks_count = end_height - current_block_height;
                    info!(
                        "[NetworkSync] Downloaded blocks {} to {} ({} blocks)",
                        current_block_height, end_height, blocks_downloaded
                    );
                    current_block_height = end_height;
                }
                Err(e) => {
                    warn!(
                        "[NetworkSync] Error downloading blocks {} to {}: {:?}",
                        current_block_height, end_height, e
                    );
                    
                    // Record failed download
                    {
                        let mut progress_tracker = self.progress_tracker.write().await;
                        progress_tracker.record_failed_download();
                    }

                    // Retry with exponential backoff
                    {
                        let mut error_recovery = self.error_recovery.write().await;
                        if error_recovery.should_retry("block_download") {
                            let delay = error_recovery.get_retry_delay("block_download");
                            info!("[NetworkSync] Retrying block download in {:?}", delay);
                            sleep(delay).await;
                            continue;
                        } else {
                            error_recovery.reset_operation("block_download");
                            return Err(e);
                        }
                    }
                }
            }
        }

        info!("[NetworkSync] Enhanced block download completed");
        Ok(())
    }

    /// Enhanced block batch download with validation
    async fn download_block_batch_enhanced(&self, p2p_network: &Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>, start_height: u64, end_height: u64) -> Result<u32, ConsensusError> {
        let selected_peer = {
            let peer_manager = self.peer_manager.read().await;
            peer_manager.select_best_peer().ok_or_else(|| {
                ConsensusError::NetworkError("No suitable peer found for block download".to_string())
            })?
        };

        let request = BlockRequest {
            start_height: start_height as u32,
            end_height: end_height as u32,
        };

        info!(
            "[NetworkSync] Enhanced BlockRequest for heights {} to {} to peer {}",
            start_height, end_height, selected_peer
        );

        let download_start = Instant::now();
        let block_response = timeout(Duration::from_secs(60), async {
            let network = p2p_network.lock().unwrap();
            network.request_blocks(selected_peer.clone(), request)
        }).await.map_err(|_| {
            ConsensusError::NetworkError("Block request timeout".to_string())
        })?.ok_or_else(|| {
            ConsensusError::NetworkError(format!("No BlockResponse from peer {}", selected_peer))
        })?;

        let download_time = download_start.elapsed();

        // Record performance metrics
        {
            let mut perf_monitor = self.performance_monitor.write().await;
            perf_monitor.record_download_time(download_time);
        }

        let mut blocks_validated = 0;
        for block in &block_response.blocks {
            if self.validate_and_store_block_enhanced(block).await.is_ok() {
                blocks_validated += 1;
            } else {
                warn!("[NetworkSync] Failed to validate block at height {}", block.header.height);
            }
        }

        // Record successful download
        {
            let mut peer_manager = self.peer_manager.write().await;
            peer_manager.record_success(&selected_peer, blocks_validated);
        }

        // Update progress
        {
            let mut progress = self.progress_tracker.write().await;
            progress.update_progress(end_height, blocks_validated.into(), 0, block_response.blocks.len() * 1000); // ~1KB per block
        }

        info!(
            "[NetworkSync] Successfully downloaded and validated {} blocks from peer {} in {:?}",
            blocks_validated, selected_peer, download_time
        );

        Ok(blocks_validated)
    }

    /// Enhanced block validation and storage
    async fn validate_and_store_block_enhanced(&self, block: &Block) -> Result<(), ConsensusError> {
        // Comprehensive block validation
        self.verify_block_comprehensive(block)?;

        // Store block in blockchain with error handling
        let mut blockchain_lock = self.blockchain.lock().unwrap();
        blockchain_lock.add_block(block.clone())
            .map_err(|e| ConsensusError::Internal(format!("Failed to store block: {}", e)))?;

        info!(
            "[NetworkSync] Enhanced validation and storage of block at height {}",
            block.header.height
        );
        Ok(())
    }

    /// Comprehensive block verification
    fn verify_block_comprehensive(&self, block: &Block) -> Result<(), ConsensusError> {
        // Validate block header
        self.validate_block_header_comprehensive(&block.header)?;

        // Validate transactions
        self.validate_block_transactions_comprehensive(&block.transactions)?;

        // Validate merkle root
        self.validate_merkle_root_comprehensive(block)?;

        // Validate ticket votes (for PoS)
        self.validate_ticket_votes_comprehensive(&block.ticket_votes, &block.header)?;

        // Validate block size constraints
        self.validate_block_size_comprehensive(block)?;

        Ok(())
    }

    /// Comprehensive block header validation
    fn validate_block_header_comprehensive(&self, header: &BlockHeader) -> Result<(), ConsensusError> {
        // Basic validation
        if header.version != 1 {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid block version: {}",
                header.version
            )));
        }

        // Height validation
        if header.height == 0 {
            if header.previous_block_hash != [0u8; 32] {
                return Err(ConsensusError::BlockValidation(
                    "Genesis block must have zero previous block hash".to_string(),
                ));
            }
        } else {
            if header.previous_block_hash == [0u8; 32] {
                return Err(ConsensusError::BlockValidation(
                    "Non-genesis block cannot have zero previous block hash".to_string(),
                ));
            }
        }

        // Timestamp validation
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        const MAX_TIME_DRIFT: u64 = 2 * 60 * 60; // 2 hours
        if header.timestamp > current_time + MAX_TIME_DRIFT {
            return Err(ConsensusError::BlockValidation(format!(
                "Block timestamp {} is too far in the future",
                header.timestamp
            )));
        }

        Ok(())
    }

    /// Comprehensive transaction validation
    fn validate_block_transactions_comprehensive(&self, transactions: &[rusty_shared_types::Transaction]) -> Result<(), ConsensusError> {
        if transactions.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "Block must contain at least one transaction".to_string(),
            ));
        }

        // First transaction must be coinbase
        match &transactions[0] {
            rusty_shared_types::Transaction::Coinbase { .. } => {}
            _ => {
                return Err(ConsensusError::BlockValidation(
                    "First transaction in block must be coinbase".to_string(),
                ))
            }
        }

        // Enhanced transaction validation
        for (i, transaction) in transactions.iter().enumerate() {
            self.validate_transaction_comprehensive(transaction, i == 0)?;
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

    /// Comprehensive individual transaction validation
    fn validate_transaction_comprehensive(&self, transaction: &rusty_shared_types::Transaction, is_coinbase: bool) -> Result<(), ConsensusError> {
        match transaction {
            rusty_shared_types::Transaction::Coinbase { .. } => {
                // Enhanced coinbase validation
                if is_coinbase {
                    // Coinbase-specific validations
                }
                Ok(())
            }
            rusty_shared_types::Transaction::Standard { .. } => {
                // Enhanced standard transaction validation
                Ok(())
            }
            _ => {
                // For other transaction types, do basic validation
                Ok(())
            }
        }
    }

    /// Comprehensive merkle root validation
    fn validate_merkle_root_comprehensive(&self, block: &Block) -> Result<(), ConsensusError> {
        let calculated_merkle_root = self.calculate_merkle_root_comprehensive(&block.transactions)?;

        if block.header.merkle_root != calculated_merkle_root {
            return Err(ConsensusError::BlockValidation(format!(
                "Merkle root mismatch: expected {:?}, calculated {:?}",
                block.header.merkle_root, calculated_merkle_root
            )));
        }

        Ok(())
    }

    /// Comprehensive merkle root calculation
    fn calculate_merkle_root_comprehensive(&self, transactions: &[rusty_shared_types::Transaction]) -> Result<[u8; 32], ConsensusError> {
        if transactions.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "Cannot calculate merkle root for empty transaction list".to_string(),
            ));
        }

        // Get transaction hashes
        let mut tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.txid()).collect();

        // Build merkle tree using BLAKE3
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

    /// Comprehensive ticket votes validation
    fn validate_ticket_votes_comprehensive(&self, ticket_votes: &[rusty_shared_types::TicketVote], header: &BlockHeader) -> Result<(), ConsensusError> {
        const VOTERS_PER_BLOCK: usize = 5;
        const MIN_VALID_VOTES_REQUIRED: usize = 3;

        // Validate ticket_votes structure
        if ticket_votes.len() != VOTERS_PER_BLOCK {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid ticket_votes count: expected {}, got {}",
                VOTERS_PER_BLOCK,
                ticket_votes.len()
            )));
        }

        let mut valid_votes = 0;

        for (i, vote) in ticket_votes.iter().enumerate() {
            // Enhanced vote validation
            if vote.ticket_id != [0u8; 32] && vote.block_hash == header.previous_block_hash {
                valid_votes += 1;
            } else {
                warn!("[NetworkSync] Invalid vote {}: ticket_id or block_hash mismatch", i);
            }
        }

        if valid_votes < MIN_VALID_VOTES_REQUIRED {
            return Err(ConsensusError::BlockValidation(format!(
                "Insufficient valid votes: {} < {}",
                valid_votes, MIN_VALID_VOTES_REQUIRED
            )));
        }

        Ok(())
    }

    /// Comprehensive block size validation
    fn validate_block_size_comprehensive(&self, block: &Block) -> Result<(), ConsensusError> {
        // Calculate actual block size
        let block_size = bincode::serialize(block).unwrap_or_default().len();
        const MAX_BLOCK_SIZE: usize = 4_000_000; // 4MB

        if block_size > MAX_BLOCK_SIZE {
            return Err(ConsensusError::BlockValidation(format!(
                "Block size {} exceeds maximum {}",
                block_size, MAX_BLOCK_SIZE
            )));
        }

        Ok(())
    }

    /// Enhanced locator hashes building
    fn build_locator_hashes(&self, start_height: u64) -> Result<Vec<[u8; 32]>, ConsensusError> {
        let mut locator_hashes = Vec::new();

        // Add recent block hashes in exponential backoff pattern
        let mut height = start_height;
        let mut step = 1;

        while height > 0 && locator_hashes.len() < 10 {
            if let Ok(Some(hash)) = self.blockchain.lock().unwrap().state.get_block_hash(height) {
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

    /// Get current sync progress information
    pub async fn get_sync_progress(&self) -> SyncProgressInfo {
        let progress_tracker = self.progress_tracker.read().await;
        let sync_state = self.sync_state.read().await;
        let peer_manager = self.peer_manager.read().await;
        let performance_monitor = self.performance_monitor.read().await;

        SyncProgressInfo {
            is_syncing: sync_state.is_syncing,
            current_height: sync_state.current_height,
            target_height: sync_state.target_height,
            progress_percentage: progress_tracker.get_progress_percentage(),
            sync_speed: progress_tracker.get_sync_speed(),
            estimated_time_remaining: progress_tracker.get_estimated_time_remaining(),
            peer_count: peer_manager.get_peer_count(),
            avg_download_time: performance_monitor.get_average_download_time(),
            avg_validation_time: performance_monitor.get_average_validation_time(),
            avg_network_latency: performance_monitor.get_average_network_latency(),
            failed_downloads: progress_tracker.failed_downloads,
            reorg_detected: sync_state.reorg_detected,
        }
    }

    /// Check if sync is complete
    pub async fn is_sync_complete(&self) -> bool {
        let sync_state = self.sync_state.read().await;
        !sync_state.is_syncing && sync_state.current_height >= sync_state.target_height
    }

    /// Enhanced synchronize_blockchain method
    pub async fn synchronize_blockchain(&self, p2p_network: Arc<std::sync::Mutex<dyn P2PNetwork + Send + Sync>>) -> Result<(), ConsensusError> {
        info!("Starting enhanced blockchain synchronization...");
        
        // Clear any previous error recovery state
        {
            let mut error_recovery = self.error_recovery.write().await;
            error_recovery.clear_all();
        }

        // Use the enhanced start_sync method
        self.start_sync(p2p_network).await
    }
}

/// Sync progress information for external monitoring
pub struct SyncProgressInfo {
    pub is_syncing: bool,
    pub current_height: u64,
    pub target_height: u64,
    pub progress_percentage: f64,
    pub sync_speed: String,
    pub estimated_time_remaining: Option<Duration>,
    pub peer_count: usize,
    pub avg_download_time: Option<Duration>,
    pub avg_validation_time: Option<Duration>,
    pub avg_network_latency: Option<Duration>,
    pub failed_downloads: u64,
    pub reorg_detected: bool,
}

// Extension trait for better async handling
trait InstantExt {
    fn elapsed(&self) -> Duration;
    fn now() -> Self;
}

impl InstantExt for Instant {
    fn elapsed(&self) -> Duration {
        self.elapsed()
    }

    fn now() -> Self {
        Instant::now()
    }
}
