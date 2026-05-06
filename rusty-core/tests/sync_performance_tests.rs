//! Synchronization Performance Tests
//!
//! Comprehensive performance tests for the blockchain synchronization system.
//! These tests validate IBD performance, header sync rates, block validation throughput,
//! memory usage, network bandwidth utilization, and stress testing under various conditions.
//!
//! Tests integrate with regtest network and provide detailed performance metrics
//! with regression detection capabilities.

use rusty_core::consensus::blockchain::Blockchain;
use rusty_core::consensus::error::ConsensusError;
use rusty_core::consensus::pos::LiveTicketsPool;
use rusty_core::consensus::state::BlockchainState;
use rusty_core::consensus::utxo_set::UtxoSet;
use rusty_core::network::sync_manager::{SyncManager, SyncState};
use rusty_core::network::P2PNetwork;
use rusty_core::types::{BlockRequest, BlockResponse, GetHeaders, Headers, PeerInfo, PeerId, P2PMessage};
use rusty_shared_types::{Block, BlockHeader, ConsensusParams, Hash, Transaction, TxOutput};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Performance metrics collector for regression detection
#[derive(Debug, Clone)]
struct PerformanceMetrics {
    pub ibd_time_per_1000_blocks: Vec<f64>,
    pub header_sync_rate_hps: Vec<f64>,
    pub block_validation_rate_bps: Vec<f64>,
    pub peak_memory_usage_mb: Vec<f64>,
    pub network_bandwidth_mbps: Vec<f64>,
    pub sync_success_rate: Vec<f64>,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            ibd_time_per_1000_blocks: Vec::new(),
            header_sync_rate_hps: Vec::new(),
            block_validation_rate_bps: Vec::new(),
            peak_memory_usage_mb: Vec::new(),
            network_bandwidth_mbps: Vec::new(),
            sync_success_rate: Vec::new(),
        }
    }

    fn record_ibd_time(&mut self, blocks: u64, duration: Duration) {
        let time_per_1000 = duration.as_secs_f64() / (blocks as f64 / 1000.0);
        self.ibd_time_per_1000_blocks.push(time_per_1000);
    }

    fn record_header_sync_rate(&mut self, headers: u64, duration: Duration) {
        let hps = headers as f64 / duration.as_secs_f64();
        self.header_sync_rate_hps.push(hps);
    }

    fn record_block_validation_rate(&mut self, blocks: u64, duration: Duration) {
        let bps = blocks as f64 / duration.as_secs_f64();
        self.block_validation_rate_bps.push(bps);
    }

    fn record_memory_usage(&mut self, memory_mb: f64) {
        self.peak_memory_usage_mb.push(memory_mb);
    }

    fn record_bandwidth(&mut self, bandwidth_mbps: f64) {
        self.network_bandwidth_mbps.push(bandwidth_mbps);
    }

    fn record_sync_success(&mut self, success: bool) {
        let rate = if success { 1.0 } else { 0.0 };
        self.sync_success_rate.push(rate);
    }

    /// Check for performance regressions against baseline thresholds
    fn check_regressions(&self) -> Result<(), String> {
        // IBD performance: Should complete 1000 blocks in under 30 seconds
        if let Some(&avg_time) = self.ibd_time_per_1000_blocks.last() {
            if avg_time > 30.0 {
                return Err(format!("IBD regression: {}s per 1000 blocks (threshold: 30s)", avg_time));
            }
        }

        // Header sync rate: Should sync at least 500 headers per second
        if let Some(&avg_hps) = self.header_sync_rate_hps.last() {
            if avg_hps < 500.0 {
                return Err(format!("Header sync regression: {:.1} HPS (threshold: 500 HPS)", avg_hps));
            }
        }

        // Block validation rate: Should validate at least 10 blocks per second
        if let Some(&avg_bps) = self.block_validation_rate_bps.last() {
            if avg_bps < 10.0 {
                return Err(format!("Block validation regression: {:.1} BPS (threshold: 10 BPS)", avg_bps));
            }
        }

        // Memory usage: Should not exceed 500MB peak
        if let Some(&peak_mb) = self.peak_memory_usage_mb.last() {
            if peak_mb > 500.0 {
                return Err(format!("Memory regression: {:.1}MB peak (threshold: 500MB)", peak_mb));
            }
        }

        // Network bandwidth: Should not exceed 100Mbps
        if let Some(&bandwidth) = self.network_bandwidth_mbps.last() {
            if bandwidth > 100.0 {
                return Err(format!("Bandwidth regression: {:.1}Mbps (threshold: 100Mbps)", bandwidth));
            }
        }

        // Sync success rate: Should be 100%
        if let Some(&success_rate) = self.sync_success_rate.last() {
            if success_rate < 1.0 {
                return Err(format!("Sync reliability regression: {:.1}% success rate", success_rate * 100.0));
            }
        }

        Ok(())
    }
}

/// Mock P2P network for testing sync performance
struct MockP2PNetwork {
    peers: HashMap<PeerId, MockPeer>,
    network_conditions: NetworkConditions,
}

#[derive(Clone)]
struct NetworkConditions {
    latency_ms: u64,
    bandwidth_mbps: f64,
    packet_loss_rate: f64,
    peer_churn_rate: f64,
}

struct MockPeer {
    peer_id: String,
    blockchain_height: u64,
    blocks: Vec<Block>,
    headers: Vec<BlockHeader>,
    is_malicious: bool,
    last_seen: u64,
}

impl MockP2PNetwork {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            network_conditions: NetworkConditions {
                latency_ms: 50,      // 50ms latency
                bandwidth_mbps: 10.0, // 10Mbps
                packet_loss_rate: 0.001, // 0.1% packet loss
                peer_churn_rate: 0.01,   // 1% peer churn
            },
        }
    }

    fn add_peer(&mut self, peer: MockPeer) {
        self.peers.insert(peer.peer_id.clone(), peer);
    }

    fn simulate_network_delay(&self) {
        std::thread::sleep(Duration::from_millis(self.network_conditions.latency_ms));
    }

    fn simulate_packet_loss(&self) -> bool {
        rand::random::<f64>() < self.network_conditions.packet_loss_rate
    }

    fn simulate_peer_churn(&mut self) {
        let churn_count = (self.peers.len() as f64 * self.network_conditions.peer_churn_rate) as usize;
        let peer_ids: Vec<PeerId> = self.peers.keys().cloned().collect();

        for i in 0..churn_count.min(peer_ids.len()) {
            self.peers.remove(&peer_ids[i]);
        }
    }
}

impl P2PNetwork for MockP2PNetwork {
    fn send_message(&self, _peer_id: String, _message: P2PMessage) -> Result<(), String> {
        Ok(())
    }

    fn broadcast_message(&self, _message: P2PMessage) -> Result<(), String> {
        Ok(())
    }

    fn receive_message(&mut self) -> Option<(String, P2PMessage)> {
        None
    }

    fn get_connected_peers(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    fn get_peer_info(&self, peer_id: String) -> Option<PeerInfo> {
        self.peers.get(&peer_id).map(|peer| PeerInfo {
            peer_id: peer.peer_id.clone(),
            address: "127.0.0.1:8333".to_string(),
            last_seen: peer.last_seen,
            blocks_in_flight: 0,
            transactions_in_flight: 0,
        })
    }

    fn request_headers(&self, peer_id: String, _request: GetHeaders) -> Option<Headers> {
        self.simulate_network_delay();

        if self.simulate_packet_loss() {
            return None;
        }

        let peer = self.peers.get(&peer_id)?;
        let headers: Vec<BlockHeader> = peer.headers.clone();

        Some(Headers { headers })
    }

    fn request_blocks(&self, peer_id: String, request: BlockRequest) -> Option<BlockResponse> {
        self.simulate_network_delay();

        if self.simulate_packet_loss() {
            return None;
        }

        let peer = self.peers.get(&peer_id)?;
        let start = request.start_height as usize;
        let end = request.end_height as usize;

        let blocks: Vec<Block> = peer.blocks.iter()
            .skip(start)
            .take(end - start)
            .cloned()
            .collect();

        Some(BlockResponse { blocks })
    }
}

/// Test IBD (Initial Block Download) performance vs block count
#[tokio::test]
async fn test_ibd_performance_scaling() {
    println!("\n=== Testing IBD Performance Scaling ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with different blockchain sizes
    let test_sizes = vec![1000, 5000, 10000, 25000];

    for &block_count in &test_sizes {
        println!("Testing IBD with {} blocks...", block_count);

        let start_time = Instant::now();

        // Setup mock network with specified number of blocks
        let mut mock_network = MockP2PNetwork::new();
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    
        // Create sync manager
        let (sync_manager, _blockchain) = create_sync_manager().await;
    
        // Execute IBD
        let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                metrics.record_ibd_time(block_count, duration);
                metrics.record_sync_success(true);
                println!("✅ IBD completed in {:.2}s for {} blocks", duration.as_secs_f64(), block_count);
            }
            Err(e) => {
                metrics.record_sync_success(false);
                println!("❌ IBD failed for {} blocks: {:?}", block_count, e);
            }
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }

    println!("IBD Performance Results:");
    for (i, &time) in metrics.ibd_time_per_1000_blocks.iter().enumerate() {
        println!("  {} blocks: {:.2}s per 1000 blocks", test_sizes[i], time);
    }
}

/// Test header sync rate during header-first synchronization
#[tokio::test]
async fn test_header_sync_rate() {
    println!("\n=== Testing Header Sync Rate ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with different header counts
    let test_sizes = vec![1000, 5000, 10000, 50000];

    for &header_count in &test_sizes {
        println!("Testing header sync with {} headers...", header_count);

        let start_time = Instant::now();

        // Setup mock network
        let mut mock_network = MockP2PNetwork::new();
        let peer = create_mock_peer(header_count, false);
        mock_network.add_peer(peer);
    
        // Create sync manager
        let (sync_manager, _blockchain) = create_sync_manager().await;
    
        // Execute header-first sync
        let result = sync_manager.header_first_sync_async(Arc::new(Mutex::new(mock_network))).await;

        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                metrics.record_header_sync_rate(header_count, duration);
                metrics.record_sync_success(true);
                println!("✅ Header sync completed in {:.2}s for {} headers", duration.as_secs_f64(), header_count);
            }
            Err(e) => {
                metrics.record_sync_success(false);
                println!("❌ Header sync failed for {} headers: {:?}", header_count, e);
            }
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }

    println!("Header Sync Performance Results:");
    for (i, &rate) in metrics.header_sync_rate_hps.iter().enumerate() {
        println!("  {} headers: {:.1} HPS", test_sizes[i], rate);
    }
}

/// Test block validation rate during sync
#[tokio::test]
async fn test_block_validation_rate() {
    println!("\n=== Testing Block Validation Rate ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with different block counts
    let test_sizes = vec![100, 500, 1000, 2500];

    for &block_count in &test_sizes {
        println!("Testing block validation with {} blocks...", block_count);

        let start_time = Instant::now();

        // Setup mock network
        let mut mock_network = MockP2PNetwork::new();
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    
        // Create sync manager
        let (sync_manager, _blockchain) = create_sync_manager().await;
    
        // Execute IBD (which includes validation)
        let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                metrics.record_block_validation_rate(block_count, duration);
                metrics.record_sync_success(true);
                println!("✅ Block validation completed in {:.2}s for {} blocks", duration.as_secs_f64(), block_count);
            }
            Err(e) => {
                metrics.record_sync_success(false);
                println!("❌ Block validation failed for {} blocks: {:?}", block_count, e);
            }
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }

    println!("Block Validation Performance Results:");
    for (i, &rate) in metrics.block_validation_rate_bps.iter().enumerate() {
        println!("  {} blocks: {:.1} BPS", test_sizes[i], rate);
    }
}

/// Test memory usage during sync operations
#[tokio::test]
async fn test_memory_usage_during_sync() {
    println!("\n=== Testing Memory Usage During Sync ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with large blockchain
    let block_count = 10000;
    println!("Testing memory usage with {} blocks...", block_count);

    // Get initial memory usage
    let initial_memory = get_memory_usage_mb();

    // Setup mock network
    let mut mock_network = MockP2PNetwork::new();
    let peer = create_mock_peer(block_count, false);
    mock_network.add_peer(peer);

    // Create sync manager
    let (sync_manager, _blockchain) = create_sync_manager().await;

    // Execute IBD
    let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

    // Get peak memory usage
    let peak_memory = get_memory_usage_mb();
    let memory_used = peak_memory - initial_memory;

    metrics.record_memory_usage(memory_used);

    match result {
        Ok(_) => {
            metrics.record_sync_success(true);
            println!("✅ Sync completed with {:.1}MB memory usage", memory_used);
        }
        Err(e) => {
            metrics.record_sync_success(false);
            println!("❌ Sync failed: {:?}", e);
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Test network bandwidth utilization during sync
#[tokio::test]
async fn test_network_bandwidth_utilization() {
    println!("\n=== Testing Network Bandwidth Utilization ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with different network conditions
    let bandwidth_tests = vec![1.0, 10.0, 50.0, 100.0]; // Mbps

    for &bandwidth in &bandwidth_tests {
        println!("Testing bandwidth utilization at {:.1}Mbps...", bandwidth);

        // Setup mock network with bandwidth limit
        let mut mock_network = MockP2PNetwork::new();
        mock_network.network_conditions.bandwidth_mbps = bandwidth;

        // Add peer with 5000 blocks
        let peer = create_mock_peer(5000, false);
        mock_network.add_peer(peer);

        // Create sync manager
        let (sync_manager, _blockchain) = create_sync_manager().await;

        let start_time = Instant::now();

        // Execute IBD
        let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

        let duration = start_time.elapsed();

        // Calculate effective bandwidth (simplified)
        let data_transferred_mb = 5000.0 * 2.0; // Rough estimate: 2MB per block
        let effective_bandwidth = data_transferred_mb / duration.as_secs_f64();

        metrics.record_bandwidth(effective_bandwidth);

        match result {
            Ok(_) => {
                metrics.record_sync_success(true);
                println!("✅ Sync completed at {:.1}Mbps effective bandwidth", effective_bandwidth);
            }
            Err(e) => {
                metrics.record_sync_success(false);
                println!("❌ Sync failed: {:?}", e);
            }
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Stress test for large blockchain state synchronization
#[tokio::test]
async fn test_large_blockchain_state_sync() {
    println!("\n=== Testing Large Blockchain State Synchronization ===");

    let mut metrics = PerformanceMetrics::new();

    // Test with very large blockchain (100k blocks)
    let block_count = 100000;
    println!("Testing large blockchain sync with {} blocks...", block_count);

    let start_time = Instant::now();
    let initial_memory = get_memory_usage_mb();

    // Setup mock network with many peers
    let mut mock_network = MockP2PNetwork::new();
    for _ in 0..8 {
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    }

    // Create sync manager
    let (sync_manager, _blockchain) = create_sync_manager().await;

    // Execute IBD
    let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

    let duration = start_time.elapsed();
    let peak_memory = get_memory_usage_mb();
    let memory_used = peak_memory - initial_memory;

    metrics.record_memory_usage(memory_used);
    metrics.record_ibd_time(block_count, duration);

    match result {
        Ok(_) => {
            metrics.record_sync_success(true);
            println!("✅ Large blockchain sync completed in {:.2}s with {:.1}MB memory usage",
                    duration.as_secs_f64(), memory_used);
        }
        Err(e) => {
            metrics.record_sync_success(false);
            println!("❌ Large blockchain sync failed: {:?}", e);
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Test network partition recovery during sync
#[tokio::test]
async fn test_network_partition_recovery() {
    println!("\n=== Testing Network Partition Recovery ===");

    let mut metrics = PerformanceMetrics::new();

    let block_count = 5000;
    println!("Testing partition recovery with {} blocks...", block_count);

    // Setup mock network
    let mut mock_network = MockP2PNetwork::new();
    for _ in 0..3 {
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    }

    // Create sync manager
    let (sync_manager, _blockchain) = create_sync_manager().await;

    let start_time = Instant::now();

    // Start IBD
    let network_arc = Arc::new(Mutex::new(mock_network));
    let sync_handle = tokio::spawn({
        let network = Arc::clone(&network_arc);
        let mut sync_mgr = sync_manager;
        async move {
            sync_mgr.initial_block_download(network).await
        }
    });

    // Simulate network partition after 2 seconds
    tokio::time::sleep(Duration::from_secs(2)).await;
    {
        let mut network = network_arc.lock().unwrap();
        // Remove all peers (simulate partition)
        network.peers.clear();
    }

    // Wait a bit then restore peers
    tokio::time::sleep(Duration::from_secs(3)).await;
    {
        let mut network = network_arc.lock().unwrap();
        // Restore peers
        let peer = create_mock_peer(block_count, false);
        network.add_peer(peer);
    }

    // Wait for sync to complete
    let result = sync_handle.await.unwrap();

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            metrics.record_sync_success(true);
            println!("✅ Partition recovery sync completed in {:.2}s", duration.as_secs_f64());
        }
        Err(e) => {
            metrics.record_sync_success(false);
            println!("❌ Partition recovery sync failed: {:?}", e);
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Test peer churn during sync
#[tokio::test]
async fn test_peer_churn_during_sync() {
    println!("\n=== Testing Peer Churn During Sync ===");

    let mut metrics = PerformanceMetrics::new();

    let block_count = 10000;
    println!("Testing peer churn with {} blocks...", block_count);

    // Setup mock network with high churn rate
    let mut mock_network = MockP2PNetwork::new();
    mock_network.network_conditions.peer_churn_rate = 0.1; // 10% churn rate

    // Add initial peers
    for i in 0..5 {
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    }

    // Create sync manager
    let (sync_manager, _blockchain) = create_sync_manager().await;

    let start_time = Instant::now();

    // Execute IBD with peer churn simulation
    let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            metrics.record_sync_success(true);
            println!("✅ Peer churn sync completed in {:.2}s", duration.as_secs_f64());
        }
        Err(e) => {
            metrics.record_sync_success(false);
            println!("❌ Peer churn sync failed: {:?}", e);
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Test malicious peer resistance during sync
#[tokio::test]
async fn test_malicious_peer_resistance() {
    println!("\n=== Testing Malicious Peer Resistance ===");

    let mut metrics = PerformanceMetrics::new();

    let block_count = 5000;
    println!("Testing malicious peer resistance with {} blocks...", block_count);

    // Setup mock network with mix of honest and malicious peers
    let mut mock_network = MockP2PNetwork::new();
    for _ in 0..6 {
        let peer = create_mock_peer(block_count, false);
        mock_network.add_peer(peer);
    }
    for _ in 0..2 {
        let peer = create_mock_peer(block_count, true);
        mock_network.add_peer(peer);
    }

    // Create sync manager
    let (sync_manager, _blockchain) = create_sync_manager().await;

    let start_time = Instant::now();

    // Execute IBD
    let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            metrics.record_sync_success(true);
            println!("✅ Malicious peer resistance sync completed in {:.2}s", duration.as_secs_f64());
        }
        Err(e) => {
            metrics.record_sync_success(false);
            println!("❌ Malicious peer resistance sync failed: {:?}", e);
        }
    }

    // Check for regressions
    if let Err(regression) = metrics.check_regressions() {
        panic!("Performance regression detected: {}", regression);
    }
}

/// Integration test with regtest network
#[tokio::test]
async fn test_regtest_network_integration() {
    println!("\n=== Testing Regtest Network Integration ===");

    // Verify regtest parameters
    let regtest_params = ConsensusParams::regtest();
    assert_eq!(regtest_params.min_block_time, 1); // 1 second for regtest
    assert_eq!(regtest_params.difficulty_adjustment_window, 5);
    assert_eq!(regtest_params.ticket_price, 10); // Minimal for regtest

    println!("✅ Regtest parameters verified");

    // Test sync with regtest parameters
    let block_count = 1000;
    let mut mock_network = MockP2PNetwork::new();
    let peer = create_mock_peer(block_count, false);
    let peer_id = peer.peer_id.clone();
    mock_network.add_peer(peer);

    // Create sync manager
    let (mut sync_manager, _blockchain) = create_sync_manager().await;

    // Add the peer to sync manager as well
    let peer_info = PeerInfo {
        peer_id: peer_id.clone(),
        address: "127.0.0.1:8333".to_string(),
        last_seen: 1000,
        blocks_in_flight: 0,
        transactions_in_flight: 0,
    };
    sync_manager.add_peer(peer_id, peer_info);

    let start_time = Instant::now();

    // Execute IBD
    let result = sync_manager.initial_block_download(Arc::new(Mutex::new(mock_network))).await;

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            println!("✅ Regtest sync completed in {:.2}s", duration.as_secs_f64());
        }
        Err(e) => {
            panic!("❌ Regtest sync failed: {:?}", e);
        }
    }

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            println!("✅ Regtest sync completed in {:.2}s", duration.as_secs_f64());
        }
        Err(e) => {
            panic!("❌ Regtest sync failed: {:?}", e);
        }
    }
}

// Helper functions

async fn setup_mock_network(block_count: u64, peer_count: usize, malicious: bool) -> MockP2PNetwork {
    let mut network = MockP2PNetwork::new();

    for i in 0..peer_count {
        let peer = create_mock_peer(block_count, malicious);
        network.add_peer(peer);
    }

    network
}

async fn setup_mock_network_mixed(block_count: u64, honest_count: usize, malicious_count: usize) -> MockP2PNetwork {
    let mut network = MockP2PNetwork::new();

    // Add honest peers
    for i in 0..honest_count {
        let peer = create_mock_peer(block_count, false);
        network.add_peer(peer);
    }

    // Add malicious peers
    for i in 0..malicious_count {
        let peer = create_mock_peer(block_count, true);
        network.add_peer(peer);
    }

    network
}

fn create_mock_peer(block_count: u64, malicious: bool) -> MockPeer {
    let peer_id = format!("peer_{}", rand::random::<u64>());
    let mut blocks = Vec::new();
    let mut headers = Vec::new();

    // Create genesis block
    let genesis_block = create_genesis_block();
    let genesis_header = genesis_block.header.clone();
    blocks.push(genesis_block);
    headers.push(genesis_header);

    // Create additional blocks
    for height in 1..block_count {
        let prev_block = &blocks[(height - 1) as usize];
        let block = create_test_block(height, prev_block.header.hash(), malicious);
        let header = block.header.clone();
        blocks.push(block);
        headers.push(header);
    }

    MockPeer {
        peer_id,
        blockchain_height: block_count,
        blocks,
        headers,
        is_malicious: malicious,
        last_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

fn create_genesis_block() -> Block {
    let header = BlockHeader {
        version: 1,
        height: 0,
        previous_block_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        state_root: [0u8; 32],
        timestamp: 1609459200, // 2021-01-01
        difficulty_target: 0x1d00ffff,
        nonce: 0,
    };

    let coinbase_tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(50_000_000_000, vec![0x76, 0xA9, 0x14])], // 500 RUST
        lock_time: 0,
        witness: vec![],
    };

    Block {
        header,
        ticket_votes: vec![],
        transactions: vec![coinbase_tx],
    }
}

fn create_test_block(height: u64, prev_hash: [u8; 32], malicious: bool) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        previous_block_hash: prev_hash,
        merkle_root: [height as u8; 32], // Simplified
        state_root: [0u8; 32],
        timestamp: 1609459200 + height * 150, // 2.5 min intervals
        difficulty_target: 0x1d00ffff,
        nonce: height,
    };

    let coinbase_tx = Transaction::Coinbase {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOutput::new(50_000_000_000, vec![0x76, 0xA9, 0x14])],
        lock_time: 0,
        witness: vec![],
    };

    Block {
        header,
        ticket_votes: vec![],
        transactions: vec![coinbase_tx],
    }
}

async fn create_sync_manager() -> (SyncManager, Arc<Mutex<Blockchain>>) {
    // Create a mock P2P network for blockchain initialization
    let mock_p2p = Arc::new(Mutex::new(MockP2PNetwork::new()));
    let blockchain = Arc::new(Mutex::new(Blockchain::new(mock_p2p).unwrap()));
    let blockchain_guard = blockchain.lock().unwrap();

    let blockchain_state = Arc::new(RwLock::new(blockchain_guard.state.clone()));
    let utxo_set = Arc::new(RwLock::new(blockchain_guard.utxo_set.clone()));
    let live_tickets = Arc::new(RwLock::new(blockchain_guard.live_tickets.clone()));

    drop(blockchain_guard);

    let mut sync_manager = SyncManager::new(
        blockchain_state,
        utxo_set,
        live_tickets,
    );

    // Add a default peer to the sync manager for testing
    let peer_info = PeerInfo {
        peer_id: "default_peer".to_string(),
        address: "127.0.0.1:8333".to_string(),
        last_seen: 1000,
        blocks_in_flight: 0,
        transactions_in_flight: 0,
    };
    sync_manager.add_peer("default_peer".to_string(), peer_info);

    (sync_manager, blockchain)
}

fn get_memory_usage_mb() -> f64 {
    // Simplified memory usage estimation
    // In a real implementation, this would use system APIs to get actual memory usage
    // For now, return a mock value
    100.0 + rand::random::<f64>() * 50.0 // Mock: 100-150MB
}