//! Advanced peer selection algorithms for optimal P2P network performance
//! 
//! This module implements sophisticated peer selection strategies that go beyond
//! basic random selection to optimize network performance, security, and resilience.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use libp2p::PeerId;
use serde::{Serialize, Deserialize};

/// Comprehensive peer scoring system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    /// Base reputation score (-100 to 100)
    pub reputation: i32,
    /// Connection reliability (0.0 to 1.0)
    pub reliability: f64,
    /// Average response time in milliseconds
    pub avg_response_time: u64,
    /// Bandwidth capacity (bytes per second)
    pub bandwidth: u64,
    /// Geographic diversity score (0.0 to 1.0)
    pub geographic_diversity: f64,
    /// Network diversity score (0.0 to 1.0)
    pub network_diversity: f64,
    /// Security score (0.0 to 1.0)
    pub security_score: f64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Connection uptime percentage
    pub uptime: f64,
    /// Protocol compliance score (0.0 to 1.0)
    pub protocol_compliance: f64,
}

/// Peer selection strategy
#[derive(Debug, Clone, Copy)]
pub enum SelectionStrategy {
    /// Random selection (baseline)
    Random,
    /// Score-based selection (weighted by peer scores)
    ScoreBased,
    /// Diversity-focused selection (maximize network diversity)
    DiversityFocused,
    /// Performance-optimized selection (prioritize fast, reliable peers)
    PerformanceOptimized,
    /// Security-focused selection (prioritize secure, trusted peers)
    SecurityFocused,
    /// Hybrid selection (balanced approach)
    Hybrid,
}

/// Geographic region classification
#[derive(Debug, Clone, Hash, PartialEq)]
pub enum GeographicRegion {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Asia,
    Africa,
    Oceania,
    Unknown,
}

/// Network provider classification
#[derive(Debug, Clone, Hash, PartialEq)]
pub enum NetworkProvider {
    Residential,
    DataCenter,
    Cloud,
    Mobile,
    University,
    Government,
    Unknown,
}

/// Peer metadata for selection algorithms
#[derive(Debug, Clone)]
pub struct PeerMetadata {
    pub peer_id: PeerId,
    pub ip_address: IpAddr,
    pub score: PeerScore,
    pub region: GeographicRegion,
    pub provider: NetworkProvider,
    pub connection_count: usize,
    pub is_outbound: bool,
    pub connected_at: Instant,
}

/// Advanced peer selection engine
pub struct PeerSelector {
    peers: HashMap<PeerId, PeerMetadata>,
    strategy: SelectionStrategy,
    max_peers: usize,
    diversity_targets: DiversityTargets,
}

/// Diversity targets for peer selection
#[derive(Debug, Clone)]
pub struct DiversityTargets {
    /// Target percentage of peers from different regions
    pub geographic_diversity: f64,
    /// Target percentage of peers from different network providers
    pub network_diversity: f64,
    /// Maximum percentage of peers from same /24 subnet
    pub subnet_diversity: f64,
    /// Target percentage of high-reputation peers
    pub reputation_diversity: f64,
}

impl Default for DiversityTargets {
    fn default() -> Self {
        Self {
            geographic_diversity: 0.6,  // 60% from different regions
            network_diversity: 0.7,     // 70% from different providers
            subnet_diversity: 0.2,      // Max 20% from same subnet
            reputation_diversity: 0.8,  // 80% high-reputation peers
        }
    }
}

impl PeerScore {
    /// Create a new peer score with default values
    pub fn new() -> Self {
        Self {
            reputation: 0,
            reliability: 0.5,
            avg_response_time: 1000,
            bandwidth: 1_000_000, // 1 MB/s default
            geographic_diversity: 0.5,
            network_diversity: 0.5,
            security_score: 0.5,
            last_seen: Instant::now(),
            uptime: 0.0,
            protocol_compliance: 1.0,
        }
    }

    /// Calculate composite score (0.0 to 1.0)
    pub fn composite_score(&self) -> f64 {
        let reputation_score = (self.reputation + 100) as f64 / 200.0; // Normalize to 0-1
        let response_score = 1.0 - (self.avg_response_time as f64 / 10000.0).min(1.0);
        let bandwidth_score = (self.bandwidth as f64 / 10_000_000.0).min(1.0); // Normalize to 10MB/s max
        
        // Weighted composite score
        (reputation_score * 0.25 +
         self.reliability * 0.20 +
         response_score * 0.15 +
         bandwidth_score * 0.10 +
         self.geographic_diversity * 0.10 +
         self.network_diversity * 0.10 +
         self.security_score * 0.05 +
         self.uptime * 0.05).min(1.0)
    }

    /// Update score based on successful interaction
    pub fn record_success(&mut self, response_time: Duration) {
        self.reputation = (self.reputation + 1).min(100);
        self.reliability = (self.reliability * 0.9 + 0.1).min(1.0);
        self.avg_response_time = (self.avg_response_time * 9 + response_time.as_millis() as u64) / 10;
        self.last_seen = Instant::now();
    }

    /// Update score based on failed interaction
    pub fn record_failure(&mut self) {
        self.reputation = (self.reputation - 5).max(-100);
        self.reliability = (self.reliability * 0.9).max(0.0);
        self.last_seen = Instant::now();
    }
}

impl PeerSelector {
    /// Create a new peer selector
    pub fn new(strategy: SelectionStrategy, max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            strategy,
            max_peers,
            diversity_targets: DiversityTargets::default(),
        }
    }

    /// Add or update a peer
    pub fn add_peer(&mut self, metadata: PeerMetadata) {
        self.peers.insert(metadata.peer_id, metadata);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Select optimal peers based on current strategy
    pub fn select_peers(&self, count: usize) -> Vec<PeerId> {
        match self.strategy {
            SelectionStrategy::Random => self.select_random(count),
            SelectionStrategy::ScoreBased => self.select_score_based(count),
            SelectionStrategy::DiversityFocused => self.select_diversity_focused(count),
            SelectionStrategy::PerformanceOptimized => self.select_performance_optimized(count),
            SelectionStrategy::SecurityFocused => self.select_security_focused(count),
            SelectionStrategy::Hybrid => self.select_hybrid(count),
        }
    }

    /// Random peer selection (baseline)
    fn select_random(&self, count: usize) -> Vec<PeerId> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let peer_ids: Vec<PeerId> = self.peers.keys().cloned().collect();
        peer_ids.choose_multiple(&mut rng, count).cloned().collect()
    }

    /// Score-based peer selection
    fn select_score_based(&self, count: usize) -> Vec<PeerId> {
        let mut scored_peers: Vec<(PeerId, f64)> = self.peers
            .iter()
            .map(|(id, metadata)| (*id, metadata.score.composite_score()))
            .collect();
        
        scored_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored_peers.into_iter().take(count).map(|(id, _)| id).collect()
    }

    /// Diversity-focused peer selection
    fn select_diversity_focused(&self, count: usize) -> Vec<PeerId> {
        let mut selected = Vec::new();
        let mut region_counts = HashMap::new();
        let mut provider_counts = HashMap::new();
        
        // Sort by diversity scores
        let mut candidates: Vec<&PeerMetadata> = self.peers.values().collect();
        candidates.sort_by(|a, b| {
            let a_diversity = a.score.geographic_diversity + a.score.network_diversity;
            let b_diversity = b.score.geographic_diversity + b.score.network_diversity;
            b_diversity.partial_cmp(&a_diversity).unwrap()
        });
        
        for peer in candidates {
            if selected.len() >= count {
                break;
            }
            
            // Check diversity constraints
            let region_count = region_counts.get(&peer.region).unwrap_or(&0);
            let provider_count = provider_counts.get(&peer.provider).unwrap_or(&0);
            
            let max_per_region = (count as f64 * (1.0 - self.diversity_targets.geographic_diversity)) as usize + 1;
            let max_per_provider = (count as f64 * (1.0 - self.diversity_targets.network_diversity)) as usize + 1;
            
            if *region_count < max_per_region && *provider_count < max_per_provider {
                selected.push(peer.peer_id);
                *region_counts.entry(peer.region.clone()).or_insert(0) += 1;
                *provider_counts.entry(peer.provider.clone()).or_insert(0) += 1;
            }
        }
        
        selected
    }

    /// Performance-optimized peer selection
    fn select_performance_optimized(&self, count: usize) -> Vec<PeerId> {
        let mut performance_peers: Vec<(PeerId, f64)> = self.peers
            .iter()
            .map(|(id, metadata)| {
                let performance_score = metadata.score.reliability * 0.4 +
                    (1.0 - (metadata.score.avg_response_time as f64 / 5000.0).min(1.0)) * 0.3 +
                    (metadata.score.bandwidth as f64 / 10_000_000.0).min(1.0) * 0.3;
                (*id, performance_score)
            })
            .collect();
        
        performance_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        performance_peers.into_iter().take(count).map(|(id, _)| id).collect()
    }

    /// Security-focused peer selection
    fn select_security_focused(&self, count: usize) -> Vec<PeerId> {
        let mut security_peers: Vec<(PeerId, f64)> = self.peers
            .iter()
            .filter(|(_, metadata)| metadata.score.reputation >= 0) // Only positive reputation
            .map(|(id, metadata)| {
                let security_score = metadata.score.security_score * 0.4 +
                    ((metadata.score.reputation + 100) as f64 / 200.0) * 0.3 +
                    metadata.score.protocol_compliance * 0.3;
                (*id, security_score)
            })
            .collect();
        
        security_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        security_peers.into_iter().take(count).map(|(id, _)| id).collect()
    }

    /// Hybrid peer selection (balanced approach)
    fn select_hybrid(&self, count: usize) -> Vec<PeerId> {
        let performance_count = count / 3;
        let diversity_count = count / 3;
        let security_count = count - performance_count - diversity_count;
        
        let mut selected = Vec::new();
        
        // Select high-performance peers
        let performance_peers = self.select_performance_optimized(performance_count);
        selected.extend(performance_peers);
        
        // Select diverse peers (excluding already selected)
        let remaining_peers: HashMap<PeerId, PeerMetadata> = self.peers
            .iter()
            .filter(|(id, _)| !selected.contains(id))
            .map(|(id, metadata)| (*id, metadata.clone()))
            .collect();
        
        let temp_selector = PeerSelector {
            peers: remaining_peers,
            strategy: SelectionStrategy::DiversityFocused,
            max_peers: self.max_peers,
            diversity_targets: self.diversity_targets.clone(),
        };
        
        let diversity_peers = temp_selector.select_diversity_focused(diversity_count);
        selected.extend(diversity_peers);
        
        // Select secure peers (excluding already selected)
        let remaining_peers: HashMap<PeerId, PeerMetadata> = self.peers
            .iter()
            .filter(|(id, _)| !selected.contains(id))
            .map(|(id, metadata)| (*id, metadata.clone()))
            .collect();
        
        let temp_selector = PeerSelector {
            peers: remaining_peers,
            strategy: SelectionStrategy::SecurityFocused,
            max_peers: self.max_peers,
            diversity_targets: self.diversity_targets.clone(),
        };
        
        let security_peers = temp_selector.select_security_focused(security_count);
        selected.extend(security_peers);
        
        selected
    }

    /// Get current network diversity metrics
    pub fn get_diversity_metrics(&self) -> DiversityMetrics {
        let total_peers = self.peers.len();
        if total_peers == 0 {
            return DiversityMetrics::default();
        }

        let mut region_counts = HashMap::new();
        let mut provider_counts = HashMap::new();
        let mut subnet_counts = HashMap::new();
        let high_reputation_count = self.peers.values()
            .filter(|p| p.score.reputation >= 50)
            .count();

        for peer in self.peers.values() {
            *region_counts.entry(peer.region.clone()).or_insert(0) += 1;
            *provider_counts.entry(peer.provider.clone()).or_insert(0) += 1;
            
            // Extract /24 subnet
            let subnet = match peer.ip_address {
                IpAddr::V4(ip) => {
                    let octets = ip.octets();
                    format!("{}.{}.{}", octets[0], octets[1], octets[2])
                }
                IpAddr::V6(ip) => {
                    let segments = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}", segments[0], segments[1], segments[2], segments[3])
                }
            };
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }

        DiversityMetrics {
            geographic_diversity: 1.0 - (region_counts.len() as f64 / total_peers as f64),
            network_diversity: 1.0 - (provider_counts.len() as f64 / total_peers as f64),
            subnet_diversity: subnet_counts.values().max().unwrap_or(&0) / total_peers,
            reputation_diversity: high_reputation_count as f64 / total_peers as f64,
        }
    }
}

/// Current diversity metrics
#[derive(Debug, Clone, Default)]
pub struct DiversityMetrics {
    pub geographic_diversity: f64,
    pub network_diversity: f64,
    pub subnet_diversity: f64,
    pub reputation_diversity: f64,
}

/// Classify IP address into geographic region (simplified)
pub fn classify_geographic_region(ip: &IpAddr) -> GeographicRegion {
    // This is a simplified classification - in production, use a GeoIP database
    match ip {
        IpAddr::V4(ipv4) => {
            let first_octet = ipv4.octets()[0];
            match first_octet {
                1..=126 => GeographicRegion::NorthAmerica,
                128..=191 => GeographicRegion::Europe,
                192..=223 => GeographicRegion::Asia,
                _ => GeographicRegion::Unknown,
            }
        }
        IpAddr::V6(_) => GeographicRegion::Unknown, // Simplified for IPv6
    }
}

/// Classify network provider type (simplified)
pub fn classify_network_provider(ip: &IpAddr) -> NetworkProvider {
    // This is a simplified classification - in production, use ASN databases
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            match (octets[0], octets[1]) {
                (10, _) | (172, 16..=31) | (192, 168) => NetworkProvider::Residential,
                (1..=9, _) | (11..=126, _) => NetworkProvider::DataCenter,
                _ => NetworkProvider::Unknown,
            }
        }
        IpAddr::V6(_) => NetworkProvider::Unknown,
    }
}
