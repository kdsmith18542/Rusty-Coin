//! Peer management and DoS mitigation for Rusty Coin P2P network
//!
//! This module implements peer scoring, connection limits, and rate limiting
//! per docs/specs/07_p2p_protocol_spec.md Section 7.1.3

use libp2p::PeerId;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::peer_selection::{
    classify_geographic_region, classify_network_provider, PeerMetadata, PeerScore,
};

/// Per-peer rate limiting information
#[derive(Debug, Clone)]
struct PeerRateLimit {
    /// Timestamp of last INV message
    last_inv_message: Option<Instant>,
    /// Number of INV messages in current window
    inv_message_count: u32,
    /// Timestamp of last GetHeaders message
    last_getheaders_message: Option<Instant>,
    /// Number of GetHeaders messages in current window
    getheaders_message_count: u32,
    /// Timestamp of last BlockRequest message
    last_blockrequest_message: Option<Instant>,
    /// Number of BlockRequest messages in current window
    blockrequest_message_count: u32,
    /// Timestamp of last ProofRequest message
    last_proofrequest_message: Option<Instant>,
    /// Number of ProofRequest messages in current window
    proofrequest_message_count: u32,
    /// Window start time for rate limiting
    window_start: Instant,
}

impl PeerRateLimit {
    fn new() -> Self {
        Self {
            last_inv_message: None,
            inv_message_count: 0,
            last_getheaders_message: None,
            getheaders_message_count: 0,
            last_blockrequest_message: None,
            blockrequest_message_count: 0,
            last_proofrequest_message: None,
            proofrequest_message_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Check if INV message is allowed (rate limit: 10 per second)
    fn check_inv_rate_limit(&mut self, max_per_second: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            // Reset window
            self.window_start = now;
            self.inv_message_count = 0;
        }

        if self.inv_message_count >= max_per_second {
            warn!("Rate limit exceeded for INV messages from peer");
            false
        } else {
            self.inv_message_count += 1;
            self.last_inv_message = Some(now);
            true
        }
    }

    /// Check if GetHeaders message is allowed (rate limit: 5 per second)
    fn check_getheaders_rate_limit(&mut self, max_per_second: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            // Reset window
            self.window_start = now;
            self.getheaders_message_count = 0;
        }

        if self.getheaders_message_count >= max_per_second {
            warn!("Rate limit exceeded for GetHeaders messages from peer");
            false
        } else {
            self.getheaders_message_count += 1;
            self.last_getheaders_message = Some(now);
            true
        }
    }

    /// Check if BlockRequest message is allowed (rate limit: 2 per second)
    fn check_blockrequest_rate_limit(&mut self, max_per_second: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            // Reset window
            self.window_start = now;
            self.blockrequest_message_count = 0;
        }

        if self.blockrequest_message_count >= max_per_second {
            warn!("Rate limit exceeded for BlockRequest messages from peer");
            false
        } else {
            self.blockrequest_message_count += 1;
            self.last_blockrequest_message = Some(now);
            true
        }
    }

    /// Check if ProofRequest message is allowed (rate limit: 1 per second)
    fn check_proofrequest_rate_limit(&mut self, max_per_second: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            // Reset window
            self.window_start = now;
            self.proofrequest_message_count = 0;
        }

        if self.proofrequest_message_count >= max_per_second {
            warn!("Rate limit exceeded for ProofRequest messages from peer");
            false
        } else {
            self.proofrequest_message_count += 1;
            self.last_proofrequest_message = Some(now);
            true
        }
    }
}

/// Peer connection information
#[derive(Debug, Clone)]
struct PeerConnection {
    peer_id: PeerId,
    ip_address: Option<IpAddr>,
    is_outbound: bool,
    connected_at: Instant,
    score: PeerScore,
    rate_limit: PeerRateLimit,
    protocol_violations: u32,
    failed_requests: u32,
    successful_requests: u32,
}

impl PeerConnection {
    fn new(peer_id: PeerId, is_outbound: bool, ip_address: Option<IpAddr>) -> Self {
        Self {
            peer_id,
            ip_address,
            is_outbound,
            connected_at: Instant::now(),
            score: PeerScore::new(),
            rate_limit: PeerRateLimit::new(),
            protocol_violations: 0,
            failed_requests: 0,
            successful_requests: 0,
        }
    }

    /// Record a successful interaction
    fn record_success(&mut self, response_time: Duration) {
        self.score.record_success(response_time);
        self.successful_requests += 1;
    }

    /// Record a failed interaction
    fn record_failure(&mut self) {
        self.score.record_failure();
        self.failed_requests += 1;
    }

    /// Record a protocol violation
    fn record_violation(&mut self) {
        self.protocol_violations += 1;
        self.score.protocol_compliance = (self.score.protocol_compliance * 0.9).max(0.0);
        if self.protocol_violations > 5 {
            warn!(
                "Peer {} has {} protocol violations",
                self.peer_id, self.protocol_violations
            );
        }
    }
}

/// Peer manager for tracking peers, enforcing limits, and managing connections
pub struct PeerManager {
    /// Map of connected peers
    peers: HashMap<PeerId, PeerConnection>,
    /// Maximum outbound connections
    max_outbound_connections: usize,
    /// Maximum inbound connections
    max_inbound_connections: usize,
    /// Rate limit: max INV messages per second per peer
    max_inv_per_second: u32,
    /// Rate limit: max GetHeaders messages per second per peer
    max_getheaders_per_second: u32,
    /// Rate limit: max BlockRequest messages per second per peer
    max_blockrequest_per_second: u32,
    /// Rate limit: max ProofRequest messages per second per peer
    max_proofrequest_per_second: u32,
    /// Blacklisted peer IDs
    blacklisted_peers: std::collections::HashSet<PeerId>,
}

impl PeerManager {
    /// Create a new peer manager with the given limits
    pub fn new(max_outbound_connections: usize, max_inbound_connections: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_outbound_connections,
            max_inbound_connections,
            max_inv_per_second: 10, // Per spec: reasonable rate limit for INV
            max_getheaders_per_second: 5, // Per spec: reasonable rate limit for GetHeaders
            max_blockrequest_per_second: 2, // Per spec: reasonable rate limit for BlockRequest
            max_proofrequest_per_second: 1, // Per spec: conservative rate limit for ProofRequest
            blacklisted_peers: std::collections::HashSet::new(),
        }
    }

    /// Check if a peer is blacklisted
    pub fn is_blacklisted(&self, peer_id: &PeerId) -> bool {
        self.blacklisted_peers.contains(peer_id)
    }

    /// Blacklist a peer (permanent ban)
    pub fn blacklist_peer(&mut self, peer_id: PeerId) {
        info!("Blacklisting peer {}", peer_id);
        self.blacklisted_peers.insert(peer_id);
        self.peers.remove(&peer_id);
    }

    /// Check if we can accept a new outbound connection
    pub fn can_accept_outbound(&self) -> bool {
        let outbound_count = self.peers.values().filter(|p| p.is_outbound).count();
        outbound_count < self.max_outbound_connections
    }

    /// Check if we can accept a new inbound connection
    pub fn can_accept_inbound(&self) -> bool {
        let inbound_count = self.peers.values().filter(|p| !p.is_outbound).count();
        inbound_count < self.max_inbound_connections
    }

    /// Add a new peer connection
    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        is_outbound: bool,
        ip_address: Option<IpAddr>,
    ) -> bool {
        if self.is_blacklisted(&peer_id) {
            warn!("Attempted to add blacklisted peer {}", peer_id);
            return false;
        }

        if self.peers.contains_key(&peer_id) {
            debug!("Peer {} already tracked", peer_id);
            return true;
        }

        // Check connection limits
        if is_outbound && !self.can_accept_outbound() {
            warn!(
                "Cannot accept new outbound connection: limit reached ({}/{})",
                self.peers.values().filter(|p| p.is_outbound).count(),
                self.max_outbound_connections
            );
            return false;
        }

        if !is_outbound && !self.can_accept_inbound() {
            warn!(
                "Cannot accept new inbound connection: limit reached ({}/{})",
                self.peers.values().filter(|p| !p.is_outbound).count(),
                self.max_inbound_connections
            );
            return false;
        }

        let connection = PeerConnection::new(peer_id, is_outbound, ip_address);
        self.peers.insert(peer_id, connection);
        debug!("Added peer {} (outbound: {})", peer_id, is_outbound);
        true
    }

    /// Remove a peer connection
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        if self.peers.remove(peer_id).is_some() {
            debug!("Removed peer {}", peer_id);
        }
    }

    /// Get peer connection info
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerConnection> {
        self.peers.get(peer_id)
    }

    /// Get mutable peer connection info
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerConnection> {
        self.peers.get_mut(peer_id)
    }

    /// Check if INV message is allowed (rate limiting)
    pub fn check_inv_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.rate_limit
                .check_inv_rate_limit(self.max_inv_per_second)
        } else {
            false
        }
    }

    /// Check if GetHeaders message is allowed (rate limiting)
    pub fn check_getheaders_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.rate_limit
                .check_getheaders_rate_limit(self.max_getheaders_per_second)
        } else {
            false
        }
    }

    /// Check if BlockRequest message is allowed (rate limiting)
    pub fn check_blockrequest_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.rate_limit
                .check_blockrequest_rate_limit(self.max_blockrequest_per_second)
        } else {
            false
        }
    }

    /// Check if ProofRequest message is allowed (rate limiting)
    pub fn check_proof_request_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.rate_limit
                .check_proofrequest_rate_limit(self.max_proofrequest_per_second)
        } else {
            false
        }
    }

    /// Record a successful interaction with a peer
    pub fn record_success(&mut self, peer_id: &PeerId, response_time: Duration) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.record_success(response_time);
        }
    }

    /// Record a failed interaction with a peer
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.record_failure();

            // Auto-blacklist if too many failures
            if peer.failed_requests > 20 && peer.score.reputation < -50 {
                self.blacklist_peer(*peer_id);
            }
        }
    }

    /// Record a protocol violation
    pub fn record_violation(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.record_violation();

            // Auto-blacklist if too many violations
            if peer.protocol_violations > 10 {
                self.blacklist_peer(*peer_id);
            }
        }
    }

    /// Get all peer IDs
    pub fn get_peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().cloned().collect()
    }

    /// Get outbound peer count
    pub fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_outbound).count()
    }

    /// Get inbound peer count
    pub fn inbound_count(&self) -> usize {
        self.peers.values().filter(|p| !p.is_outbound).count()
    }

    /// Get total peer count
    pub fn total_count(&self) -> usize {
        self.peers.len()
    }

    /// Clean up stale peers (peers that haven't been seen in a while)
    pub fn cleanup_stale_peers(&mut self, max_idle_time: Duration) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (peer_id, peer) in &self.peers {
            let idle_time = now.duration_since(peer.score.last_seen);
            if idle_time > max_idle_time {
                to_remove.push(*peer_id);
            }
        }

        for peer_id in to_remove {
            info!("Removing stale peer {}", peer_id);
            self.remove_peer(&peer_id);
        }
    }

    /// Get peer scores for selection
    pub fn get_peer_metadata(&self) -> Vec<PeerMetadata> {
        self.peers
            .values()
            .map(|conn| {
                let ip = conn.ip_address.unwrap_or_else(|| {
                    // Default to localhost if IP is unknown
                    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
                });
                PeerMetadata {
                    peer_id: conn.peer_id,
                    ip_address: ip,
                    score: conn.score.clone(),
                    region: classify_geographic_region(&ip),
                    provider: classify_network_provider(&ip),
                    connection_count: 1,
                    is_outbound: conn.is_outbound,
                    connected_at: conn.connected_at,
                }
            })
            .collect()
    }
}
