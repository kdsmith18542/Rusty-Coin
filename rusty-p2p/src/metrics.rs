use prometheus::{Registry, IntCounter, IntGauge, Histogram, Gauge, IntCounterVec, HistogramOpts, Encoder, TextEncoder};
use lazy_static::lazy_static;
use std::net::SocketAddr;
use hyper::{Body, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use log::{error, warn, info, debug};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MetricsError {
    #[error("Prometheus initialization failed: {0}")]
    InitializationError(#[from] prometheus::Error),
    #[error("Metrics collection failed")]
    CollectionError,
}

lazy_static! {
    pub static ref FRAGMENTATION_METRICS: FragmentationMetrics = FragmentationMetrics::new()
        .expect("Failed to initialize fragmentation metrics");

    pub static ref P2P_METRICS: P2PMetrics = P2PMetrics::new()
        .expect("Failed to initialize P2P metrics");
}

pub struct FragmentationMetrics {
    pub messages_reassembled: IntCounter,
    pub chunks_received: IntCounter,
    pub timeouts: IntCounter,
    pub bytes_processed: IntCounter,
    pub reassembly_time: Histogram,
    pub chunk_size_dist: Histogram,
    pub error_rates: IntCounterVec,
    pub buffer_usage: Gauge,
}

impl FragmentationMetrics {
    pub fn new() -> Result<Self, MetricsError> {
        info!("Initializing fragmentation metrics");
        
        let metrics = Self {
            messages_reassembled: IntCounter::new(
                "p2p_fragmentation_messages_reassembled_total",
                "Total messages successfully reassembled"
            ).map_err(|e| {
                error!("Failed to create messages_reassembled metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            chunks_received: IntCounter::new(
                "p2p_fragmentation_chunks_received_total", 
                "Total chunks received"
            ).map_err(|e| {
                error!("Failed to create chunks_received metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            timeouts: IntCounter::new(
                "p2p_fragmentation_timeouts_total",
                "Total partial message timeouts"
            ).map_err(|e| {
                error!("Failed to create timeouts metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            bytes_processed: IntCounter::new(
                "p2p_fragmentation_bytes_processed_total",
                "Total bytes processed"
            ).map_err(|e| {
                error!("Failed to create bytes_processed metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            reassembly_time: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_fragmentation_reassembly_time_seconds",
                    "Time taken to reassemble full messages"
                ).buckets(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0])
            ).map_err(|e| {
                error!("Failed to create reassembly_time metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            chunk_size_dist: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_fragmentation_chunk_size_bytes",
                    "Distribution of chunk sizes"
                ).buckets(vec![1024.0, 8192.0, 32768.0, 131072.0, 524288.0, 1048576.0])
            ).map_err(|e| {
                error!("Failed to create chunk_size_dist metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            error_rates: IntCounterVec::new(
                "p2p_fragmentation_errors_total",
                "Error types encountered",
                &["type"]
            ).map_err(|e| {
                error!("Failed to create error_rates metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
            
            buffer_usage: Gauge::new(
                "p2p_fragmentation_buffer_usage",
                "Current reassembly buffers in use"
            ).map_err(|e| {
                error!("Failed to create buffer_usage metric: {}", e);
                MetricsError::InitializationError(e)
            })?,
        };
        
        info!("Successfully initialized all fragmentation metrics");
        Ok(metrics)
    }
}

/// Comprehensive P2P network metrics
pub struct P2PMetrics {
    // Connection metrics
    pub active_connections: IntGauge,
    pub outbound_connections: IntGauge,
    pub inbound_connections: IntGauge,
    pub connection_failures: IntCounter,
    pub connection_duration: Histogram,

    // Traffic metrics
    pub bytes_sent: IntCounter,
    pub bytes_received: IntCounter,
    pub messages_sent: IntCounterVec,
    pub messages_received: IntCounterVec,
    pub bandwidth_utilization: Gauge,

    // Performance metrics
    pub message_latency: Histogram,
    pub block_propagation_time: Histogram,
    pub tx_propagation_time: Histogram,
    pub peer_discovery_time: Histogram,
    pub sync_performance: Gauge,

    // Security metrics
    pub invalid_messages: IntCounter,
    pub rate_limit_violations: IntCounter,
    pub peer_reputation: Histogram,
    pub security_incidents: IntCounterVec,
    pub auth_failures: IntCounter,

    // Protocol-specific metrics
    pub block_sync_requests: IntCounter,
    pub block_sync_responses: IntCounter,
    pub tx_propagation_success: IntCounter,
    pub masternode_messages: IntCounterVec,
    pub compact_block_efficiency: Gauge,
}

impl P2PMetrics {
    pub fn new() -> Result<Self, MetricsError> {
        info!("Initializing comprehensive P2P metrics");

        let metrics = Self {
            // Connection metrics
            active_connections: IntGauge::new(
                "p2p_connections_active",
                "Number of active P2P connections"
            )?,

            outbound_connections: IntGauge::new(
                "p2p_connections_outbound",
                "Number of outbound P2P connections"
            )?,

            inbound_connections: IntGauge::new(
                "p2p_connections_inbound",
                "Number of inbound P2P connections"
            )?,

            connection_failures: IntCounter::new(
                "p2p_connection_failures_total",
                "Total P2P connection failures"
            )?,

            connection_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_connection_duration_seconds",
                    "Duration of P2P connections"
                ).buckets(vec![1.0, 10.0, 60.0, 300.0, 1800.0, 3600.0])
            )?,

            // Traffic metrics
            bytes_sent: IntCounter::new(
                "p2p_bytes_sent_total",
                "Total bytes sent over P2P network"
            )?,

            bytes_received: IntCounter::new(
                "p2p_bytes_received_total",
                "Total bytes received over P2P network"
            )?,

            messages_sent: IntCounterVec::new(
                "p2p_messages_sent_total",
                "Total messages sent by type",
                &["message_type"]
            )?,

            messages_received: IntCounterVec::new(
                "p2p_messages_received_total",
                "Total messages received by type",
                &["message_type"]
            )?,

            bandwidth_utilization: Gauge::new(
                "p2p_bandwidth_utilization_bytes_per_second",
                "Current bandwidth utilization"
            )?,

            // Performance metrics
            message_latency: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_message_latency_seconds",
                    "Message round-trip latency"
                ).buckets(vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0])
            )?,

            block_propagation_time: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_block_propagation_seconds",
                    "Time for block to propagate across network"
                ).buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0])
            )?,

            tx_propagation_time: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_tx_propagation_seconds",
                    "Time for transaction to propagate across network"
                ).buckets(vec![0.01, 0.1, 0.5, 1.0, 2.0, 5.0])
            )?,

            peer_discovery_time: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_peer_discovery_seconds",
                    "Time to discover new peers"
                ).buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0, 300.0])
            )?,

            sync_performance: Gauge::new(
                "p2p_sync_blocks_per_second",
                "Block synchronization performance"
            )?,

            // Security metrics
            invalid_messages: IntCounter::new(
                "p2p_invalid_messages_total",
                "Total invalid messages rejected"
            )?,

            rate_limit_violations: IntCounter::new(
                "p2p_rate_limit_violations_total",
                "Total rate limit violations"
            )?,

            peer_reputation: Histogram::with_opts(
                HistogramOpts::new(
                    "p2p_peer_reputation_score",
                    "Distribution of peer reputation scores"
                ).buckets(vec![-100.0, -50.0, 0.0, 25.0, 50.0, 75.0, 100.0])
            )?,

            security_incidents: IntCounterVec::new(
                "p2p_security_incidents_total",
                "Security incidents by type",
                &["incident_type"]
            )?,

            auth_failures: IntCounter::new(
                "p2p_auth_failures_total",
                "Total authentication failures"
            )?,

            // Protocol-specific metrics
            block_sync_requests: IntCounter::new(
                "p2p_block_sync_requests_total",
                "Total block sync requests"
            )?,

            block_sync_responses: IntCounter::new(
                "p2p_block_sync_responses_total",
                "Total block sync responses"
            )?,

            tx_propagation_success: IntCounter::new(
                "p2p_tx_propagation_success_total",
                "Successful transaction propagations"
            )?,

            masternode_messages: IntCounterVec::new(
                "p2p_masternode_messages_total",
                "Masternode messages by type",
                &["message_type"]
            )?,

            compact_block_efficiency: Gauge::new(
                "p2p_compact_block_efficiency_percent",
                "Compact block bandwidth efficiency percentage"
            )?,
        };

        info!("Successfully initialized comprehensive P2P metrics");
        Ok(metrics)
    }
}

pub async fn serve_metrics(addr: SocketAddr) {
    info!("Starting metrics server on {}:9090", addr.ip());
    
    let service = make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(|_| async {
            debug!("Metrics endpoint accessed");
            let encoder = TextEncoder::new();
            let mut buffer = vec![];
            encoder.encode(&prometheus::gather(), &mut buffer)
                .map_err(|e| {
                    error!("Failed to encode metrics: {}", e);
                    e
                })?;
            Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
        }))
    });

    Server::bind(&addr).serve(service).await.unwrap_or_else(|e| {
        error!("Metrics server failed: {}", e);
    });
}
