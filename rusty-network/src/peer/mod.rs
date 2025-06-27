//! Peer connection management

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::error::{NetworkError, NetworkResult};
use crate::protocol::{Message, Network, NetworkAddress};

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state
    Disconnected,
    /// TCP connection established
    Connected,
    /// Version handshake completed
    HandshakeComplete,
    /// Peer is ready for normal operation
    Ready,
    /// Connection is being closed
    ShuttingDown,
}

/// Peer connection information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Remote address
    pub addr: SocketAddr,
    /// User agent string
    pub user_agent: Option<String>,
    /// Protocol version
    pub version: i32,
    /// Services supported by the peer
    pub services: u64,
    /// Block height
    pub start_height: i32,
    /// Whether the peer will relay transactions
    pub relay: bool,
    /// Last message time
    pub last_seen: std::time::Instant,
    /// Connection state
    pub state: PeerState,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().unwrap(),
            user_agent: None,
            version: 0,
            services: 0,
            start_height: 0,
            relay: false,
            last_seen: std::time::Instant::now(),
            state: PeerState::Disconnected,
        }
    }
}

/// Peer connection handle
use crate::network::NetworkConfig;
use rusty_core::consensus::state::BlockchainState;
use tokio::sync::RwLock;
pub struct Peer {
    /// Connection info
    info: Arc<Mutex<PeerInfo>>,
    /// Message sender
    sender: mpsc::UnboundedSender<Message>,
    /// Message receiver
    receiver: mpsc::UnboundedReceiver<Message>,
    /// Network type
    network: Network,
    /// Network configuration
    config: Arc<NetworkConfig>,
    /// Event sender for network events
    event_tx: tokio::sync::broadcast::Sender<crate::network::NetworkEvent>,
    /// Blockchain state
    blockchain_state: Arc<RwLock<BlockchainState>>,
}

impl Peer {
    /// Create a new peer connection from an existing WebSocket stream
    pub async fn from_stream(
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        addr: SocketAddr,
        config: Arc<NetworkConfig>,
        event_tx: tokio::sync::broadcast::Sender<crate::network::NetworkEvent>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>, 
        blockchain_state: Arc<RwLock<BlockchainState>>
    ) -> NetworkResult<Self> {
        // Create channels for message passing
        let (tx, rx) = mpsc::unbounded_channel();

        // Create peer info
        let info = Arc::new(Mutex::new(PeerInfo {
            addr,
            state: PeerState::Connected,
            ..Default::default()
        }));

        // Start message processing tasks
        let peer = Self {
            info: info.clone(),
            sender: tx,
            receiver: rx,
            network: config.network,
            config,
            event_tx,
            blockchain_state,
        };

        // Start the read and write tasks
        peer.start_tasks(ws_stream, shutdown_rx).await?;

        Ok(peer)
    }

    /// Create a new peer connection by connecting to an address
    pub async fn connect(
        addr: SocketAddr,
        config: Arc<NetworkConfig>,
        event_tx: tokio::sync::broadcast::Sender<crate::network::NetworkEvent>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>, 
        blockchain_state: Arc<RwLock<BlockchainState>>
    ) -> NetworkResult<Self> {
        // Create WebSocket connection
        let url = format!("ws://{}/ws", addr);
        let (ws_stream, _) = connect_async(url).await?;

        Self::from_stream(ws_stream, addr, config, event_tx, shutdown_rx, blockchain_state).await
    }
    
    /// Start the read and write tasks
    async fn start_tasks(
        &self,
        ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>
    ) -> NetworkResult<()> {
        let (mut write, mut read) = ws_stream.split();
        let info = self.info.clone();
        let network = self.network;
        let event_tx = self.event_tx.clone();

        // Spawn read task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    ws_message = read.next() => {
                        match ws_message {
                            Some(Ok(WsMessage::Binary(data))) => {
                                // Process incoming message
                                if let Err(e) = self.handle_incoming(&data).await {
                                    log::error!("Error handling message: {}", e);
                                    break;
                                }
                            }
                            Some(Ok(WsMessage::Close(_))) => {
                                log::info!("Peer closed connection");
                                break;
                            }
                            Some(Err(e)) => {
                                log::error!("WebSocket error: {}", e);
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        log::info!("Peer read task shutting down.");
                        break;
                    }
                }
            }

            // Update connection state
            if let Ok(mut info) = info.lock().await {
                info.state = PeerState::Disconnected;
                let _ = event_tx.send(crate::network::NetworkEvent::PeerDisconnected(info.addr));
            }
        });

        // Spawn write task
        let info = self.info.clone();
        let mut receiver = self.receiver.clone();
        let mut shutdown_rx_write = self.event_tx.subscribe(); // Separate shutdown receiver for write task

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    message = receiver.recv() => {
                        if let Some(message) = message {
                            // Serialize and send message
                            if let Err(e) = Self::send_message(&mut write, &message, network).await {
                                log::error!("Failed to send message: {}", e);
                                break;
                            }

                            // Update last seen time
                            if let Ok(mut info) = info.lock().await {
                                info.last_seen = std::time::Instant::now();
                            }
                        } else {
                            // Sender half of the channel was closed
                            break;
                        }
                    }
                    _ = shutdown_rx_write.recv() => {
                        log::info!("Peer write task shutting down.");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
    
    /// Handle incoming message
    async fn handle_incoming(
        &self,
        data: &[u8],
    ) -> NetworkResult<()> {
        // Deserialize message
        let message: Message = bincode::deserialize(data)?;

        // Update last seen time
        if let Ok(mut info) = self.info.lock().await {
            info.last_seen = std::time::Instant::now();

            // Update peer info based on message
            match &message {
                Message::Version(version) => {
                    info.version = version.version;
                    info.services = version.services;
                    info.user_agent = Some(version.user_agent.clone());
                    info.start_height = version.start_height;
                    info.relay = version.relay;
                    info.state = PeerState::HandshakeComplete;

                    // Send verack
                    if let Err(e) = self.send(Message::Verack).await {
                        log::error!("Failed to send verack message to {}: {}", info.addr, e);
                    }
                }
                _ => {}
            }
        }

        // Send message received event
        let _ = self.event_tx.send(crate::network::NetworkEvent::MessageReceived(self.info.lock().await.addr, message));

        Ok(())
    }
    
    /// Send a message to the peer
    async fn send_message(
        write: &mut tokio_tungstenite::WebSocketWriteHalf<MaybeTlsStream<TcpStream>>,
        message: &Message,
        network: Network,
    ) -> NetworkResult<()> {
        // Serialize message
        let payload = bincode::serialize(message)?;
        
        // Create message header
        let header = MessageHeader::new(network, message.command(), &payload)?;
        
        // Send header and payload
        write.send(WsMessage::Binary(bincode::serialize(&header)?)).await?;
        write.send(WsMessage::Binary(payload)).await?;
        
        Ok(())
    }
    
    /// Send a message to the peer
    pub async fn send(&self, message: Message) -> NetworkResult<()> {
        self.sender.send(message)
            .map_err(|_| NetworkError::Disconnected("Failed to send message".to_string()))
    }
    
    /// Get peer information
    pub async fn info(&self) -> PeerInfo {
        self.info.lock().await.clone()
    }
    
    /// Check if the peer is connected
    pub async fn is_connected(&self) -> bool {
        self.info.lock().await.state != PeerState::Disconnected
    }
    
    /// Send a version message to the peer
    pub async fn send_version(&self, start_height: i32) -> NetworkResult<()> {
        let current_height = self.blockchain_state.read().await.get_current_block_height().unwrap_or(0) as i32;
        let version_message = Message::Version(crate::protocol::VersionMessage {
            version: self.config.protocol_version,
            services: self.config.services,
            timestamp: chrono::Utc::now().timestamp(),
            receiver_addr: NetworkAddress::new(
                self.config.services,
                self.info.lock().await.addr.ip().to_string(),
                self.info.lock().await.addr.port(),
            ),
            sender_addr: NetworkAddress::new(
                self.config.services,
                self.config.bind_address.ip().to_string(),
                self.config.bind_address.port(),
            ),
            nonce: rand::random(),
            user_agent: self.config.user_agent.clone(),
            start_height: current_height,
            relay: true,
        });
        self.send(version_message).await
    }

    /// Disconnect from the peer
    pub async fn disconnect(&self) {
        if let Ok(mut info) = self.info.lock().await {
            info.state = PeerState::ShuttingDown;
        }
        // The connection will be closed when the tasks exit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_peer_connect() {
        // This is a simple test that just checks if we can create a peer
        // In a real test, you would need a mock WebSocket server
        let config = Arc::new(crate::network::NetworkConfig::default());
        let (event_tx, _) = tokio::sync::broadcast::channel(100);
        let shutdown_rx = event_tx.subscribe();
        let _peer = Peer::connect("127.0.0.1:8333".parse().unwrap(), config, event_tx, shutdown_rx).await;
        // The connection will fail, but we're just testing that the code compiles
    }
}
