//! WebSocket server for JSON-RPC real-time notifications
//!
//! This module provides WebSocket support for the JSON-RPC API, enabling
//! real-time notifications for blocks, transactions, and mempool changes.

use futures_util::{SinkExt, StreamExt};
use jsonrpc_core::IoHandler;
use log::{debug, error, info};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::auth::ApiKeyManager;

/// Notification types for WebSocket subscriptions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NotificationType {
    NewBlock,
    NewTransaction,
    MempoolChange,
    BlockConfirmation,
    ProposalUpdate,
}

/// WebSocket notification payload
#[derive(Debug, Clone)]
pub struct Notification {
    pub notification_type: NotificationType,
    pub data: Value,
}

/// WebSocket connection manager
pub struct WebSocketManager {
    /// Broadcast channel for notifications
    notification_tx: broadcast::Sender<Notification>,
    /// Active WebSocket connections
    connections: Arc<RwLock<HashMap<u64, broadcast::Receiver<Notification>>>>,
    /// Connection ID counter
    next_connection_id: Arc<RwLock<u64>>,
    /// RPC handler for processing requests
    rpc_handler: Arc<IoHandler>,
    /// API key manager for authentication
    api_key_manager: Arc<ApiKeyManager>,
}

impl WebSocketManager {
    /// Create a new WebSocket manager
    pub fn new(rpc_handler: IoHandler, api_key_manager: Arc<ApiKeyManager>) -> Self {
        let (notification_tx, _) = broadcast::channel(1000);

        Self {
            notification_tx,
            connections: Arc::new(RwLock::new(HashMap::new())),
            next_connection_id: Arc::new(RwLock::new(0)),
            rpc_handler: Arc::new(rpc_handler),
            api_key_manager,
        }
    }

    /// Get the notification sender for broadcasting
    pub fn notification_sender(&self) -> broadcast::Sender<Notification> {
        self.notification_tx.clone()
    }

    /// Handle a new WebSocket connection
    pub async fn handle_connection(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
    ) {
        info!("New WebSocket connection from {}", peer_addr);

        // Accept the WebSocket handshake
        let ws_stream = match accept_async(stream).await {
            Ok(ws) => ws,
            Err(e) => {
                error!("WebSocket handshake failed: {}", e);
                return;
            }
        };

        // Generate connection ID
        let connection_id = {
            let mut id = self.next_connection_id.write().await;
            *id += 1;
            *id
        };

        // Create notification receiver for this connection (will be used in task)
        let mut notification_rx = self.notification_tx.subscribe();

        // Track connection ID (we don't store the receiver since it's moved into the task)
        {
            let mut connections = self.connections.write().await;
            // Insert a placeholder receiver just to track the connection
            connections.insert(connection_id, self.notification_tx.subscribe());
        }

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let rpc_handler = self.rpc_handler.clone();
        let connections = self.connections.clone();
        let notification_tx = self.notification_tx.clone();

        // Spawn task to handle connection
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Handle incoming WebSocket messages
                    msg = ws_receiver.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                debug!("Received WebSocket message: {}", text);

                                // Parse JSON-RPC request
                                if let Ok(request_value) = serde_json::from_str::<Value>(&text) {
                                    // Extract method and id from request
                                    let method = request_value.get("method")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("");
                                    let request_id = request_value.get("id").cloned();

                                    // Handle subscription requests
                                    if method.starts_with("subscribe_") {
                                        // Extract subscription type
                                        let notification_type = if method == "subscribe_newblock" {
                                            Some(NotificationType::NewBlock)
                                        } else if method == "subscribe_newtransaction" {
                                            Some(NotificationType::NewTransaction)
                                        } else if method == "subscribe_mempoolchange" {
                                            Some(NotificationType::MempoolChange)
                                        } else if method == "subscribe_blockconfirmation" {
                                            Some(NotificationType::BlockConfirmation)
                                        } else if method == "subscribe_proposalupdate" {
                                            Some(NotificationType::ProposalUpdate)
                                        } else {
                                            None
                                        };

                                        if let Some(nt) = notification_type {
                                            // Subscription successful
                                            let response = json!({
                                                "jsonrpc": "2.0",
                                                "id": request_id,
                                                "result": {
                                                    "subscription_id": connection_id,
                                                    "notification_type": format!("{:?}", nt),
                                                    "status": "subscribed"
                                                }
                                            });

                                            if let Err(e) = ws_sender.send(Message::Text(response.to_string())).await {
                                                error!("Failed to send subscription response: {}", e);
                                                break;
                                            }
                                        } else {
                                            // Unknown subscription type
                                            let response = json!({
                                                "jsonrpc": "2.0",
                                                "id": request_id,
                                                "error": {
                                                    "code": -32601,
                                                    "message": "Method not found"
                                                }
                                            });

                                            if let Err(e) = ws_sender.send(Message::Text(response.to_string())).await {
                                                error!("Failed to send error response: {}", e);
                                                break;
                                            }
                                        }
                                    } else {
                                        // Regular JSON-RPC request - process through handler
                                        // Note: jsonrpc_core IoHandler.handle_request returns a future
                                        // We'll handle it asynchronously
                                        let handler = rpc_handler.clone();
                                        let text_clone = text.clone();

                                        // Use handle_request which returns a future
                                        let response_future = handler.handle_request(&text_clone);
                                        let response = response_future.await;

                                        // Convert response to string
                                        if let Some(resp) = response {
                                            let resp_str = serde_json::to_string(&resp).unwrap_or_else(|_| {
                                                json!({
                                                    "jsonrpc": "2.0",
                                                    "error": {
                                                        "code": -32603,
                                                        "message": "Internal error: failed to serialize response"
                                                    }
                                                }).to_string()
                                            });

                                            if let Err(e) = ws_sender.send(Message::Text(resp_str)).await {
                                                error!("Failed to send RPC response: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    // Invalid JSON-RPC request
                                    let response = json!({
                                        "jsonrpc": "2.0",
                                        "id": serde_json::Value::Null,
                                        "error": {
                                            "code": -32700,
                                            "message": "Parse error"
                                        }
                                    });

                                    if let Err(e) = ws_sender.send(Message::Text(response.to_string())).await {
                                        error!("Failed to send parse error: {}", e);
                                        break;
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) => {
                                info!("WebSocket connection {} closed", connection_id);
                                break;
                            }
                            Some(Ok(Message::Ping(data))) => {
                                if let Err(e) = ws_sender.send(Message::Pong(data)).await {
                                    error!("Failed to send pong: {}", e);
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                error!("WebSocket error: {}", e);
                                break;
                            }
                            None => {
                                // Stream ended
                                break;
                            }
                            _ => {}
                        }
                    }
                    // Handle notifications from broadcast channel
                    Ok(notification) = notification_rx.recv() => {
                        let notification_json = json!({
                            "jsonrpc": "2.0",
                            "method": "notification",
                            "params": {
                                "type": format!("{:?}", notification.notification_type),
                                "data": notification.data
                            }
                        });

                        if let Err(e) = ws_sender.send(Message::Text(notification_json.to_string())).await {
                            debug!("Failed to send notification (connection may be closed): {}", e);
                            break;
                        }
                    }
                }
            }

            // Clean up connection
            let mut connections = connections.write().await;
            connections.remove(&connection_id);
            info!("WebSocket connection {} removed", connection_id);
        });
    }

    /// Broadcast a notification to all connected clients
    pub async fn broadcast_notification(&self, notification: Notification) {
        let _ = self.notification_tx.send(notification);
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}

/// Start WebSocket server
pub async fn start_websocket_server(
    addr: &str,
    rpc_handler: IoHandler,
    api_key_manager: Arc<ApiKeyManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("WebSocket server listening on {}", addr);

    let manager = Arc::new(WebSocketManager::new(rpc_handler, api_key_manager));

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let manager_clone = manager.clone();
                tokio::spawn(async move {
                    manager_clone.handle_connection(stream, peer_addr).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
