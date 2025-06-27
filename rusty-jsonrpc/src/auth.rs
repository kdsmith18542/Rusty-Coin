use jsonrpc_http_server::{RequestMiddleware, RequestMiddlewareAction};
use hyper::{Request, Body, StatusCode};
use jsonrpc_core::{
    futures::FutureExt,
    Error as JsonRpcError,
    ErrorCode,
    Value,
};
use log::{info, warn, debug};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex; // Using Mutex for simplicity, consider a more persistent/secure storage in production

// In a real application, API keys would be securely stored (e.g., database, encrypted file)
// For demonstration, we'll use an in-memory hashmap.
// Permissions would also be managed more granularly.
pub struct ApiKeyManager {
    // Stores API key -> user/permission mapping
    keys: Mutex<HashMap<String, String>>,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        let mut keys = HashMap::new();
        // Example: Generate a dummy API key for testing
        // In production, these should be securely generated and stored.
        keys.insert("supersecretapikey".to_string(), "admin".to_string());
        ApiKeyManager { keys: Mutex::new(keys) }
    }

    pub async fn validate_api_key(&self, api_key: &str) -> Option<String> {
        let keys_guard = self.keys.lock().await;
        keys_guard.get(api_key).cloned()
    }

    // This would be expanded to check method-specific permissions
    pub async fn has_permission(&self, api_key: &str, method: &str) -> bool {
        let user_role = self.validate_api_key(api_key).await;
        match user_role.as_deref() {
            Some("admin") => true, // Admin has all permissions
            Some("user") => {
                // Example: 'user' role can access public methods
                !matches!(method, "send_raw_transaction" | "stop_node") // Add sensitive methods here
            },
            _ => false, // Unknown or invalid key
        }
    }
}

pub struct AuthMiddleware {
    api_key_manager: Arc<ApiKeyManager>,
}

impl AuthMiddleware {
    pub fn new(api_key_manager: Arc<ApiKeyManager>) -> Self {
        AuthMiddleware { api_key_manager }
    }

    fn auth_error_response() -> RequestMiddlewareAction {
        let error_response = jsonrpc_core::Response::single(jsonrpc_core::Output::
            Failure(JsonRpcError {
                code: ErrorCode::ServerError(401), // Custom error code for Unauthorized
                message: "Unauthorized".into(),
                data: None,
            }));
        RequestMiddlewareAction::Respond {
            // Need to convert jsonrpc_core::Response to hyper::Response<Body>
            response: hyper::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&error_response).unwrap_or_default()))
                .unwrap_or_default()
        }
    }
}

impl RequestMiddleware for AuthMiddleware {
    fn on_request(&self, request: Request<Body>) -> RequestMiddlewareAction {
        let api_key_manager = self.api_key_manager.clone();
        let auth_header = request.headers().get(hyper::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ").map(|s| s.to_string()));

        // Clone the request to pass it to the async block
        let (parts, body) = request.into_parts();
        let cloned_request = Request::from_parts(parts, body);

        RequestMiddlewareAction::Future(async move {
            let (parts, body) = cloned_request.into_parts();
            let raw_body = match hyper::body::to_bytes(body).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to read request body: {}", e);
                    return AuthMiddleware::auth_error_response();
                }
            };
            let body_str = String::from_utf8_lossy(&raw_body);
            debug!("Request body: {}", body_str);

            let json_request: serde_json::Value = match serde_json::from_str(&body_str) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Failed to parse JSON request: {}", e);
                    // This might be a malformed JSON, or a non-RPC request.
                    // For now, we'll let it proceed if it's not a JSON-RPC request.
                    // A more robust solution might handle non-JSON RPC differently.
                    return RequestMiddlewareAction::Proceed { request: Request::from_parts(parts, raw_body.into()) };
                }
            };

            let method = json_request["method"].as_str().unwrap_or_default();

            // Define public methods that don't require authentication
            let public_methods = ["get_block_count", "get_block_hash", "get_block", "get_transaction",
                                  "get_utxo_set", "masternode_count", "get_masternode_list",
                                  "get_peer_info", "get_connection_count", "get_governance_proposals",
                                  "get_governance_votes", "get_mempool_info", "get_raw_mempool", "get_blockchain_info"];


            if public_methods.contains(&method) {
                debug!("Public method: {}. Proceeding without authentication.", method);
                return RequestMiddlewareAction::Proceed { request: Request::from_parts(parts, raw_body.into()) };
            }

            match auth_header {
                Some(api_key) => {
                    if api_key_manager.has_permission(&api_key, method).await {
                        info!("Authenticated API key for method: {}", method);
                        RequestMiddlewareAction::Proceed { request: Request::from_parts(parts, raw_body.into()) }
                    } else {
                        warn!("Authentication failed: Insufficient permissions for method: {}", method);
                        AuthMiddleware::auth_error_response()
                    }
                },
                None => {
                    warn!("Authentication failed: No API key provided for method: {}", method);
                    AuthMiddleware::auth_error_response()
                }
            }
        }.boxed()) // .boxed() is needed to make the future Send + 'static
    }
} 