use hyper::{Body, Request};
use jsonrpc_http_server::{hyper, RequestMiddleware, RequestMiddlewareAction};
use log::{debug, warn};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum PermissionLevel {
    ReadOnly,   // Can read blockchain data, get info
    Standard,   // Can submit transactions, mine blocks
    Admin,      // Can access governance, masternode operations
    SuperAdmin, // Can access all methods including dangerous operations
}

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key: String,
    pub permissions: PermissionLevel,
    pub name: String,
}

pub struct ApiKeyManager {
    api_keys: HashMap<String, ApiKey>,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        let mut api_keys = HashMap::new();

        // Default API keys for development/testing
        // In production, these should be loaded from secure configuration
        api_keys.insert(
            "readonly_key_123".to_string(),
            ApiKey {
                key: "readonly_key_123".to_string(),
                permissions: PermissionLevel::ReadOnly,
                name: "Read-only client".to_string(),
            },
        );

        api_keys.insert(
            "standard_key_456".to_string(),
            ApiKey {
                key: "standard_key_456".to_string(),
                permissions: PermissionLevel::Standard,
                name: "Standard client".to_string(),
            },
        );

        api_keys.insert(
            "admin_key_789".to_string(),
            ApiKey {
                key: "admin_key_789".to_string(),
                permissions: PermissionLevel::Admin,
                name: "Admin client".to_string(),
            },
        );

        api_keys.insert(
            "superadmin_key_000".to_string(),
            ApiKey {
                key: "superadmin_key_000".to_string(),
                permissions: PermissionLevel::SuperAdmin,
                name: "Super admin client".to_string(),
            },
        );

        ApiKeyManager { api_keys }
    }

    pub fn validate_api_key(&self, api_key: &str) -> Option<&ApiKey> {
        self.api_keys.get(api_key)
    }

    pub fn has_permission(&self, api_key: &str, method: &str) -> bool {
        let Some(key_info) = self.validate_api_key(api_key) else {
            warn!("Invalid API key attempted: {}", api_key);
            return false;
        };

        let required_permission = Self::get_required_permission(method);
        Self::check_permission(&key_info.permissions, &required_permission)
    }

    fn get_required_permission(method: &str) -> PermissionLevel {
        match method {
            // Read-only methods
            "get_block_count"
            | "get_block_hash"
            | "get_block"
            | "get_transaction"
            | "get_utxo_set"
            | "get_governance_proposals"
            | "get_governance_votes"
            | "get_mining_info"
            | "get_masternode_status"
            | "get_masternode_list"
            | "get_ticket_pool_info"
            | "get_active_tickets"
            | "get_proposal_status"
            | "list_governance_proposals"
            | "get_governance_proposal"
            | "get_proposal_votes"
            | "get_governance_params"
            | "get_treasury_balance"
            | "get_treasury_history"
            | "get_ticket_info"
            | "getbalance"
            | "listunspent"
            | "getwalletinfo" => PermissionLevel::ReadOnly,

            // Standard methods (transaction operations, mining)
            "send_raw_transaction"
            | "generate"
            | "submit_block"
            | "mine_block"
            | "purchase_tickets"
            | "vote_on_block" => PermissionLevel::Standard,

            // Admin methods (governance, masternode operations)
            "register_masternode"
            | "masternode_ping"
            | "create_governance_proposal"
            | "vote_on_proposal"
            | "finalize_proposal" => PermissionLevel::Admin,

            // Super admin methods (network sync operations)
            "start_sync" => PermissionLevel::SuperAdmin,

            // Default to highest permission level for unknown methods
            _ => {
                warn!(
                    "Unknown method '{}' - requiring SuperAdmin permission",
                    method
                );
                PermissionLevel::SuperAdmin
            }
        }
    }

    fn check_permission(
        user_permission: &PermissionLevel,
        required_permission: &PermissionLevel,
    ) -> bool {
        use PermissionLevel::*;
        match (user_permission, required_permission) {
            (SuperAdmin, _) => true,
            (Admin, SuperAdmin) => false,
            (Admin, _) => true,
            (Standard, Admin | SuperAdmin) => false,
            (Standard, _) => true,
            (ReadOnly, ReadOnly) => true,
            (ReadOnly, _) => false,
        }
    }

    pub fn add_api_key(&mut self, key: String, permissions: PermissionLevel, name: String) {
        let api_key = ApiKey {
            key: key.clone(),
            permissions,
            name,
        };
        self.api_keys.insert(key, api_key);
    }

    pub fn remove_api_key(&mut self, key: &str) -> bool {
        self.api_keys.remove(key).is_some()
    }
}

pub struct AuthMiddleware {
    api_key_manager: ApiKeyManager,
}

impl AuthMiddleware {
    pub fn new() -> Self {
        AuthMiddleware {
            api_key_manager: ApiKeyManager::new(),
        }
    }

    fn extract_api_key(&self, request: &Request<Body>) -> Option<String> {
        // Try Authorization header first (Bearer token)
        if let Some(auth_header) = request.headers().get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    return Some(auth_str[7..].to_string());
                }
            }
        }

        // Try X-API-Key header
        if let Some(api_key_header) = request.headers().get("x-api-key") {
            if let Ok(api_key) = api_key_header.to_str() {
                return Some(api_key.to_string());
            }
        }

        None
    }
}

impl RequestMiddleware for AuthMiddleware {
    fn on_request(&self, request: Request<Body>) -> RequestMiddlewareAction {
        debug!("Processing authentication for request");

        // Extract API key from headers
        let api_key = match self.extract_api_key(&request) {
            Some(key) => key,
            None => {
                warn!("No API key provided in request");
                let response = hyper::Response::builder()
                    .status(401)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"error": {"code": -32001, "message": "Authentication required. Provide API key via Authorization header (Bearer token) or X-API-Key header."}}"#))
                    .unwrap();
                return RequestMiddlewareAction::Respond {
                    should_validate_hosts: true,
                    response: Box::pin(async move { Ok(response) }),
                };
            }
        };

        // Validate API key exists
        if self.api_key_manager.validate_api_key(&api_key).is_none() {
            warn!("Invalid API key attempted: {}", api_key);
            let response = hyper::Response::builder()
                .status(401)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"error": {"code": -32002, "message": "Invalid API key"}}"#,
                ))
                .unwrap();
            return RequestMiddlewareAction::Respond {
                should_validate_hosts: true,
                response: Box::pin(async move { Ok(response) }),
            };
        }

        // For method-specific permission checking, we'd need to parse the body
        // This is a simplified version - in practice, you might want to implement
        // a more sophisticated approach that can handle the request body
        debug!("API key {} authenticated successfully", api_key);

        RequestMiddlewareAction::Proceed {
            should_continue_on_invalid_cors: false,
            request,
        }
    }
}
