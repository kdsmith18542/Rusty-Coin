//! Authentication and authorization for RPC methods.

use jsonrpsee::core::Error;
use jsonrpsee::types::error::{CallError, ErrorObjectOwned};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Permission levels for RPC methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionLevel {
    /// Read-only access (block info, transaction info, etc.)
    ReadOnly,
    /// Standard operations (send transactions, wallet operations)
    Standard,
    /// Administrative operations (node management, mining control)
    Admin,
    /// Super administrative operations (protocol changes, debug operations)
    SuperAdmin,
}

/// API key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub key: String,
    pub permission_level: PermissionLevel,
    pub description: String,
    pub enabled: bool,
}

/// Authentication manager for RPC methods
pub struct AuthManager {
    api_keys: Arc<Mutex<HashMap<String, ApiKey>>>,
    method_permissions: HashMap<String, PermissionLevel>,
}

impl AuthManager {
    pub fn new() -> Self {
        let mut method_permissions = HashMap::new();

        // Define permission requirements for each RPC method
        // Read-only methods
        method_permissions.insert(
            "rusty_coin_get_block_count".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_block_hash".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_block".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_transaction".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_blockchain_info".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_mempool_info".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_peer_info".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_get_network_info".to_string(),
            PermissionLevel::ReadOnly,
        );

        // Standard operations
        method_permissions.insert(
            "rusty_coin_send_raw_transaction".to_string(),
            PermissionLevel::Standard,
        );
        method_permissions.insert(
            "rusty_coin_create_raw_transaction".to_string(),
            PermissionLevel::Standard,
        );
        method_permissions.insert(
            "rusty_coin_sign_raw_transaction".to_string(),
            PermissionLevel::Standard,
        );
        method_permissions.insert(
            "rusty_coin_estimate_fee".to_string(),
            PermissionLevel::Standard,
        );
        method_permissions.insert(
            "rusty_coin_list_unspent".to_string(),
            PermissionLevel::Standard,
        );
        method_permissions.insert(
            "rusty_coin_get_balance".to_string(),
            PermissionLevel::Standard,
        );

        // Administrative operations
        method_permissions.insert(
            "rusty_coin_start_mining".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert("rusty_coin_stop_mining".to_string(), PermissionLevel::Admin);
        method_permissions.insert(
            "rusty_coin_set_mining_address".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert("rusty_coin_add_peer".to_string(), PermissionLevel::Admin);
        method_permissions.insert("rusty_coin_remove_peer".to_string(), PermissionLevel::Admin);
        method_permissions.insert("rusty_coin_ban_peer".to_string(), PermissionLevel::Admin);
        method_permissions.insert("rusty_coin_unban_peer".to_string(), PermissionLevel::Admin);
        method_permissions.insert(
            "rusty_coin_invalidate_block".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert(
            "rusty_coin_reconsider_block".to_string(),
            PermissionLevel::Admin,
        );

        // Super administrative operations
        method_permissions.insert(
            "rusty_coin_shutdown".to_string(),
            PermissionLevel::SuperAdmin,
        );
        method_permissions.insert(
            "rusty_coin_debug_level".to_string(),
            PermissionLevel::SuperAdmin,
        );
        method_permissions.insert(
            "rusty_coin_generate_blocks".to_string(),
            PermissionLevel::SuperAdmin,
        );
        method_permissions.insert(
            "rusty_coin_reset_blockchain".to_string(),
            PermissionLevel::SuperAdmin,
        );
        method_permissions.insert(
            "rusty_coin_export_private_key".to_string(),
            PermissionLevel::SuperAdmin,
        );
        method_permissions.insert(
            "rusty_coin_import_private_key".to_string(),
            PermissionLevel::SuperAdmin,
        );

        // Governance operations (Admin level)
        method_permissions.insert(
            "rusty_coin_submit_proposal".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert(
            "rusty_coin_vote_proposal".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert(
            "rusty_coin_get_governance_info".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_list_proposals".to_string(),
            PermissionLevel::ReadOnly,
        );

        // Masternode operations (Admin level)
        method_permissions.insert(
            "rusty_coin_start_masternode".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert(
            "rusty_coin_stop_masternode".to_string(),
            PermissionLevel::Admin,
        );
        method_permissions.insert(
            "rusty_coin_get_masternode_status".to_string(),
            PermissionLevel::ReadOnly,
        );
        method_permissions.insert(
            "rusty_coin_list_masternodes".to_string(),
            PermissionLevel::ReadOnly,
        );

        let api_keys = Arc::new(Mutex::new(HashMap::new()));

        // Add some default API keys for testing
        {
            let mut keys = api_keys.lock().unwrap();
            keys.insert(
                "readonly_test_key_12345".to_string(),
                ApiKey {
                    key: "readonly_test_key_12345".to_string(),
                    permission_level: PermissionLevel::ReadOnly,
                    description: "Test read-only API key".to_string(),
                    enabled: true,
                },
            );
            keys.insert(
                "standard_test_key_67890".to_string(),
                ApiKey {
                    key: "standard_test_key_67890".to_string(),
                    permission_level: PermissionLevel::Standard,
                    description: "Test standard API key".to_string(),
                    enabled: true,
                },
            );
            keys.insert(
                "admin_test_key_abcdef".to_string(),
                ApiKey {
                    key: "admin_test_key_abcdef".to_string(),
                    permission_level: PermissionLevel::Admin,
                    description: "Test admin API key".to_string(),
                    enabled: true,
                },
            );
            keys.insert(
                "superadmin_test_key_xyz789".to_string(),
                ApiKey {
                    key: "superadmin_test_key_xyz789".to_string(),
                    permission_level: PermissionLevel::SuperAdmin,
                    description: "Test super admin API key".to_string(),
                    enabled: true,
                },
            );
        }

        AuthManager {
            api_keys,
            method_permissions,
        }
    }

    /// Add a new API key
    pub fn add_api_key(&self, api_key: ApiKey) {
        let mut keys = self.api_keys.lock().unwrap();
        keys.insert(api_key.key.clone(), api_key);
    }

    /// Create a new API key with the specified parameters
    pub fn create_api_key(&self, permission_level: PermissionLevel, description: String) -> String {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        // Generate a random 32-character API key
        let api_key: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let new_key = ApiKey {
            key: api_key.clone(),
            permission_level,
            description,
            enabled: true,
        };

        self.add_api_key(new_key);
        api_key
    }

    /// Remove an API key
    pub fn remove_api_key(&self, key: &str) -> bool {
        let mut keys = self.api_keys.lock().unwrap();
        keys.remove(key).is_some()
    }

    /// Enable or disable an API key
    pub fn set_api_key_enabled(&self, key: &str, enabled: bool) -> bool {
        let mut keys = self.api_keys.lock().unwrap();
        if let Some(api_key) = keys.get_mut(key) {
            api_key.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// List all API keys (without revealing the actual key values)
    pub fn list_api_keys(&self) -> Vec<(String, PermissionLevel, String, bool)> {
        let keys = self.api_keys.lock().unwrap();
        keys.values()
            .map(|k| {
                (
                    format!("{}***", &k.key[..4.min(k.key.len())]),
                    k.permission_level,
                    k.description.clone(),
                    k.enabled,
                )
            })
            .collect()
    }

    /// Authenticate an API key and check if it has permission for a method
    pub fn authenticate_and_authorize(
        &self,
        api_key: Option<&str>,
        method: &str,
    ) -> Result<PermissionLevel, Error> {
        // Get required permission level for the method
        let required_permission = self
            .method_permissions
            .get(method)
            .unwrap_or(&PermissionLevel::SuperAdmin); // Default to highest permission if method not found

        // Check if API key is provided
        let api_key = api_key.ok_or_else(|| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32001,
                "Authentication required: API key missing",
                None::<()>,
            )))
        })?;

        // Validate API key
        let keys = self.api_keys.lock().unwrap();
        let key_info = keys.get(api_key).ok_or_else(|| {
            Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32001,
                "Authentication failed: Invalid API key",
                None::<()>,
            )))
        })?;

        // Check if key is enabled
        if !key_info.enabled {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32001,
                "Authentication failed: API key disabled",
                None::<()>,
            ))));
        }

        // Check permission level
        if !Self::has_permission(key_info.permission_level, *required_permission) {
            return Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
                -32002,
                format!(
                    "Authorization failed: Method '{}' requires {:?} permission, but key has {:?}",
                    method, required_permission, key_info.permission_level
                ),
                None::<()>,
            ))));
        }

        Ok(key_info.permission_level)
    }

    /// Check if a permission level has access to a required permission level
    fn has_permission(user_level: PermissionLevel, required_level: PermissionLevel) -> bool {
        match required_level {
            PermissionLevel::ReadOnly => true, // Everyone has read access
            PermissionLevel::Standard => matches!(
                user_level,
                PermissionLevel::Standard | PermissionLevel::Admin | PermissionLevel::SuperAdmin
            ),
            PermissionLevel::Admin => matches!(
                user_level,
                PermissionLevel::Admin | PermissionLevel::SuperAdmin
            ),
            PermissionLevel::SuperAdmin => matches!(user_level, PermissionLevel::SuperAdmin),
        }
    }

    /// Get the required permission level for a method
    pub fn get_method_permission(&self, method: &str) -> PermissionLevel {
        self.method_permissions
            .get(method)
            .cloned()
            .unwrap_or(PermissionLevel::SuperAdmin)
    }

    /// Extract API key from HTTP headers
    pub fn extract_api_key_from_headers(headers: &[(&str, &str)]) -> Option<String> {
        for (name, value) in headers {
            match name.to_lowercase().as_str() {
                "x-api-key" => return Some(value.to_string()),
                "authorization" => {
                    // Support both "Bearer <token>" and "ApiKey <token>" formats
                    if value.starts_with("Bearer ") {
                        return Some(value[7..].to_string());
                    } else if value.starts_with("ApiKey ") {
                        return Some(value[7..].to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// Middleware for method-level permission checking
pub struct PermissionMiddleware {
    auth_manager: Arc<AuthManager>,
}

impl PermissionMiddleware {
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        PermissionMiddleware { auth_manager }
    }

    /// Check permissions for an RPC method call
    pub fn check_permission(
        &self,
        method: &str,
        api_key: Option<&str>,
    ) -> Result<PermissionLevel, Error> {
        self.auth_manager
            .authenticate_and_authorize(api_key, method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_hierarchy() {
        assert!(AuthManager::has_permission(
            PermissionLevel::SuperAdmin,
            PermissionLevel::ReadOnly
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::SuperAdmin,
            PermissionLevel::Standard
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::SuperAdmin,
            PermissionLevel::Admin
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::SuperAdmin,
            PermissionLevel::SuperAdmin
        ));

        assert!(AuthManager::has_permission(
            PermissionLevel::Admin,
            PermissionLevel::ReadOnly
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::Admin,
            PermissionLevel::Standard
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::Admin,
            PermissionLevel::Admin
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::Admin,
            PermissionLevel::SuperAdmin
        ));

        assert!(AuthManager::has_permission(
            PermissionLevel::Standard,
            PermissionLevel::ReadOnly
        ));
        assert!(AuthManager::has_permission(
            PermissionLevel::Standard,
            PermissionLevel::Standard
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::Standard,
            PermissionLevel::Admin
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::Standard,
            PermissionLevel::SuperAdmin
        ));

        assert!(AuthManager::has_permission(
            PermissionLevel::ReadOnly,
            PermissionLevel::ReadOnly
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::ReadOnly,
            PermissionLevel::Standard
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::ReadOnly,
            PermissionLevel::Admin
        ));
        assert!(!AuthManager::has_permission(
            PermissionLevel::ReadOnly,
            PermissionLevel::SuperAdmin
        ));
    }

    #[test]
    fn test_api_key_management() {
        let auth_manager = AuthManager::new();

        // Test adding a new API key
        let new_key = ApiKey {
            key: "test_key_123".to_string(),
            permission_level: PermissionLevel::Standard,
            description: "Test key".to_string(),
            enabled: true,
        };
        auth_manager.add_api_key(new_key);

        // Test authentication with the new key
        let result = auth_manager
            .authenticate_and_authorize(Some("test_key_123"), "rusty_coin_send_raw_transaction");
        assert!(result.is_ok());

        // Test disabling the key
        assert!(auth_manager.set_api_key_enabled("test_key_123", false));
        let result = auth_manager
            .authenticate_and_authorize(Some("test_key_123"), "rusty_coin_send_raw_transaction");
        assert!(result.is_err());

        // Test removing the key
        assert!(auth_manager.remove_api_key("test_key_123"));
        assert!(!auth_manager.remove_api_key("nonexistent_key"));
    }

    #[test]
    fn test_extract_api_key_from_headers() {
        let headers = vec![
            ("content-type", "application/json"),
            ("x-api-key", "test_key_123"),
        ];
        let api_key = AuthManager::extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_key_123".to_string()));

        let headers = vec![
            ("content-type", "application/json"),
            ("authorization", "Bearer test_bearer_token"),
        ];
        let api_key = AuthManager::extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_bearer_token".to_string()));

        let headers = vec![
            ("content-type", "application/json"),
            ("authorization", "ApiKey test_apikey_token"),
        ];
        let api_key = AuthManager::extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_apikey_token".to_string()));

        let headers = vec![("content-type", "application/json")];
        let api_key = AuthManager::extract_api_key_from_headers(&headers);
        assert_eq!(api_key, None);
    }
}
