//! Middleware for RPC server authentication and request processing.

use crate::auth::AuthManager;
use crate::server::RustyRpcServerImpl;
use jsonrpsee::core::Error;
use jsonrpsee::types::error::{CallError, ErrorObjectOwned};
use std::sync::Arc;

/// Middleware for API key extraction and authentication
pub struct ApiKeyMiddleware {
    auth_manager: Arc<AuthManager>,
    rpc_server: Arc<RustyRpcServerImpl>,
}

impl ApiKeyMiddleware {
    pub fn new(auth_manager: Arc<AuthManager>, rpc_server: Arc<RustyRpcServerImpl>) -> Self {
        Self {
            auth_manager,
            rpc_server,
        }
    }

    /// Extract API key from HTTP headers
    pub fn extract_api_key_from_headers(&self, headers: &[(&str, &str)]) -> Option<String> {
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

    /// Process request and extract API key
    pub fn process_request(&self, headers: &[(&str, &str)]) -> Result<(), Error> {
        // Extract API key from headers
        if let Some(api_key) = self.extract_api_key_from_headers(headers) {
            // Validate the API key exists and is enabled
            if self
                .auth_manager
                .authenticate_and_authorize(Some(&api_key), "rusty_coin_get_block_count")
                .is_ok()
            {
                // Set the API key in the request context
                self.rpc_server.set_request_api_key(api_key);
                return Ok(());
            }
        }

        // If no valid API key found, try environment variable fallback
        if let Ok(api_key) = std::env::var("RUSTY_RPC_API_KEY") {
            if !api_key.is_empty() {
                self.rpc_server.set_request_api_key(api_key);
                return Ok(());
            }
        }

        // If still no API key, try to use a default enabled key
        let available_keys = self.auth_manager.list_api_keys();
        for (key_masked, _permission_level, _description, enabled) in available_keys {
            if enabled {
                // Extract the actual key from the masked version
                if key_masked.len() > 4 && key_masked.ends_with("***") {
                    let actual_key = &key_masked[..key_masked.len() - 3];
                    // Try to authenticate with this key
                    if self
                        .auth_manager
                        .authenticate_and_authorize(Some(actual_key), "rusty_coin_get_block_count")
                        .is_ok()
                    {
                        self.rpc_server.set_request_api_key(actual_key.to_string());
                        return Ok(());
                    }
                }
            }
        }

        // No valid API key found
        Err(Error::Call(CallError::Custom(ErrorObjectOwned::owned(
            -32001,
            "Authentication required: No valid API key provided",
            None::<()>,
        ))))
    }

    /// Clear request context after processing
    pub fn clear_request_context(&self) {
        self.rpc_server.clear_request_api_key();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ApiKey, PermissionLevel};

    // Use real RateLimiter for testing
    use crate::server::RateLimiter;

    #[test]
    fn test_extract_api_key_from_headers() {
        let auth_manager = Arc::new(AuthManager::new());
        let rpc_server = Arc::new(crate::server::RustyRpcServerImpl::new(
            Arc::new(std::sync::Mutex::new(RateLimiter::new())),
            auth_manager.clone(),
            None,
            None,
        ));

        let middleware = ApiKeyMiddleware::new(auth_manager, rpc_server);

        // Test X-API-Key header
        let headers = vec![
            ("content-type", "application/json"),
            ("x-api-key", "test_key_123"),
        ];
        let api_key = middleware.extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_key_123".to_string()));

        // Test Authorization Bearer header
        let headers = vec![
            ("content-type", "application/json"),
            ("authorization", "Bearer test_bearer_token"),
        ];
        let api_key = middleware.extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_bearer_token".to_string()));

        // Test Authorization ApiKey header
        let headers = vec![
            ("content-type", "application/json"),
            ("authorization", "ApiKey test_apikey_token"),
        ];
        let api_key = middleware.extract_api_key_from_headers(&headers);
        assert_eq!(api_key, Some("test_apikey_token".to_string()));

        // Test no API key
        let headers = vec![("content-type", "application/json")];
        let api_key = middleware.extract_api_key_from_headers(&headers);
        assert_eq!(api_key, None);
    }

    #[test]
    fn test_process_request_with_valid_key() {
        let auth_manager = Arc::new(AuthManager::new());
        let rpc_server = Arc::new(crate::server::RustyRpcServerImpl::new(
            Arc::new(std::sync::Mutex::new(RateLimiter::new())),
            auth_manager.clone(),
            None,
            None,
        ));

        // Add a test API key
        let new_key = ApiKey {
            key: "test_key_123".to_string(),
            permission_level: PermissionLevel::Standard,
            description: "Test key".to_string(),
            enabled: true,
        };
        auth_manager.add_api_key(new_key);

        let middleware = ApiKeyMiddleware::new(auth_manager, rpc_server);

        let headers = vec![("x-api-key", "test_key_123")];

        let result = middleware.process_request(&headers);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_request_with_invalid_key() {
        let auth_manager = Arc::new(AuthManager::new());
        let rpc_server = Arc::new(crate::server::RustyRpcServerImpl::new(
            Arc::new(std::sync::Mutex::new(RateLimiter::new())),
            auth_manager.clone(),
            None,
            None,
        ));

        let middleware = ApiKeyMiddleware::new(auth_manager, rpc_server);

        let headers = vec![("x-api-key", "invalid_key")];

        let result = middleware.process_request(&headers);
        assert!(result.is_err());
    }
}
