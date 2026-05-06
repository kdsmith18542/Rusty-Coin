//! Example demonstrating API key extraction functionality

use rusty_rpc::auth::{ApiKey, AuthManager, PermissionLevel};
use rusty_rpc::middleware::ApiKeyMiddleware;
use std::sync::Arc;

// Mock RPC server for demonstration
struct MockRpcServer;

impl MockRpcServer {
    fn new() -> Self {
        MockRpcServer
    }

    fn set_request_api_key(&self, _api_key: String) {
        println!("  ✓ API key set in request context: {}", _api_key);
    }
}

fn main() {
    println!("=== RPC API Key Extraction Demonstration ===\n");

    // Create auth manager with test API keys
    let auth_manager = Arc::new(AuthManager::new());
    let rpc_server = Arc::new(MockRpcServer::new());

    // Add some test API keys
    let test_keys = vec![
        (
            "readonly_key_123",
            PermissionLevel::ReadOnly,
            "Read-only test key",
        ),
        (
            "standard_key_456",
            PermissionLevel::Standard,
            "Standard test key",
        ),
        ("admin_key_789", PermissionLevel::Admin, "Admin test key"),
        (
            "superadmin_key_abc",
            PermissionLevel::SuperAdmin,
            "Super admin test key",
        ),
    ];

    for (key, level, description) in test_keys {
        let api_key = ApiKey {
            key: key.to_string(),
            permission_level: level,
            description: description.to_string(),
            enabled: true,
        };
        auth_manager.add_api_key(api_key);
    }

    let middleware = ApiKeyMiddleware::new(auth_manager, rpc_server);

    // Test different header formats
    println!("1. Testing X-API-Key header:");
    let headers = vec![
        ("content-type", "application/json"),
        ("x-api-key", "readonly_key_123"),
    ];
    match middleware.extract_api_key_from_headers(&headers) {
        Some(api_key) => println!("  ✓ Extracted API key: {}", api_key),
        None => println!("  ✗ No API key found"),
    }

    println!("\n2. Testing Authorization Bearer header:");
    let headers = vec![
        ("content-type", "application/json"),
        ("authorization", "Bearer standard_key_456"),
    ];
    match middleware.extract_api_key_from_headers(&headers) {
        Some(api_key) => println!("  ✓ Extracted API key: {}", api_key),
        None => println!("  ✗ No API key found"),
    }

    println!("\n3. Testing Authorization ApiKey header:");
    let headers = vec![
        ("content-type", "application/json"),
        ("authorization", "ApiKey admin_key_789"),
    ];
    match middleware.extract_api_key_from_headers(&headers) {
        Some(api_key) => println!("  ✓ Extracted API key: {}", api_key),
        None => println!("  ✗ No API key found"),
    }

    println!("\n4. Testing no API key in headers:");
    let headers = vec![("content-type", "application/json")];
    match middleware.extract_api_key_from_headers(&headers) {
        Some(api_key) => println!("  ✓ Extracted API key: {}", api_key),
        None => println!("  ✗ No API key found"),
    }

    println!("\n5. Testing request processing with valid API key:");
    let headers = vec![("x-api-key", "readonly_key_123")];
    match middleware.process_request(&headers) {
        Ok(()) => println!("  ✓ Request processed successfully"),
        Err(e) => println!("  ✗ Request processing failed: {}", e),
    }

    println!("\n6. Testing request processing with invalid API key:");
    let headers = vec![("x-api-key", "invalid_key")];
    match middleware.process_request(&headers) {
        Ok(()) => println!("  ✓ Request processed successfully"),
        Err(e) => println!("  ✗ Request processing failed: {}", e),
    }

    println!("\n7. Testing environment variable fallback:");
    // Set environment variable for testing
    std::env::set_var("RUSTY_RPC_API_KEY", "env_api_key_999");

    let headers = vec![("content-type", "application/json")]; // No API key in headers
    match middleware.process_request(&headers) {
        Ok(()) => println!("  ✓ Successfully used environment variable API key"),
        Err(e) => println!("  ✗ Failed to use environment variable: {}", e),
    }

    // Clean up
    std::env::remove_var("RUSTY_RPC_API_KEY");

    println!("\n8. Testing default API key fallback:");
    let headers = vec![("content-type", "application/json")]; // No API key in headers
    match middleware.process_request(&headers) {
        Ok(()) => println!("  ✓ Successfully used default API key from auth manager"),
        Err(e) => println!("  ✗ Failed to use default API key: {}", e),
    }

    println!("\n=== API Key Extraction Features ===");
    println!("✓ Support for X-API-Key header");
    println!("✓ Support for Authorization: Bearer <token>");
    println!("✓ Support for Authorization: ApiKey <token>");
    println!("✓ Environment variable fallback (RUSTY_RPC_API_KEY)");
    println!("✓ Default API key fallback from auth manager");
    println!("✓ Thread-local request context storage");
    println!("✓ Proper error handling for invalid keys");
    println!("✓ Integration with permission-based access control");

    println!("\n=== API Key Extraction Complete ===");
}
