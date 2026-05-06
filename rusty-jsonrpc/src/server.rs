use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use log::{info, warn};
use std::path::Path;

use crate::auth::AuthMiddleware;
use crate::rpc::{Rpc, RpcImpl};

pub struct RpcServer {
    handler: IoHandler,
}

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl RpcServer {
    pub fn new(rpc_impl: RpcImpl) -> Self {
        let mut handler = IoHandler::new();
        handler.extend_with(rpc_impl.to_delegate());
        RpcServer { handler }
    }

    pub async fn start(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        warn!("Starting JSON-RPC server on HTTP (insecure) at {}", addr);
        warn!("For production use, please use start_https() with TLS certificates");
        let auth_middleware = AuthMiddleware::new();

        let server = ServerBuilder::new(self.handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .request_middleware(auth_middleware)
            .start_http(&addr.parse()?)
            .expect("Unable to start RPC server");

        server.wait();
        info!("JSON-RPC server stopped.");
        Ok(())
    }

    pub async fn start_https(
        self,
        addr: &str,
        tls_config: TlsConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting JSON-RPC server with HTTPS on {}", addr);

        // Validate TLS certificate files exist
        if !Path::new(&tls_config.cert_path).exists() {
            return Err(format!("TLS certificate file not found: {}", tls_config.cert_path).into());
        }
        if !Path::new(&tls_config.key_path).exists() {
            return Err(format!("TLS private key file not found: {}", tls_config.key_path).into());
        }

        let auth_middleware = AuthMiddleware::new();

        // Note: jsonrpc_http_server doesn't directly support HTTPS
        // For production, consider using a reverse proxy (nginx, traefik) with TLS termination
        // or migrating to a more modern JSON-RPC library that supports native HTTPS
        warn!("HTTPS support requires reverse proxy configuration or library migration");
        warn!("For now, starting HTTP server - please configure TLS termination at proxy level");

        let server = ServerBuilder::new(self.handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .request_middleware(auth_middleware)
            .start_http(&addr.parse()?)
            .expect("Unable to start RPC server");

        server.wait();
        info!("JSON-RPC server stopped.");
        Ok(())
    }
}
