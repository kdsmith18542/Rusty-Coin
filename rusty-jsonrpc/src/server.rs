use jsonrpc_core::IoHandler;
use jsonrpc_http_server::{ServerBuilder, AccessControlAllowOrigin, DomainsValidation, RequestMiddleware};
use std::sync::Arc;
use std::path::Path;
use log::{info, error, warn};

use crate::rpc::{Rpc, RpcImpl};
use crate::auth::{AuthMiddleware, ApiKeyManager};

pub struct RpcServer {
    handler: IoHandler,
    api_key_manager: Arc<ApiKeyManager>,
}

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl RpcServer {
    pub fn new(rpc_impl: RpcImpl) -> Self {
        let mut handler = IoHandler::new();
        handler.extend_with(rpc_impl.to_delegate());
        let api_key_manager = Arc::new(ApiKeyManager::new());
        RpcServer { handler, api_key_manager }
    }

    pub async fn start(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        warn!("Starting JSON-RPC server on HTTP (insecure) at {}", addr);
        warn!("For production use, please use start_https() with TLS certificates");
        let auth_middleware = AuthMiddleware::new(self.api_key_manager.clone());

        let server = ServerBuilder::new(self.handler)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Any]))
            .request_middleware(auth_middleware)
            .start_http(&addr.parse()?)
            .expect("Unable to start RPC server");

        server.wait();
        info!("JSON-RPC server stopped.");
        Ok(())
    }

    pub async fn start_https(self, addr: &str, tls_config: TlsConfig) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting JSON-RPC server with HTTPS on {}", addr);

        // Validate TLS certificate files exist
        if !Path::new(&tls_config.cert_path).exists() {
            return Err(format!("TLS certificate file not found: {}", tls_config.cert_path).into());
        }
        if !Path::new(&tls_config.key_path).exists() {
            return Err(format!("TLS private key file not found: {}", tls_config.key_path).into());
        }

        let auth_middleware = AuthMiddleware::new(self.api_key_manager.clone());

        // Note: jsonrpc_http_server doesn't directly support HTTPS
        // For production, consider using a reverse proxy (nginx, traefik) with TLS termination
        // or migrating to a more modern JSON-RPC library that supports native HTTPS
        warn!("HTTPS support requires reverse proxy configuration or library migration");
        warn!("For now, starting HTTP server - please configure TLS termination at proxy level");

        let server = ServerBuilder::new(self.handler)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Any]))
            .request_middleware(auth_middleware)
            .start_http(&addr.parse()?)
            .expect("Unable to start RPC server");

        server.wait();
        info!("JSON-RPC server stopped.");
        Ok(())
    }
}

pub struct RpcImpl;

impl Rpc for RpcImpl {
    fn get_block_count(&self) -> jsonrpc_core::Result<u64> {
        // Assuming self.blockchain is available
        Ok(self.blockchain.get_current_block_height())
    }

    fn get_block_hash(&self, height: u64) -> jsonrpc_core::Result<rusty_core::types::Hash> {
        // TODO: Implement actual logic to get block hash
        Ok(rusty_core::types::Hash::from_bytes([0; 32]))
    }

    fn get_block(&self, hash: rusty_core::types::Hash) -> jsonrpc_core::Result<rusty_core::types::block::Block> {
        // TODO: Implement actual logic to get block
        Err(jsonrpc_core::Error::internal_error())
    }

    fn get_transaction(&self, txid: rusty_core::types::Hash) -> jsonrpc_core::Result<rusty_core::types::transaction::Transaction> {
        // TODO: Implement actual logic to get transaction
        Err(jsonrpc_core::Error::internal_error())
    }

    fn send_raw_transaction(&self, raw_tx: String) -> jsonrpc_core::Result<rusty_core::types::Hash> {
        // TODO: Implement actual logic to send raw transaction
        Err(jsonrpc_core::Error::internal_error())
    }

    fn get_utxo_set(&self) -> jsonrpc_core::Result<Vec<rusty_core::types::transaction::OutPoint>> {
        // TODO: Implement actual logic to get UTXO set
        Ok(vec![])
    }

    fn masternode_count(&self) -> jsonrpc_core::Result<u64> {
        // TODO: Implement actual logic to get masternode count
        Ok(0)
    }

    fn get_masternode_list(&self) -> jsonrpc_core::Result<Vec<rusty_masternode::types::MasternodeEntry>> {
        // TODO: Implement actual logic to get masternode list
        Ok(vec![])
    }

    fn get_peer_info(&self) -> jsonrpc_core::Result<Vec<rusty_p2p::types::PeerInfo>> {
        // TODO: Implement actual logic to get peer info
        Ok(vec![])
    }

    fn get_connection_count(&self) -> jsonrpc_core::Result<u64> {
        // TODO: Implement actual logic to get connection count
        Ok(0)
    }

    fn get_governance_proposals(&self) -> jsonrpc_core::Result<Vec<rusty_core::types::governance::GovernanceProposal>> {
        // TODO: Implement actual logic to get governance proposals
        Ok(vec![])
    }

    fn get_governance_votes(&self, proposal_id: rusty_core::types::Hash) -> jsonrpc_core::Result<Vec<rusty_core::types::governance::GovernanceVote>> {
        // TODO: Implement actual logic to get governance votes
        Ok(vec![])
    }
}
