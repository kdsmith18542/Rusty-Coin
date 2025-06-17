use rusty_coin_core::types::{Block, BlockHeader};
use rusty_coin_core::crypto::Hash;
use tonic::{Request, Response, Status};
use serde_json;

mod proto {
    tonic::include_proto!("rustcoin");
}

// mod network;  // Temporarily disabled

#[derive(Debug, Default)]
pub struct RustyCoinNode;

#[tonic::async_trait]
impl proto::node_server::Node for RustyCoinNode {
    async fn get_block(
        &self,
        _request: Request<proto::GetBlockRequest>,
    ) -> Result<Response<proto::GetBlockResponse>, Status> {
        // Create a default block header
        let header = BlockHeader::new(
            1, // version
            Hash::default(), // prev_block_hash
            Hash::default(), // merkle_root
            0, // bits
            Hash::default(), // ticket_hash
        );
        let block = Block::new(header, vec![]);
        
        // Serialize using serde_json temporarily
        let block_json = serde_json::to_vec(&block).map_err(|e| {
            Status::internal(format!("Failed to serialize block: {}", e))
        })?;
        
        Ok(Response::new(proto::GetBlockResponse {
            block: block_json,
        }))
    }

    async fn send_transaction(
        &self,
        _request: Request<proto::SendTransactionRequest>,
    ) -> Result<Response<proto::SendTransactionResponse>, Status> {
        Ok(Response::new(proto::SendTransactionResponse {
            accepted: true,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // network::start_network().await?;  // Temporarily disabled
    Ok(())
}
