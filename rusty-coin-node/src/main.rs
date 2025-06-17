use tonic::{transport::Server, Request, Response, Status};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/rustcoin.rs"));
}

mod network; // Declare the new network module

use proto::{
    node_server::{Node, NodeServer},
    Block, GetBlockRequest, GetBlockResponse, Hash, PublicKey, SendTransactionRequest,
    SendTransactionResponse, Signature, Transaction,
};

#[derive(Debug, Default)]
pub struct RustyCoinNode;

#[tonic::async_trait]
impl Node for RustyCoinNode {
    async fn get_block(
        &self,
        request: Request<GetBlockRequest>,
    ) -> Result<Response<GetBlockResponse>, Status> {
        println!("Got a GetBlockRequest: {:?}", request);

        let reply = GetBlockResponse {
            block: Some(Block {
                header_hash: Some(Hash { data: vec![0u8; 32] }),
                height: 1,
                prev_block_hash: None,
                timestamp: 0,
                nonce: 0,
                merkle_root: Some(Hash { data: vec![0u8; 32] }),
                transactions: vec![],
            }),
        };
        Ok(Response::new(reply))
    }

    async fn send_transaction(
        &self,
        request: Request<SendTransactionRequest>,
    ) -> Result<Response<SendTransactionResponse>, Status> {
        println!("Got a SendTransactionRequest: {:?}", request);

        let reply = SendTransactionResponse {
            success: true,
            message: "Transaction received successfully!".to_string(),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the gRPC server
    let grpc_addr = "[::1]:50051".parse().map_err(|e| e.into())?;
    let grpc_node = RustyCoinNode::default();

    let grpc_server_handle = tokio::spawn(async move {
        println!("RustyCoinNode gRPC server listening on {}", grpc_addr);
        Server::builder()
            .add_service(NodeServer::new(grpc_node))
            .serve(grpc_addr)
            .await
            .map_err(|e| e.into())
    });

    // Start the libp2p node
    println!("Starting libp2p node...");
    network::start_p2p_node().await?;

    grpc_server_handle.await?.map_err(|e| e.into())
}
