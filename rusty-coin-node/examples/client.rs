use tonic::transport::Channel;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/rustcoin.rs"));
}

use proto::{
    node_client::NodeClient,
    GetBlockRequest, SendTransactionRequest, Hash, Transaction, PublicKey, Signature,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;

    let mut client = NodeClient::new(channel);

    // Test GetBlock RPC
    let request = tonic::Request::new(GetBlockRequest {
        block_hash: Some(Hash { data: vec![0u8; 32] }),
    });
    println!("\n*** Sending GetBlockRequest ***");
    let response = client.get_block(request).await?;
    println!("GetBlockResponse: {:?}", response.into_inner());

    // Test SendTransaction RPC
    let transaction = Transaction {
        id: Some(Hash { data: vec![1u8; 32] }),
        inputs: vec!["input1".to_string(), "input2".to_string()],
        outputs: vec!["output1".to_string(), "output2".to_string()],
        signature: Some(Signature { data: vec![2u8; 64] }),
        public_key: Some(PublicKey { data: vec![3u8; 32] }),
        timestamp: 1234567890,
    };
    let request = tonic::Request::new(SendTransactionRequest {
        transaction: Some(transaction),
    });
    println!("\n*** Sending SendTransactionRequest ***");
    let response = client.send_transaction(request).await?;
    println!("SendTransactionResponse: {:?}", response.into_inner());

    Ok(())
} 