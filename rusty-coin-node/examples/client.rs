use tonic::transport::Channel;
use rusty_coin_core::{
    crypto::{Hash, KeyPair, PublicKey},
    types::{Block, BlockHeader, Transaction, TxInput, TxOutput, OutPoint, UTXO},
    proto,
    error::Error
};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/rustcoin.rs"));
}

use proto::{
    node_client::NodeClient,
    GetBlockRequest, SendTransactionRequest
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://[::1]:50051").connect().await?;
    let mut client = NodeClient::new(channel);

    // Generate a keypair for the client (dummy for now)
    let sender_keypair = KeyPair::new();
    let recipient_pubkey_hash = [0x02; 20]; // Dummy recipient address

    // Test GetBlock RPC
    let request = GetBlockRequest {
        hash: Some(Hash::default().into()),
        height: None
    };
    println!("\n*** Sending GetBlockRequest ***");
    let response = client.get_block(request).await?;
    println!("GetBlockResponse: {:?}", response.into_inner());

    // Simulate having some UTXOs for the sender
    let dummy_utxo = UTXO {
        tx_hash: Hash::blake3(b"dummy_prev_tx_hash"), // A dummy previous transaction hash
        output_index: 0,
        value: 100_000_000_000, // 100 RustyCoins
        script_pubkey: sender_keypair.public_key.as_bytes()[0..20].try_into().unwrap(),
    };

    // Create a regular transaction
    let amount_to_send = 1_000_000_000; // 1 RustyCoin
    let fee = 10_000; // Example fee

    let transaction = Transaction::new_regular_transaction(
        &sender_keypair,
        vec![dummy_utxo],
        recipient_pubkey_hash,
        amount_to_send,
        sender_keypair.public_key.as_bytes()[0..20].try_into().unwrap(), // Change address is sender's
        fee,
        false, // is_instant_send
    )?;

    // Test SendTransaction RPC
    let proto_transaction = proto::Transaction {
        data: bincode::encode_to_vec(&transaction, bincode::config::standard()).map_err(|e| Error::SerializationError(e.to_string()))?,
    };
    let request = SendTransactionRequest {
        transaction: Some(proto_transaction)
    };
    println!("\n*** Sending SendTransactionRequest ***");
    let response = client.send_transaction(request).await?;
    println!("SendTransactionResponse: {:?}", response.into_inner());

    // Simulate having a UTXO for the instant send transaction
    let dummy_utxo_instant_send = UTXO {
        tx_hash: Hash::blake3(b"dummy_prev_tx_hash_instant_send"),
        output_index: 0,
        value: 50_000_000_000, // 50 RustyCoins
        script_pubkey: sender_keypair.public_key.as_bytes()[0..20].try_into().unwrap(),
    };

    // Create an instant send transaction
    let instant_send_amount = 500_000_000; // 0.5 RustyCoins
    let instant_send_fee = 50_000; // Example fee for instant send

    let instant_transaction = Transaction::new_regular_transaction(
        &sender_keypair,
        vec![dummy_utxo_instant_send],
        recipient_pubkey_hash,
        instant_send_amount,
        sender_keypair.public_key.as_bytes()[0..20].try_into().unwrap(), // Change address is sender's
        instant_send_fee,
        true, // is_instant_send set to true
    )?;

    // Test SendTransaction RPC for instant send
    let proto_instant_transaction = proto::Transaction {
        data: bincode::encode_to_vec(&instant_transaction, bincode::config::standard()).map_err(|e| Error::SerializationError(e.to_string()))?,
    };
    let request = SendTransactionRequest {
        transaction: Some(proto_instant_transaction)
    };
    println!("\n*** Sending Instant Send TransactionRequest ***");
    let response = client.send_transaction(request).await?;
    println!("Instant Send TransactionResponse: {:?}", response.into_inner());

    // Simulate having an active ticket for revocation
    let dummy_ticket_hash = Hash::blake3(b"dummy_ticket_hash");
    let dummy_ticket_outpoint = OutPoint {
        tx_hash: Hash::blake3(b"dummy_ticket_purchase_tx"),
        output_index: 0,
    };
    let redemption_amount = 90_000_000_000; // Example redemption amount, less than original stake due to fees/maturity
    let redemption_fee = 50_000; // Example fee for redemption

    // Create a ticket revocation transaction
    let revocation_transaction = Transaction::new_ticket_revocation(
        &sender_keypair,
        dummy_ticket_outpoint,
        dummy_ticket_hash,
        sender_keypair.public_key.as_bytes()[0..20].try_into().unwrap(), // Send redeemed funds back to sender
        redemption_amount,
        redemption_fee,
    )?;

    // Test SendTransaction RPC for ticket revocation
    let proto_revocation_transaction = proto::Transaction {
        data: bincode::encode_to_vec(&revocation_transaction, bincode::config::standard()).map_err(|e| Error::SerializationError(e.to_string()))?,
    };
    let request = SendTransactionRequest {
        transaction: Some(proto_revocation_transaction)
    };
    println!("\n*** Sending TicketRevocationRequest ***");
    let response = client.send_transaction(request).await?;
    println!("TicketRevocationResponse: {:?}", response.into_inner());

    Ok(())
}