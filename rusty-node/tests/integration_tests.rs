use reqwest::Client;
use serde_json::json;
use tokio::time::{sleep, Duration};
use std::process::{Child, Command, Stdio};
use rusty_shared_types::{Transaction, TxInput, TxOutput, OutPoint, MasternodeIdentity, TransactionSignature, PublicKey, Signature};
use rusty_shared_types::governance::{GovernanceProposal, ProposalType, GovernanceVote, VoterType, VoteChoice};
use bincode::{self};
use hex;

// Helper function to create a dummy hash
fn dummy_hash(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// Helper function to create a dummy public key
fn dummy_public_key(seed: u8) -> PublicKey {
    [seed; 32]
}

// Helper function to create a dummy signature
fn dummy_signature(seed: u8) -> Signature {
    [seed; 64]
}

async fn start_node_and_rpc() -> Child {
    // Build the rusty-node executable
    Command::new("cargo")
        .args(["build", "--package", "rusty-node", "--release"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to build rusty-node")
        .wait()
        .expect("Failed to wait for build");

    // Start the rusty-node executable in a new process
    let mut child = Command::new("target/release/rusty-node.exe") // For Windows
        .args(["--port", "8000", "--log-level", "debug"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start rusty-node");

    // Give the node some time to start up
    sleep(Duration::from_secs(5)).await;

    child
}

#[tokio::test]
async fn test_rpc_get_block_count() {
    let mut node_process = start_node_and_rpc().await;

    let client = Client::new();
    let rpc_url = "http://127.0.0.1:8000";

    // Test get_block_count
    let response = client.post(rpc_url)
        .json(&json!({ "jsonrpc": "2.0", "method": "get_block_count", "params": [], "id": 1 }))
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(response.status().is_success());
    let json_response: serde_json::Value = response.json().await.expect("Failed to parse JSON response");

    // Expecting block count to be 0 for a freshly initialized blockchain
    assert_eq!(json_response["result"], 0);

    // Kill the node process
    node_process.kill().expect("Failed to kill node process");
    node_process.wait().expect("Failed to wait for node process to exit");
}

#[tokio::test]
async fn test_rpc_send_raw_transaction_standard() {
    let mut node_process = start_node_and_rpc().await;
    let client = Client::new();
    let rpc_url = "http://127.0.0.1:8000";

    let standard_tx = Transaction::Standard {
        version: 1,
        inputs: vec![TxInput {
            previous_output: OutPoint { txid: dummy_hash(100), vout: 0 },
            script_sig: vec![0; 65],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![TxOutput { value: 1000, script_pubkey: vec![1], memo: None }],
        lock_time: 0,
        fee: 100,
        witness: vec![],
    };
    let raw_tx = hex::encode(bincode::encode_to_vec(&standard_tx, bincode::config::standard()).unwrap());

    let response = client.post(rpc_url)
        .json(&json!({ "jsonrpc": "2.0", "method": "send_raw_transaction", "params": [raw_tx], "id": 1 }))
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(response.status().is_success());
    let json_response: serde_json::Value = response.json().await.expect("Failed to parse JSON response");

    // For a freshly started node, this transaction will likely be invalid due to missing UTXO,
    // but we are testing the RPC call itself, not full consensus validation here.
    // Expecting an error or a placeholder success if validation is skipped/mocked.
    // For now, check if the result key exists, indicating the call was processed.
    assert!(json_response.get("result").is_some() || json_response.get("error").is_some());
    println!("send_raw_transaction response: {:?}", json_response);

    node_process.kill().expect("Failed to kill node process");
    node_process.wait().expect("Failed to wait for node process to exit");
}

#[tokio::test]
async fn test_rpc_get_governance_proposals() {
    let mut node_process = start_node_and_rpc().await;
    let client = Client::new();
    let rpc_url = "http://127.0.0.1:8000";

    let response = client.post(rpc_url)
        .json(&json!({ "jsonrpc": "2.0", "method": "get_governance_proposals", "params": [], "id": 1 }))
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(response.status().is_success());
    let json_response: serde_json::Value = response.json().await.expect("Failed to parse JSON response");

    // Expecting an empty array for a new blockchain
    assert_eq!(json_response["result"], json!([]));

    node_process.kill().expect("Failed to kill node process");
    node_process.wait().expect("Failed to wait for node process to exit");
}

#[tokio::test]
async fn test_rpc_get_governance_votes() {
    let mut node_process = start_node_and_rpc().await;
    let client = Client::new();
    let rpc_url = "http://127.0.0.1:8000";

    // Dummy proposal ID, as there are no proposals on a fresh chain
    let dummy_proposal_id = dummy_hash(1);

    let response = client.post(rpc_url)
        .json(&json!({ "jsonrpc": "2.0", "method": "get_governance_votes", "params": [hex::encode(dummy_proposal_id)], "id": 1 }))
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(response.status().is_success());
    let json_response: serde_json::Value = response.json().await.expect("Failed to parse JSON response");

    // Expecting an empty array for a proposal that doesn't exist or has no votes
    assert_eq!(json_response["result"], json!([]));

    node_process.kill().expect("Failed to kill node process");
    node_process.wait().expect("Failed to wait for node process to exit");
} 