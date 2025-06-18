//! Peer-to-peer networking implementation for Rusty Coin.
//!
//! This module handles:
//! - Node discovery and peer management
//! - Network message propagation
//! - Connection establishment and maintenance
//! - Protocol negotiation and multiplexing
//!
//! Built on libp2p for cross-platform networking capabilities.
//!
//! # Example
//! ```rust
//! use rusty_coin_node::network;
//! 
//! // Start a network node
//! async fn start_node() -> Result<(), Box<dyn std::error::Error>> {
//!     network::start_p2p_node().await
//! }
//! ```

use libp2p::{
    core::{upgrade, transport::Transport, PeerId, identity},
    futures::StreamExt,
    mplex::MplexConfig,
    noise::{NoiseAuthenticated, X25519Spec},
    ping::{Ping, PingConfig, PingEvent},
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp::TokioTcpConfig,
    yamux::YamuxConfig,
    request_response::{
        self, ProtocolSupport, RequestResponse,
        RequestResponseEvent, RequestResponseMessage,
        RequestId, Protocol, Codec,
    },
    kad::{
        Kademlia, KademliaConfig, KademliaEvent, Mode, PutRecordOk, QueryResult, Record,
        store::MemoryStore,
    },
    gossipsub::{Gossipsub, GossipsubEvent, MessageId, ValidationMode, MessageAuthenticity, RawGossipsubMessage, Topic},
    autonat::{self, NatStatus},
    identify::{Identify, IdentifyEvent},
};
use rusty_coin_core::{
    types::{Block, Transaction, BlockchainState, OutPoint, TxOutput},
    crypto::Hash,
};
use std::collections::HashSet;
use std::error::Error;
use log::{info, warn};
use async_std::io;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::collections::HashMap;
use tokio_util::codec::{Decoder, Encoder};
use futures::prelude::*;
use async_trait::async_trait;

// Define custom network message types
#[derive(Debug, Clone, PartialEq, Eq, libp2p::request_response::Request, libp2p::request_response::Response)]
pub enum RustyCoinRequest {
    GetBlock { hash: Hash },
    GetTransaction { hash: Hash },
    AnnounceBlock { block: Block },
    AnnounceTransaction { transaction: Transaction },
    PoSeChallenge { challenge_id: Hash, masternode_public_key: Vec<u8>, challenge_data: Vec<u8> },
    PoSeResponse { challenge_id: Hash, masternode_public_key: Vec<u8>, signature: Vec<u8> },
    TxLockRequest { tx_hash: Hash, inputs: Vec<OutPoint> },
    CoinJoinRequest { inputs: Vec<OutPoint>, outputs: Vec<TxOutput> },
}

#[derive(Debug, Clone, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub enum RustyCoinResponse {
    Block(Block),
    Transaction(Transaction),
    NotFound,
    Acknowledged, // For announcements
    PoSeResponse(Hash, Vec<u8>, Vec<u8>), // challenge_id, masternode_public_key, signature
    PoSeResponseAcknowledgement { challenge_id: Hash, accepted: bool },
    TxLockVote { tx_hash: Hash, signature: Vec<u8>, masternode_pro_reg_tx_hash: Hash, is_valid: bool },
    CoinJoinResponse { accepted: bool, message: String },
}

// Custom protocol for Rusty Coin messages
#[derive(Debug, Clone)]
pub struct RustyCoinProtocol;

impl Protocol for RustyCoinProtocol {
    type Message = RustyCoinRequest;
    type Codec = RustyCoinCodec;
    const PROTOCOL: &'static [u8] = b"/rusty-coin/1.0.0";
}

// Codec for serializing/deserializing Rusty Coin messages
#[derive(Clone)]
pub struct RustyCoinCodec;

impl Codec for RustyCoinCodec {
    type Request = RustyCoinRequest;
    type Response = RustyCoinResponse;
    type Protocol = RustyCoinProtocol;

    fn read_request<TReader: futures::AsyncRead + Unpin + Send>(
        self,
        _protocol: &[u8],
        mut reader: TReader,
    ) -> futures::future::BoxFuture<'static, Result<Self::Request, io::Error>> {
        Box::pin(async move {
            let mut encoded = Vec::new();
            reader.read_to_end(&mut encoded).await?;
            let (request, _): (RustyCoinRequest, usize) = bincode::decode_from_slice(
                &encoded,
                bincode::config::standard(),
            ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(request)
        })
    }

    fn read_response<TReader: futures::AsyncRead + Unpin + Send>(
        self,
        _protocol: &[u8],
        mut reader: TReader,
    ) -> futures::future::BoxFuture<'static, Result<Self::Response, io::Error>> {
        Box::pin(async move {
            let mut encoded = Vec::new();
            reader.read_to_end(&mut encoded).await?;
            let (response, _): (RustyCoinResponse, usize) = bincode::decode_from_slice(
                &encoded,
                bincode::config::standard(),
            ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(response)
        })
    }

    fn write_request<TWriter: futures::AsyncWrite + Unpin + Send>(
        self,
        _protocol: &[u8],
        request: Self::Request,
        mut writer: TWriter,
    ) -> futures::future::BoxFuture<'static, Result<(), io::Error>> {
        Box::pin(async move {
            let encoded = bincode::encode_to_vec(&request, bincode::config::standard())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            writer.write_all(&encoded).await?;
            Ok(())
        })
    }

    fn write_response<TWriter: futures::AsyncWrite + Unpin + Send>(
        self,
        _protocol: &[u8],
        response: Self::Response,
        mut writer: TWriter,
    ) -> futures::future::BoxFuture<'static, Result<(), io::Error>> {
        Box::pin(async move {
            let encoded = bincode::encode_to_vec(&response, bincode::config::standard())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            writer.write_all(&encoded).await?;
            Ok(())
        })
    }
}

impl AsRef<str> for RustyCoinProtocol {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(Self::PROTOCOL).expect("Protocol name is valid UTF-8")
    }
}

/// Core network behavior for Rusty Coin nodes.
///
/// Combines all network protocols and behaviors including:
/// - Peer discovery and identification
/// - Ping protocol for liveness checking
/// - Custom message protocols (to be implemented)
///
/// The behavior is used by the Swarm to handle network events.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "RustyCoinNetworkEvent")]
pub struct RustyCoinBehaviour {
    /// Ping protocol for connection liveness checks
    ping: Ping,
    /// Request/response protocol for custom Rusty Coin messages
    request_response: RequestResponse<RustyCoinCodec>,
    /// Kademlia DHT for peer discovery and content routing
    kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
pub enum RustyCoinNetworkEvent {
    Ping(PingEvent),
    RequestResponse(RequestResponseEvent<RustyCoinRequest, RustyCoinResponse>),
    Kademlia(KademliaEvent),
}

impl From<PingEvent> for RustyCoinNetworkEvent {
    fn from(event: PingEvent) -> Self {
        RustyCoinNetworkEvent::Ping(event)
    }
}

impl From<RequestResponseEvent<RustyCoinRequest, RustyCoinResponse>> for RustyCoinNetworkEvent {
    fn from(event: RequestResponseEvent<RustyCoinRequest, RustyCoinResponse>) -> Self {
        RustyCoinNetworkEvent::RequestResponse(event)
    }
}

impl From<KademliaEvent> for RustyCoinNetworkEvent {
    fn from(event: KademliaEvent) -> Self {
        RustyCoinNetworkEvent::Kademlia(event)
    }
}

#[derive(Debug)]
pub enum NetworkCommand {
    PublishBlock(Block),
    PublishTransaction(Transaction),
    SendPoSeChallenge { peer_id: libp2p::PeerId, challenge_id: Hash, masternode_pro_reg_tx_hash: Hash, challenge_data: Vec<u8> },
    SendPoSeResponse { peer_id: libp2p::PeerId, challenge_id: Hash, masternode_public_key: Vec<u8>, signature: Vec<u8> },
    SendTxLockRequest { tx_hash: Hash, inputs: Vec<OutPoint>, masternode_peer_ids: Vec<libp2p::PeerId> },
    SendCoinJoinRequest { peer_id: libp2p::PeerId, inputs: Vec<OutPoint>, outputs: Vec<TxOutput> },
}

#[derive(Debug)]
pub enum IncomingNetworkEvent {
    NewBlock(Block),
    NewTransaction(Transaction),
    PoSeChallenge { peer_id: libp2p::PeerId, request_id: RequestId, challenge_id: Hash, masternode_public_key: Vec<u8>, challenge_data: Vec<u8> },
    PoSeResponse { challenge_id: Hash, signature: Vec<u8>, masternode_public_key: Vec<u8> },
    TxLockVote { tx_hash: Hash, signature: Vec<u8>, masternode_pro_reg_tx_hash: Hash, is_valid: bool },
}

pub struct NetworkService {
    swarm: Swarm<RustyCoinBehaviour>,
    pending_requests: HashSet<Hash>,
    blockchain_state: Arc<dyn BlockchainState + Send + Sync>,
    command_receiver: mpsc::Receiver<NetworkCommand>,
    event_sender: mpsc::Sender<IncomingNetworkEvent>,
    keypair: identity::Keypair,
    pending_pose_challenges: HashMap<RequestId, (libp2p::PeerId, Hash, Vec<u8>, Vec<u8>)>,
    pending_pose_responses: HashMap<RequestId, (libp2p::PeerId, Hash, Vec<u8>, Vec<u8>)>,
    pending_tx_lock_requests: HashMap<RequestId, (Hash, Vec<OutPoint>)>,
}

impl NetworkService {
    pub async fn new(keypair: identity::Keypair, blockchain_state: Arc<dyn BlockchainState + Send + Sync>, command_receiver: mpsc::Receiver<NetworkCommand>, event_sender: mpsc::Sender<IncomingNetworkEvent>) -> Result<Self, Box<dyn Error>> {
        let peer_id = PeerId::from(keypair.public());
        info!("Local peer id: {:?}", peer_id);

        let transport = TokioTcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseAuthenticated::xx(&keypair).unwrap())
            .multiplex(YamuxConfig::default())
            .boxed();

        let mut cfg = KademliaConfig::default();
        cfg.set_query_timeout(std::time::Duration::from_secs(60));
        let kademlia = Kademlia::new(peer_id.clone(), MemoryStore::new(peer_id.clone()));

        let behaviour = RustyCoinBehaviour {
            ping: Ping::new(PingConfig::new().with_keep_alive(true)),
            request_response: RequestResponse::new(
                RustyCoinCodec,
                vec![(RustyCoinProtocol, ProtocolSupport::Full)],
                Default::default(),
            ),
            kademlia,
        };

        let swarm = Swarm::new(transport, behaviour, peer_id);

        Ok(Self {
            swarm,
            pending_requests: HashSet::new(),
            blockchain_state,
            command_receiver,
            event_sender,
            keypair,
            pending_pose_challenges: HashMap::new(),
            pending_pose_responses: HashMap::new(),
            pending_tx_lock_requests: HashMap::new(),
        })
    }

    pub fn publish_block(&mut self, block: Block) {
        info!("Publishing block: {:?}", block.hash());
        let request = RustyCoinRequest::AnnounceBlock { block: block.clone() };
        for peer_id in self.swarm.connected_peers() {
            self.swarm.behaviour_mut().request_response.send_request(peer_id.clone(), request.clone());
        }
    }

    pub fn publish_transaction(&mut self, tx: Transaction) {
        info!("Publishing transaction: {:?}", tx.hash());
        let request = RustyCoinRequest::AnnounceTransaction { transaction: tx.clone() };
        for peer_id in self.swarm.connected_peers() {
            self.swarm.behaviour_mut().request_response.send_request(peer_id.clone(), request.clone());
        }
    }

    pub async fn start(mut self) -> Result<(), Box<dyn Error>> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        info!("Node listening on {:?}", self.swarm.external_addresses());

        // Start Kademlia in client mode
        self.swarm.behaviour_mut().kademlia.set_mode(Some(Mode::Client));
        // Bootstrap with known peers (if any), for now, we'll try to find peers on the local network
        self.swarm.behaviour_mut().kademlia.bootstrap().expect("Kademlia bootstrap failed");

        loop {
            tokio::select! {
                swarm_event = self.swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {address:?}");
                            self.swarm.behaviour_mut().kademlia.add_listening_address(address);
                        }
                        SwarmEvent::Behaviour(event) => match event {
                            RustyCoinNetworkEvent::Ping(ping_event) => {
                                info!("Ping event: {:?}", ping_event);
                            }
                            RustyCoinNetworkEvent::RequestResponse(event) => {
                                match event {
                                    RequestResponseEvent::Message { peer, message } => {
                                        match message {
                                            RequestResponseMessage::Request { request_id, request, channel } => {
                                                match request {
                                                    RustyCoinRequest::GetBlock { hash } => {
                                                        if let Some(block) = self.blockchain_state.get_block(&hash) {
                                                            self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Block(block)).expect("Failed to send response");
                                                        } else {
                                                            self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::NotFound).expect("Failed to send response");
                                                        }
                                                    },
                                                    RustyCoinRequest::GetTransaction { hash } => {
                                                        if let Some(tx) = self.blockchain_state.get_transaction(&hash) {
                                                            self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Transaction(tx)).expect("Failed to send response");
                                                        } else {
                                                            self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::NotFound).expect("Failed to send response");
                                                        }
                                                    },
                                                    RustyCoinRequest::AnnounceBlock { block } => {
                                                        info!("Received announced block: {:?}", block.hash());
                                                        if let Err(e) = self.event_sender.send(IncomingNetworkEvent::NewBlock(block)).await {
                                                            eprintln!("Failed to send new block to main loop: {}", e);
                                                        }
                                                        self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                    },
                                                    RustyCoinRequest::AnnounceTransaction { transaction } => {
                                                        info!("Received announced transaction: {:?}", transaction.hash());
                                                        if let Err(e) = self.event_sender.send(IncomingNetworkEvent::NewTransaction(transaction)).await {
                                                            eprintln!("Failed to send new transaction to main loop: {}", e);
                                                        }
                                                        self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                    },
                                                    RustyCoinRequest::PoSeChallenge { challenge_id, masternode_public_key, challenge_data } => {
                                                        info!("Received PoSe challenge for masternode: {:?}", masternode_public_key);
                                                        // In a real implementation, verify if this node is the challenged masternode
                                                        // For this example, we'll assume the local node's peer_id is derived from the masternode's public key
                                                        // and the masternode_pro_reg_tx_hash is stored in the node's state.

                                                        // Find the masternode in the blockchain state
                                                        let masternodes = self.blockchain_state.masternodes();
                                                        if let Some(masternode) = masternodes.iter().find(|mn| mn.public_key.as_bytes() == masternode_public_key) {
                                                            let local_public_key = self.keypair.public();
                                                            if masternode.public_key.as_bytes() == local_public_key.as_ref() {
                                                                let challenge_response = rusty_coin_core::crypto::sign(
                                                                    &self.keypair.to_owned().try_into().map_err(|_| Error::Other("Invalid keypair for signing".to_string()))?,
                                                                    &challenge_data,
                                                                )?;
                                                                self.event_sender.send(IncomingNetworkEvent::PoSeResponse { 
                                                                    challenge_id,
                                                                    signature: challenge_response.0.to_vec(),
                                                                    masternode_public_key: masternode.public_key.as_bytes().to_vec(),
                                                                }).await.map_err(|e| Error::Other(format!("Failed to send PoSeResponse to main loop: {}", e)))?;
                                                                self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                            } else {
                                                                self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                            }
                                                        } else {
                                                            self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::NotFound).expect("Failed to send response");
                                                        }
                                                    },
                                                    RustyCoinRequest::PoSeResponse { challenge_id, masternode_public_key, signature } => {
                                                        info!("Received PoSe response from masternode: {:?}", masternode_public_key);
                                                        // Forward the response to the main node logic for verification
                                                        if let Err(e) = self.event_sender.send(IncomingNetworkEvent::PoSeResponse {
                                                            challenge_id,
                                                            signature,
                                                            masternode_public_key,
                                                        }).await {
                                                            eprintln!("Failed to send PoSeResponse to main loop: {}", e);
                                                        }
                                                        self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                    },
                                                    RustyCoinRequest::TxLockRequest { tx_hash, inputs } => {
                                                        info!("Received TxLockRequest for transaction: {:?}", tx_hash);
                                                        // In a real Masternode, this would involve verifying the inputs and then voting.
                                                        // For simulation, we'll just send a dummy vote.
                                                        let is_valid = true; // Assume valid for now
                                                        let masternode_pro_reg_tx_hash = Hash::zero(); // Placeholder
                                                        let signature = rusty_coin_core::crypto::sign(&self.keypair.to_owned().try_into().map_err(|_| Error::Other("Invalid keypair for signing".to_string()))?, tx_hash.as_bytes())?;

                                                        self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::TxLockVote {
                                                            tx_hash,
                                                            signature: signature.0.to_vec(),
                                                            masternode_pro_reg_tx_hash,
                                                            is_valid,
                                                        }).expect("Failed to send response");
                                                    },
                                                    RustyCoinRequest::CoinJoinRequest { inputs, outputs } => {
                                                        info!("Received CoinJoin request with inputs: {:?} and outputs: {:?}", inputs, outputs);
                                                        // In a full implementation, the masternode would coordinate the CoinJoin.
                                                        // For this simulation, just acknowledge the request.
                                                        self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::CoinJoinResponse { accepted: true, message: "CoinJoin request acknowledged".to_string() }).expect("Failed to send response");
                                                    },
                                                }
                                            },
                                            RequestResponseMessage::Response { request_id, response } => {
                                                info!("Received RequestResponse response for request {}: {:?}", request_id, response);
                                                // Handle responses to our requests (e.g., GetBlock, GetTransaction)
                                                // For PoSe challenges, update pending_pose_challenges
                                                if let Some((peer_id, challenge_id, masternode_public_key, challenge_data)) = self.pending_pose_challenges.remove(&request_id) {
                                                    // Process the response, e.g., verify signature, update masternode status
                                                    match response {
                                                        RustyCoinResponse::PoSeResponse(received_challenge_id, received_masternode_public_key, received_signature) => {
                                                            if received_challenge_id == challenge_id && received_masternode_public_key == masternode_public_key {
                                                                // Verify signature if necessary. For now, assume valid if IDs match.
                                                                if let Err(e) = self.event_sender.send(IncomingNetworkEvent::PoSeResponse { 
                                                                    challenge_id,
                                                                    signature: received_signature,
                                                                    masternode_public_key: received_masternode_public_key,
                                                                }).await {
                                                                    eprintln!("Failed to send PoSeResponse to main loop: {}", e);
                                                                }
                                                                self.swarm.behaviour_mut().request_response.send_response(channel, RustyCoinResponse::Acknowledged).expect("Failed to send response");
                                                            } else {
                                                                warn!("Mismatched PoSe response for challenge {}", challenge_id);
                                                            }
                                                        },
                                                        _ => warn!("Unexpected response type for PoSe challenge: {:?}", response),
                                                    }
                                                } else if let Some((tx_hash, inputs)) = self.pending_tx_lock_requests.remove(&request_id) {
                                                    match response {
                                                        RustyCoinResponse::TxLockVote { tx_hash: received_tx_hash, signature, masternode_pro_reg_tx_hash, is_valid } => {
                                                            if received_tx_hash == tx_hash && is_valid {
                                                                // Forward this vote to the main node logic for aggregation
                                                                if let Err(e) = self.event_sender.send(IncomingNetworkEvent::TxLockVote {
                                                                    tx_hash,
                                                                    signature,
                                                                    masternode_pro_reg_tx_hash,
                                                                    is_valid,
                                                                }).await {
                                                                    eprintln!("Failed to send TxLockVote to main loop: {}", e);
                                                                }
                                                            } else {
                                                                warn!("Received invalid or mismatched TxLockVote for transaction {}", tx_hash);
                                                            }
                                                        },
                                                        _ => warn!("Unexpected response type for TxLockRequest: {:?}", response),
                                                    }
                                                }
                                                // Handle other responses similarly
                                            }
                                        }
                                    }
                                }
                            }
                            RustyCoinNetworkEvent::Kademlia(kademlia_event) => {
                                info!("Kademlia event: {:?}", kademlia_event);
                                match kademlia_event {
                                    KademliaEvent::OutboundQueryCompleted { result, .. } => match result {
                                        QueryResult::GetProviders(Ok(get_providers)) => {
                                            for peer in get_providers.providers {
                                                info!("Found provider: {:?}", peer);
                                            }
                                        }
                                        QueryResult::GetRecord(Ok(get_record)) => {
                                            for record in get_record.records {
                                                info!("Found record: {:?}", record);
                                            }
                                        }
                                        _ => {}
                                    },
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                command = self.command_receiver.recv() => {
                    if let Some(cmd) = command {
                        match cmd {
                            NetworkCommand::PublishBlock(block) => self.publish_block(block),
                            NetworkCommand::PublishTransaction(tx) => self.publish_transaction(tx),
                            NetworkCommand::SendPoSeChallenge { peer_id, challenge_id, masternode_pro_reg_tx_hash, challenge_data } => {
                                info!("Sending PoSe challenge to {:?}", peer_id);
                                let request_id = self.swarm.behaviour_mut().request_response.send_request(
                                    peer_id.clone(),
                                    RustyCoinRequest::PoSeChallenge { challenge_id, masternode_public_key: self.keypair.public().to_bytes().to_vec(), challenge_data},
                                );
                                self.pending_pose_challenges.insert(request_id, (peer_id, challenge_id, self.keypair.public().to_bytes().to_vec(), challenge_data));
                            },
                            NetworkCommand::SendPoSeResponse { peer_id, challenge_id, masternode_public_key, signature } => {
                                info!("Sending PoSe response to {:?}", peer_id);
                                let request_id = self.swarm.behaviour_mut().request_response.send_request(
                                    peer_id.clone(),
                                    RustyCoinRequest::PoSeResponse { challenge_id, masternode_public_key, signature },
                                );
                                // This is a response to a challenge, not a new challenge. We might not need to track it as pending.
                                // For now, we'll just send it.
                            },
                            NetworkCommand::SendTxLockRequest { tx_hash, inputs, masternode_peer_ids } => {
                                info!("Sending TxLockRequest for {:?} to masternodes: {:?}", tx_hash, masternode_peer_ids);
                                let request = RustyCoinRequest::TxLockRequest { tx_hash, inputs };
                                for peer_id in masternode_peer_ids {
                                    let request_id = self.swarm.behaviour_mut().request_response.send_request(peer_id, request.clone());
                                    self.pending_tx_lock_requests.insert(request_id, (tx_hash, request.inputs.clone()));
                                }
                            },
                            NetworkCommand::SendCoinJoinRequest { peer_id, inputs, outputs } => {
                                info!("Sending CoinJoin request to {:?}", peer_id);
                                let request_id = self.swarm.behaviour_mut().request_response.send_request(
                                    peer_id,
                                    RustyCoinRequest::CoinJoinRequest { inputs, outputs },
                                );
                                // For now, no tracking needed for pending CoinJoin requests in NetworkService
                            },
                        }
                    }
                }
            }
        }
    }
}

// pub async fn start_p2p_node() -> Result<(), Box<dyn Error>> {
//     let local_key = identity::Keypair::generate_ed25519();
//     let local_peer_id = PeerId::from(local_key.public());
//     println!("Local peer id: {local_peer_id:?}");

//     let transport = TokioTcpConfig::new()
//         .nodelay(true)
//         .upgrade(upgrade::Version::V1)
//         .authenticate(NoiseAuthenticated::xx(&local_key).unwrap())
//         .multiplex(YamuxConfig::default())
//         .boxed();

//     let behaviour = RustyCoinBehaviour {
//         ping: Ping::new(PingConfig::new().with_keep_alive(true)),
//     };

//     let mut swarm = Swarm::new(transport, behaviour, local_peer_id);
//     swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

//     println!("Node listening on {:?}", swarm.external_addresses());

//     loop {
//         match swarm.select_next_some().await {
//             SwarmEvent::NewListenAddr { address, .. } => {
//                 println!("Listening on {address:?}");
//             }
//             SwarmEvent::Behaviour(PingEvent { peer, result }) => {
//                 match result {
//                     Ok(rtt) => println!("Ping to {peer} successful: {rtt:?}"),
//                     Err(e) => println!("Ping to {peer} failed: {e:?}"),
//                 }
//             }
//             _ => {}
//         }
//     }
// }