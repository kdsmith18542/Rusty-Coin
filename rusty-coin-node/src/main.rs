use rusty_coin_core::{
    types::{Block, BlockHeader, Transaction, UTXO, OutPoint, Masternode, MasternodeStatus, GovernanceProposalPayload, GovernanceVotePayload, TxInput, TxOutput, PoSVote, prelude::*},
    consensus::{ConsensusParams, validate_transaction, validate_block_full, pow, pos::VotingTicket},
    crypto::{KeyPair, PublicKey, Signature, Hash, verify_signature},
    error::{Error, Result},
};
use crate::{
    network::{NetworkService, NetworkCommand, IncomingNetworkEvent, RustyCoinRequest, RustyCoinResponse, TxLockVote, PeerRequest},
    storage::SledBlockchainState as ConcreteSledBlockchainState,
};
use tonic::{Request, Response, Status};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tokio::sync::Mutex;
use std::collections::{HashMap, HashSet};
use log::{warn, info};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use clap::Parser;

const ADAPTIVE_BLOCK_SIZE_WINDOW: u64 = 51840; // ~3 months of blocks at 2.5 min/block
const HARD_CAP_MAX_BLOCK_SIZE_BYTES: u64 = 4_000_000; // 4 MB hard cap

mod proto {
    tonic::include_proto!("rustcoin");
}

mod storage;
mod network;

/// Command line arguments for the RustyCoin node.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Port to run the gRPC server on
    #[clap(long, default_value = "50051")]
    grpc_port: u16,

    /// Port to listen for p2p connections on
    #[clap(long, default_value = "6000")]
    p2p_port: u16,

    /// Address of a peer to connect to
    #[clap(long)]
    peer: Option<String>,

    /// Path to the blockchain data directory
    #[clap(long, default_value = "./data")]
    data_dir: String,
}

pub struct RustyCoinNode {
    pub keypair: KeyPair,
    pub mempool: Mutex<HashMap<Hash, Transaction>>,
    pub blockchain_state: Arc<dyn BlockchainState + Send + Sync>,
    pub consensus_params: ConsensusParams,
    pub network_sender: mpsc::Sender<NetworkCommand>,
    pub network_event_receiver: Mutex<mpsc::Receiver<IncomingNetworkEvent>>,
    pub current_ticket_price: Mutex<u64>,
    pub locked_transactions: Mutex<HashSet<Hash>>,
}

impl RustyCoinNode {
    pub async fn new(
        keypair: KeyPair,
        blockchain_state: Arc<dyn BlockchainState + Send + Sync>,
        consensus_params: ConsensusParams,
        network_sender: mpsc::Sender<NetworkCommand>,
        network_event_receiver: mpsc::Receiver<IncomingNetworkEvent>,
    ) -> Result<Self> {
        let current_ticket_price = Self::get_initial_ticket_price(&*blockchain_state).await?;
        Ok(Self {
            keypair,
            mempool: Mutex::new(HashMap::new()),
            blockchain_state,
            consensus_params,
            network_sender,
            network_event_receiver: Mutex::new(network_event_receiver),
            current_ticket_price: Mutex::new(current_ticket_price),
            locked_transactions: Mutex::new(HashSet::new()),
        })
    }

    async fn get_initial_ticket_price(blockchain_state: &dyn BlockchainState) -> Result<u64> {
        // For now, a fixed initial price. Later, this will be dynamic.
        // In a real scenario, this would involve fetching the last block and calculating.
        Ok(100_000_000_000) // 1000 RUST
    }

    /// Processes a newly received block, applies it to the blockchain state.
    /// This includes validating the block, updating UTXOs, and adding to the chain.
    pub async fn process_new_block(&self, block: Block) -> Result<()> {
        info!("Processing new block: {}", block.header.hash());

        // 1. Validate block against current state
        let mut locked_transactions = self.locked_transactions.lock().await;
        let active_tickets_current = self.blockchain_state.active_tickets();

        // Fetch last N headers for LWMA difficulty adjustment
        let last_headers = self.blockchain_state.get_last_n_headers(self.consensus_params.difficulty_adjustment_window);

        validate_block_full(
            &block,
            &last_headers?,
            &active_tickets_current,
            self.blockchain_state.height(),
            &self.consensus_params,
        )?;

        // Remove spent UTXOs and add new UTXOs
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    self.blockchain_state.remove_utxo(&input.outpoint.tx_hash, input.outpoint.output_index)?;
                }
            }
            for (index, output) in tx.outputs.iter().enumerate() {
                let utxo = UTXO {
                    tx_hash: tx.hash(),
                    output_index: index as u32,
                    value: output.value,
                    script_pubkey: output.pubkey_hash,
                };
                self.blockchain_state.add_utxo(utxo)?;
            }

            // Remove transactions from mempool and locked_transactions
            self.mempool.lock().await.remove(&tx.hash());
            locked_transactions.remove(&tx.hash());
        }

        // Update blockchain state
        self.blockchain_state.put_block(&block)?;
        self.blockchain_state.put_header(&block.header)?;
        let current_height = self.blockchain_state.height();
        self.blockchain_state.update_height(current_height + 1)?;

        let active_tickets_count = self.blockchain_state.active_tickets().len() as u64;

        // Update dynamic ticket price (PoS)
        let next_ticket_price = self.consensus_params.ticket_params.calculate_next_ticket_price(
            active_tickets_count,
            self.consensus_params.ticket_params.target_active_tickets,
            self.consensus_params.ticket_params.ticket_price_adjustment_factor,
        );
        *self.current_ticket_price.lock().await = next_ticket_price;
        info!("New ticket price: {}", next_ticket_price);

        info!("Block {} processed successfully. Current height: {}", block.header.hash(), self.blockchain_state.height());

        // Process ticket revocations
        for tx in &block.transactions {
            if let Some(payload) = &tx.outputs.iter().find_map(|output| output.revocation_data.clone()) {
                if let Some(ticket) = self.blockchain_state.active_tickets().iter().find(|t| t.hash == payload.ticket_hash).cloned() {
                    self.blockchain_state.remove_active_ticket(&ticket.hash)?;
                    println!("Removed used active ticket from quorum: {:?}", ticket.hash);
                }
            }
        }

        // Process masternode registrations, updates, and revocations
        for tx in &block.transactions {
            if let Some(payload) = &tx.outputs.iter().find_map(|output| output.masternode_data.clone()) {
                let masternode = Masternode::new(
                    tx.hash(),
                    tx.inputs[0].outpoint.tx_hash, // Assuming collateral is the first input
                    tx.inputs[0].outpoint.output_index,
                    payload.public_key.clone(),
                    payload.payout_address,
                    payload.ip_address.clone(),
                    payload.port,
                    block.header.height,
                );

                if let Some(existing_masternode) = self.blockchain_state.masternodes().iter().find(|mn| mn.pro_reg_tx_hash == tx.hash()) {
                    // Masternode update
                    // In a real system, you'd verify the update details (e.g., signature).
                    // For now, we'll just update its last_seen and status if needed.
                    let mut updated_mn = existing_masternode.clone();
                    updated_mn.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    // Potentially update other fields from payload if applicable
                    self.blockchain_state.update_masternode(updated_mn)?;
                    info!("Masternode updated: {}", tx.hash());
                } else {
                    // New masternode registration
                    self.blockchain_state.add_masternode(masternode)?;
                    info!("Masternode registered: {}", tx.hash());
                }
            }

            // Masternode revocation (assuming a specific output type or a dedicated transaction type for revocation)
            // For simplicity, let's assume a revocation transaction burns the collateral and references the original pro_reg_tx_hash
            // This part needs a proper definition of how masternode revocations are handled.
            // If a masternode is revoked, remove it from the active masternode set.
            // Example: if a special output exists that signals revocation for a given pro_reg_tx_hash
            if tx.outputs.iter().any(|output| output.value == MASTERNODE_COLLATERAL && output.pubkey_hash == PublicKey::zero().blake3().into()) { // Dummy check for a burn output
                // Find the original masternode registration tx hash. This is a simplification.
                // In a real system, a revocation tx would explicitly link to the masternode.
                if let Some(reg_tx_hash) = tx.inputs.get(0).map(|input| input.outpoint.tx_hash) {
                    if let Some(_removed_mn) = self.blockchain_state.masternodes().iter().find(|mn| mn.pro_reg_tx_hash == reg_tx_hash).cloned() {
                        self.blockchain_state.remove_masternode(&reg_tx_hash)?;
                        info!("Masternode revoked: {}", reg_tx_hash);
                    }
                }
            }

            // Handle governance proposals and votes
            if let Some(proposal_payload) = tx.extract_governance_proposal_from_outputs() {
                self.blockchain_state.put_governance_proposal(&tx.hash(), &proposal_payload)?;
                info!("Governance proposal added: {}", tx.hash());
            }
            if let Some(vote_payload) = tx.extract_vote_from_outputs(&tx.hash()) { // Pass tx.hash() here
                self.blockchain_state.put_governance_vote(&tx.hash(), &vote_payload)?;
                info!("Governance vote added for proposal {}: {}", vote_payload.proposal_id, tx.hash());
            }
        }

        // Store block size history
        let block_size = bincode::encode_to_vec(&block, bincode::config::standard()).unwrap_or_default().len() as u64;
        self.blockchain_state.put_block_size(block.header.height, block_size)?;

        Ok(())
    }

    /// Reverts a block from the blockchain state (used during reorgs).
    pub async fn revert_block_changes(&self, block: Block) -> Result<()> {
        info!("Reverting block changes for block: {}", block.header.hash());

        // Revert UTXO changes
        for tx in &block.transactions {
            // Add back spent UTXOs (assuming get_spent_utxo can retrieve them)
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    if let Some(utxo) = self.blockchain_state.get_utxo(&input.outpoint.tx_hash, input.outpoint.output_index) { // Use get_utxo instead of get_spent_utxo
                        self.blockchain_state.add_utxo(utxo)?;
                    }
                }
            }
            // Remove UTXOs created by this block
            for (index, _output) in tx.outputs.iter().enumerate() {
                self.blockchain_state.remove_utxo(&tx.hash(), index as u32)?;
            }
        }

        // Revert ticket and masternode changes (simplified)
        for tx in &block.transactions {
            if let Some(ticket) = tx.outputs.iter().find_map(|output| output.ticket_data.clone()).map(|payload| {
                // Reconstruct VotingTicket. This is a simplification and might need more data.
                VotingTicket::new(tx.hash(), payload.staker_public_key, 0, payload.creation_height, vec![]) // Dummy stake_amount and signature
            }) {
                self.blockchain_state.remove_active_ticket(&ticket.hash)?;
            }
            // Revert masternode registrations/updates/revocations
            if let Some(_payload) = &tx.outputs.iter().find_map(|output| output.masternode_data.clone()) {
                // This logic needs to be robust, possibly by storing historical masternode states
                // For now, if a masternode was added by this block, remove it. If updated, revert to previous state.
                // This is a placeholder.
            }

            // Revert governance proposals and votes
            if let Some(_proposal_payload) = tx.extract_governance_proposal_from_outputs() {
                self.blockchain_state.remove_governance_proposal(&tx.hash())?;
            }
            if let Some(vote_payload) = tx.extract_vote_from_outputs(&tx.hash()) { // Pass tx.hash() here
                self.blockchain_state.remove_governance_vote(&tx.hash(), &vote_payload.proposal_id)?;
            }
        }

        // Revert block size history
        // Need to add `remove_from_tree` to BlockchainState trait or `SledBlockchainState` if not already there.
        // For now, we'll comment this out if not directly supported by trait.
        // self.blockchain_state.remove_from_tree(&self.blockchain_state.block_size_history, &block.header.height.to_be_bytes())?;

        // Revert height and tip hash (simplified)
        self.blockchain_state.update_height(block.header.height - 1)?;
        // This also implies reverting the tip_hash in metadata to the previous block's hash.
        // A proper implementation would need to retrieve the hash of block.header.height - 1.
        // For now, we'll just update height.

        info!("Block {} reverted successfully.", block.header.hash());
        Ok(())
    }

    /// Periodically checks for inactive masternodes and deactivates them.
    pub async fn check_for_inactive_masternodes(&self) -> Result<()> {
        let masternodes = self.blockchain_state.masternodes();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let pose_timeout = self.consensus_params.masternode_params.pose_timeout_seconds;
        let max_pose_failures = self.consensus_params.masternode_params.max_pose_failures;

        for mn in masternodes {
            if mn.status == MasternodeStatus::Active && (current_time - mn.last_seen) > pose_timeout {
                self.blockchain_state.increment_masternode_pose_failures(&mn.pro_reg_tx_hash)?;
                if mn.failed_pose_challenges >= max_pose_failures {
                    self.blockchain_state.deactivate_masternode(&mn.pro_reg_tx_hash)?;
                    info!("Masternode {} deactivated due to PoSe failures.", mn.pro_reg_tx_hash);
                }
            }
        }
        Ok(())
    }

    /// Calculates the adaptive block size limit based on recent block sizes.
    pub async fn calculate_adaptive_block_size_limit(&self) -> u64 {
        let current_height = self.blockchain_state.height();
        if current_height == 0 {
            return 1_000_000; // Initial block size limit (1 MB)
        }

        let start_height = if current_height > 100 { current_height - 100 } else { 0 };
        let recent_block_sizes = self.blockchain_state.get_block_sizes_in_range(start_height, current_height);

        if recent_block_sizes.is_empty() {
            return 1_000_000; // Default if no history
        }

        let total_size: u64 = recent_block_sizes.iter().sum();
        let average_size = total_size / (recent_block_sizes.len() as u64);

        // Adjust limit based on average. For simplicity, let's say 1.5x average.
        (average_size * 150) / 100 // 1.5 multiplier
    }

    // Example: send PoSe challenge to a random masternode
    pub async fn send_pose_challenge_to_random_masternode(&self) -> Result<()> {
        let masternodes = self.blockchain_state.masternodes();
        if masternodes.is_empty() {
            return Ok(());
        }

        let mut rng = rand::thread_rng();
        let random_index = rng.next_u64() as usize % masternodes.len();
        let target_masternode = &masternodes[random_index];

        info!("Sending PoSe challenge to masternode: {}", target_masternode.ip_address);

        let challenge_id = Hash::blake3(format!("pose_challenge_{}_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), rng.next_u64()).as_bytes());
        let dummy_challenge_data = Hash::blake3(format!("challenge_data_{}", challenge_id).as_ref()).to_vec(); // Use as_ref()

        self.network_sender.send(NetworkCommand::SendPoSeChallenge {
            peer_id: target_masternode.public_key.to_lib_p2p_public_key().to_peer_id(),
            challenge_id: challenge_id.to_vec(),
            data: dummy_challenge_data,
        }).await.map_err(|e| Error::NetworkError(e.to_string()))?;
        Ok(())
    }

    // CoinJoin initiation (client-side simplified)
    pub async fn initiate_coinjoin(&self) -> Result<()> {
        info!("Initiating CoinJoin request...");
        // In a real CoinJoin, this would involve selecting UTXOs, finding other participants, etc.
        // For now, we just send a dummy request.
        
        // This needs to be a valid PeerId, maybe a known CoinJoin coordinator or random peer.
        // For now, let's send to a dummy PeerId.
        let dummy_peer_id = libp2p::PeerId::random(); 

        self.network_sender.send(NetworkCommand::SendCoinJoinRequest {
            peer_id: dummy_peer_id,
            amount: 100_000_000, // Example amount
            num_participants: 3,
        }).await.map_err(|e| Error::NetworkError(e.to_string()))?;
        Ok(())
    }

    // Main mining/staking loop
    pub async fn run_mining_loop(node_arc: Arc<RustyCoinNode>) -> Result<()> {
        let mut last_block_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        loop {
            sleep(Duration::from_secs(node_arc.consensus_params.target_block_time)).await;

            let current_height = node_arc.blockchain_state.height();
            let latest_block_hash = node_arc.blockchain_state.get_block_hash_at_height(current_height).unwrap_or(Hash::zero());
            let latest_block = node_arc.blockchain_state.get_block(&latest_block_hash).unwrap_or_else(|| Block::create_genesis_block(
                create_coinbase_transaction(0, KeyPair::generate().public_key.blake3().into()),
                &KeyPair::generate(),
                node_arc.consensus_params.min_difficulty.to_bits(), // Use min_difficulty for genesis
            ).expect("Failed to create genesis block"));

            let current_height = node_arc.blockchain_state.height();

            // Select a staker from active tickets
            let active_tickets = node_arc.blockchain_state.active_tickets();
            let staker_ticket = if active_tickets.is_empty() {
                warn!("No active staking tickets available. Cannot create PoS block.");
                // Fallback to PoW or wait
                continue;
            } else {
                let mut rng = rand::thread_rng();
                let chosen_ticket_index = rng.next_u64() as usize % active_tickets.len();
                active_tickets[chosen_ticket_index].clone()
            };

            // Calculate next difficulty
            let difficulty_adjustment_window = node_arc.consensus_params.difficulty_adjustment_window;
            let target_block_time = node_arc.consensus_params.target_block_time;

            let last_n_headers = node_arc.blockchain_state.get_last_n_headers(difficulty_adjustment_window);
            let target_difficulty_bits = pow::calculate_next_work_required(
                &last_n_headers?,
                &node_arc.consensus_params,
            )?;

            let locked_transactions = node_arc.locked_transactions.lock().await;
            let mempool = node_arc.mempool.lock().await;

            // Prioritize locked transactions
            let mut block_transactions: Vec<Transaction> = locked_transactions.iter()
                .filter_map(|tx_hash| mempool.get(tx_hash).cloned())
                .collect();
            
            // Add other transactions from mempool up to block size limit
            let adaptive_block_size_limit = node_arc.calculate_adaptive_block_size_limit().await;
            let mut current_block_size = 0;
            for tx_hash in mempool.keys().filter(|tx_hash| !locked_transactions.contains(tx_hash)) {
                if let Some(tx) = mempool.get(tx_hash) {
                    let tx_size = bincode::encode_to_vec(&tx, bincode::config::standard()).unwrap_or_default().len() as u64;
                    if current_block_size + tx_size <= adaptive_block_size_limit {
                        block_transactions.push(tx.clone());
                        current_block_size += tx_size;
                    } else {
                        break;
                    }
                }
            }
            
            // Create coinbase transaction (mining reward)
            let coinbase_reward = rusty_coin_core::consensus::calculate_coinbase_reward(current_height + 1);
            let coinbase_tx = Transaction::new_coinbase(
                node_arc.keypair.public_key.blake3().into(), // Reward to miner's address
                coinbase_reward,
                current_height + 1,
            );
            block_transactions.insert(0, coinbase_tx);

            let merkle_root = Block::compute_merkle_root_from_transactions(&block_transactions);
            let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            let mut new_block_header = BlockHeader::new(
                1, // version
                latest_block.header.hash(), // prev_block_hash
                merkle_root, // merkle_root
                current_timestamp, // timestamp
                target_difficulty_bits, // bits (difficulty)
                0, // nonce (for PoW)
                staker_ticket.hash, // ticket_hash (PoS)
                latest_block.header.cumulative_work + pow::calculate_work_from_bits(target_difficulty_bits), // cumulative_work
                current_height + 1, // height
                Hash::zero(), // sidechain_commitment_hash
                vec![], // pos_votes (filled after block creation for current block)
            );

            // Sign the block header with the staker's private key
            let header_hash = new_block_header.hash();
            let signature = rusty_coin_core::crypto::sign(
                &node_arc.keypair,
                header_hash.as_ref()
            )?;
            
            // Create PoS vote for this block
            let pos_vote = PoSVote::new(
                staker_ticket.hash,
                new_block_header.hash(),
                signature.0.to_vec(),
            );
            new_block_header.pos_votes.push(pos_vote);

            let new_block = Block::new(new_block_header, block_transactions);
            info!("Created new block: {}", new_block.header.hash());

            // Broadcast new block
            node_arc.network_sender.send(NetworkCommand::BroadcastBlock(new_block.clone()))
                .await
                .map_err(|e| Error::NetworkError(e.to_string()))?;
            
            node_arc.process_new_block(new_block.clone()).await?;
        }
    }
}

#[tonic::async_trait]
impl proto::node_server::Node for RustyCoinNode {
    async fn get_latest_block(
        &self,
        request: Request<GetLatestBlockRequest>,
    ) -> Result<Response<GetLatestBlockResponse>, Status> {
        // Implementation for GetLatestBlock
        let current_height = self.blockchain_state.height();
        let latest_block_hash = self.blockchain_state.get_block_hash_at_height(current_height).unwrap_or(Hash::zero());
        let latest_block = self.blockchain_state.get_block(&latest_block_hash).ok_or(Status::not_found("Latest block not found"))?;
        
        Ok(Response::new(GetLatestBlockResponse {
            block: Some(latest_block.into()), // Convert Block to ProtoBlock
        }))
    }

    async fn get_block(
        &self,
        request: Request<GetBlockRequest>,
    ) -> Result<Response<GetBlockResponse>, Status> {
        // Implementation for GetBlock
        let block_hash = Hash::from_slice(&request.get_ref().hash)
            .ok_or(Status::invalid_argument("Invalid block hash"))?;
        let block = self.blockchain_state.get_block(&block_hash)
            .ok_or(Status::not_found("Block not found"))?;
        Ok(Response::new(GetBlockResponse {
            block: Some(block.into()),
        }))
    }

    async fn submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        // Implementation for SubmitTransaction
        let proto_tx = request.into_inner().transaction.ok_or(Status::invalid_argument("Transaction missing"))?;
        let tx: Transaction = proto_tx.try_into().map_err(|e: Error| Status::invalid_argument(format!("Invalid transaction: {}", e.to_string())))?;

        // Basic validation (more comprehensive validation is in process_new_block)
        validate_transaction(&tx, &*self.blockchain_state)
            .map_err(|e| Status::invalid_argument(format!("Transaction validation failed: {}", e.to_string())))?;

        self.mempool.lock().await.insert(tx.hash(), tx.clone());
        info!("Transaction {} submitted to mempool.", tx.hash());

        // Broadcast transaction
        self.network_sender.send(NetworkCommand::BroadcastTransaction(tx.clone()))
            .await
            .map_err(|e| Status::internal(format!("Failed to broadcast transaction: {}", e.to_string())))?;

        Ok(Response::new(SubmitTransactionResponse {
            success: true,
            message: format!("Transaction {} submitted", tx.hash()),
        }))
    }

    async fn get_utxo(
        &self,
        request: Request<GetUTXORequest>,
    ) -> Result<Response<GetUTXOResponse>, Status> {
        // Implementation for GetUTXO
        let req = request.into_inner();
        let tx_hash = Hash::from_slice(&req.tx_hash).ok_or(Status::invalid_argument("Invalid tx hash"))?;
        let utxo = self.blockchain_state.get_utxo(&tx_hash, req.output_index)
            .ok_or(Status::not_found("UTXO not found"))?;
        Ok(Response::new(GetUTXOResponse {
            utxo: Some(utxo.into()),
        }))
    }

    async fn get_mempool(
        &self,
        _request: Request<GetMempoolRequest>,
    ) -> Result<Response<GetMempoolResponse>, Status> {
        let mempool_txs: Vec<ProtoTransaction> = self.mempool.lock().await.values()
            .map(|tx| tx.clone().into())
            .collect();
        Ok(Response::new(GetMempoolResponse { transactions: mempool_txs }))
    }

    async fn get_blockchain_state(
        &self,
        _request: Request<GetBlockchainStateRequest>,
    ) -> Result<Response<GetBlockchainStateResponse>, Status> {
        let current_height = self.blockchain_state.height();
        let latest_block_hash = self.blockchain_state.get_block_hash_at_height(current_height).unwrap_or(Hash::zero());
        let latest_block = self.blockchain_state.get_block(&latest_block_hash);
        
        let mut masternodes: Vec<ProtoMasternode> = Vec::new();
        for mn in self.blockchain_state.masternodes() {
            masternodes.push(mn.into());
        }

        Ok(Response::new(GetBlockchainStateResponse {
            current_height,
            latest_block_hash: latest_block_hash.to_vec(),
            latest_block_timestamp: latest_block.map_or(0, |b| b.header.timestamp),
            active_tickets_count: self.blockchain_state.active_tickets().len() as u64,
            current_ticket_price: *self.current_ticket_price.lock().await,
            masternodes,
        }))
    }

    async fn get_masternodes(
        &self,
        _request: Request<GetMasternodesRequest>,
    ) -> Result<Response<GetMasternodesResponse>, Status> {
        let masternodes: Vec<ProtoMasternode> = self.blockchain_state.masternodes().into_iter()
            .map(|mn| mn.into())
            .collect();
        Ok(Response::new(GetMasternodesResponse { masternodes }))
    }

    async fn get_governance_proposal(
        &self,
        request: Request<GetGovernanceProposalRequest>,
    ) -> Result<Response<GetGovernanceProposalResponse>, Status> {
        let proposal_id = Hash::from_slice(&request.get_ref().proposal_id)
            .ok_or(Status::invalid_argument("Invalid proposal ID"))?;
        let proposal = self.blockchain_state.get_governance_proposal(&proposal_id)
            .ok_or(Status::not_found("Proposal not found"))?;
        Ok(Response::new(GetGovernanceProposalResponse { proposal: Some(proposal.into()) }))
    }

    async fn get_governance_proposals(
        &self,
        _request: Request<GetGovernanceProposalsRequest>,
    ) -> Result<Response<GetGovernanceProposalsResponse>, Status> {
        let proposals: Vec<proto::GovernanceProposalPayload> = self.blockchain_state.get_all_governance_proposals().into_iter()
            .map(|p| p.into())
            .collect();
        Ok(Response::new(GetGovernanceProposalsResponse { proposals }))
    }

    async fn submit_governance_proposal(
        &self,
        request: Request<SubmitGovernanceProposalRequest>,
    ) -> Result<Response<SubmitGovernanceProposalResponse>, Status> {
        let proposal_payload_proto = request.into_inner().proposal.ok_or(Status::invalid_argument("Proposal missing"))?;
        let proposal_payload: GovernanceProposalPayload = proposal_payload_proto.try_into().map_err(|e: Error| Status::invalid_argument(format!("Invalid proposal payload: {}", e.to_string())))?;

        // For simplicity, we directly add to state. In a real system, this would involve a transaction.
        self.blockchain_state.put_governance_proposal(&proposal_payload.proposal_id, &proposal_payload)
            .map_err(|e| Status::internal(format!("Failed to store proposal: {}", e.to_string())))?;

        Ok(Response::new(SubmitGovernanceProposalResponse { success: true, message: "Proposal submitted".to_string() }))
    }

    async fn submit_governance_vote(
        &self,
        request: Request<SubmitGovernanceVoteRequest>,
    ) -> Result<Response<SubmitGovernanceVoteResponse>, Status> {
        let vote_payload_proto = request.into_inner().vote.ok_or(Status::invalid_argument("Vote missing"))?;
        let vote_payload: GovernanceVotePayload = vote_payload_proto.try_into().map_err(|e: Error| Status::invalid_argument(format!("Invalid vote payload: {}", e.to_string())))?;

        // For simplicity, directly add to state. In a real system, this would involve a transaction.
        self.blockchain_state.put_governance_vote(&Hash::blake3(&vote_payload.proposal_id.to_vec()), &vote_payload) // Using proposal_id as part of the vote_tx_hash
            .map_err(|e| Status::internal(format!("Failed to store vote: {}", e.to_string())))?;

        Ok(Response::new(SubmitGovernanceVoteResponse { success: true, message: "Vote submitted".to_string() }))
    }

    async fn get_governance_votes_for_proposal(
        &self,
        request: Request<GetGovernanceVotesForProposalRequest>,
    ) -> Result<Response<GetGovernanceVotesForProposalResponse>, Status> {
        let proposal_id = Hash::from_slice(&request.get_ref().proposal_id)
            .ok_or(Status::invalid_argument("Invalid proposal ID"))?;
        let votes: Vec<proto::GovernanceVotePayload> = self.blockchain_state.get_governance_votes_for_proposal(&proposal_id).into_iter()
            .map(|v| v.into())
            .collect();
        Ok(Response::new(GetGovernanceVotesForProposalResponse { votes }))
    }

    async fn get_active_tickets(
        &self,
        _request: Request<GetActiveTicketsRequest>,
    ) -> Result<Response<GetActiveTicketsResponse>, Status> {
        let tickets: Vec<ProtoVotingTicket> = self.blockchain_state.active_tickets().into_iter()
            .map(|t| t.into())
            .collect();
        Ok(Response::new(GetActiveTicketsResponse { tickets }))
    }
}

fn create_coinbase_transaction(height: u64, pubkey_hash: [u8; 20]) -> Transaction {
    Transaction::new_coinbase(pubkey_hash, 50_000_000_000, height)
}

#[tokio::main] // Use tokio::main for async main function
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    let keypair = KeyPair::generate();
    info!("Node Public Key: {:?}", keypair.public_key);

    let blockchain_state: Arc<dyn BlockchainState + Send + Sync> = Arc::new(ConcreteSledBlockchainState::new(&args.data_dir)?);
    let consensus_params = ConsensusParams::default();

    // Initialize genesis block if chain is empty
    if blockchain_state.height() == 0 {
        info!("Initializing genesis block...");
        let genesis_tx = create_coinbase_transaction(0, keypair.public_key.blake3().into());
        let genesis_block = Block::create_genesis_block(genesis_tx, &keypair, consensus_params.min_difficulty.to_bits()).expect("Failed to create genesis block");
        blockchain_state.put_block(&genesis_block)?;
        blockchain_state.put_header(&genesis_block.header)?;
        blockchain_state.update_height(1)?;
        info!("Genesis block created and added.");
    }

    let (network_sender, network_event_receiver) = mpsc::channel(100);

    let node = Arc::new(RustyCoinNode::new(
        keypair,
        blockchain_state.clone(),
        consensus_params,
        network_sender.clone(),
        network_event_receiver,
    ).await?);

    // Start network service
    let network_service_node = node.clone();
    let p2p_port = args.p2p_port;
    let peer_addr = args.peer.clone();
    tokio::spawn(async move {
        if let Err(e) = NetworkService::start(network_service_node, p2p_port, peer_addr).await {
            error!("Network service failed: {}", e);
        }
    });

    let grpc_node = node.clone();
    let grpc_port = args.grpc_port;
    let grpc_server_task = tokio::spawn(async move {
        info!("gRPC server listening on port {}", grpc_port);
        Server::builder()
            .add_service(proto::node_server::NodeServer::new(grpc_node))
            .serve(format!("0.0.0.0:{}", grpc_port).parse()?)
            .await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let mining_loop_node = node.clone();
    let mining_loop_task = tokio::spawn(async move {
        if let Err(e) = RustyCoinNode::run_mining_loop(mining_loop_node).await {
            error!("Mining loop failed: {}", e);
        }
    });

    let network_event_processor_node = node.clone();
    let network_event_processor_task = tokio::spawn(async move {
        let mut receiver = network_event_processor_node.network_event_receiver.lock().await;
        loop {
            tokio::select! {
                Some(event) = receiver.recv() => {
                    match event {
                        IncomingNetworkEvent::NewPeerConnected(peer_id) => {
                            info!("New peer connected: {}", peer_id);
                        }
                        IncomingNetworkEvent::PeerDisconnected(peer_id) => {
                            info!("Peer disconnected: {}", peer_id);
                        }
                        IncomingNetworkEvent::ReceivedRequest(peer_id, request) => {
                            info!("Received request from {}: {:?}", peer_id, request);
                            match request {
                                RustyCoinRequest::Block(block) => {
                                    info!("Received block {} from {}", block.header.hash(), peer_id);
                                    // Process the received block asynchronously
                                    let node_clone = network_event_processor_node.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = node_clone.process_new_block(block).await {
                                            error!("Error processing received block: {}", e);
                                        }
                                    });
                                }
                                RustyCoinRequest::Transaction(tx) => {
                                    info!("Received transaction {} from {}", tx.hash(), peer_id);
                                    // Add to mempool and broadcast if valid
                                    if let Err(e) = validate_transaction(&tx, &*network_event_processor_node.blockchain_state) {
                                        warn!("Invalid transaction received from {}: {}", peer_id, e);
                                    } else {
                                        network_event_processor_node.mempool.lock().await.insert(tx.hash(), tx.clone());
                                        info!("Transaction {} added to mempool.", tx.hash());
                                        // Broadcast to other peers
                                        if let Err(e) = network_event_processor_node.network_sender.send(NetworkCommand::BroadcastTransaction(tx)).await {
                                            error!("Failed to broadcast received transaction: {}", e);
                                        }
                                    }
                                }
                                RustyCoinRequest::TxLockVote(vote) => {
                                    info!("Received TxLockVote for {} from {}", Hash::from_slice(&vote.tx_hash).unwrap_or_default(), peer_id);
                                    let tx_hash = Hash::from_slice(&vote.tx_hash).unwrap_or_default();
                                    network_event_processor_node.locked_transactions.lock().await.insert(tx_hash);
                                    info!("Transaction {} locked.", tx_hash);
                                }
                                RustyCoinRequest::PoSeChallenge { challenge_id, data } => {
                                    info!("Received PoSeChallenge {} from {}", Hash::from_slice(&challenge_id).unwrap_or_default(), peer_id);
                                    // Respond to PoSe challenge
                                    let response_data = Hash::blake3(&data);
                                    let signature = rusty_coin_core::crypto::sign(
                                        &network_event_processor_node.keypair,
                                        response_data.as_ref()
                                    )?;
                                    network_event_processor_node.network_sender.send(NetworkCommand::SendPoSeResponse {
                                        peer_id,
                                        challenge_id,
                                        response_data: response_data.to_vec(),
                                        signature: signature.0.to_vec(),
                                    }).await.map_err(|e| Error::NetworkError(e.to_string()))?;
                                }
                                RustyCoinRequest::CoinJoinRequest { amount, num_participants } => {
                                    info!("Received CoinJoinRequest from {} for amount {} with {} participants", peer_id, amount, num_participants);
                                    // This node would act as a CoinJoin coordinator or participant
                                    // For now, we just acknowledge or respond trivially.
                                    network_event_processor_node.network_sender.send(NetworkCommand::SendCoinJoinResponse {
                                        peer_id,
                                        success: true,
                                        message: "CoinJoin request received and acknowledged.".to_string(),
                                    }).await.map_err(|e| Error::NetworkError(e.to_string()))?;
                                }
                                _ => {
                                    warn!("Unhandled RustyCoinRequest from {}: {:?}", peer_id, request);
                                }
                            }
                        }
                        IncomingNetworkEvent::ReceivedResponse(peer_id, response) => {
                            info!("Received response from {}: {:?}", peer_id, response);
                            match response {
                                RustyCoinResponse::PoSeResponse { challenge_id, response_data, signature } => {
                                    info!("Received PoSeResponse for {} from {}", Hash::from_slice(&challenge_id).unwrap_or_default(), peer_id);
                                    let challenge_hash = Hash::blake3(&Hash::from_slice(&challenge_id).unwrap_or_default().to_vec());
                                    let pubkey = network_event_processor_node.blockchain_state.masternodes().iter().find(|mn| mn.public_key.to_lib_p2p_public_key().to_peer_id() == peer_id).map(|mn| mn.public_key.clone());
                                    if let Some(pk) = pubkey {
                                        if verify_signature(&pk, challenge_hash.as_ref(), &Signature::try_from(signature).unwrap())? {
                                            info!("PoSe challenge {} from {} verified successfully.", Hash::from_slice(&challenge_id).unwrap_or_default(), peer_id);
                                            // Update masternode's last_seen timestamp and reset failure count
                                            if let Err(e) = network_event_processor_node.blockchain_state.update_masternode_last_seen(
                                                &network_event_processor_node.blockchain_state.masternodes().iter().find(|mn| mn.public_key == pk).unwrap().pro_reg_tx_hash
                                            ) {
                                                error!("Failed to update masternode last seen: {}", e);
                                            }
                                        } else {
                                            warn!("PoSe challenge {} from {} verification failed.", Hash::from_slice(&challenge_id).unwrap_or_default(), peer_id);
                                            // Increment masternode's failed PoSe challenges count
                                            if let Err(e) = network_event_processor_node.blockchain_state.increment_masternode_pose_failures(
                                                &network_event_processor_node.blockchain_state.masternodes().iter().find(|mn| mn.public_key == pk).unwrap().pro_reg_tx_hash
                                            ) {
                                                error!("Failed to increment masternode PoSe failures: {}", e);
                                            }
                                        }
                                    }
                                }
                                RustyCoinResponse::CoinJoinResponse { success, message } => {
                                    info!("Received CoinJoinResponse from {}: Success: {}, Message: {}", peer_id, success, message);
                                    // Handle CoinJoin response
                                }
                                _ => {
                                    warn!("Unhandled RustyCoinResponse from {}: {:?}", peer_id, response);
                                }
                            }
                        }
                        IncomingNetworkEvent::Other(msg) => {
                            info!("Received other network event: {:?}", msg);
                        }
                    }
                }
                // Periodically send PoSe challenges
                _ = sleep(Duration::from_secs(60)) => {
                    let node_clone = network_event_processor_node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node_clone.send_pose_challenge_to_random_masternode().await {
                            error!("Error sending PoSe challenge: {}", e);
                        }
                    });
                }
                // Periodically check for inactive masternodes
                _ = sleep(Duration::from_secs(300)) => { // Every 5 minutes
                    let node_clone = network_event_processor_node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node_clone.check_for_inactive_masternodes().await {
                            error!("Error checking for inactive masternodes: {}", e);
                        }
                    });
                }
                // Periodically initiate CoinJoin (for testing/example purposes)
                _ = sleep(Duration::from_secs(120)) => {
                    let node_clone = network_event_processor_node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node_clone.initiate_coinjoin().await {
                            error!("Error initiating CoinJoin: {}", e);
                        }
                    });
                }
            }
        }
    });

    // Wait for all tasks to complete (or for an error)
    tokio::try_join!(
        grpc_server_task,
        mining_loop_task,
        network_event_processor_task,
    )?;

    Ok(())
}
