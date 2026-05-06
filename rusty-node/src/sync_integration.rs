use rusty_core::network::sync_manager::SyncManager;
use std::sync::Arc;
use tokio::task;

#[allow(dead_code)]
pub async fn start_sync_manager(
    blockchain: Arc<std::sync::Mutex<rusty_core::consensus::blockchain::Blockchain>>,
    p2p_network: Arc<std::sync::Mutex<dyn rusty_core::network::P2PNetwork + Send + Sync>>,
) {
    // Extract the required components from the blockchain
    let blockchain_guard = blockchain.lock().unwrap();
    let blockchain_state = Arc::new(tokio::sync::RwLock::new(blockchain_guard.state.clone()));
    let utxo_set = Arc::new(tokio::sync::RwLock::new(blockchain_guard.utxo_set.clone()));
    let live_tickets_pool = Arc::new(tokio::sync::RwLock::new(
        blockchain_guard.live_tickets.clone(),
    ));
    drop(blockchain_guard); // Release the lock

    let sync_manager = SyncManager::new(
        blockchain_state,
        utxo_set,
        live_tickets_pool,
    );

    // Spawn header-first sync as a background task
    task::spawn(async move {
        if let Err(e) = sync_manager.header_first_sync_async(p2p_network).await {
            eprintln!("[Node] Header-first sync failed: {:?}", e);
        } else {
            println!("[Node] Header-first sync completed successfully.");
        }
    });
}
