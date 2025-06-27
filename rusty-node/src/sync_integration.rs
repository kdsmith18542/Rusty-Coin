use rusty_core::network::sync_manager::SyncManager;
use std::sync::Arc;
use std::path::Path;
use tokio::task;

pub async fn start_sync_manager(blockchain: Arc<rusty_core::consensus::blockchain::Blockchain>) {
    let sync_manager = SyncManager::new(blockchain.clone());
    // Spawn header-first sync as a background task
    task::spawn(async move {
        if let Err(e) = sync_manager.header_first_sync_async().await {
            eprintln!("[Node] Header-first sync failed: {:?}", e);
        } else {
            println!("[Node] Header-first sync completed successfully.");
        }
    });
}
