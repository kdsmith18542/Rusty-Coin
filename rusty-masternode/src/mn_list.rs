use std::collections::HashMap;

use blake3;

use rusty_shared_types::masternode::{MasternodeEntry, MasternodeID, MasternodeList};
use rusty_shared_types::Hash;

pub struct MasternodeListManager {
    // This would typically be a reference to the global masternode list
    // or a mechanism to update it.
}

impl MasternodeListManager {
    pub fn new() -> Self {
        MasternodeListManager {}
    }

    // Function to update the active/inactive status of masternodes
    pub fn update_masternode_status(
        &self,
        masternode_list: &mut MasternodeList,
        masternode_id: &MasternodeID,
        is_active: bool,
    ) -> Result<(), String> {
        use rusty_shared_types::masternode::MasternodeStatus;
        if let Some(entry) = masternode_list.map.get_mut(masternode_id) {
            entry.status = if is_active {
                MasternodeStatus::Active
            } else {
                MasternodeStatus::Offline
            };
            Ok(())
        } else {
            Err("Masternode not found".to_string())
        }
    }

    // Function to calculate the hash of the masternode list for security
    pub fn calculate_mnlist_hash(
        &self,
        masternode_list: &HashMap<MasternodeID, MasternodeEntry>,
    ) -> Result<Hash, String> {
        // Sort the entries by masternode ID for deterministic hashing
        let mut entries: Vec<_> = masternode_list.iter().collect();
        entries.sort_by_key(|(id, _)| *id);

        // Serialize the sorted list
        let serialized = bincode::serialize(&entries)
            .map_err(|e| format!("Failed to serialize masternode list: {}", e))?;

        // Hash the serialized data
        Ok(blake3::hash(&serialized).into())
    }

    /// Update the masternode list
    pub fn update_masternode_list(
        &self,
        masternode_list: &mut MasternodeList,
        updates: HashMap<MasternodeID, MasternodeEntry>,
    ) -> Result<(), String> {
        // Apply updates
        for (id, entry) in updates {
            masternode_list.map.insert(id, entry);
        }

        Ok(())
    }
}
