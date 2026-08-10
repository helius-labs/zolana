use crate::api::error::PhotonApiError;
use crate::dao::generated::{prelude::*, tree_metadata};
use crate::ingester::error::IngesterError;
use crate::monitor::tree_metadata_sync;
use crate::rpc::RpcClient;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, TransactionTrait};
use solana_pubkey::Pubkey;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct TreeInfo {
    pub tree: Pubkey,
    pub queue: Pubkey,
    pub height: u32,
    pub root_history_capacity: u64,
    pub input_queue_zkp_batch_size: u64,
}

impl TreeInfo {
    pub async fn get<T>(conn: &T, pubkey: &str) -> Result<Option<TreeInfo>, PhotonApiError>
    where
        T: ConnectionTrait + TransactionTrait,
    {
        let pubkey_parsed = Pubkey::from_str(pubkey)
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Invalid pubkey: {}", e)))?;

        Self::get_by_pubkey(conn, &pubkey_parsed).await
    }

    pub async fn get_by_pubkey<T>(
        conn: &T,
        pubkey: &Pubkey,
    ) -> Result<Option<TreeInfo>, PhotonApiError>
    where
        T: ConnectionTrait + TransactionTrait,
    {
        let tree_bytes = pubkey.to_bytes().to_vec();

        let metadata = TreeMetadata::find()
            .filter(tree_metadata::Column::TreePubkey.eq(tree_bytes.clone()))
            .one(conn)
            .await
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Database error: {}", e)))?;

        if let Some(metadata) = metadata {
            return Ok(Some(TreeInfo::from_metadata(metadata, *pubkey)?));
        }

        let metadata = TreeMetadata::find()
            .filter(tree_metadata::Column::QueuePubkey.eq(tree_bytes.clone()))
            .one(conn)
            .await
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Database error: {}", e)))?;

        if let Some(metadata) = metadata {
            let tree_bytes: [u8; 32] =
                metadata.tree_pubkey.as_slice().try_into().map_err(|_| {
                    PhotonApiError::UnexpectedError("Invalid tree pubkey length in DB".to_string())
                })?;
            return Ok(Some(TreeInfo::from_metadata(
                metadata,
                Pubkey::from(tree_bytes),
            )?));
        }

        Ok(None)
    }

    pub async fn get_tree_info_batch<T>(
        conn: &T,
        pubkeys: &[Pubkey],
    ) -> Result<std::collections::HashMap<Pubkey, TreeInfo>, PhotonApiError>
    where
        T: ConnectionTrait + TransactionTrait,
    {
        let tree_bytes_vec: Vec<Vec<u8>> = pubkeys.iter().map(|p| p.to_bytes().to_vec()).collect();

        let metadata_list = TreeMetadata::find()
            .filter(tree_metadata::Column::TreePubkey.is_in(tree_bytes_vec))
            .all(conn)
            .await
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Database error: {}", e)))?;

        let mut result = std::collections::HashMap::new();

        for metadata in metadata_list {
            let tree_bytes: [u8; 32] =
                metadata.tree_pubkey.as_slice().try_into().map_err(|_| {
                    PhotonApiError::UnexpectedError("Invalid tree pubkey length in DB".to_string())
                })?;
            let tree_pubkey = Pubkey::from(tree_bytes);

            let tree_info = TreeInfo::from_metadata(metadata, tree_pubkey)?;
            result.insert(tree_pubkey, tree_info);
        }

        Ok(result)
    }

    fn from_metadata(
        metadata: tree_metadata::Model,
        tree_pubkey: Pubkey,
    ) -> Result<TreeInfo, PhotonApiError> {
        let queue_bytes: [u8; 32] = metadata.queue_pubkey.as_slice().try_into().map_err(|_| {
            PhotonApiError::UnexpectedError("Invalid queue pubkey length in DB".to_string())
        })?;
        let queue_pubkey = Pubkey::from(queue_bytes);

        Ok(TreeInfo {
            tree: tree_pubkey,
            queue: queue_pubkey,
            height: u32::try_from(metadata.height).map_err(|_| {
                PhotonApiError::UnexpectedError(format!(
                    "Invalid tree height in DB: {}",
                    metadata.height
                ))
            })?,
            root_history_capacity: u64::try_from(metadata.root_history_capacity).map_err(|_| {
                PhotonApiError::UnexpectedError(format!(
                    "Invalid root history capacity in DB: {}",
                    metadata.root_history_capacity
                ))
            })?,
            input_queue_zkp_batch_size: u64::try_from(metadata.input_queue_zkp_batch_size)
                .map_err(|_| {
                    PhotonApiError::UnexpectedError(format!(
                        "Invalid input queue ZKP batch size in DB: {}",
                        metadata.input_queue_zkp_batch_size
                    ))
                })?,
        })
    }
}

/// Bundles an RPC client with a negative cache of pubkeys that failed discovery.
/// Created once per block batch and threaded through the parsing call chain,
/// so the same garbage pubkey is never queried twice.
pub struct TreeResolver<'a> {
    rpc_client: &'a RpcClient,
    failed_discoveries: std::collections::HashSet<Pubkey>,
}

impl<'a> TreeResolver<'a> {
    pub fn new(rpc_client: &'a RpcClient) -> Self {
        Self {
            rpc_client,
            failed_discoveries: std::collections::HashSet::new(),
        }
    }

    pub async fn discover_tree<T>(
        &mut self,
        conn: &T,
        pubkey: &Pubkey,
        slot: u64,
    ) -> Result<Option<TreeInfo>, IngesterError>
    where
        T: ConnectionTrait + TransactionTrait,
    {
        if self.failed_discoveries.contains(pubkey) {
            log::debug!("Skipping previously failed tree discovery for {}", pubkey);
            return Ok(None);
        }

        let mut account = match self.rpc_client.get_account(pubkey).await {
            Ok(account) => account,
            Err(e) => {
                log::warn!("RPC error fetching tree {}: {}", pubkey, e);
                self.failed_discoveries.insert(*pubkey);
                return Ok(None);
            }
        };

        match tree_metadata_sync::process_tree_account(conn, *pubkey, &mut account, slot).await {
            Ok(true) => {
                log::info!("Discovered and synced new tree: {}", pubkey);
                TreeInfo::get_by_pubkey(conn, pubkey)
                    .await
                    .map_err(|e| IngesterError::ParserError(e.to_string()))
            }
            Ok(false) => {
                self.failed_discoveries.insert(*pubkey);
                Ok(None)
            }
            Err(e) => {
                log::warn!("Failed to process discovered tree {}: {}", pubkey, e);
                self.failed_discoveries.insert(*pubkey);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::MigratorTrait;

    async fn setup_test_db() -> sea_orm::DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::RingsMigrator::up(&db, None)
            .await
            .unwrap();
        db
    }

    #[tokio::test]
    async fn test_discover_tree_rpc_error_returns_none_and_caches() {
        let rpc_client = RpcClient::new("http://localhost:1".to_string());
        let db = setup_test_db().await;
        let mut resolver = TreeResolver::new(&rpc_client);
        let pubkey = Pubkey::new_unique();

        let result = resolver.discover_tree(&db, &pubkey, 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(resolver.failed_discoveries.contains(&pubkey));
    }

    #[tokio::test]
    async fn test_discover_tree_skips_cached_failures() {
        let rpc_client = RpcClient::new("http://localhost:1".to_string());
        let db = setup_test_db().await;
        let mut resolver = TreeResolver::new(&rpc_client);
        let pubkey = Pubkey::new_unique();
        resolver.failed_discoveries.insert(pubkey);

        // Should return immediately without making RPC call
        let start = std::time::Instant::now();
        let result = resolver.discover_tree(&db, &pubkey, 0).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert!(elapsed.as_millis() < 10);
    }

    #[tokio::test]
    async fn test_discover_tree_multiple_unknown_pubkeys_all_cached() {
        let rpc_client = RpcClient::new("http://localhost:1".to_string());
        let db = setup_test_db().await;
        let mut resolver = TreeResolver::new(&rpc_client);

        let pubkeys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();

        for pk in &pubkeys {
            let result = resolver.discover_tree(&db, pk, 0).await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
        assert_eq!(resolver.failed_discoveries.len(), 5);

        // Second round: all should skip immediately
        let start = std::time::Instant::now();
        for pk in &pubkeys {
            let result = resolver.discover_tree(&db, pk, 0).await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
        assert!(start.elapsed().as_millis() < 10);
        assert_eq!(resolver.failed_discoveries.len(), 5);
    }

    #[tokio::test]
    async fn test_process_tree_account_garbage_data_returns_false() {
        let db = setup_test_db().await;
        let pubkey = Pubkey::new_unique();
        let mut account = solana_account::Account {
            lamports: 1_000_000,
            data: vec![0u8; 256],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        };

        let result = tree_metadata_sync::process_tree_account(&db, pubkey, &mut account, 0).await;
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Garbage account should not be recognized as a tree"
        );
    }
}
