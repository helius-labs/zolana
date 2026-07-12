pub mod tree_metadata_sync;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use cadence_macros::{statsd_count, statsd_gauge};
use log::{error, info, warn};
use once_cell::sync::Lazy;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use tokio::{
    task::JoinHandle,
    time::{interval, sleep},
};

use crate::{
    api::method::get_indexer_health::HEALTH_CHECK_SLOT_DISTANCE,
    common::{fetch_current_slot_with_infinite_retry, rings_tree::RingsTreeKind},
    dao::generated::{state_trees, tree_metadata},
    metric,
};

use solana_account::Account as SolanaAccount;

use crate::common::indexer_context::extract as extract_context;

use solana_pubkey::Pubkey;
use zolana_indexer_api::Hash;

const CHUNK_SIZE: usize = 100;

pub static LATEST_SLOT: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0)));
static TREE_VALIDATION_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct TreeValidationGuard;

impl Drop for TreeValidationGuard {
    fn drop(&mut self) {
        TREE_VALIDATION_IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

async fn fetch_last_indexed_slot_with_infinite_retry(db: &DatabaseConnection) -> u64 {
    loop {
        if let Ok(context) = extract_context(db).await {
            return context.slot;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

// Return a tokio join handle for the monitoring task
pub fn continuously_monitor_photon(
    db: Arc<DatabaseConnection>,
    rpc_client: Arc<RpcClient>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) =
            tree_metadata_sync::sync_tree_metadata(rpc_client.as_ref(), db.as_ref()).await
        {
            error!("Failed to sync tree metadata: {}", e);
        } else {
            info!("Tree metadata sync completed successfully");
        }

        let mut has_been_healthy = false;
        start_latest_slot_updater(rpc_client.clone()).await;

        // Use interval timer to ensure fixed intervals regardless of execution time
        let mut interval = interval(Duration::from_millis(5000));

        loop {
            interval.tick().await;

            let latest_slot = LATEST_SLOT.load(Ordering::SeqCst);
            let last_indexed_slot = fetch_last_indexed_slot_with_infinite_retry(db.as_ref()).await;
            let lag = latest_slot.saturating_sub(last_indexed_slot);
            metric! {
                statsd_gauge!("indexing_lag", lag);
            }
            if lag < HEALTH_CHECK_SLOT_DISTANCE {
                has_been_healthy = true;
            }
            info!("Indexing lag: {}", lag);
            if lag > HEALTH_CHECK_SLOT_DISTANCE {
                if has_been_healthy {
                    error!("Indexing lag is too high: {}", lag);
                }
            } else {
                if TREE_VALIDATION_IN_PROGRESS
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let db_clone = db.clone();
                    let rpc_clone = rpc_client.clone();

                    tokio::spawn(async move {
                        let _validation_guard = TreeValidationGuard;
                        let tree_roots =
                            load_db_tree_roots_with_infinite_retry(db_clone.as_ref()).await;
                        validate_tree_roots(rpc_clone.as_ref(), tree_roots).await;
                    });
                }
            }
        }
    })
}

pub async fn update_latest_slot(rpc_client: &RpcClient) {
    let slot = fetch_current_slot_with_infinite_retry(rpc_client).await;
    LATEST_SLOT.fetch_max(slot, Ordering::SeqCst);
}

pub async fn start_latest_slot_updater(rpc_client: Arc<RpcClient>) {
    if LATEST_SLOT.load(Ordering::SeqCst) != 0 {
        return;
    }
    update_latest_slot(&rpc_client).await;
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            update_latest_slot(&rpc_client).await;
        }
    });
}

fn parse_historical_roots(pubkey: Pubkey, account: SolanaAccount) -> Option<Vec<Hash>> {
    if let Some(roots) = tree_metadata_sync::rings_state_roots(pubkey, &account) {
        return Some(roots.into_iter().map(Hash::from).collect());
    }

    warn!("Skipping root validation for non-Rings tree account layout");
    None
}

async fn load_db_tree_roots_with_infinite_retry(db: &DatabaseConnection) -> Vec<(Pubkey, Hash)> {
    loop {
        let models = state_trees::Entity::find()
            .filter(state_trees::Column::NodeIdx.eq(1))
            .all(db)
            .await;
        match models {
            Ok(models) => {
                // Filter to trees discovered from Rings-owned TreeAccount data.
                // This avoids root mismatch errors for unknown/external trees.
                let known_trees = {
                    match tree_metadata::Entity::find().all(db).await {
                        Ok(metadata) => metadata
                            .into_iter()
                            .map(|m| m.tree_pubkey)
                            .collect::<std::collections::HashSet<_>>(),
                        Err(e) => {
                            log::error!("Error loading tree metadata: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                };
                return models
                    .iter()
                    .filter(|model| model.tree_kind == i32::from(RingsTreeKind::State))
                    .filter(|model| known_trees.contains(&model.tree))
                    .filter_map(|model| {
                        let raw_tree = match Pubkey::try_from(model.tree.clone()) {
                            Ok(raw_tree) => raw_tree,
                            Err(_) => {
                                log::error!("Invalid tree root pubkey bytes");
                                return None;
                            }
                        };
                        let hash = match Hash::try_from(model.hash.clone()) {
                            Ok(hash) => hash,
                            Err(e) => {
                                log::error!("Invalid tree root hash bytes: {}", e);
                                return None;
                            }
                        };
                        Some((raw_tree, hash))
                    })
                    .collect();
            }
            Err(e) => {
                log::error!("Error loading tree roots: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn load_accounts_with_infinite_retry(
    rpc_client: &RpcClient,
    pubkeys: Vec<Pubkey>,
) -> Vec<Option<SolanaAccount>> {
    loop {
        let accounts = rpc_client.get_multiple_accounts(&pubkeys).await;
        match accounts {
            Ok(accounts) => {
                return accounts;
            }
            Err(e) => {
                log::error!("Error loading accounts: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn validate_tree_roots(rpc_client: &RpcClient, db_roots: Vec<(Pubkey, Hash)>) {
    for chunk in db_roots.chunks(CHUNK_SIZE) {
        let pubkeys = chunk.iter().map(|(pubkey, _)| *pubkey).collect();
        let accounts = load_accounts_with_infinite_retry(rpc_client, pubkeys).await;
        for ((pubkey, db_hash), account) in chunk.iter().zip(accounts) {
            if let Some(account) = account {
                let Some(account_roots) = parse_historical_roots(*pubkey, account) else {
                    warn!("Skipping root validation for unparseable tree account {pubkey:?}");
                    continue;
                };
                if !account_roots.contains(db_hash) {
                    log::error!(
                        "Root mismatch for pubkey {:?}. db_hash: {}, account_roots: {:?}",
                        pubkey,
                        db_hash,
                        account_roots
                    );
                    return;
                }
            }
        }
    }
    metric! {
        statsd_count!("root_validation_success", 1);
    }
}
