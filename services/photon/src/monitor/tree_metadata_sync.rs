use log::{debug, info, warn};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, Set};
use solana_account::Account;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_pubkey::Pubkey;

use crate::api::error::PhotonApiError;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::{prelude::*, tree_metadata};
use rings_interface::{pda, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR};
use rings_tree::TreeAccount;

/// Tree account data extracted from on-chain account
pub struct TreeAccountData {
    pub queue_pubkey: Pubkey,
    pub root_history_capacity: u64,
    pub input_queue_zkp_batch_size: u64,
    pub height: u32,
    pub sequence_number: u64,
    pub next_index: u64,
}

pub async fn sync_tree_metadata(
    rpc_client: &RpcClient,
    db: &DatabaseConnection,
) -> Result<(), PhotonApiError> {
    info!("Starting tree metadata sync from on-chain...");

    let program_id = pda::shielded_pool_program_id();
    info!("Fetching all accounts for program: {}", program_id);

    let current_slot = rpc_client.get_slot().await.map_err(|e| {
        PhotonApiError::UnexpectedError(format!("Failed to fetch current slot: {}", e))
    })?;
    info!("Current slot: {}", current_slot);

    let accounts = rpc_client
        .get_program_accounts(&program_id)
        .await
        .map_err(|e| {
            PhotonApiError::UnexpectedError(format!("Failed to fetch program accounts: {}", e))
        })?;

    info!("Found {} accounts to process", accounts.len());

    let mut synced_count = 0;
    let mut failed_count = 0;

    for (pubkey, mut account) in accounts {
        match process_tree_account(db, pubkey, &mut account, current_slot).await {
            Ok(true) => synced_count += 1,
            Ok(false) => {} // Not a tree account, skip
            Err(e) => {
                warn!("Failed to process account {}: {}", pubkey, e);
                failed_count += 1;
            }
        }
    }

    info!(
        "Tree metadata sync completed. Synced: {}, Failed: {}",
        synced_count, failed_count
    );

    Ok(())
}

pub async fn process_tree_account<C>(
    db: &C,
    pubkey: Pubkey,
    account: &mut Account,
    slot: u64,
) -> Result<bool, PhotonApiError>
where
    C: ConnectionTrait,
{
    if let Some(data) = process_rings_tree_account(pubkey, account) {
        // `tree_metadata` is keyed by tree account. Rings stores UTXO/state and
        // nullifier trees in that one account, so this row only says the account
        // is known and tracks the on-chain nullifier/indexed-tree metadata.
        upsert_tree_metadata(db, pubkey, &data, slot).await?;
        info!(
            "Synced Rings tree account {} with indexed height {}, root_history_capacity {}, next_idx {}",
            pubkey, data.height, data.root_history_capacity, data.next_index
        );
        return Ok(true);
    }

    debug!("Account {} is not a recognized tree type", pubkey);
    Ok(false)
}

fn process_rings_tree_account(pubkey: Pubkey, account: &Account) -> Option<TreeAccountData> {
    let mut data = account.data.clone();
    let mut tree = parse_rings_tree_account(pubkey, account, &mut data)?;
    let nullifier_metadata = *tree.nullifer_tree().get_metadata();

    Some(TreeAccountData {
        // Rings UTXO and nullifier trees live in the same account; there is
        // no separate queue account for Photon to reference.
        queue_pubkey: pubkey,
        root_history_capacity: u64::from(nullifier_metadata.root_history_capacity),
        input_queue_zkp_batch_size: nullifier_metadata.queue_batches.zkp_batch_size,
        height: nullifier_metadata.height,
        sequence_number: nullifier_metadata.sequence_number,
        next_index: nullifier_metadata.next_index,
    })
}

fn parse_rings_tree_account<'a>(
    pubkey: Pubkey,
    account: &Account,
    data: &'a mut [u8],
) -> Option<TreeAccount<'a>> {
    let rings_program = pda::shielded_pool_program_id();
    if account.owner != rings_program {
        return None;
    }
    let tree = TreeAccount::from_bytes(data, pubkey.to_bytes()).ok()?;
    if tree.discriminator() != TREE_ACCOUNT_DISCRIMINATOR {
        return None;
    }

    Some(tree)
}

pub(crate) fn rings_state_roots(pubkey: Pubkey, account: &Account) -> Option<Vec<[u8; 32]>> {
    let mut data = account.data.clone();
    let mut tree = parse_rings_tree_account(pubkey, account, &mut data)?;
    let current_root = tree.utxo_tree().root();
    let root_history_capacity =
        usize::try_from(RingsTreeKind::State.root_history_capacity()).ok()?;
    let mut roots = Vec::with_capacity(root_history_capacity);
    if current_root.iter().any(|byte| *byte != 0) {
        roots.push(current_root);
    }

    for root_index in 0..root_history_capacity {
        let Ok(root_index) = u16::try_from(root_index) else {
            break;
        };
        let Ok(root) = tree.get_utxo_tree_root(root_index) else {
            continue;
        };
        if root.iter().any(|byte| *byte != 0) && !roots.contains(&root) {
            roots.push(root);
        }
    }

    Some(roots)
}

pub async fn upsert_tree_metadata<C>(
    db: &C,
    tree_pubkey: Pubkey,
    data: &TreeAccountData,
    slot: u64,
) -> Result<(), PhotonApiError>
where
    C: ConnectionTrait,
{
    let tree_bytes = tree_pubkey.to_bytes().to_vec();

    let model = tree_metadata::ActiveModel {
        tree_pubkey: Set(tree_bytes),
        queue_pubkey: Set(data.queue_pubkey.to_bytes().to_vec()),
        height: Set(i32_from_u32(data.height, "tree height")?),
        root_history_capacity: Set(i64_from_u64(
            data.root_history_capacity,
            "root history capacity",
        )?),
        input_queue_zkp_batch_size: Set(i64_from_u64(
            data.input_queue_zkp_batch_size,
            "input queue ZKP batch size",
        )?),
        sequence_number: Set(i64_from_u64(data.sequence_number, "sequence number")?),
        next_index: Set(i64_from_u64(data.next_index, "next index")?),
        last_synced_slot: Set(i64_from_u64(slot, "last synced slot")?),
    };

    TreeMetadata::insert(model)
        .on_conflict(
            sea_orm::sea_query::OnConflict::column(tree_metadata::Column::TreePubkey)
                .update_columns([
                    tree_metadata::Column::QueuePubkey,
                    tree_metadata::Column::Height,
                    tree_metadata::Column::RootHistoryCapacity,
                    tree_metadata::Column::InputQueueZkpBatchSize,
                    tree_metadata::Column::SequenceNumber,
                    tree_metadata::Column::NextIndex,
                    tree_metadata::Column::LastSyncedSlot,
                ])
                .to_owned(),
        )
        .exec(db)
        .await?;

    debug!("Upserted tree metadata for {}", tree_pubkey);

    Ok(())
}

fn i32_from_u32(value: u32, field: &str) -> Result<i32, PhotonApiError> {
    i32::try_from(value).map_err(|_| {
        PhotonApiError::UnexpectedError(format!("{} {} does not fit in i32", field, value))
    })
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PhotonApiError> {
    i64::try_from(value).map_err(|_| {
        PhotonApiError::UnexpectedError(format!("{} {} does not fit in i64", field, value))
    })
}
