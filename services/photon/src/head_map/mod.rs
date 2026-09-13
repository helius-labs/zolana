//! Head rollback never changes SPP state.

pub mod api;
mod parser;
mod proof;
mod storage;

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use futures::{stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;

use crate::{
    ingester::typedefs::block_info::{parse_ui_confirmed_blocked, BlockInfo},
    rpc::{RpcClient, RpcError},
};
use parser::Transition;
use storage::{BlockJournal, Cursor, Map, Member, Undo};

pub fn spawn(
    db: Arc<DatabaseConnection>,
    rpc: Arc<RpcClient>,
    start_slot: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut delay = 1;
        loop {
            match synchronize(&db, &rpc, start_slot).await {
                Ok(()) => delay = 1,
                Err(error) => {
                    log::error!("ring head projector failed ({error:#})");
                    if let Ok(Some(mut cursor)) = storage::cursor(db.as_ref()).await {
                        cursor.ready = false;
                        if let Err(error) = storage::save_cursor(db.as_ref(), &cursor).await {
                            log::error!("cannot mark head projector unavailable ({error:#})");
                        }
                    }
                    delay = (delay * 2).min(15);
                }
            }
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    })
}

fn skipped(error: &RpcError) -> bool {
    // Archive gaps must remain errors.
    matches!(error.response_code(), Some(-32007))
}

async fn synchronize(db: &DatabaseConnection, rpc: &RpcClient, start_slot: u64) -> Result<()> {
    let mut cursor = match storage::cursor(db).await? {
        Some(value) => value,
        None => {
            let value = Cursor {
                start_slot,
                scanned_slot: start_slot,
                tip: None,
                revision: 0,
                ready: false,
            };
            storage::save_cursor(db, &value).await?;
            value
        }
    };
    while let Some(tip) = &cursor.tip {
        let canonical = match rpc.get_block(tip.slot, TransactionDetails::None).await {
            Ok(block) => block.blockhash == tip.blockhash.to_string(),
            Err(error) if skipped(&error) => false,
            Err(error) => return Err(error.into()),
        };
        if canonical {
            break;
        }
        cursor.ready = false;
        storage::save_cursor(db, &cursor).await?;
        let tx = db.begin().await?;
        storage::rollback(&tx, &mut cursor).await?;
        tx.commit().await?;
    }
    for candidate in storage::pending(db).await? {
        if !registered_ring(rpc, &Pubkey::new_from_array(candidate.program)).await? {
            continue;
        }
        let canonical = match rpc
            .get_block(candidate.slot, TransactionDetails::None)
            .await
        {
            Ok(block) => block.blockhash == candidate.blockhash.to_string(),
            Err(error) if skipped(&error) => false,
            Err(error) => return Err(error.into()),
        };
        if !canonical {
            storage::delete_pending(db, &candidate.program).await?;
            continue;
        }
        cursor.ready = false;
        storage::save_cursor(db, &cursor).await?;
        while cursor
            .tip
            .as_ref()
            .is_some_and(|tip| tip.slot >= candidate.slot)
        {
            let tx = db.begin().await?;
            storage::rollback(&tx, &mut cursor).await?;
            tx.commit().await?;
        }
        break;
    }
    // A confirmed fork can fill previously skipped slots.
    cursor.scanned_slot = cursor
        .tip
        .as_ref()
        .map_or(cursor.start_slot, |tip| tip.slot);
    let target = rpc.get_slot().await?;
    if cursor.scanned_slot < target {
        cursor.ready = false;
        storage::save_cursor(db, &cursor).await?;
        let batch = block_batch(rpc, cursor.scanned_slot + 1..=target).await?;
        let blocks = stream::iter(batch.slots)
            .map(|slot| async move {
                let block = rpc.get_block(slot, TransactionDetails::Full).await?;
                Ok::<_, anyhow::Error>(parse_ui_confirmed_blocked(block, slot)?)
            })
            .buffered(4)
            .collect::<Vec<Result<BlockInfo>>>()
            .await;
        for block in blocks {
            let block = block?;
            if let Some(tip) = &cursor.tip {
                if !linked(tip, &block.metadata) {
                    bail!("head-map parent mismatch");
                }
            }
            let tx = db.begin().await?;
            apply_block(&tx, rpc, &block, &mut cursor).await?;
            tx.commit().await?;
        }
        cursor.scanned_slot = batch.scanned_slot;
        storage::save_cursor(db, &cursor).await?;
    }
    if cursor.scanned_slot < target {
        return Ok(());
    }
    for map in storage::maps(db).await? {
        api::check_chain(rpc, &map).await?;
    }
    cursor.ready = true;
    storage::save_cursor(db, &cursor).await?;
    Ok(())
}

fn linked(
    parent: &crate::ingester::typedefs::block_info::BlockMetadata,
    child: &crate::ingester::typedefs::block_info::BlockMetadata,
) -> bool {
    child.parent_slot == parent.slot && child.parent_blockhash == parent.blockhash
}

struct BlockBatch {
    slots: Vec<u64>,
    scanned_slot: u64,
}

async fn block_batch(rpc: &RpcClient, slots: std::ops::RangeInclusive<u64>) -> Result<BlockBatch> {
    let mut start = *slots.start();
    let target = *slots.end();
    let mut batch = Vec::new();
    loop {
        let end = target.min(start.saturating_add(4095));
        let page = rpc.get_blocks(start..=end).await?;
        if page.iter().any(|slot| !(start..=end).contains(slot))
            || page.windows(2).any(|pair| pair[0] >= pair[1])
        {
            bail!("invalid confirmed block order");
        }
        let available = 32 - batch.len();
        if page.len() > available {
            batch.extend(page.into_iter().take(available));
            let scanned = *batch.last().context("empty block batch")?;
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: scanned,
            });
        }
        batch.extend(page);
        if end == target || batch.len() == 32 {
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: end,
            });
        }
        start = end.checked_add(1).context("slot overflow")?;
    }
}

async fn registered_ring(rpc: &RpcClient, program: &Pubkey) -> Result<bool> {
    let ring_auth = zolana_interface::pda::ring_auth(program).0;
    let accounts = rpc.get_multiple_accounts(&[ring_auth]).await?;
    let Some(Some(config)) = accounts.first() else {
        return Ok(false);
    };
    let offset = std::mem::offset_of!(zolana_interface::state::RingConfig, program_id);
    Ok(
        config.owner == zolana_interface::pda::shielded_pool_program_id()
            && config.data.len() == zolana_interface::state::RingConfig::SIZE
            && config.data[0] == zolana_interface::state::discriminator::RING_CONFIG
            && config.data[offset..offset + 32] == program.to_bytes(),
    )
}

async fn apply_block(
    tx: &DatabaseTransaction,
    rpc: &RpcClient,
    block: &BlockInfo,
    cursor: &mut Cursor,
) -> Result<()> {
    let mut undo = Vec::new();
    for transaction in &block.transactions {
        for (instruction, subtree) in parser::invocations(transaction)? {
            let program = instruction.program_id.to_bytes();
            if let Some(address) = parser::initialization(&instruction) {
                if !registered_ring(rpc, &instruction.program_id).await? {
                    storage::save_pending(
                        tx,
                        &storage::Pending {
                            program,
                            slot: block.metadata.slot,
                            blockhash: block.metadata.blockhash.clone(),
                        },
                    )
                    .await?;
                    continue;
                }
                if storage::map(tx, &program).await?.is_some() {
                    bail!("head map initialized twice");
                }
                let account = rpc.get_account(&Pubkey::new_from_array(address)).await?;
                if account.owner != instruction.program_id
                    || account.data.len() != custom_ring_interface::HeadMapRoot::SIZE
                    || account.data[0] != custom_ring_interface::HEAD_MAP_ROOT
                {
                    bail!("invalid head-map initialization account");
                }
                storage::delete_pending(tx, &program).await?;
                let map = Map {
                    program,
                    address,
                    root: custom_ring_interface::HEAD_MAP_EMPTY_ROOT,
                    next_index: 1,
                };
                let sentinel = Member {
                    member: [0; 32],
                    index: 0,
                    next: zolana_ring_head_map::FIELD_MAX,
                    nullifier: [0; 32],
                    record: None,
                };
                let root = storage::write_leaves(
                    tx,
                    &map,
                    &[(0, sentinel.hash()?)],
                    cursor.advance_revision()?,
                )
                .await?;
                if root != map.root {
                    bail!("head-map sentinel root mismatch");
                }
                storage::save_map(tx, &map).await?;
                storage::save_member(tx, &program, &sentinel).await?;
                undo.push(Undo {
                    program,
                    before: None,
                    members: vec![],
                    leaves: vec![],
                });
                continue;
            }
            let Some(map) = storage::map(tx, &program).await? else {
                continue;
            };
            let policy = policy_config(rpc, &instruction.program_id).await?;
            if let Some(transition) = parser::transition(
                &instruction,
                &subtree,
                parser::TransitionContext {
                    slot: block.metadata.slot,
                    entries_tree: policy.entries_tree.to_bytes(),
                    entries_tree_id: policy.entries_tree_id(),
                },
            )? {
                undo.push(
                    apply_transition(tx, &map, transition, cursor.advance_revision()?).await?,
                );
            }
        }
    }
    storage::save_journal(
        tx,
        &BlockJournal {
            metadata: block.metadata.clone(),
            previous_tip: cursor.tip.clone(),
            undo,
        },
    )
    .await?;
    cursor.tip = Some(block.metadata.clone());
    cursor.scanned_slot = block.metadata.slot;
    cursor.ready = false;
    storage::save_cursor(tx, cursor).await
}

async fn policy_config(
    rpc: &RpcClient,
    program: &Pubkey,
) -> Result<custom_ring_interface::PolicyConfig> {
    let address =
        Pubkey::find_program_address(&[custom_ring_interface::PolicyConfig::SEED], program).0;
    let account = rpc.get_account(&address).await?;
    if account.owner != *program {
        bail!("head-map policy config has the wrong owner");
    }
    let policy = bytemuck::try_from_bytes::<custom_ring_interface::PolicyConfig>(&account.data)
        .map_err(|_| anyhow::anyhow!("head-map policy config has the wrong layout"))?;
    if policy.discriminator != custom_ring_interface::POLICY_CONFIG {
        bail!("head-map policy config has the wrong discriminator");
    }
    Ok(*policy)
}

async fn apply_transition(
    tx: &DatabaseTransaction,
    before: &Map,
    transition: Transition,
    revision: u64,
) -> Result<Undo> {
    let mut map = before.clone();
    let mut undo = Undo {
        program: map.program,
        before: Some(before.clone()),
        members: vec![],
        leaves: vec![],
    };
    let (old_root, new_root, updates) = match transition {
        Transition::Register {
            old_root,
            new_root,
            next_index,
            member,
            nullifier,
            record,
        } => {
            if next_index != map.next_index || next_index >= proof::CAPACITY {
                bail!("registration append cursor mismatch");
            }
            if storage::member(tx, &map.program, &member).await?.is_some() {
                bail!("duplicate registered member");
            }
            let low = storage::predecessor(tx, &map.program, &member).await?;
            let (empty, _) = proof::path(tx, &map, next_index).await?;
            if empty != [0; 32] {
                bail!("registration append slot occupied");
            }
            undo.members = vec![(low.member, Some(low.clone())), (member, None)];
            undo.leaves = vec![(low.index, low.hash()?), (next_index, [0; 32])];
            let added = Member {
                member,
                index: next_index,
                next: low.next,
                nullifier,
                record: Some(record),
            };
            let mut changed = low;
            changed.next = member;
            map.next_index = next_index
                .checked_add(1)
                .context("append cursor overflow")?;
            (old_root, new_root, vec![changed, added])
        }
        Transition::Transfer {
            old_root,
            new_root,
            member,
            spent,
            nullifier,
            record,
        } => {
            let mut current = storage::member(tx, &map.program, &member)
                .await?
                .context("transfer member is unregistered")?;
            if current.nullifier != spent {
                bail!("transfer consumed a record other than its registered head");
            }
            undo.members.push((member, Some(current.clone())));
            undo.leaves.push((current.index, current.hash()?));
            current.nullifier = nullifier;
            current.record = Some(record);
            (old_root, new_root, vec![current])
        }
    };
    if old_root != before.root {
        bail!("head-map transition old root mismatch");
    }
    let leaves = updates
        .iter()
        .map(|member| Ok((member.index, member.hash()?)))
        .collect::<Result<Vec<_>>>()?;
    let computed = storage::write_leaves(tx, &map, &leaves, revision).await?;
    if computed != new_root {
        bail!("head-map transition new root mismatch");
    }
    for member in updates {
        storage::save_member(tx, &map.program, &member).await?;
    }
    map.root = new_root;
    storage::save_map(tx, &map).await?;
    Ok(undo)
}

#[cfg(test)]
mod tests;
