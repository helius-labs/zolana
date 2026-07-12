use nullifier_tree_batch_update_parser::parse_nullifier_tree_batch_update;
use rings_event_parser::parse_rings_events;
use solana_pubkey::Pubkey;
use std::collections::HashSet;

use super::{error::IngesterError, typedefs::block_info::TransactionInfo};

use self::state_update::{StateUpdate, Transaction};
use self::tree_info::TreeInfo;
pub use self::tree_info::TreeResolver;

pub mod nullifier_tree_batch_update_parser;
pub mod rings_event_parser;
pub mod state_update;
pub mod tree_info;

pub async fn parse_transaction<T>(
    conn: &T,
    tx: &TransactionInfo,
    slot: u64,
    resolver: &mut TreeResolver<'_>,
) -> Result<StateUpdate, IngesterError>
where
    T: sea_orm::ConnectionTrait + sea_orm::TransactionTrait,
{
    if tx.error.is_some() {
        log::debug!(
            "Skipping failed transaction {} with error: {:?}",
            tx.signature,
            tx.error
        );
        return Ok(StateUpdate::new());
    }

    let mut state_updates = Vec::new();
    let mut is_rings_transaction = false;

    if let Some(rings_state_update) = parse_rings_events(tx, slot)? {
        is_rings_transaction = true;
        state_updates.push(rings_state_update);
    }

    for instruction_group in &tx.instruction_groups {
        for instruction in std::iter::once(&instruction_group.outer_instruction)
            .chain(instruction_group.inner_instructions.iter())
        {
            if let Some(state_update) = parse_nullifier_tree_batch_update(instruction, tx)? {
                if state_update != StateUpdate::default() {
                    state_updates.push(state_update);
                }
            }
        }
    }

    let mut state_update = StateUpdate::merge_updates(state_updates);
    if state_update != StateUpdate::default() {
        discover_rings_trees(conn, &state_update, slot, resolver).await?;
    }
    if is_rings_transaction {
        state_update.transactions.insert(Transaction {
            signature: tx.signature,
            slot,
            error: tx.error.clone(),
        });
    }

    Ok(state_update)
}

async fn discover_rings_trees<T>(
    conn: &T,
    state_update: &StateUpdate,
    slot: u64,
    resolver: &mut TreeResolver<'_>,
) -> Result<(), IngesterError>
where
    T: sea_orm::ConnectionTrait + sea_orm::TransactionTrait,
{
    let mut tree_pubkeys = HashSet::new();

    for rings_tx in &state_update.rings_transactions {
        tree_pubkeys.insert(Pubkey::from(rings_tx.output_tree));
        for output in &rings_tx.outputs {
            tree_pubkeys.insert(Pubkey::from(output.output_tree));
        }
        for nullifier in &rings_tx.nullifiers {
            tree_pubkeys.insert(Pubkey::from(nullifier.nullifier_tree));
        }
    }
    for update in &state_update.nullifier_tree_batch_updates {
        tree_pubkeys.insert(update.tree);
    }

    for tree in tree_pubkeys {
        if TreeInfo::get_by_pubkey(conn, &tree)
            .await
            .map_err(|e| IngesterError::ParserError(format!("Failed to get tree info: {}", e)))?
            .is_some()
        {
            continue;
        }

        match resolver.discover_tree(conn, &tree, slot).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                log::debug!("Rings tree {} not discoverable, leaving it unknown", tree);
            }
            Err(e) => {
                log::warn!("Failed to discover Rings tree {}: {}", tree, e);
            }
        }
    }

    Ok(())
}
