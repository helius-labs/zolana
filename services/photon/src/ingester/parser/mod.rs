use nullifier_tree_batch_update_parser::parse_nullifier_tree_batch_updates;
use ring_config_parser::parse_ring_configs;
use rings_event_parser::parse_rings_events;
use solana_pubkey::Pubkey;
use std::collections::HashSet;

use super::{error::IngesterError, typedefs::block_info::TransactionInfo};

use self::state_update::{StateUpdate, Transaction};
use self::tree_info::TreeInfo;
pub use self::tree_info::TreeResolver;

pub mod event_site;
pub mod nullifier_tree_batch_update_parser;
pub mod ring_config_parser;
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

    if let Some(state_update) = parse_ring_configs(tx, slot)? {
        state_updates.push(state_update);
    }

    if let Some(state_update) = parse_nullifier_tree_batch_updates(tx)? {
        state_updates.push(state_update);
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
            // The block batch fails and the ingest retry re-runs discovery;
            // swallowing the error would commit the batch without the tree
            // and silently drop every transaction that references it.
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::parser::state_update::RingsTransactionUpdate;
    use sea_orm_migration::MigratorTrait;
    use solana_signature::Signature;

    async fn setup_test_db() -> sea_orm::DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::RingsMigrator::up(&db, None)
            .await
            .unwrap();
        db
    }

    fn rings_transaction_referencing(output_tree: Pubkey) -> StateUpdate {
        let mut state_update = StateUpdate::new();
        state_update
            .rings_transactions
            .push(RingsTransactionUpdate {
                signature: Signature::from([8; 64]),
                event_index: 0,
                slot: 1,
                ring_config: None,
                source_instruction_tag: 1,
                output_tree: output_tree.to_bytes(),
                first_output_leaf_index: 0,
                tx_viewing_pk: None,
                salt: None,
                proofless: false,
                encrypted_utxos: None,
                raw_event: None,
                parse_version: 1,
                outputs: Vec::new(),
                messages: Vec::new(),
                nullifiers: Vec::new(),
            });
        state_update
    }

    /// A tree the indexer has never seen is discovered while its transactions
    /// are parsed; a discovery failure must fail the batch so the ingest
    /// retry re-runs it. Swallowing it would commit the batch without the
    /// tree and silently drop every transaction that references it.
    #[tokio::test]
    async fn a_tree_discovery_failure_fails_the_batch() {
        let db = setup_test_db().await;
        let rpc = crate::rpc::RpcClient::new("http://localhost:1".to_string());
        let mut resolver = TreeResolver::new(&rpc);
        let state_update =
            rings_transaction_referencing(solana_pubkey::Pubkey::new_from_array([7; 32]));

        let error = discover_rings_trees(&db, &state_update, 1, &mut resolver)
            .await
            .unwrap_err();

        assert!(matches!(error, IngesterError::ParserError(_)));
    }
}
