use crate::{
    common::{rings_tree::RingsTreeKind, typedefs::hash::Hash},
    dao::generated::transactions,
    ingester::parser::{
        state_update::{RingsTransactionUpdate, StateUpdate, Transaction},
        tree_info::TreeInfo,
    },
    metric,
};
use cadence_macros::statsd_count;
use error::IngesterError;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use log::debug;
use nullifier_tree_batch_update::persist_nullifier_tree_batch_updates;
use rings_transactions::persist_rings_transactions;
use sea_orm::{
    sea_query::OnConflict, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set,
};
use solana_pubkey::Pubkey;
use std::collections::HashMap;

use super::error;
use ark_bn254::Fr;

pub mod indexed_merkle_tree;
pub mod nullifier_tree_batch_update;
pub mod persisted_indexed_merkle_tree;
pub mod persisted_state_tree;

pub use merkle_proof_with_context::MerkleProofWithContext;

mod leaf_node;
mod leaf_node_proof;
mod merkle_proof_with_context;
mod rings_transactions;

pub use self::leaf_node::{persist_leaf_nodes, LeafNode};
pub use self::leaf_node_proof::{
    get_multiple_compressed_leaf_proofs_by_indices_with_height,
    get_multiple_compressed_leaf_proofs_from_full_leaf_info,
};

// To avoid exceeding the 64k total parameter limit.
pub const MAX_SQL_INSERTS: usize = 500;

pub async fn persist_state_update(
    txn: &DatabaseTransaction,
    state_update: StateUpdate,
) -> Result<(), IngesterError> {
    if state_update == StateUpdate::default() {
        return Ok(());
    }

    let filtered = state_update.filter_by_known_trees(txn).await.map_err(|e| {
        IngesterError::ParserError(format!("Failed to filter by known trees: {}", e))
    })?;

    let state_update = filtered.state_update;
    let tree_info_cache = filtered.tree_info_cache;

    let StateUpdate {
        transactions,
        rings_transactions,
        nullifier_tree_batch_updates,
    } = state_update;

    let nullifier_tree_batch_updates_len = nullifier_tree_batch_updates.len();

    let transactions_vec = transactions.into_iter().collect::<Vec<_>>();

    debug!("Persisting transaction metadata...");
    persist_transactions(txn, &transactions_vec).await?;

    debug!("Persisting Rings transactions...");
    persist_rings_output_leaf_nodes(txn, &rings_transactions, &tree_info_cache).await?;
    persist_rings_transactions(txn, &rings_transactions).await?;

    debug!("Persisting reconstructed nullifier tree batch updates...");
    persist_nullifier_tree_batch_updates(txn, &nullifier_tree_batch_updates, &tree_info_cache)
        .await?;

    metric! {
        statsd_count!(
            "state_update.nullifier_tree_batch_updates",
            metric_count_from_usize(nullifier_tree_batch_updates_len)
        );
    }

    Ok(())
}

pub(crate) fn get_node_direct_ancestors(leaf_index: i64) -> Vec<i64> {
    let mut path: Vec<i64> = Vec::new();
    let mut current_index = leaf_index;
    while current_index > 1 {
        current_index >>= 1;
        path.push(current_index);
    }
    path
}

pub fn compute_parent_hash(left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>, IngesterError> {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(|e| {
        IngesterError::ParserError(format!("Failed to initialize Poseidon hasher: {}", e))
    })?;
    poseidon
        .hash_bytes_be(&[&left, &right])
        .map_err(|e| IngesterError::ParserError(format!("Failed to compute parent hash: {}", e)))
        .map(|x| x.to_vec())
}

async fn persist_transactions(
    txn: &DatabaseTransaction,
    transactions: &[Transaction],
) -> Result<(), IngesterError> {
    let transaction_models = transactions
        .iter()
        .map(|transaction| {
            Ok(transactions::ActiveModel {
                signature: Set(Into::<[u8; 64]>::into(transaction.signature).to_vec()),
                slot: Set(leaf_node::i64_from_u64(
                    transaction.slot,
                    "transaction slot",
                )?),
                error: Set(transaction.error.clone()),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    for chunk in transaction_models.chunks(MAX_SQL_INSERTS) {
        let query = transactions::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([transactions::Column::Signature])
                    .do_nothing()
                    .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist transactions: {}", e))
        })?;
    }

    Ok(())
}

async fn persist_rings_output_leaf_nodes(
    txn: &DatabaseTransaction,
    rings_updates: &[RingsTransactionUpdate],
    tree_info_cache: &HashMap<Pubkey, TreeInfo>,
) -> Result<(), IngesterError> {
    let mut leaf_nodes_by_tree: HashMap<Pubkey, Vec<LeafNode>> = HashMap::new();

    for update in rings_updates {
        for output in &update.outputs {
            let tree = Pubkey::from(output.output_tree);
            let tree_info = tree_info_cache.get(&tree).ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Tree metadata not found for Rings output tree {}",
                    tree
                ))
            })?;
            if tree_info.tree != tree {
                return Err(IngesterError::ParserError(format!(
                    "Tree metadata mismatch for Rings output tree {}: metadata points to {}",
                    tree, tree_info.tree
                )));
            }

            let seq = output.leaf_index.checked_add(1).ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Rings output sequence {} overflowed",
                    output.leaf_index
                ))
            })?;

            leaf_nodes_by_tree.entry(tree).or_default().push(LeafNode {
                tree: tree.to_bytes().to_vec(),
                tree_kind: RingsTreeKind::State,
                leaf_index: output.leaf_index,
                hash: Hash::from(output.utxo_hash),
                seq: Some(seq),
            });
        }
    }

    for (tree, leaf_nodes) in leaf_nodes_by_tree {
        debug!(
            "Persisting {} Rings output leaf nodes for tree {}",
            leaf_nodes.len(),
            tree
        );
        persist_leaf_nodes(txn, leaf_nodes, RingsTreeKind::State.tree_height() + 1).await?;
    }

    Ok(())
}

fn metric_count_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
