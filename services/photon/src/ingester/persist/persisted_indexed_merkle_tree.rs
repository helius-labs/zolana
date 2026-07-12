use std::collections::HashMap;

use super::MAX_SQL_INSERTS;
use crate::common::rings_tree::RingsTreeKind;
use crate::ingester::persist::indexed_merkle_tree::{
    compute_hash_by_tree_kind, get_zeroeth_nullifier_exclusion_range,
};
use crate::ingester::persist::leaf_node::{
    i64_from_u64, i64_from_usize, persist_leaf_nodes, u64_from_i64, u64_from_usize, usize_from_i64,
    LeafNode,
};
use crate::{
    common::typedefs::hash::Hash,
    dao::generated::indexed_trees,
    ingester::{
        error::IngesterError,
        parser::state_update::{IndexedTreeLeafUpdate, RawIndexedElement},
    },
};
use itertools::Itertools;
use sea_orm::{
    sea_query::OnConflict, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set,
};
use solana_pubkey::Pubkey;
use solana_signature::Signature;

/// Ensures the zeroeth element (leaf_index 0) exists if not already present
fn ensure_zeroeth_element_exists(
    indexed_leaf_updates: &mut HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
    tree: Pubkey,
    tree_kind: RingsTreeKind,
) -> Result<(), IngesterError> {
    let zeroeth_update = indexed_leaf_updates.get(&(tree, 0));
    if zeroeth_update.is_none() {
        let zeroeth_leaf = match tree_kind {
            RingsTreeKind::Nullifier => {
                get_zeroeth_nullifier_exclusion_range(tree.to_bytes().to_vec())
            }
            RingsTreeKind::State => {
                return Err(IngesterError::ParserError(
                    "State trees do not use indexed-tree zeroeth elements".to_string(),
                ));
            }
        };
        let zeroeth_hash = compute_hash_by_tree_kind(&zeroeth_leaf, tree_kind).map_err(|e| {
            IngesterError::ParserError(format!("Failed to compute zeroeth element hash: {}", e))
        })?;

        let zeroeth_leaf_index = u64_from_i64(zeroeth_leaf.leaf_index, "zeroeth leaf index")?;
        indexed_leaf_updates.insert(
            (tree, zeroeth_leaf_index),
            IndexedTreeLeafUpdate {
                tree,
                tree_kind,
                hash: zeroeth_hash.0,
                leaf: RawIndexedElement {
                    value: zeroeth_leaf.value.clone().try_into().map_err(|_e| {
                        IngesterError::ParserError(format!(
                            "Failed to convert zeroeth element value to array {:?}",
                            zeroeth_leaf.value
                        ))
                    })?,
                    next_index: usize_from_i64(zeroeth_leaf.next_index, "zeroeth next index")?,
                    next_value: zeroeth_leaf.next_value.try_into().map_err(|_e| {
                        IngesterError::ParserError(
                            "Failed to convert zeroeth element next value to array".to_string(),
                        )
                    })?,
                    index: usize_from_i64(zeroeth_leaf.leaf_index, "zeroeth leaf index")?,
                },
                seq: 0,
                signature: Signature::from([0; 64]), // Placeholder for synthetic element
            },
        );
    }
    Ok(())
}

fn ordered_indexed_leaf_updates(
    indexed_leaf_updates: HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
) -> Vec<IndexedTreeLeafUpdate> {
    let mut updates = indexed_leaf_updates.into_values().collect_vec();
    updates.sort_by(|a, b| {
        a.tree
            .to_bytes()
            .cmp(&b.tree.to_bytes())
            .then_with(|| i32::from(a.tree_kind).cmp(&i32::from(b.tree_kind)))
            .then_with(|| a.seq.cmp(&b.seq))
            .then_with(|| a.leaf.index.cmp(&b.leaf.index))
    });
    updates
}

/// Persists indexed Merkle tree updates to the database, maintaining the linked structure
/// required for indexed trees where each element points to the next element in sorted order.
///
/// This function implements indexed Merkle tree operations including both new element
/// appends and the corresponding low element updates that maintain tree integrity.
///
/// ## Steps performed:
/// 1. **Tree Processing**: Iterate through each unique tree in the updates
/// 2. **Tree Type Detection**: Determine tree height and hash behavior from metadata
/// 3. **Low Element Updates**:
///    - Query existing tree state from database to build local view
///    - For empty trees, initialize with the zeroeth element as needed
///    - For each new element being appended:
///      - Find the "low element" (largest existing element smaller than new value)
///      - Update the low element to point to the new element (update its next_index/next_value)
///      - Configure the new element to point to what the low element was pointing to
///      - Recompute hashes for the updated low element
///      - Add low element update to the batch
/// 4. **Initialization Elements**: Ensure required initialization elements exist:
///    - Zeroeth element (leaf_index 0): Points to the first real element
/// 5. **Database Persistence**:
///    - Sort updates by tree/kind/sequence, then batch into chunks to avoid SQL parameter limits
///    - Use upsert logic with sequence number checks to handle conflicts
///    - Insert/update records in indexed_trees table
/// 6. **State Tree Integration**: Persist Merkle nodes per tree/kind in ascending sequence order
pub async fn persist_indexed_tree_updates(
    txn: &DatabaseTransaction,
    mut indexed_leaf_updates: HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
    tree_info_cache: &std::collections::HashMap<
        solana_pubkey::Pubkey,
        crate::ingester::parser::tree_info::TreeInfo,
    >,
) -> Result<(), IngesterError> {
    // Step 1: Tree Processing - Collect unique trees and use the update role
    // for hashing/proof dimensions. The metadata cache is still authoritative
    // for whether the tree is known.
    let mut unique_trees: HashMap<Pubkey, RingsTreeKind> = HashMap::new();
    for update in indexed_leaf_updates.values() {
        if let Some(existing_kind) = unique_trees.insert(update.tree, update.tree_kind) {
            if existing_kind != update.tree_kind {
                return Err(IngesterError::ParserError(format!(
                    "Conflicting tree kinds for tree {}: {:?} vs {:?}",
                    update.tree, existing_kind, update.tree_kind
                )));
            }
        }
    }

    let mut trees: HashMap<Pubkey, (RingsTreeKind, u32)> = HashMap::new();
    for (tree, tree_kind) in unique_trees {
        tree_info_cache.get(&tree).ok_or_else(|| {
            IngesterError::ParserError(format!("Tree metadata not found for tree {}", tree))
        })?;
        trees.insert(tree, (tree_kind, tree_kind.tree_height()));
    }

    for (tree, (tree_kind, _tree_height)) in trees.clone() {
        // Step 4: Initialization Elements - Ensure required initialization elements exist
        ensure_zeroeth_element_exists(&mut indexed_leaf_updates, tree, tree_kind)?;
    }
    let ordered_updates = ordered_indexed_leaf_updates(indexed_leaf_updates);

    // Step 5: Database Persistence - Batch updates and insert/update records
    for chunk in ordered_updates.chunks(MAX_SQL_INSERTS) {
        let models = chunk
            .iter()
            .map(|x| {
                Ok(indexed_trees::ActiveModel {
                    tree: Set(x.tree.to_bytes().to_vec()),
                    leaf_index: Set(i64_from_usize(x.leaf.index, "indexed leaf index")?),
                    value: Set(x.leaf.value.to_vec()),
                    next_index: Set(i64_from_usize(x.leaf.next_index, "indexed next index")?),
                    next_value: Set(x.leaf.next_value.to_vec()),
                    seq: Set(Some(i64_from_u64(x.seq, "indexed sequence")?)),
                })
            })
            .collect::<Result<Vec<_>, IngesterError>>()?;

        let mut query = indexed_trees::Entity::insert_many(models)
            .on_conflict(
                OnConflict::columns([
                    indexed_trees::Column::Tree,
                    indexed_trees::Column::LeafIndex,
                ])
                .update_columns([
                    indexed_trees::Column::Value,
                    indexed_trees::Column::NextIndex,
                    indexed_trees::Column::NextValue,
                    indexed_trees::Column::Seq,
                ])
                .to_owned(),
            )
            .build(txn.get_database_backend());

        query.sql = format!("{} WHERE excluded.seq >= indexed_trees.seq", query.sql);

        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to insert indexed tree elements: {}", e))
        })?;
    }

    // Step 6: State Tree Integration - persist ordered chunks per logical tree.
    let mut start = 0;
    while start < ordered_updates.len() {
        let tree = ordered_updates[start].tree;
        let tree_kind = ordered_updates[start].tree_kind;
        let end = ordered_updates[start..]
            .iter()
            .position(|update| update.tree != tree || update.tree_kind != tree_kind)
            .map(|offset| start + offset)
            .unwrap_or(ordered_updates.len());
        let tree_height = trees
            .get(&tree)
            .map(|(_, height)| height + 1)
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Tree height not found for tree {} during persist",
                    tree
                ))
            })?;

        for chunk in ordered_updates[start..end].chunks(MAX_SQL_INSERTS) {
            let state_tree_leaf_nodes = chunk
                .iter()
                .map(|x| {
                    Ok(LeafNode {
                        tree: x.tree.to_bytes().to_vec(),
                        tree_kind: x.tree_kind,
                        leaf_index: u64_from_usize(x.leaf.index, "indexed leaf index")?,
                        hash: Hash::from(x.hash),
                        seq: Some(x.seq),
                    })
                })
                .collect::<Result<Vec<LeafNode>, IngesterError>>()?;
            persist_leaf_nodes(txn, state_tree_leaf_nodes, tree_height).await?;
        }

        start = end;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::generated::state_trees;
    use crate::ingester::parser::tree_info::TreeInfo;
    use crate::ingester::persist::indexed_merkle_tree::compute_nullifier_range_node_hash;
    use crate::ingester::persist::persisted_state_tree::zero_hash_for_level;
    use crate::migration::RingsMigrator;
    use sea_orm::{
        ColumnTrait, Database, DatabaseConnection, DatabaseTransaction, EntityTrait, QueryFilter,
        TransactionTrait,
    };
    use sea_orm_migration::MigratorTrait;

    #[test]
    fn nullifier_zeroeth_element_hash_is_not_zero_bytes_0() {
        let dummy_tree_id = vec![1u8; 32];
        let zeroeth_element = get_zeroeth_nullifier_exclusion_range(dummy_tree_id.clone());
        let zeroeth_element_hash_result = compute_nullifier_range_node_hash(&zeroeth_element);
        assert!(
            zeroeth_element_hash_result.is_ok(),
            "Failed to compute zeroeth_element_hash: {:?}",
            zeroeth_element_hash_result.err()
        );
        let zeroeth_element_hash = zeroeth_element_hash_result.unwrap();

        let zero_hash_at_level_0 = zero_hash_for_level(0).expect("zero hash level 0 should exist");
        assert_ne!(zeroeth_element_hash.to_vec(), zero_hash_at_level_0.to_vec(),);
    }

    #[tokio::test]
    async fn persists_over_chunk_limit_nullifier_nodes_in_sequence_order() {
        let tree = Pubkey::new_from_array([7; 32]);
        let update_count = MAX_SQL_INSERTS + 17;
        let mut updates = HashMap::new();
        for seq in (1..=u64::try_from(update_count).unwrap()).rev() {
            updates.insert((tree, seq), test_indexed_update(tree, seq));
        }

        let tree_info_cache = tree_info_cache([tree]);

        let actual_db = setup_test_db().await;
        let tx = actual_db.begin().await.unwrap();
        persist_indexed_tree_updates(&tx, updates.clone(), &tree_info_cache)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let expected_db = setup_test_db().await;
        let tx = expected_db.begin().await.unwrap();
        persist_expected_indexed_updates_by_tree(&tx, updates, [tree]).await;
        tx.commit().await.unwrap();

        let actual_root = root_node(&actual_db, tree).await;
        let expected_root = root_node(&expected_db, tree).await;
        assert_eq!(actual_root.seq, expected_root.seq);
        assert_eq!(actual_root.hash, expected_root.hash);
    }

    #[tokio::test]
    async fn persists_over_chunk_limit_nullifier_nodes_per_tree() {
        let tree_a = Pubkey::new_from_array([7; 32]);
        let tree_b = Pubkey::new_from_array([8; 32]);
        let trees = [
            (tree_a, MAX_SQL_INSERTS + 17),
            (tree_b, MAX_SQL_INSERTS + 31),
        ];
        let mut updates = HashMap::new();
        let max_update_count = trees
            .iter()
            .map(|(_, count)| *count)
            .max()
            .expect("test should include at least one tree");
        for seq in (1..=u64::try_from(max_update_count).unwrap()).rev() {
            for (tree, update_count) in trees {
                if seq <= u64::try_from(update_count).unwrap() {
                    updates.insert((tree, seq), test_indexed_update(tree, seq));
                }
            }
        }

        let tree_info_cache = tree_info_cache(trees.map(|(tree, _)| tree));

        let actual_db = setup_test_db().await;
        let tx = actual_db.begin().await.unwrap();
        persist_indexed_tree_updates(&tx, updates.clone(), &tree_info_cache)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let expected_db = setup_test_db().await;
        let tx = expected_db.begin().await.unwrap();
        persist_expected_indexed_updates_by_tree(&tx, updates, trees.map(|(tree, _)| tree)).await;
        tx.commit().await.unwrap();

        for (tree, _) in trees {
            let actual_root = root_node(&actual_db, tree).await;
            let expected_root = root_node(&expected_db, tree).await;
            assert_eq!(actual_root.seq, expected_root.seq, "root seq for {tree}");
            assert_eq!(actual_root.hash, expected_root.hash, "root hash for {tree}");
        }

        let tree_a_root = root_node(&actual_db, tree_a).await;
        let tree_b_root = root_node(&actual_db, tree_b).await;
        assert_ne!(tree_a_root.hash, tree_b_root.hash);
    }

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        db
    }

    fn tree_info_cache(trees: impl IntoIterator<Item = Pubkey>) -> HashMap<Pubkey, TreeInfo> {
        trees
            .into_iter()
            .map(|tree| {
                (
                    tree,
                    TreeInfo {
                        tree,
                        queue: tree,
                        height: RingsTreeKind::Nullifier.tree_height(),
                        root_history_capacity: RingsTreeKind::Nullifier.root_history_capacity(),
                        input_queue_zkp_batch_size:
                            rings_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
                    },
                )
            })
            .collect()
    }

    async fn persist_expected_indexed_updates_by_tree(
        tx: &DatabaseTransaction,
        mut updates: HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
        trees: impl IntoIterator<Item = Pubkey>,
    ) {
        for tree in trees {
            ensure_zeroeth_element_exists(&mut updates, tree, RingsTreeKind::Nullifier).unwrap();
            let mut tree_updates = updates
                .values()
                .filter(|update| update.tree == tree)
                .cloned()
                .collect_vec();
            tree_updates.sort_by(|a, b| {
                a.seq
                    .cmp(&b.seq)
                    .then_with(|| a.leaf.index.cmp(&b.leaf.index))
            });

            for chunk in tree_updates.chunks(MAX_SQL_INSERTS) {
                let leaf_nodes = chunk.iter().map(leaf_node_from_update).collect();
                persist_leaf_nodes(tx, leaf_nodes, RingsTreeKind::Nullifier.tree_height() + 1)
                    .await
                    .unwrap();
            }
        }
    }

    async fn root_node(db: &DatabaseConnection, tree: Pubkey) -> state_trees::Model {
        state_trees::Entity::find()
            .filter(state_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
            .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
            .filter(state_trees::Column::NodeIdx.eq(1))
            .one(db)
            .await
            .unwrap()
            .expect("root should be persisted")
    }

    fn leaf_node_from_update(update: &IndexedTreeLeafUpdate) -> LeafNode {
        LeafNode {
            tree: update.tree.to_bytes().to_vec(),
            tree_kind: update.tree_kind,
            leaf_index: u64::try_from(update.leaf.index).unwrap(),
            hash: Hash::from(update.hash),
            seq: Some(update.seq),
        }
    }

    fn test_indexed_update(tree: Pubkey, seq: u64) -> IndexedTreeLeafUpdate {
        IndexedTreeLeafUpdate {
            tree,
            tree_kind: RingsTreeKind::Nullifier,
            leaf: RawIndexedElement {
                value: test_bytes(seq),
                next_index: 0,
                next_value: test_bytes(seq + 1),
                index: usize::try_from(seq).unwrap(),
            },
            hash: test_bytes(seq + 2),
            seq,
            signature: Signature::from([1; 64]),
        }
    }

    fn test_bytes(value: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
}
