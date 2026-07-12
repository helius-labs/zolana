use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::state_trees;
use crate::ingester::error::IngesterError;
use crate::ingester::persist::persisted_state_tree::{get_proof_nodes, zero_hash_for_level};
use crate::ingester::persist::{compute_parent_hash, get_node_direct_ancestors};
use crate::migration::OnConflict;
use sea_orm::{ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set};
use std::cmp::max;
use std::collections::HashMap;
use zolana_indexer_api::Hash;

#[derive(Clone, Debug)]
pub struct LeafNode {
    /// Raw tree account identity returned in API proof contexts.
    pub tree: Vec<u8>,
    /// Logical tree role stored alongside `tree` in `state_trees`.
    pub tree_kind: RingsTreeKind,
    pub leaf_index: u64,
    pub hash: Hash,
    pub seq: Option<u64>,
}

impl LeafNode {
    pub fn node_index(&self, tree_height: u32) -> Result<i64, IngesterError> {
        leaf_index_to_node_index(self.leaf_index, tree_height)
    }
}

pub fn leaf_index_to_node_index(leaf_index: u64, tree_height: u32) -> Result<i64, IngesterError> {
    if tree_height == 0 {
        return Err(IngesterError::ParserError(
            "Tree height must be greater than zero".to_string(),
        ));
    }
    let first_leaf_index = 1_i64.checked_shl(tree_height - 1).ok_or_else(|| {
        IngesterError::ParserError(format!("Tree height {} is too large", tree_height))
    })?;
    let leaf_index = i64_from_u64(leaf_index, "leaf index")?;
    if leaf_index >= first_leaf_index {
        return Err(IngesterError::ParserError(format!(
            "Leaf index {} is out of range for tree height {}",
            leaf_index, tree_height
        )));
    }
    first_leaf_index.checked_add(leaf_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Node index overflow for leaf index {} and tree height {}",
            leaf_index, tree_height
        ))
    })
}

pub async fn persist_leaf_nodes(
    txn: &DatabaseTransaction,
    mut leaf_nodes: Vec<LeafNode>,
    tree_height: u32,
) -> Result<(), IngesterError> {
    if leaf_nodes.is_empty() {
        return Ok(());
    }

    leaf_nodes.sort_by_key(|node| node.seq);

    let leaf_locations = leaf_nodes
        .iter()
        .map(|node| {
            Ok((
                node.tree.clone(),
                i32::from(node.tree_kind),
                node.node_index(tree_height)?,
            ))
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    let node_locations_to_models =
        get_proof_nodes(txn, leaf_locations, true, false, tree_height).await?;
    let mut node_locations_to_hashes_and_seq = node_locations_to_models
        .iter()
        .map(|(key, value)| (key.clone(), (value.hash.clone(), value.seq)))
        .collect::<HashMap<_, _>>();

    let mut models_to_updates = HashMap::new();

    for leaf_node in leaf_nodes.clone() {
        let node_idx = leaf_node.node_index(tree_height)?;
        let key = (
            leaf_node.tree.clone(),
            i32::from(leaf_node.tree_kind),
            node_idx,
        );

        let model = state_trees::ActiveModel {
            tree: Set(leaf_node.tree.clone()),
            tree_kind: Set(i32::from(leaf_node.tree_kind)),
            level: Set(0),
            node_idx: Set(node_idx),
            hash: Set(leaf_node.hash.to_vec()),
            leaf_idx: Set(Some(i64_from_u64(leaf_node.leaf_index, "leaf index")?)),
            seq: Set(leaf_node
                .seq
                .map(|seq| i64_from_u64(seq, "sequence"))
                .transpose()?),
        };

        let existing_seq = node_locations_to_hashes_and_seq
            .get(&key)
            .map(|x| x.1)
            .unwrap_or(Some(0));

        if let Some(existing_seq) = existing_seq {
            if let Some(leaf_node_seq) = leaf_node.seq {
                let existing_seq = u64_from_i64(existing_seq, "existing sequence")?;
                if leaf_node_seq >= existing_seq {
                    models_to_updates.insert(key.clone(), model);
                    node_locations_to_hashes_and_seq.insert(
                        key,
                        (
                            leaf_node.hash.to_vec(),
                            Some(i64_from_u64(leaf_node_seq, "sequence")?),
                        ),
                    );
                }
            }
        }
    }

    let mut all_ancestors = Vec::new();
    for leaf_node in &leaf_nodes {
        for (i, idx) in get_node_direct_ancestors(leaf_node.node_index(tree_height)?)
            .iter()
            .enumerate()
        {
            all_ancestors.push((
                leaf_node.tree.clone(),
                i32::from(leaf_node.tree_kind),
                *idx,
                i,
            ));
        }
    }
    all_ancestors.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    all_ancestors.dedup();

    for (tree, tree_kind, node_index, child_level) in all_ancestors.into_iter().rev() {
        let zero_hash = zero_hash_for_level(child_level)
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Tree level {} exceeds zero hash table",
                    child_level
                ))
            })?
            .to_vec();
        let (left_child_hash, left_child_seq) = node_locations_to_hashes_and_seq
            .get(&(tree.clone(), tree_kind, node_index * 2))
            .cloned()
            .unwrap_or((zero_hash.clone(), Some(0)));

        let (right_child_hash, right_child_seq) = node_locations_to_hashes_and_seq
            .get(&(tree.clone(), tree_kind, node_index * 2 + 1))
            .cloned()
            .unwrap_or((zero_hash, Some(0)));

        let level = child_level + 1;

        let hash = compute_parent_hash(left_child_hash.clone(), right_child_hash.clone())?;

        let seq = max(left_child_seq, right_child_seq);
        let model = state_trees::ActiveModel {
            tree: Set(tree.clone()),
            tree_kind: Set(tree_kind),
            level: Set(i64::try_from(level).map_err(|_| {
                IngesterError::ParserError(format!("Tree level {} does not fit in i64", level))
            })?),
            node_idx: Set(node_index),
            hash: Set(hash.clone()),
            leaf_idx: Set(None),
            seq: Set(seq),
        };

        let key = (tree.clone(), tree_kind, node_index);
        models_to_updates.insert(key.clone(), model);
        node_locations_to_hashes_and_seq.insert(key, (hash, seq));
    }

    // We first build the query and then execute it because SeaORM has a bug where it always throws
    // an error if we do not insert a record in an insert statement. However, in this case, it's
    // expected not to insert anything if the key already exists.
    let update_count = models_to_updates.len();
    let mut seq_values: Vec<i64> = models_to_updates
        .values()
        .filter_map(|m| match &m.seq {
            sea_orm::ActiveValue::Set(opt) => *opt,
            _ => None,
        })
        .collect();
    seq_values.sort();
    let min_seq = seq_values.first().copied();
    let max_seq = seq_values.last().copied();

    log::debug!(
        "Persisting {} tree nodes (seq range: {:?} to {:?}) for tree {:?} kind {:?}",
        update_count,
        min_seq,
        max_seq,
        leaf_nodes.first().map(|n| &n.tree),
        leaf_nodes.first().map(|n| n.tree_kind)
    );

    let mut query = state_trees::Entity::insert_many(models_to_updates.into_values())
        .on_conflict(
            OnConflict::columns([
                state_trees::Column::Tree,
                state_trees::Column::TreeKind,
                state_trees::Column::NodeIdx,
            ])
            .update_columns([
                state_trees::Column::Hash,
                state_trees::Column::Seq,
                state_trees::Column::LeafIdx,
            ])
            .to_owned(),
        )
        .build(txn.get_database_backend());
    query.sql = format!(
        "{} WHERE state_trees.seq IS NULL OR excluded.seq >= state_trees.seq",
        query.sql
    );
    txn.execute(query).await.map_err(|e| {
        IngesterError::DatabaseError(format!("Failed to persist path nodes: {}", e))
    })?;

    log::debug!(
        "Successfully persisted {} nodes for tree {:?} kind {:?}",
        update_count,
        leaf_nodes.first().map(|n| &n.tree),
        leaf_nodes.first().map(|n| n.tree_kind)
    );
    Ok(())
}

pub(crate) fn i64_from_u64(value: u64, field: &str) -> Result<i64, IngesterError> {
    i64::try_from(value)
        .map_err(|_| IngesterError::ParserError(format!("{} {} does not fit in i64", field, value)))
}

pub(crate) fn u64_from_i64(value: i64, field: &str) -> Result<u64, IngesterError> {
    u64::try_from(value).map_err(|_| {
        IngesterError::ParserError(format!("{} {} must be non-negative", field, value))
    })
}

pub(crate) fn i64_from_usize(value: usize, field: &str) -> Result<i64, IngesterError> {
    i64::try_from(value)
        .map_err(|_| IngesterError::ParserError(format!("{} {} does not fit in i64", field, value)))
}

pub(crate) fn u64_from_usize(value: usize, field: &str) -> Result<u64, IngesterError> {
    u64::try_from(value)
        .map_err(|_| IngesterError::ParserError(format!("{} {} does not fit in u64", field, value)))
}

pub(crate) fn usize_from_i64(value: i64, field: &str) -> Result<usize, IngesterError> {
    usize::try_from(value).map_err(|_| {
        IngesterError::ParserError(format!("{} {} must be non-negative", field, value))
    })
}
