use crate::api::error::PhotonApiError;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::state_trees;
use crate::ingester::persist::leaf_node::{u64_from_i64, LeafNode};
use crate::ingester::persist::persisted_state_tree::{
    get_proof_nodes, get_proof_path, zero_hash_for_level,
};
use crate::ingester::persist::MerkleProofWithContext;
use sea_orm::QueryFilter;
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait};
use std::collections::HashMap;
use zolana_indexer_api::{Hash, SerializablePubkey};

pub async fn get_multiple_compressed_leaf_proofs_by_indices_with_height(
    txn: &DatabaseTransaction,
    merkle_tree_pubkey: SerializablePubkey,
    tree_kind: RingsTreeKind,
    indices: Vec<u64>,
    tree_height: u32,
) -> Result<Vec<MerkleProofWithContext>, PhotonApiError> {
    if indices.is_empty() {
        return Ok(Vec::new());
    }

    let tree_bytes = merkle_tree_pubkey.0.to_bytes();
    let root_seq = current_tree_sequence(txn, &tree_bytes, tree_kind).await?;

    log::debug!(
        "Fetching proofs for {} indices on tree {} kind {:?}, current root_seq: {:?}",
        indices.len(),
        merkle_tree_pubkey,
        tree_kind,
        root_seq
    );

    let requested_indices = indices
        .iter()
        .map(|&index| {
            i64::try_from(index).map_err(|_| {
                PhotonApiError::UnexpectedError(format!(
                    "requested leaf index {} does not fit in i64",
                    index
                ))
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;

    let existing_leaves = state_trees::Entity::find()
        .filter(
            state_trees::Column::LeafIdx
                .is_in(requested_indices)
                .and(state_trees::Column::Level.eq(0))
                .and(state_trees::Column::Tree.eq(merkle_tree_pubkey.to_bytes_vec()))
                .and(state_trees::Column::TreeKind.eq(i32::from(tree_kind))),
        )
        .all(txn)
        .await?;

    let mut index_to_leaf = HashMap::new();
    for leaf in existing_leaves {
        let leaf_index = u64_from_i64(leaf.leaf_idx.unwrap_or_default(), "stored leaf index")
            .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?;
        index_to_leaf.insert(leaf_index, leaf);
    }

    let mut leaf_nodes = Vec::new();

    for idx in indices {
        if let Some(existing) = index_to_leaf.remove(&idx) {
            leaf_nodes.push((
                LeafNode {
                    tree: merkle_tree_pubkey.to_bytes_vec(),
                    tree_kind,
                    leaf_index: idx,
                    hash: Hash::try_from(existing.hash)?,
                    seq: root_seq,
                },
                existing.node_idx,
            ));
        } else {
            return Err(PhotonApiError::UnexpectedError(format!(
                "Missing state-tree leaf for expected leaf index {} on tree {} kind {:?}",
                idx, merkle_tree_pubkey, tree_kind
            )));
        }
    }

    get_multiple_compressed_leaf_proofs_from_full_leaf_info(txn, leaf_nodes, tree_height).await
}

async fn current_tree_sequence(
    txn: &DatabaseTransaction,
    tree: &[u8; 32],
    tree_kind: RingsTreeKind,
) -> Result<Option<u64>, PhotonApiError> {
    let root = state_trees::Entity::find()
        .filter(
            state_trees::Column::Tree
                .eq(tree.to_vec())
                .and(state_trees::Column::TreeKind.eq(i32::from(tree_kind)))
                .and(state_trees::Column::NodeIdx.eq(1)),
        )
        .one(txn)
        .await?;

    root.and_then(|node| node.seq)
        .map(|seq| u64_from_i64(seq, "root sequence"))
        .transpose()
        .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))
}

pub async fn get_multiple_compressed_leaf_proofs_from_full_leaf_info(
    txn: &DatabaseTransaction,
    leaf_nodes_with_node_index: Vec<(LeafNode, i64)>,
    tree_height: u32,
) -> Result<Vec<MerkleProofWithContext>, PhotonApiError> {
    let include_leafs = false;
    let leaf_locations_to_required_nodes = leaf_nodes_with_node_index
        .iter()
        .map(|(leaf_node, node_index)| {
            let required_node_indices = get_proof_path(*node_index, include_leafs);
            (
                (
                    leaf_node.tree.clone(),
                    i32::from(leaf_node.tree_kind),
                    *node_index,
                ),
                required_node_indices,
            )
        })
        .collect::<HashMap<(Vec<u8>, i32, i64), Vec<i64>>>();

    let node_to_model = get_proof_nodes(
        txn,
        leaf_nodes_with_node_index
            .iter()
            .map(|(node, node_index)| (node.tree.clone(), i32::from(node.tree_kind), *node_index))
            .collect::<Vec<(Vec<u8>, i32, i64)>>(),
        include_leafs,
        true,
        tree_height,
    )
    .await?;

    let proofs: Result<Vec<MerkleProofWithContext>, PhotonApiError> = leaf_nodes_with_node_index
        .iter()
        .map(|(leaf_node, node_index)| {
            let required_node_indices = leaf_locations_to_required_nodes
                .get(&(
                    leaf_node.tree.clone(),
                    i32::from(leaf_node.tree_kind),
                    *node_index,
                ))
                .ok_or(PhotonApiError::RecordNotFound(format!(
                    "Leaf node not found for tree and index: {} {}",
                    SerializablePubkey::try_from(leaf_node.tree.clone())
                        .map(|tree| tree.to_string())
                        .unwrap_or_else(|_| format!("{:?}", leaf_node.tree)),
                    node_index
                )))?;

            let mut proof = required_node_indices
                .iter()
                .enumerate()
                .map(|(level, idx)| {
                    match node_to_model.get(&(
                        leaf_node.tree.clone(),
                        i32::from(leaf_node.tree_kind),
                        *idx,
                    )) {
                        Some(node) => Hash::try_from(node.hash.clone()).map_err(|_| {
                            PhotonApiError::UnexpectedError(
                                "Failed to convert hash to bytes".to_string(),
                            )
                        }),
                        None => zero_hash(level),
                    }
                })
                .collect::<Result<Vec<Hash>, PhotonApiError>>()?;

            let root_seq = match node_to_model.get(&(
                leaf_node.tree.clone(),
                i32::from(leaf_node.tree_kind),
                1,
            )) {
                Some(root) => root.seq,
                None => None,
            };

            let root = proof.pop().ok_or(PhotonApiError::UnexpectedError(
                "Root node not found in proof".to_string(),
            ))?;

            Ok(MerkleProofWithContext {
                proof,
                root,
                leaf_index: leaf_node.leaf_index,
                hash: leaf_node.hash.clone(),
                merkle_tree: SerializablePubkey::try_from(leaf_node.tree.clone()).map_err(|e| {
                    PhotonApiError::UnexpectedError(format!("Invalid tree pubkey bytes: {}", e))
                })?,
                root_seq: root_seq
                    .map(|seq| u64_from_i64(seq, "root sequence"))
                    .transpose()
                    .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?,
            })
        })
        .collect();
    let proofs = proofs?;
    Ok(proofs)
}

fn zero_hash(level: usize) -> Result<Hash, PhotonApiError> {
    zero_hash_for_level(level).map(Hash::from).ok_or_else(|| {
        PhotonApiError::UnexpectedError(format!("Tree level {} exceeds zero hash table", level))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::RingsMigrator;
    use sea_orm::{Database, Set, TransactionTrait};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn current_tree_sequence_distinguishes_absent_root_from_seq_zero() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        let tx = db.begin().await.unwrap();
        let tree = [7u8; 32];

        assert_eq!(
            current_tree_sequence(&tx, &tree, RingsTreeKind::Nullifier)
                .await
                .unwrap(),
            None
        );

        state_trees::Entity::insert(state_trees::ActiveModel {
            tree: Set(tree.to_vec()),
            tree_kind: Set(i32::from(RingsTreeKind::Nullifier)),
            node_idx: Set(1),
            leaf_idx: Set(None),
            level: Set(40),
            hash: Set([9u8; 32].to_vec()),
            seq: Set(Some(0)),
        })
        .exec(&tx)
        .await
        .unwrap();

        assert_eq!(
            current_tree_sequence(&tx, &tree, RingsTreeKind::Nullifier)
                .await
                .unwrap(),
            Some(0)
        );
    }
}
