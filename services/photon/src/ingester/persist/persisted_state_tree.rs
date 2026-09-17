use std::collections::HashMap;

use itertools::Itertools;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait, Statement, TransactionTrait, Value};

use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::state_trees;

pub fn get_proof_path(index: i64, include_leaf: bool) -> Vec<i64> {
    let mut indexes = vec![];
    let mut idx = index;
    if include_leaf {
        indexes.push(index);
    }
    while idx > 1 {
        if idx % 2 == 0 {
            indexes.push(idx + 1)
        } else {
            indexes.push(idx - 1)
        }
        idx >>= 1
    }
    indexes.push(1);
    indexes
}

pub fn get_level_by_node_index(index: i64, tree_height: u32) -> i64 {
    if index <= 0 {
        return 0;
    }

    let depth_from_root = i64::from(index.ilog2());
    let leaf_depth = i64::from(tree_height.saturating_sub(1));
    leaf_depth.saturating_sub(depth_from_root)
}

pub async fn get_proof_nodes<T>(
    txn_or_conn: &T,
    leaf_nodes_locations: Vec<(Vec<u8>, i32, i64)>,
    include_leafs: bool,
    include_empty_leaves: bool,
    tree_height: u32,
) -> Result<HashMap<(Vec<u8>, i32, i64), state_trees::Model>, DbErr>
where
    T: ConnectionTrait + TransactionTrait,
{
    let all_required_node_indices = leaf_nodes_locations
        .iter()
        .flat_map(|(tree, tree_kind, index)| {
            get_proof_path(*index, include_leafs)
                .iter()
                .map(move |&idx| (tree.clone(), *tree_kind, idx))
                .collect::<Vec<(Vec<u8>, i32, i64)>>()
        })
        .sorted_by(|a, b| {
            // Need to sort elements before dedup
            a.0.cmp(&b.0) // Sort by tree
                .then_with(|| a.1.cmp(&b.1)) // Then by tree kind
                .then_with(|| a.2.cmp(&b.2)) // Then by node index
        })
        .dedup()
        .collect::<Vec<(Vec<u8>, i32, i64)>>();

    let mut params = Vec::new();
    let mut placeholders = Vec::new();

    for (index, (tree, tree_kind, node_idx)) in all_required_node_indices.into_iter().enumerate() {
        let param_index = index * 3; // each location contributes three parameters
        params.push(Value::from(tree));
        params.push(Value::from(tree_kind));
        params.push(Value::from(node_idx));
        placeholders.push(format!(
            "(${}, ${}, ${})",
            param_index + 1,
            param_index + 2,
            param_index + 3
        ));
    }

    let placeholder_str = placeholders.join(", ");
    let sql = format!(
            "WITH vals(tree, tree_kind, node_idx) AS (VALUES {}) SELECT st.* FROM state_trees st JOIN vals v ON st.tree = v.tree AND st.tree_kind = v.tree_kind AND st.node_idx = v.node_idx",
            placeholder_str
        );

    let proof_nodes = state_trees::Entity::find()
        .from_raw_sql(Statement::from_sql_and_values(
            txn_or_conn.get_database_backend(),
            &sql,
            params,
        ))
        .all(txn_or_conn)
        .await?;

    let mut result = proof_nodes
        .iter()
        .map(|node| {
            (
                (node.tree.clone(), node.tree_kind, node.node_idx),
                node.clone(),
            )
        })
        .collect::<HashMap<(Vec<u8>, i32, i64), state_trees::Model>>();

    if include_empty_leaves {
        for (tree, tree_kind, index) in leaf_nodes_locations.iter() {
            let key = (tree.clone(), *tree_kind, *index);
            if result.contains_key(&key) {
                continue;
            }

            let level = get_level_by_node_index(*index, tree_height);
            result.insert(
                key,
                state_trees::Model {
                    tree: tree.clone(),
                    tree_kind: *tree_kind,
                    level,
                    node_idx: *index,
                    hash: zero_bytes_for_level(*tree_kind, level)?,
                    leaf_idx: None,
                    seq: None,
                },
            );
        }
    }

    Ok(result)
}

pub fn validate_leaf_index(leaf_index: u64, tree_height: u32) -> bool {
    tree_height
        .checked_sub(1)
        .and_then(|exponent| 2_u64.checked_pow(exponent))
        .is_some_and(|max_leaves| leaf_index < max_leaves)
}

pub fn get_merkle_proof_length(tree_height: u32) -> usize {
    usize::try_from(tree_height.saturating_sub(1)).unwrap_or(usize::MAX)
}

pub fn zero_hash_for_level(tree_kind: RingsTreeKind, level: usize) -> Option<[u8; 32]> {
    tree_kind.zero_hash(level)
}

fn zero_bytes_for_level(tree_kind: i32, level: i64) -> Result<Vec<u8>, DbErr> {
    let tree_kind = RingsTreeKind::try_from(tree_kind).map_err(|e| DbErr::Custom(e.to_string()))?;
    let level = usize::try_from(level)
        .map_err(|_| DbErr::Custom(format!("Invalid negative tree level {}", level)))?;
    zero_hash_for_level(tree_kind, level)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| DbErr::Custom(format!("Tree level {} exceeds zero hash table", level)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::persist::leaf_node::leaf_index_to_node_index;
    use crate::ingester::persist::{compute_parent_hash, MerkleProofWithContext};
    use zolana_indexer_api::{Hash, SerializablePubkey};

    fn node_index_to_leaf_index(index: i64, tree_height: u32) -> Option<i64> {
        let first_leaf_index = 1_i64.checked_shl(tree_height.checked_sub(1)?)?;
        index.checked_sub(first_leaf_index)
    }

    fn test_zero_hash(level: usize) -> [u8; 32] {
        zero_hash_for_level(RingsTreeKind::State, level).expect("test zero hash level should exist")
    }

    #[test]
    fn test_get_level_by_node_index() {
        // Tree levels are stored leaf-up: leaves are level 0 and the root is height - 1.
        assert_eq!(get_level_by_node_index(1, 3), 2);
        assert_eq!(get_level_by_node_index(2, 3), 1);
        assert_eq!(get_level_by_node_index(3, 3), 1);
        assert_eq!(get_level_by_node_index(4, 3), 0);
        assert_eq!(get_level_by_node_index(5, 3), 0);
        assert_eq!(get_level_by_node_index(6, 3), 0);
        assert_eq!(get_level_by_node_index(7, 3), 0);
    }

    // Test helper to convert byte arrays to hex strings for easier debugging
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("")
    }

    // Helper to verify node index calculations
    fn verify_node_index_conversion(leaf_index: u64, tree_height: u32) -> bool {
        let Ok(node_index) = leaf_index_to_node_index(leaf_index, tree_height) else {
            return false;
        };
        let recovered_leaf_index = node_index_to_leaf_index(node_index, tree_height);
        recovered_leaf_index == i64::try_from(leaf_index).ok()
    }

    #[test]
    fn test_zero_bytes_consistency() {
        // Each level of the zero table is the hash of two copies of the level below
        for level in (1..=zolana_hasher::zero_bytes::MAX_HEIGHT).rev() {
            let parent_hash = compute_parent_hash(
                RingsTreeKind::State,
                test_zero_hash(level - 1).to_vec(),
                test_zero_hash(level - 1).to_vec(),
            )
            .unwrap();

            assert_eq!(
                parent_hash,
                test_zero_hash(level).to_vec(),
                "Zero bytes hash mismatch at level {}\nComputed: {}\nExpected: {}",
                level,
                bytes_to_hex(&parent_hash),
                bytes_to_hex(&test_zero_hash(level))
            );
        }
    }

    #[test]
    fn test_leaf_index_conversions() {
        let test_cases = vec![
            (0u64, 32u32),             // First leaf in height 32 tree
            (1u64, 32u32),             // Second leaf
            (2_147_483_647u64, 32u32), // Last valid leaf in height 32 tree
            (0u64, 3u32),              // Small tree test
            (1u64, 3u32),
            (2u64, 3u32),
            (3u64, 3u32),
            (u64::from(u32::MAX), 33u32),
        ];

        for (leaf_index, tree_height) in test_cases {
            assert!(
                verify_node_index_conversion(leaf_index, tree_height),
                "Conversion failed for leaf_index={}, tree_height={}",
                leaf_index,
                tree_height
            );
        }
    }

    #[test]
    fn test_proof_validation_components() {
        // Test case for first non-existent leaf (index 0)
        let test_leaf_index = 0u64;
        let tree_height = 32u32;
        // Create proof components
        let node_index = leaf_index_to_node_index(test_leaf_index, tree_height).unwrap();
        let proof_path = get_proof_path(node_index, false);

        // Verify proof path length
        assert_eq!(
            proof_path.len(),
            usize::try_from(tree_height).unwrap_or(usize::MAX)
        );

        // Test level calculation for proof path nodes
        for &idx in &proof_path {
            let level = get_level_by_node_index(idx, tree_height);
            let max_level = i64::from(tree_height);
            assert!(level < max_level);
        }

        // Manually compute root hash using proof path
        let mut current_hash = test_zero_hash(0).to_vec(); // Start with leaf level zero bytes

        for (idx, _) in proof_path.iter().enumerate() {
            let is_left = (node_index >> idx) & 1 == 0;
            let sibling_hash = test_zero_hash(idx).to_vec();

            let (left_child, right_child) = if is_left {
                (current_hash.clone(), sibling_hash)
            } else {
                (sibling_hash, current_hash.clone())
            };

            current_hash =
                compute_parent_hash(RingsTreeKind::State, left_child, right_child).unwrap();

            // Verify against the zero table
            assert_eq!(
                current_hash,
                test_zero_hash(idx + 1).to_vec(),
                "Hash mismatch at level {}",
                idx + 1
            );
        }
    }

    #[test]
    fn test_validate_proof() {
        let test_leaf_index = 0u64;
        let merkle_tree = SerializablePubkey::try_from(vec![0u8; 32]).unwrap();

        // Create a proof for testing
        let mut proof = Vec::new();
        for level in 0..31 {
            // One less than tree height since root is separate
            proof.push(Hash::from(test_zero_hash(level)));
        }

        let proof_context = MerkleProofWithContext {
            tree_kind: RingsTreeKind::State,
            proof,
            root: Hash::try_from(test_zero_hash(31).to_vec()).unwrap(),
            leaf_index: test_leaf_index,
            hash: Hash::try_from(test_zero_hash(0).to_vec()).unwrap(),
            merkle_tree,
            root_seq: Some(0),
        };

        // Validate the proof
        let result = proof_context.validate();
        assert!(result.is_ok(), "Proof validation failed: {:?}", result);
    }

    #[test]
    fn test_validate_leaf_index() {
        assert!(validate_leaf_index(0, 27));
        assert!(validate_leaf_index((1 << 26) - 1, 27));
        assert!(!validate_leaf_index(1 << 26, 27));
        assert!(validate_leaf_index(0, 33));
    }

    #[test]
    fn test_merkle_proof_length() {
        assert_eq!(get_merkle_proof_length(27), 26);
        assert_eq!(get_merkle_proof_length(33), 32);
    }
}
