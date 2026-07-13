use crate::common::bn254::BN254_FIELD_SIZE_MINUS_ONE_BYTES;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::indexed_trees;
use crate::ingester::error::IngesterError;
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use zolana_indexer_api::Hash;

/// Computes range node hash based on tree type
pub fn compute_hash_by_tree_kind(
    range_node: &indexed_trees::Model,
    tree_kind: RingsTreeKind,
) -> Result<Hash, IngesterError> {
    match tree_kind {
        // Rings nullifier range nodes use H(value, next_value). next_index is
        // stored for ordering but is not part of the hash.
        RingsTreeKind::Nullifier => compute_nullifier_range_node_hash(range_node).map_err(|e| {
            IngesterError::ParserError(format!("Failed to compute nullifier range hash: {}", e))
        }),
        _ => Err(IngesterError::ParserError(format!(
            "Unsupported tree kind for range node hash computation: {:?}",
            tree_kind
        ))),
    }
}

/// Computes the Rings nullifier range node hash: H(value, next_value).
pub fn compute_nullifier_range_node_hash(
    node: &indexed_trees::Model,
) -> Result<Hash, IngesterError> {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(|e| {
        IngesterError::ParserError(format!("Failed to initialize Poseidon hasher: {}", e))
    })?;

    Hash::try_from(
        poseidon
            .hash_bytes_be(&[&node.value, &node.next_value])
            .map_err(|e| {
                IngesterError::ParserError(format!("Failed to compute nullifier range hash: {}", e))
            })
            .map(|x| x.to_vec())?,
    )
    .map_err(|e| {
        IngesterError::ParserError(format!("Failed to convert nullifier range hash: {}", e))
    })
}

pub fn get_zeroeth_nullifier_exclusion_range(tree: Vec<u8>) -> indexed_trees::Model {
    indexed_trees::Model {
        tree,
        leaf_index: 0,
        value: vec![0; 32],
        next_index: 0,
        next_value: BN254_FIELD_SIZE_MINUS_ONE_BYTES.to_vec(),
        seq: Some(0),
    }
}
