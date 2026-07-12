use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::indexed_trees;
use crate::ingester::error::IngesterError;
use crate::ingester::persist::indexed_merkle_tree::{
    compute_hash_by_tree_kind, get_zeroeth_nullifier_exclusion_range,
};
use crate::ingester::persist::persisted_state_tree::ZERO_BYTES;
use crate::ingester::persist::{
    compute_parent_hash, get_multiple_compressed_leaf_proofs_from_full_leaf_info,
    leaf_node::u64_from_i64, LeafNode, MerkleProofWithContext,
};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseTransaction, Statement, TransactionTrait};
use std::collections::HashMap;
use zolana_indexer_api::{Hash, SerializablePubkey};

fn zeroeth_exclusion_range(
    tree: Vec<u8>,
    tree_kind: RingsTreeKind,
) -> Result<indexed_trees::Model, PhotonApiError> {
    match tree_kind {
        RingsTreeKind::Nullifier => Ok(get_zeroeth_nullifier_exclusion_range(tree)),
        RingsTreeKind::State => Err(PhotonApiError::UnexpectedError(
            "State trees do not use indexed-tree non-inclusion proofs".to_string(),
        )),
    }
}

fn proof_for_empty_tree_with_model(
    tree: Vec<u8>,
    tree_height: u32,
    root_seq: Option<u64>,
    tree_kind: RingsTreeKind,
    zeroeth_element: indexed_trees::Model,
) -> Result<(indexed_trees::Model, MerkleProofWithContext), PhotonApiError> {
    let mut proof: Vec<Hash> = vec![];

    for i in 0..(tree_height - 1) {
        let zero_hash = ZERO_BYTES
            .get(usize::try_from(i).map_err(|_| {
                PhotonApiError::UnexpectedError(format!("Tree level {} does not fit in usize", i))
            })?)
            .ok_or_else(|| {
                PhotonApiError::UnexpectedError(format!("Tree level {} exceeds zero hash table", i))
            })?;
        let hash = Hash::from(zero_hash);
        proof.push(hash);
    }

    let zeroeth_element_hash = compute_hash_by_tree_kind(&zeroeth_element, tree_kind)
        .map_err(|e| PhotonApiError::UnexpectedError(format!("Failed to compute hash: {}", e)))?;

    let mut root = zeroeth_element_hash.clone().to_vec();
    for elem in proof.iter() {
        root = compute_parent_hash(root, elem.to_vec())
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Failed to compute hash: {e}")))?;
    }

    let merkle_proof = MerkleProofWithContext {
        proof,
        root: Hash::try_from(root.clone())
            .map_err(|e| PhotonApiError::UnexpectedError(format!("Failed to convert hash: {e}")))?,
        leaf_index: 0,
        hash: zeroeth_element_hash,
        merkle_tree: SerializablePubkey::try_from(tree.clone()).map_err(|e| {
            PhotonApiError::UnexpectedError(format!("Failed to serialize pubkey: {e}"))
        })?,
        root_seq,
    };

    merkle_proof.validate()?;
    Ok((zeroeth_element, merkle_proof))
}

/// Optimized version for API use: Query the next smallest element for each input address.
/// Returns a HashMap mapping INPUT ADDRESS -> range node model.
/// This is O(1) lookup per address instead of O(n) scan in the caller.
pub async fn query_next_smallest_elements_by_address<T>(
    txn_or_conn: &T,
    values: Vec<Vec<u8>>,
    tree: Vec<u8>,
) -> Result<HashMap<Vec<u8>, indexed_trees::Model>, IngesterError>
where
    T: ConnectionTrait + TransactionTrait,
{
    if values.is_empty() {
        return Ok(HashMap::new());
    }

    let backend = txn_or_conn.get_database_backend();
    let mut indexed_tree: HashMap<Vec<u8>, indexed_trees::Model> =
        HashMap::with_capacity(values.len());

    match backend {
        DatabaseBackend::Postgres => {
            // Batch queries in chunks to avoid query plan explosion
            // Each chunk uses UNION ALL which PostgreSQL optimizes well with index scans
            // Include input_address as a constant column to track which result belongs to which input
            const BATCH_SIZE: usize = 100;

            for chunk in values.chunks(BATCH_SIZE) {
                let mut params = Vec::new();
                let tree_param = bind_sql_value(&mut params, backend, tree.clone());
                let sql_statements = chunk.iter().map(|value| {
                    let input_address = bind_blob_expression(
                        bind_sql_value(&mut params, backend, value.clone()),
                        backend,
                    )?;
                    let value_param = bind_sql_value(&mut params, backend, value.clone());
                    Ok(format!(
                        "(SELECT {input_address} as input_address, tree, leaf_index, value, next_index, next_value, seq \
                         FROM indexed_trees WHERE tree = {tree_param} AND value < {value_param} ORDER BY value DESC LIMIT 1)",
                    ))
                });
                let full_query = sql_statements
                    .collect::<Result<Vec<_>, IngesterError>>()?
                    .join(" UNION ALL ");

                let chunk_results = txn_or_conn
                    .query_all(Statement::from_sql_and_values(backend, full_query, params))
                    .await
                    .map_err(|e| {
                        IngesterError::DatabaseError(format!(
                            "Failed to execute indexed query: {e}"
                        ))
                    })?;

                for row in chunk_results {
                    let input_address: Vec<u8> = row.try_get("", "input_address")?;
                    let model = indexed_trees::Model {
                        tree: row.try_get("", "tree")?,
                        leaf_index: row.try_get("", "leaf_index")?,
                        value: row.try_get("", "value")?,
                        next_index: row.try_get("", "next_index")?,
                        next_value: row.try_get("", "next_value")?,
                        seq: row.try_get("", "seq")?,
                    };
                    indexed_tree.insert(input_address, model);
                }
            }
        }
        DatabaseBackend::Sqlite => {
            for value in values {
                let mut params = Vec::new();
                let input_address = bind_blob_expression(
                    bind_sql_value(&mut params, backend, value.clone()),
                    backend,
                )?;
                let tree_param = bind_sql_value(&mut params, backend, tree.clone());
                let value_param = bind_sql_value(&mut params, backend, value.clone());
                let full_query = format!(
                    "SELECT {input_address} as input_address, tree, leaf_index, value, next_index, next_value, seq \
                     FROM indexed_trees WHERE tree = {tree_param} AND value < {value_param} ORDER BY value DESC LIMIT 1",
                );
                let results = txn_or_conn
                    .query_all(Statement::from_sql_and_values(backend, full_query, params))
                    .await
                    .map_err(|e| {
                        IngesterError::DatabaseError(format!(
                            "Failed to execute indexed query: {e}"
                        ))
                    })?;

                for row in results {
                    let input_address: Vec<u8> = row.try_get("", "input_address")?;
                    let model = indexed_trees::Model {
                        tree: row.try_get("", "tree")?,
                        leaf_index: row.try_get("", "leaf_index")?,
                        value: row.try_get("", "value")?,
                        next_index: row.try_get("", "next_index")?,
                        next_value: row.try_get("", "next_value")?,
                        seq: row.try_get("", "seq")?,
                    };
                    indexed_tree.insert(input_address, model);
                }
            }
        }
        backend => {
            return Err(IngesterError::DatabaseError(format!(
                "Unsupported database backend for indexed proof query: {:?}",
                backend
            )));
        }
    };

    Ok(indexed_tree)
}

fn bind_blob_expression(
    placeholder: String,
    backend: DatabaseBackend,
) -> Result<String, IngesterError> {
    match backend {
        DatabaseBackend::Postgres => Ok(format!("{placeholder}::bytea")),
        DatabaseBackend::Sqlite => Ok(format!("CAST({placeholder} AS BLOB)")),
        backend => Err(IngesterError::DatabaseError(format!(
            "Unsupported database backend for blob expression: {:?}",
            backend
        ))),
    }
}

fn validate_non_inclusion_range(
    address: &[u8],
    range: &indexed_trees::Model,
) -> Result<(), PhotonApiError> {
    if range.value.as_slice() == address || range.next_value.as_slice() == address {
        return Err(PhotonApiError::ValidationError(
            "Cannot create a non-inclusion proof for a value already present in the tree"
                .to_string(),
        ));
    }

    if range.value.as_slice() >= address || address >= range.next_value.as_slice() {
        return Err(PhotonApiError::ValidationError(
            "Resolved indexed-tree range does not strictly contain requested value".to_string(),
        ));
    }

    Ok(())
}

fn matching_range_proof<'a>(
    proofs: &'a [MerkleProofWithContext],
    range: &indexed_trees::Model,
    range_hash: &Hash,
) -> Result<&'a MerkleProofWithContext, PhotonApiError> {
    let range_leaf_index = u64_from_i64(range.leaf_index, "range leaf index")
        .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?;

    proofs
        .iter()
        .find(|proof| proof.leaf_index == range_leaf_index && proof.hash == *range_hash)
        .ok_or_else(|| {
            PhotonApiError::UnexpectedError(format!(
                "Missing indexed-tree proof for range leaf index {} and hash {}",
                range_leaf_index, range_hash
            ))
        })
}

pub async fn get_multiple_indexed_exclusion_ranges_with_custom_empty_proofs(
    txn: &DatabaseTransaction,
    tree: Vec<u8>,
    tree_height: u32,
    addresses: Vec<Vec<u8>>,
    tree_kind: RingsTreeKind,
    empty_range_model: Option<indexed_trees::Model>,
) -> Result<HashMap<Vec<u8>, (indexed_trees::Model, MerkleProofWithContext)>, PhotonApiError> {
    if addresses.is_empty() {
        return Ok(HashMap::new());
    }

    // Query returns HashMap<input_address, range_node> - O(1) lookup per address
    let address_to_range =
        query_next_smallest_elements_by_address(txn, addresses.clone(), tree.clone())
            .await
            .map_err(|e| {
                PhotonApiError::UnexpectedError(format!(
                    "Failed to query next smallest elements: {}",
                    e
                ))
            })?;

    let mut results = HashMap::new();
    let mut leaf_nodes_with_indices = Vec::new();
    let mut address_to_model: HashMap<Vec<u8>, (indexed_trees::Model, Hash)> = HashMap::new();
    SerializablePubkey::try_from(tree.clone()).map_err(|e| {
        PhotonApiError::UnexpectedError(format!("Invalid tree pubkey bytes: {}", e))
    })?;

    // Process addresses that have range proofs - O(1) lookup per address
    for address in &addresses {
        if let Some(range_node) = address_to_range.get(address) {
            validate_non_inclusion_range(address, range_node)?;
            let hash = compute_hash_by_tree_kind(range_node, tree_kind).map_err(|e| {
                PhotonApiError::UnexpectedError(format!("Failed to compute hash: {}", e))
            })?;

            let leaf_node = LeafNode {
                tree: range_node.tree.clone(),
                tree_kind,
                leaf_index: u64_from_i64(range_node.leaf_index, "range leaf index")
                    .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?,
                hash: hash.clone(),
                seq: range_node
                    .seq
                    .map(|seq| u64_from_i64(seq, "range sequence"))
                    .transpose()
                    .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?,
            };
            let node_index = leaf_node
                .node_index(tree_height)
                .map_err(|error| PhotonApiError::UnexpectedError(error.to_string()))?;
            leaf_nodes_with_indices.push((leaf_node, node_index));
            address_to_model.insert(address.clone(), (range_node.clone(), hash));
        }
    }

    let leaf_proofs = if !leaf_nodes_with_indices.is_empty() {
        get_multiple_compressed_leaf_proofs_from_full_leaf_info(
            txn,
            leaf_nodes_with_indices,
            tree_height,
        )
        .await?
    } else {
        Vec::new()
    };

    for (address, (model, range_hash)) in address_to_model {
        let proof = matching_range_proof(&leaf_proofs, &model, &range_hash)?;
        results.insert(address, (model, proof.clone()));
    }

    let addresses_needing_empty_proof: Vec<Vec<u8>> = addresses
        .iter()
        .filter(|addr| !results.contains_key(*addr))
        .cloned()
        .collect();

    if !addresses_needing_empty_proof.is_empty() {
        let (empty_model, empty_proof) = match empty_range_model.clone() {
            Some(empty_range_model) => proof_for_empty_tree_with_model(
                tree.clone(),
                tree_height,
                None,
                tree_kind,
                empty_range_model,
            )?,
            None => proof_for_empty_tree_with_model(
                tree.clone(),
                tree_height,
                None,
                tree_kind,
                zeroeth_exclusion_range(tree.clone(), tree_kind)?,
            )?,
        };

        for address in addresses_needing_empty_proof {
            validate_non_inclusion_range(&address, &empty_model)?;
            results.insert(address, (empty_model.clone(), empty_proof.clone()));
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester::persist::indexed_merkle_tree::get_zeroeth_nullifier_exclusion_range;

    const RINGS_NULLIFIER_INIT_ROOT_40: [u8; 32] = [
        29, 142, 113, 166, 1, 179, 232, 222, 187, 186, 155, 85, 123, 131, 105, 199, 244, 4, 174,
        87, 190, 191, 8, 82, 35, 107, 7, 40, 32, 149, 66, 119,
    ];

    fn test_range(value: [u8; 32], next_value: [u8; 32]) -> indexed_trees::Model {
        indexed_trees::Model {
            tree: [7u8; 32].to_vec(),
            leaf_index: 0,
            value: value.to_vec(),
            next_index: 1,
            next_value: next_value.to_vec(),
            seq: Some(0),
        }
    }

    fn test_proof(leaf_index: u64, hash: [u8; 32]) -> MerkleProofWithContext {
        MerkleProofWithContext {
            proof: Vec::new(),
            root: Hash::from([0; 32]),
            leaf_index,
            hash: Hash::from(hash),
            merkle_tree: SerializablePubkey::from([7u8; 32]),
            root_seq: None,
        }
    }

    #[test]
    fn empty_rings_nullifier_proof_matches_init_root() {
        let tree = [7u8; 32].to_vec();
        let empty_range = get_zeroeth_nullifier_exclusion_range(tree.clone());
        let (_range, proof) =
            proof_for_empty_tree_with_model(tree, 41, None, RingsTreeKind::Nullifier, empty_range)
                .expect("empty proof");

        assert_eq!(proof.root.0, RINGS_NULLIFIER_INIT_ROOT_40);
        assert_eq!(proof.root_seq, None);
        assert_eq!(proof.proof.len(), 40);
    }

    #[test]
    fn nullifier_empty_range_uses_rings_sentinel() {
        let tree = [8u8; 32].to_vec();

        assert_eq!(
            zeroeth_exclusion_range(tree.clone(), RingsTreeKind::Nullifier),
            Ok(get_zeroeth_nullifier_exclusion_range(tree))
        );
    }

    #[test]
    fn non_inclusion_range_rejects_present_bounds() {
        let low = [1u8; 32];
        let requested = [2u8; 32];
        let high = [3u8; 32];

        assert!(validate_non_inclusion_range(&requested, &test_range(low, high)).is_ok());

        let high_equals_requested =
            validate_non_inclusion_range(&requested, &test_range(low, requested))
                .expect_err("requested value equal to high bound must be rejected");
        assert!(matches!(
            high_equals_requested,
            PhotonApiError::ValidationError(message)
                if message.contains("already present in the tree")
        ));

        let low_equals_requested =
            validate_non_inclusion_range(&requested, &test_range(requested, high))
                .expect_err("requested value equal to low bound must be rejected");
        assert!(matches!(
            low_equals_requested,
            PhotonApiError::ValidationError(message)
                if message.contains("already present in the tree")
        ));
    }

    #[test]
    fn range_proof_matching_requires_leaf_index_and_hash() {
        let mut range = test_range([1; 32], [3; 32]);
        range.leaf_index = 7;
        let range_hash = Hash::from([4; 32]);

        let wrong_hash = [test_proof(7, [5; 32])];
        let wrong_hash_error = matching_range_proof(&wrong_hash, &range, &range_hash)
            .expect_err("wrong range hash must not match");
        assert!(matches!(
            wrong_hash_error,
            PhotonApiError::UnexpectedError(message)
                if message.contains("Missing indexed-tree proof")
        ));

        let wrong_index = [test_proof(8, [4; 32])];
        let wrong_index_error = matching_range_proof(&wrong_index, &range, &range_hash)
            .expect_err("wrong leaf index must not match");
        assert!(matches!(
            wrong_index_error,
            PhotonApiError::UnexpectedError(message)
                if message.contains("Missing indexed-tree proof")
        ));

        let correct = [test_proof(7, [4; 32])];
        let proof = matching_range_proof(&correct, &range, &range_hash)
            .expect("matching leaf index and hash should be accepted");
        assert_eq!(proof.hash, range_hash);
    }
}
