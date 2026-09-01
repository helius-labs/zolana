use std::collections::{BTreeMap, BTreeSet};

use crate::api::error::PhotonApiError;
use crate::api::root_index_cache::RootIndexCache;
use crate::common::bind_sql_value;
use crate::common::bn254::is_bn254_field_element;
use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::{indexed_trees, rings_outputs};
use crate::ingester::parser::tree_info::TreeInfo;
use crate::ingester::persist::MerkleProofWithContext;
use crate::rpc::RpcClient;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseTransaction, EntityTrait, QueryFilter,
    QueryOrder, Value,
};
use solana_signature::{Signature, SIGNATURE_BYTES};
use zolana_indexer_api::{
    Base64String, ChainPosition, Hash, MerkleContext, MerkleProof, NonInclusionProof,
    RingsOutputContext, RingsOutputSlot, SerializablePubkey, SerializableSignature, PAGE_LIMIT,
};

pub(super) fn validate_tags(tags: &[Hash]) -> Result<(), PhotonApiError> {
    if tags.is_empty() {
        return Err(PhotonApiError::ValidationError(
            "At least one tag must be provided".to_string(),
        ));
    }
    if len_exceeds_page_limit(tags.len()) {
        return Err(PhotonApiError::ValidationError(format!(
            "Too many tags requested {}. Maximum allowed: {}",
            tags.len(),
            PAGE_LIMIT
        )));
    }
    Ok(())
}

pub(super) fn validate_nullifiers(nullifiers: &[Hash]) -> Result<(), PhotonApiError> {
    if nullifiers.is_empty() {
        return Err(PhotonApiError::ValidationError(
            "At least one nullifier must be provided".to_string(),
        ));
    }
    if len_exceeds_page_limit(nullifiers.len()) {
        return Err(PhotonApiError::ValidationError(format!(
            "Too many nullifiers requested {}. Maximum allowed: {}",
            nullifiers.len(),
            PAGE_LIMIT
        )));
    }
    Ok(())
}

pub(super) fn validate_proof_leaves(leaves: &[Hash]) -> Result<(), PhotonApiError> {
    if leaves.is_empty() {
        return Err(PhotonApiError::ValidationError(
            "At least one leaf must be provided".to_string(),
        ));
    }
    if len_exceeds_page_limit(leaves.len()) {
        return Err(PhotonApiError::ValidationError(format!(
            "Too many leaves requested {}. Maximum allowed: {}",
            leaves.len(),
            PAGE_LIMIT
        )));
    }
    if let Some(leaf) = leaves.iter().find(|leaf| !is_bn254_field_element(&leaf.0)) {
        return Err(PhotonApiError::ValidationError(format!(
            "Leaf {} is outside the BN254 scalar field",
            leaf
        )));
    }
    Ok(())
}

pub(super) async fn get_tree_info(
    tx: &DatabaseTransaction,
    tree_account: SerializablePubkey,
) -> Result<TreeInfo, PhotonApiError> {
    TreeInfo::get(tx, &tree_account.to_string())
        .await?
        .ok_or(PhotonApiError::InvalidPubkey {
            field: tree_account.to_string(),
        })
}

pub(super) async fn rings_output_leaf_indices(
    tx: &DatabaseTransaction,
    tree_account: SerializablePubkey,
    leaves: &[Hash],
) -> Result<Vec<u64>, PhotonApiError> {
    let unique_leaves = leaves.iter().map(Hash::to_vec).collect::<BTreeSet<_>>();
    let found_rows = rings_outputs::Entity::find()
        .filter(rings_outputs::Column::OutputTree.eq(tree_account.to_bytes_vec()))
        .filter(
            rings_outputs::Column::UtxoHash
                .is_in(unique_leaves.iter().cloned().collect::<Vec<_>>()),
        )
        .order_by_asc(rings_outputs::Column::LeafIndex)
        .all(tx)
        .await?;
    let mut found_indices_by_leaf = BTreeMap::new();
    for row in found_rows {
        if let Some(existing_leaf_index) =
            found_indices_by_leaf.insert(row.utxo_hash.clone(), row.leaf_index)
        {
            let leaf = hash_from_vec(row.utxo_hash)?;
            return Err(PhotonApiError::ValidationError(format!(
                "Rings output leaf {} is not unique in tree {}; found leaf indices {} and {}",
                leaf, tree_account, existing_leaf_index, row.leaf_index
            )));
        }
    }

    leaves
        .iter()
        .map(|leaf| {
            let leaf_bytes = leaf.to_vec();
            let leaf_index = found_indices_by_leaf.get(&leaf_bytes).ok_or_else(|| {
                PhotonApiError::RecordNotFound(
                    "Some Rings output leaves were not found for the requested tree".to_string(),
                )
            })?;
            u64_from_i64(*leaf_index, "leaf index")
        })
        .collect()
}

pub(super) async fn merkle_proof_from_context(
    proof: MerkleProofWithContext,
    tree_info: &TreeInfo,
    tree_kind: RingsTreeKind,
    expected_leaf: &Hash,
    rpc_client: &RpcClient,
    root_index_cache: &RootIndexCache,
) -> Result<MerkleProof, PhotonApiError> {
    let expected_tree = SerializablePubkey::from(tree_info.tree);
    if proof.merkle_tree != expected_tree {
        return Err(PhotonApiError::RecordNotFound(format!(
            "Proof tree {} did not match requested tree {}",
            proof.merkle_tree, expected_tree
        )));
    }
    if &proof.hash != expected_leaf {
        return Err(PhotonApiError::UnexpectedError(format!(
            "Proof leaf {} did not match requested leaf {}",
            proof.hash, expected_leaf
        )));
    }

    let root_seq = proof.root_seq.unwrap_or(0);
    // The chain's slot for this exact root, not a number photon counted. See
    // `RootIndexCache` for why the two cannot be kept in step by construction.
    let root_index = root_index_cache
        .index_for(rpc_client, tree_info.tree, proof.root.0)
        .await?;

    Ok(MerkleProof {
        leaf: proof.hash,
        merkle_context: MerkleContext {
            tree_type: u16::from(tree_kind),
            tree: SerializablePubkey::from(tree_info.tree),
        },
        path: proof.proof,
        leaf_index: proof.leaf_index,
        root: proof.root,
        root_seq,
        root_index,
    })
}

pub(super) fn non_inclusion_proof_from_context(
    leaf: Hash,
    range: &indexed_trees::Model,
    proof: &MerkleProofWithContext,
    tree_info: &TreeInfo,
    tree_kind: RingsTreeKind,
) -> Result<NonInclusionProof, PhotonApiError> {
    let root_seq = proof.root_seq.unwrap_or(0);
    let root_index = proof
        .root_seq
        .map(|root_seq| root_index(root_seq, tree_kind, tree_info))
        .transpose()
        .map(|root_index| root_index.unwrap_or(0))?;

    Ok(NonInclusionProof {
        leaf,
        merkle_context: MerkleContext {
            tree_type: u16::from(tree_kind),
            tree: SerializablePubkey::from(tree_info.tree),
        },
        path: proof.proof.clone(),
        low_element: hash_from_vec(range.value.clone())?,
        low_element_index: u64_from_i64(range.leaf_index, "low element index")?,
        high_element: hash_from_vec(range.next_value.clone())?,
        high_element_index: u64_from_i64(range.next_index, "high element index")?,
        root: proof.root.clone(),
        root_seq,
        root_index,
    })
}

/// Position of a root within its own tree's history ring.
///
/// Only the nullifier tree reaches here, and its sequence number *is* the
/// chain's: it comes from `BatchAddressAppendEvent`, not from a local counter.
/// The state tree has no such field in its event, so it reads its index from
/// the tree account instead -- see `RootIndexCache`.
///
/// The capacity always comes from `tree_kind`, never from a value that happens
/// to be in scope. The UTXO and nullifier trees share one account but keep
/// separate histories of different sizes (200 and 120), so `root_seq % capacity`
/// gives a different answer per tree, and the program reads that slot of the
/// ring to check the root it was handed. A capacity from the wrong tree yields a
/// valid-looking index pointing at the wrong root, which the program rejects as
/// `InvalidRootIndex` -- surfacing to the client as `StaleNullifierRoot`,
/// indistinguishable from a proof that genuinely expired. That is an expensive
/// error to recognise: we spent an hour attributing exactly this code to prover
/// latency before ruling this path out. Upstream photon shipped that bug by
/// computing both proof kinds' indices from one capacity
/// (helius-labs/photon@7113918); taking the capacity from `tree_kind` makes it
/// unrepresentable here.
///
/// `tree_info` is cross-checked rather than used: it carries the *nullifier*
/// tree's capacity, because both trees live in one account and that is the one
/// `process_rings_tree_account` stores. Where it is comparable it must agree
/// with the constant this binary was built against; a mismatch means the
/// deployed tree is not the tree this code assumes, and guessing is worse than
/// failing.
fn root_index(
    root_seq: u64,
    tree_kind: RingsTreeKind,
    tree_info: &TreeInfo,
) -> Result<u16, PhotonApiError> {
    let capacity = tree_kind.root_history_capacity();
    if matches!(tree_kind, RingsTreeKind::Nullifier) && tree_info.root_history_capacity != capacity
    {
        return Err(PhotonApiError::UnexpectedError(format!(
            "nullifier root history capacity is {} on chain but {} in this build",
            tree_info.root_history_capacity, capacity
        )));
    }

    let root_index = if capacity == 0 {
        0
    } else {
        root_seq % capacity
    };
    root_index.try_into().map_err(|_| {
        PhotonApiError::UnexpectedError(format!("Root index {} does not fit in u16", root_index))
    })
}

pub(super) fn tags_sql(tags: &[Hash], backend: DatabaseBackend, params: &mut Vec<Value>) -> String {
    let unique = tags.iter().map(|tag| tag.to_vec()).collect::<BTreeSet<_>>();
    unique
        .into_iter()
        .map(|tag| bind_sql_value(params, backend, tag))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn int_list_sql(
    values: &[i64],
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> String {
    values
        .iter()
        .map(|value| bind_sql_value(params, backend, *value))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn bind_u64_as_i64(
    params: &mut Vec<Value>,
    backend: DatabaseBackend,
    value: u64,
) -> Result<String, PhotonApiError> {
    let value = i64::try_from(value).map_err(|_| {
        PhotonApiError::ValidationError(format!("Value {} does not fit in i64", value))
    })?;
    Ok(bind_sql_value(params, backend, value))
}

/// Builds the "strictly after this transaction" predicate as a row comparison.
///
/// `alias` must name the table the query's ORDER BY uses. Filtering on one table
/// while sorting by another cannot use an index for both.
///
/// A row comparison rather than the equivalent chain of ORs: Postgres can begin
/// an index scan at `(a, b) > (x, y)` and cannot at
/// `a > x OR (a = x AND b > y)`, where each page costs more than the last.
pub(super) fn since_sql_condition(
    alias: &str,
    since: &ChainPosition,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> Result<String, PhotonApiError> {
    let slot = bind_u64_as_i64(params, backend, since.slot)?;
    let signature = bind_sql_value(params, backend, since.signature.0.as_ref().to_vec());
    Ok(format!(
        "({alias}.slot, {alias}.signature) > ({slot}, {signature})"
    ))
}

/// Rows below the first indexed block were never ingested, so a silent resume
/// from that gap would skip them forever.
pub(super) async fn ensure_since_indexed(
    tx: &DatabaseTransaction,
    since: &ChainPosition,
) -> Result<(), PhotonApiError> {
    let backend = tx.get_database_backend();
    let floor = tx
        .query_one(sea_orm::Statement::from_string(
            backend,
            "SELECT MIN(slot) AS slot FROM blocks".to_owned(),
        ))
        .await?
        .and_then(|row| row.try_get::<Option<i64>>("", "slot").ok())
        .flatten();
    let complete = match floor {
        Some(floor) => since.slot.saturating_add(1) >= u64_from_i64(floor, "slot")?,
        None => false,
    };
    if !complete {
        return Err(PhotonApiError::ValidationError(
            "since precedes the indexed history".to_string(),
        ));
    }
    Ok(())
}

/// The position of one fetched row's transaction.
pub(super) fn chain_position(slot: i64, signature: &[u8]) -> Result<ChainPosition, PhotonApiError> {
    Ok(ChainPosition {
        slot: u64_from_i64(slot, "slot")?,
        signature: signature_from_bytes(signature)?,
    })
}

pub(super) fn signature_from_bytes(bytes: &[u8]) -> Result<SerializableSignature, PhotonApiError> {
    Ok(SerializableSignature(Signature::from(signature_array(
        bytes,
    )?)))
}

pub(super) fn signature_array(bytes: &[u8]) -> Result<[u8; SIGNATURE_BYTES], PhotonApiError> {
    bytes
        .try_into()
        .map_err(|_| PhotonApiError::UnexpectedError("Invalid signature bytes".to_string()))
}

pub(super) fn hash_from_vec(bytes: Vec<u8>) -> Result<Hash, PhotonApiError> {
    Hash::try_from(bytes)
        .map_err(|_| PhotonApiError::UnexpectedError("Invalid 32-byte value".to_string()))
}

fn pubkey_from_vec(bytes: Vec<u8>) -> Result<SerializablePubkey, PhotonApiError> {
    SerializablePubkey::try_from(bytes)
        .map_err(|_| PhotonApiError::UnexpectedError("Invalid public key bytes".to_string()))
}

pub(super) fn u64_from_i64(value: i64, field: &str) -> Result<u64, PhotonApiError> {
    u64::try_from(value).map_err(|_| {
        PhotonApiError::UnexpectedError(format!("Invalid negative {}: {}", field, value))
    })
}

pub(super) fn u16_from_i16(value: i16, field: &str) -> Result<u16, PhotonApiError> {
    u16::try_from(value).map_err(|_| {
        PhotonApiError::UnexpectedError(format!("Invalid negative {}: {}", field, value))
    })
}

fn len_exceeds_page_limit(len: usize) -> bool {
    u64::try_from(len).map_or(true, |len| len > PAGE_LIMIT)
}

fn rings_output_context_from_parts(
    hash: Vec<u8>,
    tree: Vec<u8>,
    leaf_index: i64,
) -> Result<RingsOutputContext, PhotonApiError> {
    Ok(RingsOutputContext {
        hash: hash_from_vec(hash)?,
        tree: pubkey_from_vec(tree)?,
        leaf_index: u64_from_i64(leaf_index, "leaf index")?,
    })
}

pub(super) fn rings_output_slot_from_parts(
    view_tag: Vec<u8>,
    hash: Vec<u8>,
    tree: Vec<u8>,
    leaf_index: i64,
    payload: Vec<u8>,
) -> Result<RingsOutputSlot, PhotonApiError> {
    Ok(RingsOutputSlot {
        view_tag: hash_from_vec(view_tag)?,
        output_context: rings_output_context_from_parts(hash, tree, leaf_index)?,
        payload: Base64String(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_info_with(root_history_capacity: u64) -> TreeInfo {
        TreeInfo {
            tree: Default::default(),
            queue: Default::default(),
            height: 0,
            root_history_capacity,
            input_queue_zkp_batch_size: 0,
        }
    }

    /// The two trees share an account but not a history size, so the same
    /// `root_seq` lands at different ring positions for each. Getting this wrong
    /// hands the program a plausible index pointing at the wrong root, which it
    /// rejects as `InvalidRootIndex` -> `StaleNullifierRoot`, identical to a
    /// proof that genuinely expired. Upstream photon shipped exactly that
    /// (helius-labs/photon@7113918).
    #[test]
    fn each_tree_indexes_its_root_by_its_own_capacity() {
        let nullifier_capacity = RingsTreeKind::Nullifier.root_history_capacity();
        let state_capacity = RingsTreeKind::State.root_history_capacity();
        assert_ne!(
            nullifier_capacity, state_capacity,
            "this test is only meaningful while the capacities differ"
        );

        // Chosen so the two capacities disagree about where it lands.
        let root_seq = state_capacity + 5;
        let info = tree_info_with(nullifier_capacity);

        let nullifier = root_index(root_seq, RingsTreeKind::Nullifier, &info).expect("nullifier");
        let state = root_index(root_seq, RingsTreeKind::State, &info).expect("state");

        assert_eq!(nullifier as u64, root_seq % nullifier_capacity);
        assert_eq!(state as u64, root_seq % state_capacity);
        assert_ne!(
            nullifier, state,
            "a shared capacity would collapse these to one value -- the upstream bug"
        );
    }

    /// A deployed tree that disagrees with the constant this binary was built
    /// against means the assumption is wrong, and a computed index would be
    /// quietly incorrect. Fail instead.
    #[test]
    fn a_tree_whose_capacity_disagrees_with_the_build_is_rejected() {
        let info = tree_info_with(RingsTreeKind::Nullifier.root_history_capacity() + 1);
        let result = root_index(7, RingsTreeKind::Nullifier, &info);
        assert!(
            result.is_err(),
            "a capacity mismatch must fail loudly, not produce an index"
        );
    }

    /// The resume predicate must read from whichever table the query sorts by.
    /// Reading it from `po` is half of what keeps the query on its index; the
    /// ORDER BY is the other half, and the two have to agree.
    #[test]
    fn the_since_predicate_reads_from_the_table_it_is_told_to() {
        let since = ChainPosition {
            slot: 42,
            signature: SerializableSignature(Signature::from([7u8; 64])),
        };
        let mut params = Vec::new();
        let sql = since_sql_condition("po", &since, DatabaseBackend::Postgres, &mut params)
            .expect("condition");

        assert!(
            !sql.contains("pt."),
            "a po-ordered query must not filter on pt: {sql}"
        );
        for column in ["po.slot", "po.signature"] {
            assert!(sql.contains(column), "expected {column} in: {sql}");
        }
    }

    /// The predicate must stay a row comparison: Postgres cannot begin an index
    /// scan at the equivalent OR chain.
    #[test]
    fn the_since_predicate_is_a_row_comparison_so_the_index_can_seek() {
        let since = ChainPosition {
            slot: 42,
            signature: SerializableSignature(Signature::from([7u8; 64])),
        };
        let mut params = Vec::new();
        let sql = since_sql_condition("po", &since, DatabaseBackend::Postgres, &mut params)
            .expect("condition");

        assert!(
            !sql.contains(" OR "),
            "an OR chain cannot be used as an index seek: {sql}"
        );
        assert!(
            sql.starts_with("(po.slot, po.signature) > ("),
            "expected a single row comparison in sort-key order: {sql}"
        );
        assert_eq!(params.len(), 2, "one bind per column in the comparison");
    }

    /// The aliases are not interchangeable.
    #[test]
    fn the_transactions_predicate_still_reads_from_the_transactions_table() {
        let since = ChainPosition {
            slot: 42,
            signature: SerializableSignature(Signature::from([7u8; 64])),
        };
        let mut params = Vec::new();
        let sql = since_sql_condition("pt", &since, DatabaseBackend::Postgres, &mut params)
            .expect("condition");

        assert!(!sql.contains("po."), "unexpected po reference in: {sql}");
        assert!(sql.contains("pt.slot"), "expected pt.slot in: {sql}");
    }
}
