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
use bincode::{Decode, Encode};
use sea_orm::{
    ColumnTrait, DatabaseBackend, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, Value,
};
use solana_signature::{Signature, SIGNATURE_BYTES};
use zolana_indexer_api::{
    Base64String, Hash, MerkleContext, MerkleProof, NonInclusionProof, RingsOutputContext,
    RingsOutputSlot, SerializablePubkey, SerializableSignature, PAGE_LIMIT,
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

    let root_seq = proof.root_seq.ok_or_else(|| {
        PhotonApiError::UnexpectedError(format!(
            "State proof root for tree {} is missing its completed slot",
            tree_info.tree
        ))
    })?;
    // `root_seq` is completed-slot metadata, not the position in the dense
    // history ring. Slots without updates do not advance the ring, so resolve
    // the proof's exact root against the authoritative account history.
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
/// Only the nullifier tree reaches here. Its `root_seq` is the chain sequence
/// from `NullifierTreeUpdateEvent`, and its history advances once per applied
/// ZKP batch. State `root_seq` is a completed Solana slot and cannot locate a
/// root in the dense state history; state indices come from `RootIndexCache`.
///
/// The capacity comes from `tree_kind`, never from a value that happens to be
/// in scope. The UTXO and nullifier trees share one account but keep separate
/// histories of different sizes. Using the state capacity here would produce a
/// plausible nullifier index that the program rejects as `InvalidRootIndex`.
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

/// Builds the "strictly after this position" predicate as a row comparison.
///
/// `alias` must name the table the query's ORDER BY uses. Filtering on one table
/// while sorting by another cannot use an index for both.
///
/// `trailing` appends further columns, for callers whose sort key extends past
/// the transaction (the UTXO endpoint adds `output_index`).
///
/// A row comparison rather than the equivalent chain of ORs: Postgres can begin
/// an index scan at `(a, b) > (x, y)` and cannot at
/// `a > x OR (a = x AND b > y)`, where each page costs more than the last.
pub(super) fn tx_cursor_sql_condition(
    alias: &str,
    slot: u64,
    signature: &[u8],
    event_index: u16,
    trailing: &[(&str, i32)],
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> Result<String, PhotonApiError> {
    let slot = bind_u64_as_i64(params, backend, slot)?;
    let signature = bind_sql_value(params, backend, signature.to_vec());
    let event_index_value = bind_sql_value(params, backend, i32::from(event_index));

    let mut columns = vec![
        format!("{alias}.slot"),
        format!("{alias}.signature"),
        format!("{alias}.event_index"),
    ];
    let mut values = vec![slot, signature, event_index_value];
    for (column, value) in trailing {
        columns.push(format!("{alias}.{column}"));
        values.push(bind_sql_value(params, backend, *value));
    }

    Ok(format!(
        "({}) > ({})",
        columns.join(", "),
        values.join(", ")
    ))
}

/// Which stream minted a cursor, as its first byte.
///
/// Tags and nullifiers share `ShieldedTxCursor` byte for byte, so one resumes
/// cleanly in the other and skips every match before it. Encrypted-utxo cursors
/// differ only by length, which is accident, not design.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum CursorKind {
    EncryptedUtxos = 1,
    ShieldedTxByTags = 2,
    ShieldedTxByNullifiers = 3,
}

pub(super) fn decode_cursor<T: Decode<()>>(
    kind: CursorKind,
    cursor: &Base64String,
) -> Result<T, PhotonApiError> {
    let (tag, body) = cursor
        .0
        .split_first()
        .ok_or_else(|| PhotonApiError::ValidationError("Invalid cursor".to_string()))?;
    if *tag != kind as u8 {
        return Err(PhotonApiError::ValidationError(
            "Invalid cursor: it belongs to a different query".to_string(),
        ));
    }

    let config = cursor_bincode_config();
    let (decoded, bytes_read) = bincode::decode_from_slice(body, config)
        .map_err(|_| PhotonApiError::ValidationError("Invalid cursor".to_string()))?;

    if bytes_read != body.len() {
        return Err(PhotonApiError::ValidationError(
            "Invalid cursor: trailing bytes".to_string(),
        ));
    }

    Ok(decoded)
}

pub(super) fn encode_cursor<T: Encode>(
    kind: CursorKind,
    cursor: &T,
) -> Result<Vec<u8>, PhotonApiError> {
    let config = cursor_bincode_config();
    let body = bincode::encode_to_vec(cursor, config)
        .map_err(|_| PhotonApiError::UnexpectedError("Failed to encode cursor".to_string()))?;
    let mut encoded = Vec::with_capacity(1 + body.len());
    encoded.push(kind as u8);
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

fn cursor_bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_big_endian()
        .with_fixed_int_encoding()
}

/// Position of the last row returned, or `None` when there were none.
pub(super) fn next_cursor_from_rows<T>(
    rows: &[T],
    cursor_from_row: impl FnOnce(&T) -> Result<Vec<u8>, PhotonApiError>,
) -> Result<Option<Base64String>, PhotonApiError> {
    rows.last()
        .map(cursor_from_row)
        .transpose()
        .map(|cursor| cursor.map(Base64String))
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

pub(super) fn cursor_sort_key(
    slot: i64,
    signature: &[u8],
    event_index: i16,
) -> Result<(u64, [u8; SIGNATURE_BYTES], u16), PhotonApiError> {
    Ok((
        u64_from_i64(slot, "slot")?,
        signature_array(signature)?,
        u16_from_i16(event_index, "event index")?,
    ))
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
    use crate::monitor::tree_metadata_sync::rings_utxo_root_history;
    use solana_account::Account;
    use zolana_interface::{
        pda,
        state::{
            default_tree_fees, discriminator::TREE_ACCOUNT_DISCRIMINATOR, nullifier_tree_params,
            tree_account_size,
        },
    };
    use zolana_tree::TreeAccount;

    type SerializedRootHistory = Vec<(u16, [u8; 32])>;
    type UpdateRoots = Vec<[u8; 32]>;

    fn cursor_of(row: &u64) -> Result<Vec<u8>, PhotonApiError> {
        Ok(row.to_be_bytes().to_vec())
    }

    /// The cursor doubles as the client's sync watermark, so a short page has to
    /// carry one. Returning `None` there -- correct for "is there another page?"
    /// -- made every wallet whose history fits in one page refetch all of it on
    /// every sync.
    #[test]
    fn a_short_page_still_reports_its_last_row() {
        let rows = vec![10u64, 50];
        let cursor = next_cursor_from_rows(&rows, cursor_of).expect("cursor");
        assert_eq!(
            cursor.map(|c| c.0),
            Some(50u64.to_be_bytes().to_vec()),
            "a page below the limit still reports where it got to"
        );
    }

    /// How the loop terminates now: the client asks once more and gets nothing.
    #[test]
    fn an_empty_page_ends_the_stream() {
        let rows: Vec<u64> = Vec::new();
        let cursor = next_cursor_from_rows(&rows, cursor_of).expect("cursor");
        assert!(cursor.is_none(), "no rows means no position to resume from");
    }

    fn tree_info_with(root_history_capacity: u64) -> TreeInfo {
        TreeInfo {
            tree: Default::default(),
            queue: Default::default(),
            height: 0,
            root_history_capacity,
            input_queue_zkp_batch_size: 0,
        }
    }

    /// Build the same serialized account bytes the monitor reads in production,
    /// then parse its root history back through Photon's account boundary.
    fn serialized_state_history(
        tree_pubkey: solana_pubkey::Pubkey,
        slots: &[u64],
    ) -> (SerializedRootHistory, UpdateRoots) {
        let mut data = vec![0u8; tree_account_size()];
        let mut update_roots = Vec::with_capacity(slots.len());
        {
            let params = nullifier_tree_params();
            let fees = default_tree_fees(params.input_queue_zkp_batch_size)
                .expect("default fixture tree fees");
            let mut tree = TreeAccount::init(
                &mut data,
                TREE_ACCOUNT_DISCRIMINATOR,
                u8::try_from(RingsTreeKind::State.tree_height()).expect("state height fits in u8"),
                tree_pubkey.to_bytes(),
                0,
                params,
                fees,
            )
            .expect("initialize serialized Rings tree");

            for (offset, slot) in slots.iter().copied().enumerate() {
                let mut leaf = [0u8; 32];
                leaf[0] = u8::try_from(offset + 1).expect("small fixture leaf");
                tree.utxo_tree()
                    .append(leaf, slot)
                    .expect("append fixture leaf");
                update_roots.push(tree.utxo_tree().root());
            }
        }

        let account = Account {
            lamports: 1,
            data,
            owner: pda::shielded_pool_program_id(),
            executable: false,
            rent_epoch: 0,
        };
        let history = rings_utxo_root_history(tree_pubkey, &account)
            .expect("Photon parses serialized Rings tree history");
        (history, update_roots)
    }

    async fn state_proof_from_cached_history(
        tree: solana_pubkey::Pubkey,
        history: Vec<(u16, [u8; 32])>,
        root: [u8; 32],
        completed_slot: u64,
    ) -> MerkleProof {
        let leaf = Hash::from([9u8; 32]);
        let proof = MerkleProofWithContext {
            proof: Vec::new(),
            root: Hash::from(root),
            leaf_index: 0,
            hash: leaf.clone(),
            merkle_tree: SerializablePubkey::from(tree),
            root_seq: Some(completed_slot),
        };
        let mut info = tree_info_with(RingsTreeKind::Nullifier.root_history_capacity());
        info.tree = tree;
        let cache = RootIndexCache::with_roots(tree, history);
        // If the proof path attempts an account fetch instead of using the
        // parsed history, this deliberately unreachable endpoint fails it.
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());

        merkle_proof_from_context(proof, &info, RingsTreeKind::State, &leaf, &rpc, &cache)
            .await
            .expect("state proof resolves from parsed on-chain history")
    }

    #[tokio::test]
    async fn state_proof_indices_follow_dense_serialized_history_not_slot_modulo() {
        let continuous_tree = solana_pubkey::Pubkey::new_unique();
        let continuous_slots = [1_000, 1_001, 1_002];
        let (continuous_history, continuous_roots) =
            serialized_state_history(continuous_tree, &continuous_slots);
        assert_eq!(
            continuous_history
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "initial root plus three updating slots form four dense entries"
        );

        for (offset, root) in continuous_roots.iter().enumerate() {
            let expected_index = u16::try_from(offset + 1).expect("fixture index fits");
            assert!(
                continuous_history.contains(&(expected_index, *root)),
                "each updating slot advances exactly one dense history entry"
            );
        }
        let continuous_second_root = *continuous_roots
            .get(1)
            .expect("continuous fixture has a second update root");
        let continuous_proof = state_proof_from_cached_history(
            continuous_tree,
            continuous_history,
            continuous_second_root,
            continuous_slots[1],
        )
        .await;
        assert_eq!(continuous_proof.root_seq, continuous_slots[1]);
        assert_eq!(continuous_proof.root_index, 2);
        assert_ne!(
            u64::from(continuous_proof.root_index),
            continuous_proof.root_seq % RingsTreeKind::State.root_history_capacity(),
            "state history index must not be derived from completed slot"
        );

        let gap_tree = solana_pubkey::Pubkey::new_unique();
        // The second slot is far from the first, and its second update must
        // overwrite its first intermediate root at the same dense entry.
        let gap_slots = [2_000, 2_507, 2_507];
        let (gap_history, gap_roots) = serialized_state_history(gap_tree, &gap_slots);
        assert_eq!(
            gap_history
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2],
            "skipped slots add nothing and same-slot updates share one entry"
        );
        let gap_first_root = *gap_roots
            .first()
            .expect("gap fixture has a first update root");
        let gap_intermediate_root = *gap_roots
            .get(1)
            .expect("gap fixture has a same-slot intermediate root");
        let gap_final_root = *gap_roots.get(2).expect("gap fixture has a final root");
        assert!(gap_history.contains(&(1, gap_first_root)));
        assert!(
            !gap_history
                .iter()
                .any(|(_, root)| root == &gap_intermediate_root),
            "same-slot intermediate root must be overwritten"
        );
        assert!(gap_history.contains(&(2, gap_final_root)));

        let gap_proof =
            state_proof_from_cached_history(gap_tree, gap_history, gap_final_root, gap_slots[2])
                .await;
        assert_eq!(gap_proof.root_seq, gap_slots[2]);
        assert_eq!(gap_proof.root_index, 2);
        assert_ne!(
            u64::from(gap_proof.root_index),
            gap_proof.root_seq % RingsTreeKind::State.root_history_capacity(),
            "skipped Solana slots must not create root-history entries"
        );
    }

    /// Nullifier roots use the nullifier history capacity, never the state
    /// history capacity. Getting this wrong hands the program a plausible index
    /// pointing at the wrong root, which it rejects as `InvalidRootIndex` ->
    /// `StaleNullifierRoot`, identical to a proof that genuinely expired.
    #[test]
    fn nullifier_root_uses_the_nullifier_history_capacity() {
        let nullifier_capacity = RingsTreeKind::Nullifier.root_history_capacity();
        let root_seq = nullifier_capacity + 17;
        let info = tree_info_with(nullifier_capacity);

        let nullifier = root_index(root_seq, RingsTreeKind::Nullifier, &info).expect("nullifier");

        assert_eq!(nullifier as u64, root_seq % nullifier_capacity);
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

    #[tokio::test]
    async fn a_state_proof_without_a_completed_slot_is_rejected() {
        let tree = solana_pubkey::Pubkey::new_unique();
        let mut info = tree_info_with(RingsTreeKind::Nullifier.root_history_capacity());
        info.tree = tree;
        let leaf = Hash::from([2u8; 32]);
        let proof = MerkleProofWithContext {
            proof: Vec::new(),
            root: Hash::from([3u8; 32]),
            leaf_index: 0,
            hash: leaf.clone(),
            merkle_tree: SerializablePubkey::from(tree),
            root_seq: None,
        };
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        let cache = RootIndexCache::new();

        let error =
            merkle_proof_from_context(proof, &info, RingsTreeKind::State, &leaf, &rpc, &cache)
                .await
                .unwrap_err();

        assert!(matches!(
            error,
            PhotonApiError::UnexpectedError(message)
                if message.contains("missing its completed slot")
        ));
    }

    /// The cursor must read from whichever table the query sorts by. Reading it
    /// from `po` is half of what keeps the query on its index; the ORDER BY is
    /// the other half, and the two have to agree.
    #[test]
    fn the_cursor_predicate_reads_from_the_table_it_is_told_to() {
        let mut params = Vec::new();
        let sql = tx_cursor_sql_condition(
            "po",
            42,
            &[7u8; 64],
            3,
            &[],
            DatabaseBackend::Postgres,
            &mut params,
        )
        .expect("condition");

        assert!(
            !sql.contains("pt."),
            "a po-ordered query must not filter on pt: {sql}"
        );
        for column in ["po.slot", "po.signature", "po.event_index"] {
            assert!(sql.contains(column), "expected {column} in: {sql}");
        }
    }

    /// The predicate must stay a row comparison: Postgres cannot begin an index
    /// scan at the equivalent OR chain.
    #[test]
    fn the_cursor_predicate_is_a_row_comparison_so_the_index_can_seek() {
        let mut params = Vec::new();
        let sql = tx_cursor_sql_condition(
            "po",
            42,
            &[7u8; 64],
            3,
            &[("output_index", 5)],
            DatabaseBackend::Postgres,
            &mut params,
        )
        .expect("condition");

        assert!(
            !sql.contains(" OR "),
            "an OR chain cannot be used as an index seek: {sql}"
        );
        assert!(
            sql.starts_with("(po.slot, po.signature, po.event_index, po.output_index) > ("),
            "expected a single row comparison in sort-key order: {sql}"
        );
        assert_eq!(params.len(), 4, "one bind per column in the comparison");
    }

    /// The aliases are not interchangeable.
    #[test]
    fn the_transactions_cursor_still_reads_from_the_transactions_table() {
        let mut params = Vec::new();
        let sql = tx_cursor_sql_condition(
            "pt",
            42,
            &[7u8; 64],
            3,
            &[],
            DatabaseBackend::Postgres,
            &mut params,
        )
        .expect("condition");

        assert!(!sql.contains("po."), "unexpected po reference in: {sql}");
        assert!(sql.contains("pt.slot"), "expected pt.slot in: {sql}");
    }
}
