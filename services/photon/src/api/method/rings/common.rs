use std::collections::{BTreeMap, BTreeSet};

use super::types::{
    MerkleContext, MerkleProof, NonInclusionProof, RingsOutputContext, RingsOutputSlot,
};
use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::bn254::is_bn254_field_element;
use crate::common::rings_tree::RingsTreeKind;
use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::hash::Hash;
use crate::common::typedefs::limit::PAGE_LIMIT;
use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
use crate::common::typedefs::serializable_signature::SerializableSignature;
use crate::dao::generated::{indexed_trees, rings_outputs};
use crate::ingester::parser::tree_info::TreeInfo;
use crate::ingester::persist::MerkleProofWithContext;
use bincode::{Decode, Encode};
use sea_orm::{
    ColumnTrait, DatabaseBackend, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, Value,
};
use solana_signature::{Signature, SIGNATURE_BYTES};

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

pub(super) fn merkle_proof_from_context(
    proof: MerkleProofWithContext,
    tree_info: &TreeInfo,
    tree_kind: RingsTreeKind,
    expected_leaf: &Hash,
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

    let (root_seq, root_index) = proof_root_position(&proof, tree_kind)?;

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
        .map(|root_seq| root_index(root_seq, tree_info.root_history_capacity))
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

fn proof_root_position(
    proof: &MerkleProofWithContext,
    tree_kind: RingsTreeKind,
) -> Result<(u64, u16), PhotonApiError> {
    let root_seq = proof.root_seq.unwrap_or(0);
    let root_index = proof
        .root_seq
        .map(|root_seq| root_index(root_seq, tree_kind.root_history_capacity()))
        .transpose()
        .map(|root_index| root_index.unwrap_or(0))?;
    Ok((root_seq, root_index))
}

fn root_index(root_seq: u64, root_history_capacity: u64) -> Result<u16, PhotonApiError> {
    let root_index = if root_history_capacity == 0 {
        0
    } else {
        root_seq % root_history_capacity
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

pub(super) fn tx_cursor_sql_condition(
    slot: u64,
    signature: &[u8],
    event_index: u16,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> Result<String, PhotonApiError> {
    let slot_for_gt = bind_u64_as_i64(params, backend, slot)?;
    let slot_for_signature = bind_u64_as_i64(params, backend, slot)?;
    let signature_for_signature = bind_sql_value(params, backend, signature.to_vec());
    let slot_for_event = bind_u64_as_i64(params, backend, slot)?;
    let signature_for_event = bind_sql_value(params, backend, signature.to_vec());
    let event_index = bind_sql_value(params, backend, i32::from(event_index));

    Ok(format!(
        "pt.slot > {slot_for_gt}
            OR (pt.slot = {slot_for_signature} AND pt.signature > {signature_for_signature})
            OR (pt.slot = {slot_for_event} AND pt.signature = {signature_for_event} AND pt.event_index > {event_index})"
    ))
}

pub(super) fn decode_cursor<T: Decode<()>>(cursor: &Base64String) -> Result<T, PhotonApiError> {
    let config = cursor_bincode_config();
    let (decoded, bytes_read) = bincode::decode_from_slice(&cursor.0, config)
        .map_err(|_| PhotonApiError::ValidationError("Invalid cursor".to_string()))?;

    if bytes_read != cursor.0.len() {
        return Err(PhotonApiError::ValidationError(
            "Invalid cursor: trailing bytes".to_string(),
        ));
    }

    Ok(decoded)
}

pub(super) fn encode_cursor<T: Encode>(cursor: &T) -> Result<Vec<u8>, PhotonApiError> {
    let config = cursor_bincode_config();
    bincode::encode_to_vec(cursor, config)
        .map_err(|_| PhotonApiError::UnexpectedError("Failed to encode cursor".to_string()))
}

fn cursor_bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_big_endian()
        .with_fixed_int_encoding()
}

pub(super) fn next_cursor_from_rows<T>(
    rows: &[T],
    limit: u64,
    cursor_from_row: impl FnOnce(&T) -> Result<Vec<u8>, PhotonApiError>,
) -> Result<Option<Base64String>, PhotonApiError> {
    if u64_from_usize(rows.len(), "row count")? < limit {
        return Ok(None);
    }

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

fn u64_from_usize(value: usize, field: &str) -> Result<u64, PhotonApiError> {
    u64::try_from(value).map_err(|_| {
        PhotonApiError::UnexpectedError(format!("{} {} does not fit in u64", field, value))
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
