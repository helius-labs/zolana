use solana_address::Address;
use zolana_api::{
    Base64String, GetRingsByTagsRequest, Hash as ApiHash, Limit, RingsOutputSlot as ApiOutputSlot,
    SerializablePubkey,
};
use zolana_keypair::{constants::P256_PUBKEY_LEN, P256Pubkey};

use crate::{
    error::ClientError,
    rpc::{
        Context, EncryptedUtxoMatch, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, IndexedShieldedTransaction, MerkleContext,
        MerkleProof, NonInclusionProof, OutputContext, OutputSlot, RingHistoryOptions,
        ShieldedTransaction,
    },
};

pub(super) fn ring_history_request(
    options: RingHistoryOptions,
) -> Result<GetRingsByTagsRequest, ClientError> {
    let limit = options
        .limit
        .map(|value| Limit::new(u64::from(value)).map_err(|error| ClientError::Rpc(error.into())))
        .transpose()?;
    Ok(GetRingsByTagsRequest {
        tags: Vec::new(),
        cursor: encode_cursor(options.cursor),
        limit,
        ring_program_id: Some(SerializablePubkey(options.ring_program_id)),
    })
}

pub(super) fn convert_context(context: zolana_api::Context) -> Context {
    Context {
        block_time: context.block_time,
        slot: context.slot,
    }
}

pub(super) fn convert_encrypted_utxo_match(
    index: usize,
    item: zolana_api::EncryptedUtxoMatch,
) -> Result<EncryptedUtxoMatch, ClientError> {
    Ok(EncryptedUtxoMatch {
        slot: item.slot,
        tx_signature: item.tx_signature.0,
        output_slot: convert_output_slot(item.output_slot),
        tx_viewing_pk: decode_optional_p256(
            item.tx_viewing_pk,
            &format!("matches[{index}].txViewingPk"),
        )?,
        salt: decode_optional_salt(item.salt, &format!("matches[{index}].salt"))?,
    })
}

pub(super) fn convert_shielded_transactions_response(
    response: zolana_api::GetShieldedTransactionsByTagsResponse,
) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
    Ok(GetShieldedTransactionsByTagsResponse {
        context: convert_context(response.context),
        output_tree_id: response.output_tree_id,
        transactions: response
            .transactions
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                convert_shielded_transaction(&format!("transactions[{index}]"), item)
            })
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor: response.next_cursor.map(Into::into),
        scanned_through: response.scanned_through.map(Into::into),
    })
}

pub(super) fn convert_shielded_transactions_by_signature_response(
    response: zolana_api::GetShieldedTransactionsBySignatureResponse,
) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
    Ok(GetShieldedTransactionsBySignatureResponse {
        context: convert_context(response.context),
        output_tree_id: response.output_tree_id,
        transactions: response
            .transactions
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                Ok(IndexedShieldedTransaction {
                    event_index: item.event_index,
                    transaction: convert_shielded_transaction(
                        &format!("transactions[{index}].transaction"),
                        item.transaction,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?,
    })
}

pub fn decode_shielded_transaction(
    item: zolana_api::ShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    convert_shielded_transaction("transaction", item)
}

pub(super) fn convert_shielded_transaction(
    path: &str,
    item: zolana_api::ShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    Ok(ShieldedTransaction {
        slot: item.slot,
        tx_signature: item.tx_signature.0,
        event_index: item.event_index,
        tx_viewing_pk: decode_optional_p256(item.tx_viewing_pk, &format!("{path}.txViewingPk"))?,
        salt: decode_optional_salt(item.salt, &format!("{path}.salt"))?,
        output_slots: item
            .output_slots
            .into_iter()
            .map(convert_output_slot)
            .collect(),
        messages: item
            .messages
            .into_iter()
            .map(|message| zolana_event::MessageData {
                view_tag: message.view_tag.into(),
                data: message.payload.into(),
            })
            .collect(),
        nullifiers: item.nullifiers.into_iter().map(Into::into).collect(),
        proofless: item.proofless,
        ring_config: item.ring_config.map(|key| key.0),
        ring_program_id: item.ring_program_id.map(|key| key.0),
    })
}

fn convert_output_slot(slot: ApiOutputSlot) -> OutputSlot {
    OutputSlot {
        view_tag: slot.view_tag.into(),
        output_context: convert_output_context(slot.output_context),
        payload: slot.payload.into(),
    }
}

/// The wire still carries the deprecated `tree` account beside `tree_id`. Only
/// the id is read: it is what the commitment folds in, so it is checked by
/// recomputation, while the account is a derivation of it.
fn convert_output_context(context: zolana_api::RingsOutputContext) -> OutputContext {
    OutputContext {
        hash: context.hash.into(),
        tree_id: context.tree_id,
        leaf_index: context.leaf_index,
    }
}

pub(super) fn convert_merkle_proof(proof: zolana_api::MerkleProof) -> MerkleProof {
    MerkleProof {
        leaf: proof.leaf.into(),
        merkle_context: convert_merkle_context(proof.merkle_context),
        path: proof.path.into_iter().map(Into::into).collect(),
        leaf_index: proof.leaf_index,
        root: proof.root.into(),
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    }
}

pub(super) fn convert_non_inclusion_proof(
    proof: zolana_api::NonInclusionProof,
) -> NonInclusionProof {
    NonInclusionProof {
        leaf: proof.leaf.into(),
        merkle_context: convert_merkle_context(proof.merkle_context),
        path: proof.path.into_iter().map(Into::into).collect(),
        low_element: proof.low_element.into(),
        low_element_index: proof.low_element_index,
        high_element: proof.high_element.into(),
        high_element_index: proof.high_element_index,
        root: proof.root.into(),
        root_seq: proof.root_seq,
        root_index: proof.root_index,
    }
}

fn convert_merkle_context(context: zolana_api::MerkleContext) -> MerkleContext {
    MerkleContext {
        tree_type: context.tree_type,
        tree: Address::new_from_array(context.tree.0.to_bytes()),
    }
}

pub(super) fn encode_hash(hash: [u8; 32]) -> ApiHash {
    ApiHash::from(hash)
}

pub(super) fn encode_pubkey(address: Address) -> SerializablePubkey {
    SerializablePubkey::from(address.to_bytes())
}

pub(super) fn encode_cursor(cursor: Option<Vec<u8>>) -> Option<Base64String> {
    cursor.map(Base64String::from)
}

fn decode_optional_p256(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<P256Pubkey>, ClientError> {
    value
        .map(|value| {
            let bytes = fixed_bytes(value.0, P256_PUBKEY_LEN, field)?;
            P256Pubkey::from_bytes(bytes).map_err(|error| decode_error(field, error))
        })
        .transpose()
}

fn decode_optional_salt(
    value: Option<Base64String>,
    field: &str,
) -> Result<Option<[u8; 16]>, ClientError> {
    value
        .map(|value| fixed_bytes(value.0, 16, field))
        .transpose()
}

fn fixed_bytes<const N: usize>(
    bytes: Vec<u8>,
    expected_len: usize,
    field: &str,
) -> Result<[u8; N], ClientError> {
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_| {
        ClientError::Rpc(format!(
            "invalid indexer field {field}: expected {expected_len} bytes, got {actual_len}"
        ))
    })
}

fn decode_error(field: &str, error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("invalid indexer field {field}: {error}"))
}
