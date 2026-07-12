use super::common::{
    bind_u64_as_i64, cursor_sort_key, decode_cursor, encode_cursor, next_cursor_from_rows,
    rings_output_slot_from_parts, signature_from_bytes, tags_sql, tx_cursor_sql_condition,
    u16_from_i16, u64_from_i64, validate_tags,
};
use super::types::{EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetRingsByTagsRequest};
use crate::api::error::PhotonApiError;
use crate::common::typedefs::bs64_string::Base64String;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use bincode::{Decode, Encode};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, FromQueryResult,
    Statement, TransactionTrait, Value,
};
use solana_signature::SIGNATURE_BYTES;

#[derive(FromQueryResult, Debug)]
struct EncryptedUtxoRow {
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
    output_index: i16,
    view_tag: Vec<u8>,
    output_tree: Vec<u8>,
    leaf_index: i64,
    utxo_hash: Vec<u8>,
    tx_viewing_pk: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub(super) struct EncryptedUtxoCursor {
    pub(super) slot: u64,
    pub(super) signature: [u8; SIGNATURE_BYTES],
    pub(super) event_index: u16,
    pub(super) output_index: u16,
}

pub async fn get_encrypted_utxos_by_tags(
    conn: &DatabaseConnection,
    request: GetRingsByTagsRequest,
) -> Result<GetEncryptedUtxosByTagsResponse, PhotonApiError> {
    let limit = request.limit.unwrap_or_default().value();
    validate_tags(&request.tags)?;
    let cursor = request
        .cursor
        .as_ref()
        .map(decode_cursor::<EncryptedUtxoCursor>)
        .transpose()?;

    let context = Context::extract(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let rows = fetch_encrypted_utxo_rows(&tx, &request.tags, cursor.as_ref(), limit).await?;
    let next_cursor = next_cursor_from_rows(&rows, limit, encrypted_utxo_cursor_from_row)?;

    let matches = rows
        .into_iter()
        .map(|row| {
            Ok(EncryptedUtxoMatch {
                slot: u64_from_i64(row.slot, "slot")?,
                tx_signature: signature_from_bytes(&row.signature)?,
                output_slot: rings_output_slot_from_parts(
                    row.view_tag,
                    row.utxo_hash,
                    row.output_tree,
                    row.leaf_index,
                    row.payload,
                )?,
                tx_viewing_pk: row.tx_viewing_pk.map(Base64String),
                salt: row.salt.map(Base64String),
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;

    tx.commit().await?;

    Ok(GetEncryptedUtxosByTagsResponse {
        context,
        matches,
        next_cursor,
    })
}

async fn fetch_encrypted_utxo_rows(
    tx: &DatabaseTransaction,
    tags: &[Hash],
    cursor: Option<&EncryptedUtxoCursor>,
    limit: u64,
) -> Result<Vec<EncryptedUtxoRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let tag_filter = tags_sql(tags, backend, &mut params);
    let cursor_filter = cursor
        .map(|cursor| encrypted_utxo_cursor_sql(cursor, backend, &mut params))
        .transpose()?
        .unwrap_or_default();
    let limit = bind_u64_as_i64(&mut params, backend, limit)?;

    let sql = format!(
        "SELECT
            pt.slot AS slot,
            pt.signature AS signature,
            pt.event_index AS event_index,
            po.output_index AS output_index,
            po.view_tag AS view_tag,
            po.output_tree AS output_tree,
            po.leaf_index AS leaf_index,
            po.utxo_hash AS utxo_hash,
            pt.tx_viewing_pk AS tx_viewing_pk,
            pt.salt AS salt,
            pop.payload AS payload
         FROM rings_outputs po
         JOIN rings_transactions pt ON pt.rings_tx_id = po.rings_tx_id
         JOIN rings_output_payloads pop ON pop.output_id = po.output_id
         WHERE po.view_tag IN ({tag_filter})
         {cursor_filter}
         ORDER BY pt.slot ASC, pt.signature ASC, pt.event_index ASC, po.output_index ASC
         LIMIT {limit}"
    );

    tx.query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| EncryptedUtxoRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn encrypted_utxo_cursor_sql(
    cursor: &EncryptedUtxoCursor,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> Result<String, PhotonApiError> {
    let signature = cursor.signature.to_vec();
    let tx_cursor_condition =
        tx_cursor_sql_condition(cursor.slot, &signature, cursor.event_index, backend, params)?;
    let slot = bind_u64_as_i64(params, backend, cursor.slot)?;
    let signature = crate::common::bind_sql_value(params, backend, signature);
    let event_index = crate::common::bind_sql_value(params, backend, i32::from(cursor.event_index));
    let output_index =
        crate::common::bind_sql_value(params, backend, i32::from(cursor.output_index));
    Ok(format!(
        "AND (
            {tx_cursor_condition}
            OR (
                pt.slot = {slot}
                AND pt.signature = {signature}
                AND pt.event_index = {event_index}
                AND po.output_index > {output_index}
            )
        )"
    ))
}

fn encrypted_utxo_cursor_from_row(row: &EncryptedUtxoRow) -> Result<Vec<u8>, PhotonApiError> {
    let (slot, signature, event_index) =
        cursor_sort_key(row.slot, &row.signature, row.event_index)?;
    let cursor = EncryptedUtxoCursor {
        slot,
        signature,
        event_index,
        output_index: u16_from_i16(row.output_index, "output index")?,
    };
    encode_cursor(&cursor)
}
