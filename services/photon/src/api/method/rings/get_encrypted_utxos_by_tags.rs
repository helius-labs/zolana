use super::common::{
    bind_u64_as_i64, cursor_sort_key, decode_cursor, encode_cursor, over_fetch, page_cursor,
    rings_output_slot_from_parts, signature_from_bytes, tags_sql, tx_cursor_sql_condition,
    u16_from_i16, u64_from_i64, validate_tags, CursorKind,
};
use crate::api::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use bincode::{Decode, Encode};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, FromQueryResult,
    Statement, TransactionTrait, Value,
};
use solana_signature::SIGNATURE_BYTES;
use zolana_indexer_api::{
    Base64String, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetRingsByTagsRequest, Hash,
};

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
        .map(|c| decode_cursor::<EncryptedUtxoCursor>(CursorKind::EncryptedUtxos, c))
        .transpose()?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    // One row past the limit; see `page_cursor`.
    let mut rows =
        fetch_encrypted_utxo_rows(&tx, &request.tags, cursor.as_ref(), over_fetch(limit)).await?;
    let next_cursor = page_cursor(&mut rows, limit, encrypted_utxo_cursor_from_row)?;
    // The caller's watermark, now that `next_cursor` only reports paging. Only
    // meaningful on a page the limit did not truncate.
    let scanned_through = if next_cursor.is_some() {
        None
    } else {
        output_scan_position(&tx).await?
    };

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
        scanned_through,
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
         ORDER BY po.slot ASC, po.signature ASC, po.event_index ASC, po.output_index ASC
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
    // "po", matching this query's ORDER BY, so
    // idx_rings_outputs_view_tag_order serves the filter and the sort together.
    let condition = tx_cursor_sql_condition(
        "po",
        cursor.slot,
        &signature,
        cursor.event_index,
        &[("output_index", i32::from(cursor.output_index))],
        backend,
        params,
    )?;
    Ok(format!("AND {condition}"))
}

/// The last position in the output stream, as a cursor.
///
/// The transactions stream has its own version of this; outputs need a separate
/// one because their cursor carries `output_index`, so the tail of
/// `rings_transactions` does not describe where an output scan reached.
///
/// Read inside the caller's transaction, so it describes the snapshot the scan
/// saw. Sound while positions are only appended, which is the same assumption
/// the per-tag cursors already make.
async fn output_scan_position(
    tx: &DatabaseTransaction,
) -> Result<Option<Base64String>, PhotonApiError> {
    let backend = tx.get_database_backend();
    // Pinning the slot first keeps this an index lookup rather than a sort of
    // the whole table, as in `scan_position`.
    let sql = "SELECT
            po.slot AS slot,
            po.signature AS signature,
            po.event_index AS event_index,
            po.output_index AS output_index
         FROM rings_outputs po
         WHERE po.slot = (SELECT MAX(slot) FROM rings_outputs)
         ORDER BY po.signature DESC, po.event_index DESC, po.output_index DESC
         LIMIT 1"
        .to_string();

    let Some(row) = tx
        .query_all(Statement::from_sql_and_values(backend, sql, Vec::new()))
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let row = EncryptedUtxoScanRow::from_query_result(&row, "")?;
    let (slot, signature, event_index) =
        cursor_sort_key(row.slot, &row.signature, row.event_index)?;
    let cursor = EncryptedUtxoCursor {
        slot,
        signature,
        event_index,
        output_index: u16_from_i16(row.output_index, "output index")?,
    };
    Ok(Some(Base64String(encode_cursor(
        CursorKind::EncryptedUtxos,
        &cursor,
    )?)))
}

#[derive(FromQueryResult, Debug)]
struct EncryptedUtxoScanRow {
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
    output_index: i16,
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
    encode_cursor(CursorKind::EncryptedUtxos, &cursor)
}
