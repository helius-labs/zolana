use std::collections::BTreeMap;

use super::common::{
    bind_u64_as_i64, cursor_sort_key, decode_cursor, encode_cursor, hash_from_vec, int_list_sql,
    next_cursor_from_rows, rings_output_slot_from_parts, signature_from_bytes, tags_sql,
    tx_cursor_sql_condition, u64_from_i64, validate_tags,
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
    Base64String, GetRingsByTagsRequest, GetShieldedTransactionsByTagsResponse, Hash,
    RingsOutputSlot, ShieldedTransaction,
};

#[derive(FromQueryResult, Debug)]
struct MatchedRingsTxRow {
    rings_tx_id: i64,
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
    tx_viewing_pk: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    proofless: bool,
}

#[derive(FromQueryResult, Debug)]
struct RingsOutputRow {
    rings_tx_id: i64,
    output_index: i16,
    view_tag: Vec<u8>,
    output_tree: Vec<u8>,
    leaf_index: i64,
    utxo_hash: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(FromQueryResult, Debug)]
struct RingsNullifierRow {
    rings_tx_id: i64,
    input_index: i16,
    nullifier: Vec<u8>,
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub(super) struct ShieldedTxCursor {
    pub(super) slot: u64,
    pub(super) signature: [u8; SIGNATURE_BYTES],
    pub(super) event_index: u16,
}

pub async fn get_shielded_transactions_by_tags(
    conn: &DatabaseConnection,
    request: GetRingsByTagsRequest,
) -> Result<GetShieldedTransactionsByTagsResponse, PhotonApiError> {
    let limit = request.limit.unwrap_or_default().value();
    validate_tags(&request.tags)?;
    let cursor = request
        .cursor
        .as_ref()
        .map(decode_cursor::<ShieldedTxCursor>)
        .transpose()?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let matched_txs =
        fetch_matching_rings_transactions(&tx, &request.tags, cursor.as_ref(), limit).await?;
    let next_cursor = next_cursor_from_rows(&matched_txs, limit, shielded_tx_cursor_from_row)?;

    let rings_tx_ids = matched_txs
        .iter()
        .map(|row| row.rings_tx_id)
        .collect::<Vec<_>>();

    let output_rows = fetch_rings_outputs(&tx, &rings_tx_ids).await?;
    let nullifier_rows = fetch_rings_nullifiers(&tx, &rings_tx_ids).await?;

    let mut outputs_by_tx: BTreeMap<i64, Vec<RingsOutputSlot>> = BTreeMap::new();
    for row in output_rows {
        outputs_by_tx
            .entry(row.rings_tx_id)
            .or_default()
            .push(rings_output_slot_from_parts(
                row.view_tag,
                row.utxo_hash,
                row.output_tree,
                row.leaf_index,
                row.payload,
            )?);
    }

    let mut nullifiers_by_tx: BTreeMap<i64, Vec<Hash>> = BTreeMap::new();
    for row in nullifier_rows {
        nullifiers_by_tx
            .entry(row.rings_tx_id)
            .or_default()
            .push(hash_from_vec(row.nullifier)?);
    }

    let transactions = matched_txs
        .into_iter()
        .map(|row| {
            Ok(ShieldedTransaction {
                slot: u64_from_i64(row.slot, "slot")?,
                tx_signature: signature_from_bytes(&row.signature)?,
                tx_viewing_pk: row.tx_viewing_pk.map(Base64String),
                salt: row.salt.map(Base64String),
                output_slots: outputs_by_tx.remove(&row.rings_tx_id).unwrap_or_default(),
                nullifiers: nullifiers_by_tx
                    .remove(&row.rings_tx_id)
                    .unwrap_or_default(),
                proofless: row.proofless,
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;

    tx.commit().await?;

    Ok(GetShieldedTransactionsByTagsResponse {
        context,
        transactions,
        next_cursor,
    })
}

async fn fetch_matching_rings_transactions(
    tx: &DatabaseTransaction,
    tags: &[Hash],
    cursor: Option<&ShieldedTxCursor>,
    limit: u64,
) -> Result<Vec<MatchedRingsTxRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let tag_filter = tags_sql(tags, backend, &mut params);
    let cursor_filter = cursor
        .map(|cursor| shielded_tx_cursor_sql(cursor, backend, &mut params))
        .transpose()?
        .unwrap_or_default();
    let limit = bind_u64_as_i64(&mut params, backend, limit)?;

    let sql = format!(
        "SELECT
            pt.rings_tx_id AS rings_tx_id,
            pt.slot AS slot,
            pt.signature AS signature,
            pt.event_index AS event_index,
            pt.tx_viewing_pk AS tx_viewing_pk,
            pt.salt AS salt,
            pt.proofless AS proofless
         FROM rings_transactions pt
         WHERE EXISTS (
             SELECT 1
             FROM rings_outputs po
             WHERE po.rings_tx_id = pt.rings_tx_id
             AND po.view_tag IN ({tag_filter})
         )
         {cursor_filter}
         ORDER BY pt.slot ASC, pt.signature ASC, pt.event_index ASC
         LIMIT {limit}"
    );

    tx.query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| MatchedRingsTxRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn fetch_rings_outputs(
    tx: &DatabaseTransaction,
    rings_tx_ids: &[i64],
) -> Result<Vec<RingsOutputRow>, PhotonApiError> {
    if rings_tx_ids.is_empty() {
        return Ok(Vec::new());
    }

    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let ids = int_list_sql(rings_tx_ids, backend, &mut params);
    let sql = format!(
        "SELECT
            po.rings_tx_id AS rings_tx_id,
            po.output_index AS output_index,
            po.view_tag AS view_tag,
            po.output_tree AS output_tree,
            po.leaf_index AS leaf_index,
            po.utxo_hash AS utxo_hash,
            pop.payload AS payload
         FROM rings_outputs po
         JOIN rings_output_payloads pop ON pop.output_id = po.output_id
         WHERE po.rings_tx_id IN ({ids})
         ORDER BY po.rings_tx_id ASC, po.output_index ASC"
    );

    let mut rows = tx
        .query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| RingsOutputRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.rings_tx_id, row.output_index));
    Ok(rows)
}

async fn fetch_rings_nullifiers(
    tx: &DatabaseTransaction,
    rings_tx_ids: &[i64],
) -> Result<Vec<RingsNullifierRow>, PhotonApiError> {
    if rings_tx_ids.is_empty() {
        return Ok(Vec::new());
    }

    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let ids = int_list_sql(rings_tx_ids, backend, &mut params);
    let sql = format!(
        "SELECT
            rings_tx_id AS rings_tx_id,
            input_index AS input_index,
            nullifier AS nullifier
         FROM rings_tx_nullifiers
         WHERE rings_tx_id IN ({ids})
         ORDER BY rings_tx_id ASC, input_index ASC"
    );

    let mut rows = tx
        .query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| RingsNullifierRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.rings_tx_id, row.input_index));
    Ok(rows)
}

fn shielded_tx_cursor_sql(
    cursor: &ShieldedTxCursor,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> Result<String, PhotonApiError> {
    let signature = cursor.signature.to_vec();
    let tx_cursor_condition =
        tx_cursor_sql_condition(cursor.slot, &signature, cursor.event_index, backend, params)?;
    Ok(format!(
        "AND (
            {tx_cursor_condition}
        )",
    ))
}

fn shielded_tx_cursor_from_row(row: &MatchedRingsTxRow) -> Result<Vec<u8>, PhotonApiError> {
    let (slot, signature, event_index) =
        cursor_sort_key(row.slot, &row.signature, row.event_index)?;
    let cursor = ShieldedTxCursor {
        slot,
        signature,
        event_index,
    };
    encode_cursor(&cursor)
}
