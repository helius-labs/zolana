use super::common::{
    after_sql_condition, bind_u64_as_i64, chain_position, ensure_after_indexed, require_context,
    rings_output_slot_from_parts, signature_from_bytes, tags_sql, truncate_transactions,
    u64_from_i64, validate_tags,
};
use super::get_shielded_transactions_by_tags::scan_position;
use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::indexer_context::{extract as extract_context, newest_unpaused_tree_id};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, FromQueryResult,
    Statement, TransactionTrait, Value,
};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetRingsByTagsRequest, Hash,
    TransactionOutputs,
};
use zolana_interface::pda;

#[derive(FromQueryResult, Debug)]
struct EncryptedUtxoRow {
    slot: i64,
    signature: Vec<u8>,
    view_tag: Vec<u8>,
    output_tree: Vec<u8>,
    tree_id: Option<i32>,
    leaf_index: i64,
    utxo_hash: Vec<u8>,
    tx_viewing_pk: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    payload: Vec<u8>,
}

pub async fn get_encrypted_utxos_by_tags(
    conn: &DatabaseConnection,
    request: GetRingsByTagsRequest,
) -> Result<GetEncryptedUtxosByTagsResponse, PhotonApiError> {
    validate_tags(&request.tags, request.ring_program_id.as_ref())?;
    let limit = request.limit.clone().unwrap_or_default().value();
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;
    let context = extract_context(&tx).await?;
    require_context(context.slot, request.min_context_slot, request.after)?;
    let output_tree_id = newest_unpaused_tree_id(&tx).await?;
    if let Some(after) = &request.after {
        ensure_after_indexed(&tx, after).await?;
    }
    let mut rows = fetch_encrypted_utxo_rows(&tx, &request).await?;
    let has_more = truncate_transactions(&mut rows, limit, |row| {
        chain_position(row.slot, &row.signature)
    })?;
    let cursor = if has_more {
        rows.last()
            .map(|row| chain_position(row.slot, &row.signature))
            .transpose()?
    } else {
        scan_position(&tx).await?.max(request.after)
    };
    let outputs = rows
        .into_iter()
        .map(|row| {
            Ok(EncryptedUtxoMatch {
                slot: u64_from_i64(row.slot, "slot")?,
                tx_signature: signature_from_bytes(&row.signature)?,
                output_slot: rings_output_slot_from_parts(
                    row.view_tag,
                    row.utxo_hash,
                    row.output_tree,
                    row.tree_id,
                    row.leaf_index,
                    row.payload,
                )?,
                tx_viewing_pk: row.tx_viewing_pk.map(Base64String),
                salt: row.salt.map(Base64String),
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;
    let items = TransactionOutputs::group(outputs, |output| (output.slot, output.tx_signature));
    tx.commit().await?;
    Ok(GetEncryptedUtxosByTagsResponse {
        context,
        output_tree_id,
        items,
        cursor,
        has_more,
    })
}

async fn fetch_encrypted_utxo_rows(
    tx: &DatabaseTransaction,
    request: &GetRingsByTagsRequest,
) -> Result<Vec<EncryptedUtxoRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let ring_config = request
        .ring_program_id
        .as_ref()
        .map(|program| pda::ring_auth(&program.0).0);
    let selection_tags = tag_filter_sql(&request.tags, ring_config, backend, &mut params);
    let after_filter = request
        .after
        .as_ref()
        .map(|after| after_sql_condition("po", after, backend, &mut params))
        .transpose()?
        .map(|condition| format!("AND {condition}"))
        .unwrap_or_default();
    let selection_ring = ring_filter_sql(ring_config, backend, &mut params);
    let lookahead = bind_u64_as_i64(
        &mut params,
        backend,
        request.limit.clone().unwrap_or_default().value() + 1,
    )?;
    let result_tags = tag_filter_sql(&request.tags, ring_config, backend, &mut params);
    let result_ring = ring_filter_sql(ring_config, backend, &mut params);
    let sql = format!("WITH selected AS (
        SELECT DISTINCT po.slot, po.signature FROM rings_outputs po
        JOIN rings_transactions pt ON pt.rings_tx_id = po.rings_tx_id
        WHERE {selection_tags} {after_filter} {selection_ring}
        ORDER BY po.slot ASC, po.signature ASC LIMIT {lookahead}
    ) SELECT pt.slot, pt.signature, pt.event_index, po.output_index, po.view_tag,
        po.output_tree, tm.tree_id, po.leaf_index, po.utxo_hash, pt.tx_viewing_pk, pt.salt, pop.payload
      FROM rings_outputs po
      JOIN selected chosen ON chosen.slot = po.slot AND chosen.signature = po.signature
      JOIN rings_transactions pt ON pt.rings_tx_id = po.rings_tx_id
      JOIN rings_output_payloads pop ON pop.output_id = po.output_id
      LEFT JOIN tree_metadata tm ON tm.tree_pubkey = po.output_tree
      WHERE {result_tags} {result_ring}
      ORDER BY po.slot ASC, po.signature ASC, po.event_index ASC, po.output_index ASC");
    tx.query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| EncryptedUtxoRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn ring_filter_sql(
    ring: Option<Pubkey>,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> String {
    ring.map(|ring| {
        format!(
            "AND pt.ring_config = {}",
            bind_sql_value(params, backend, ring.to_bytes().to_vec())
        )
    })
    .unwrap_or_default()
}

/// An empty tag set with a ring selects the ring's full history.
fn tag_filter_sql(
    tags: &[Hash],
    ring_config: Option<Pubkey>,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> String {
    if tags.is_empty() && ring_config.is_some() {
        "TRUE".to_string()
    } else {
        format!("po.view_tag IN ({})", tags_sql(tags, backend, params))
    }
}
