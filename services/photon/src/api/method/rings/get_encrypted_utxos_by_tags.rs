use super::common::{
    bind_u64_as_i64, chain_position, ensure_since_indexed, rings_output_slot_from_parts,
    signature_from_bytes, since_sql_condition, tags_sql, u64_from_i64, validate_tags,
};
use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::indexer_context::extract as extract_context;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, FromQueryResult, Statement,
    TransactionTrait,
};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, ChainPosition, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetRingsByTagsRequest, Hash,
};
use zolana_interface::pda;

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

#[derive(FromQueryResult, Debug)]
struct EncryptedUtxoScanPositionRow {
    slot: i64,
    signature: Vec<u8>,
}

pub async fn get_encrypted_utxos_by_tags(
    conn: &DatabaseConnection,
    request: GetRingsByTagsRequest,
) -> Result<GetEncryptedUtxosByTagsResponse, PhotonApiError> {
    let limit = request.limit.unwrap_or_default().value();
    validate_tags(&request.tags)?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;
    if let Some(since) = request.since.as_ref() {
        ensure_since_indexed(&tx, since).await?;
    }

    // Derived, not looked up: the filter works for a ring whose registration
    // this index never saw.
    let ring_config = request
        .ring_program_id
        .map(|program| pda::ring_auth(&program.0).0);
    let mut rows = fetch_encrypted_utxo_rows(
        &tx,
        &request.tags,
        request.since.as_ref(),
        limit,
        ring_config,
    )
    .await?;
    let truncated = rows.len() as u64 >= limit;
    let (next, latest) = if truncated {
        // A position names a whole transaction, so pull the boundary
        // signature's remaining outputs before naming it as the resume point.
        let last = rows.last().expect("a truncated page has rows");
        let tail = fetch_boundary_outputs(
            &tx,
            &request.tags,
            last.slot,
            last.signature.clone(),
            last.event_index,
            last.output_index,
            ring_config,
        )
        .await?;
        rows.extend(tail);
        let last = rows.last().expect("a truncated page has rows");
        (Some(chain_position(last.slot, &last.signature)?), None)
    } else {
        (None, encrypted_utxo_scan_position(&tx).await?)
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
        next,
        latest,
    })
}

async fn encrypted_utxo_scan_position(
    tx: &DatabaseTransaction,
) -> Result<Option<ChainPosition>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let sql = "SELECT
            po.slot AS slot,
            po.signature AS signature
         FROM rings_outputs po
         WHERE po.slot = (SELECT MAX(slot) FROM rings_outputs)
         ORDER BY po.signature DESC
         LIMIT 1";
    let Some(row) = tx
        .query_all(Statement::from_string(backend, sql.to_owned()))
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let row = EncryptedUtxoScanPositionRow::from_query_result(&row, "")?;
    Ok(Some(chain_position(row.slot, &row.signature)?))
}

async fn fetch_encrypted_utxo_rows(
    tx: &DatabaseTransaction,
    tags: &[Hash],
    since: Option<&ChainPosition>,
    limit: u64,
    ring_config: Option<Pubkey>,
) -> Result<Vec<EncryptedUtxoRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let tag_filter = tags_sql(tags, backend, &mut params);
    // "po", matching this query's ORDER BY, so
    // idx_rings_outputs_view_tag_order serves the filter and the sort together.
    let since_filter = since
        .map(|since| since_sql_condition("po", since, backend, &mut params))
        .transpose()?
        .map(|condition| format!("AND {condition}"))
        .unwrap_or_default();
    let ring_filter = match ring_config {
        Some(config) => {
            let bound = bind_sql_value(&mut params, backend, config.to_bytes().to_vec());
            format!("AND pt.ring_config = {bound}")
        }
        None => String::new(),
    };
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
         {ring_filter}
         {since_filter}
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

/// The boundary signature's matching outputs past a truncated page.
#[allow(clippy::too_many_arguments)]
async fn fetch_boundary_outputs(
    tx: &DatabaseTransaction,
    tags: &[Hash],
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
    output_index: i16,
    ring_config: Option<Pubkey>,
) -> Result<Vec<EncryptedUtxoRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let tag_filter = tags_sql(tags, backend, &mut params);
    let ring_filter = match ring_config {
        Some(config) => {
            let bound = bind_sql_value(&mut params, backend, config.to_bytes().to_vec());
            format!("AND pt.ring_config = {bound}")
        }
        None => String::new(),
    };
    let slot_value = bind_sql_value(&mut params, backend, slot);
    let signature_value = bind_sql_value(&mut params, backend, signature);
    let event_value = bind_sql_value(&mut params, backend, i32::from(event_index));
    let output_value = bind_sql_value(&mut params, backend, i32::from(output_index));

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
         {ring_filter}
         AND po.slot = {slot_value}
         AND po.signature = {signature_value}
         AND (po.event_index, po.output_index) > ({event_value}, {output_value})
         ORDER BY po.event_index ASC, po.output_index ASC"
    );

    tx.query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| EncryptedUtxoRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}
