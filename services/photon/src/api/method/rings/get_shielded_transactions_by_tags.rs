use std::collections::BTreeMap;

use super::common::{
    bind_u64_as_i64, cursor_sort_key, decode_cursor, encode_cursor, hash_from_vec, int_list_sql,
    over_fetch, page_cursor, rings_output_slot_from_parts, signature_from_bytes, tags_sql,
    tx_cursor_sql_condition, u16_from_i16, u64_from_i64, validate_nullifiers, validate_tags,
    CursorKind,
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
    Base64String, GetRingsByNullifiersRequest, GetRingsByTagsRequest,
    GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsByTagsResponse, Hash,
    IndexedShieldedTransaction, RingsMessage, RingsOutputSlot, ShieldedTransaction,
};

#[derive(FromQueryResult, Debug)]
pub(super) struct MatchedRingsTxRow {
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
struct RingsMessageRow {
    rings_tx_id: i64,
    message_index: i16,
    view_tag: Vec<u8>,
    payload: Vec<u8>,
}

/// Just enough of a row to build a cursor from.
#[derive(FromQueryResult, Debug)]
struct ScanPositionRow {
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
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
    validate_tags(&request.tags)?;
    let page = get_shielded_transactions(
        conn,
        &request.tags,
        request.cursor.as_ref(),
        request.limit.unwrap_or_default().value(),
        MatchBy::Tags,
    )
    .await?;
    Ok(GetShieldedTransactionsByTagsResponse {
        context: page.context,
        transactions: page.transactions,
        next_cursor: page.next_cursor,
        scanned_through: page.scanned_through,
    })
}

pub async fn get_shielded_transactions_by_nullifiers(
    conn: &DatabaseConnection,
    request: GetRingsByNullifiersRequest,
) -> Result<GetShieldedTransactionsByNullifiersResponse, PhotonApiError> {
    validate_nullifiers(&request.nullifiers)?;
    let page = get_shielded_transactions(
        conn,
        &request.nullifiers,
        request.cursor.as_ref(),
        request.limit.unwrap_or_default().value(),
        MatchBy::Nullifiers,
    )
    .await?;
    Ok(GetShieldedTransactionsByNullifiersResponse {
        context: page.context,
        transactions: page.transactions,
        next_cursor: page.next_cursor,
        scanned_through: page.scanned_through,
    })
}

#[derive(Clone, Copy)]
enum MatchBy {
    Tags,
    Nullifiers,
}

struct ShieldedTransactionPage {
    context: zolana_indexer_api::Context,
    transactions: Vec<ShieldedTransaction>,
    next_cursor: Option<Base64String>,
    /// Set only for [`MatchBy::Nullifiers`]; no other response carries it.
    scanned_through: Option<Base64String>,
}

async fn get_shielded_transactions(
    conn: &DatabaseConnection,
    values: &[Hash],
    encoded_cursor: Option<&Base64String>,
    limit: u64,
    match_by: MatchBy,
) -> Result<ShieldedTransactionPage, PhotonApiError> {
    // Follows the query, so a sibling stream's cursor is rejected, not resumed.
    let cursor_kind = match match_by {
        MatchBy::Tags => CursorKind::ShieldedTxByTags,
        MatchBy::Nullifiers => CursorKind::ShieldedTxByNullifiers,
    };
    let cursor = encoded_cursor
        .map(|c| decode_cursor::<ShieldedTxCursor>(cursor_kind, c))
        .transpose()?;
    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    // One row past the limit, so an absent cursor means "this was the last page"
    // instead of "the page was empty". Without it a caller spends a whole request
    // learning there is nothing more -- 170ms of every sync on devnet.
    let mut matched_txs = fetch_matching_rings_transactions(
        &tx,
        values,
        cursor.as_ref(),
        over_fetch(limit),
        match_by,
    )
    .await?;
    let next_cursor = page_cursor(&mut matched_txs, limit, |row| {
        shielded_tx_cursor_from_row(row, cursor_kind)
    })?;

    // A cursor now means exactly that the limit cut the scan short, so nothing
    // can be claimed beyond it. Both streams report the position when it did
    // not: it is the caller's watermark now that `next_cursor` is only paging,
    // and a tag query whose page is short would otherwise have nothing to
    // resume from.
    let truncated = next_cursor.is_some();
    let scanned_through = if truncated {
        None
    } else {
        scan_position(&tx, cursor_kind).await?
    };

    let transactions = hydrate_shielded_transactions(&tx, matched_txs)
        .await?
        .into_iter()
        .map(|item| item.transaction)
        .collect();

    tx.commit().await?;

    Ok(ShieldedTransactionPage {
        context,
        transactions,
        next_cursor,
        scanned_through,
    })
}

/// The last position in the transaction stream, as a cursor.
///
/// Read inside the caller's transaction, so it describes the snapshot the scan
/// saw. `None` only when the table is empty.
///
/// Sound while positions are only appended: a row later inserted below this one
/// would be skipped by anyone resuming here. Per-tag cursors already assume the
/// same.
/// Kind from the caller: this position is returned as a cursor, so it carries the
/// stream that will resume from it.
async fn scan_position(
    tx: &DatabaseTransaction,
    kind: CursorKind,
) -> Result<Option<Base64String>, PhotonApiError> {
    let backend = tx.get_database_backend();
    // Not `ORDER BY slot, signature, event_index DESC LIMIT 1`: no index covers
    // that ordering, so it would sort the whole table. Pinning the slot first is
    // an index lookup on `idx_rings_transactions_slot_id`.
    let sql = "SELECT
            pt.slot AS slot,
            pt.signature AS signature,
            pt.event_index AS event_index
         FROM rings_transactions pt
         WHERE pt.slot = (SELECT MAX(slot) FROM rings_transactions)
         ORDER BY pt.signature DESC, pt.event_index DESC
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
    let row = ScanPositionRow::from_query_result(&row, "")?;
    Ok(Some(Base64String(shielded_tx_cursor(
        row.slot,
        &row.signature,
        row.event_index,
        kind,
    )?)))
}

pub(super) async fn hydrate_shielded_transactions(
    tx: &DatabaseTransaction,
    matched_txs: Vec<MatchedRingsTxRow>,
) -> Result<Vec<IndexedShieldedTransaction>, PhotonApiError> {
    let rings_tx_ids = matched_txs
        .iter()
        .map(|row| row.rings_tx_id)
        .collect::<Vec<_>>();

    let output_rows = fetch_rings_outputs(tx, &rings_tx_ids).await?;
    let message_rows = fetch_rings_messages(tx, &rings_tx_ids).await?;
    let nullifier_rows = fetch_rings_nullifiers(tx, &rings_tx_ids).await?;

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

    let mut messages_by_tx: BTreeMap<i64, Vec<RingsMessage>> = BTreeMap::new();
    for row in message_rows {
        messages_by_tx
            .entry(row.rings_tx_id)
            .or_default()
            .push(RingsMessage {
                view_tag: hash_from_vec(row.view_tag)?,
                payload: Base64String(row.payload),
            });
    }

    let mut nullifiers_by_tx: BTreeMap<i64, Vec<Hash>> = BTreeMap::new();
    for row in nullifier_rows {
        nullifiers_by_tx
            .entry(row.rings_tx_id)
            .or_default()
            .push(hash_from_vec(row.nullifier)?);
    }

    matched_txs
        .into_iter()
        .map(|row| {
            Ok(IndexedShieldedTransaction {
                event_index: u16_from_i16(row.event_index, "event index")?,
                transaction: ShieldedTransaction {
                    slot: u64_from_i64(row.slot, "slot")?,
                    tx_signature: signature_from_bytes(&row.signature)?,
                    tx_viewing_pk: row.tx_viewing_pk.map(Base64String),
                    salt: row.salt.map(Base64String),
                    output_slots: outputs_by_tx.remove(&row.rings_tx_id).unwrap_or_default(),
                    messages: messages_by_tx.remove(&row.rings_tx_id).unwrap_or_default(),
                    nullifiers: nullifiers_by_tx
                        .remove(&row.rings_tx_id)
                        .unwrap_or_default(),
                    proofless: row.proofless,
                },
            })
        })
        .collect()
}

async fn fetch_matching_rings_transactions(
    tx: &DatabaseTransaction,
    values: &[Hash],
    cursor: Option<&ShieldedTxCursor>,
    limit: u64,
    match_by: MatchBy,
) -> Result<Vec<MatchedRingsTxRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let match_filter = match match_by {
        MatchBy::Tags => {
            let output_filter = tags_sql(values, backend, &mut params);
            let message_filter = tags_sql(values, backend, &mut params);
            format!(
                "EXISTS (
                    SELECT 1
                    FROM rings_outputs po
                    WHERE po.rings_tx_id = pt.rings_tx_id
                    AND po.view_tag IN ({output_filter})
                )
                OR EXISTS (
                    SELECT 1
                    FROM rings_messages pm
                    WHERE pm.rings_tx_id = pt.rings_tx_id
                    AND pm.view_tag IN ({message_filter})
                )"
            )
        }
        MatchBy::Nullifiers => {
            let nullifier_filter = tags_sql(values, backend, &mut params);
            format!(
                "EXISTS (
                    SELECT 1
                    FROM rings_tx_nullifiers pn
                    WHERE pn.rings_tx_id = pt.rings_tx_id
                    AND pn.nullifier IN ({nullifier_filter})
                )"
            )
        }
    };
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
         WHERE ({match_filter})
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

async fn fetch_rings_messages(
    tx: &DatabaseTransaction,
    rings_tx_ids: &[i64],
) -> Result<Vec<RingsMessageRow>, PhotonApiError> {
    if rings_tx_ids.is_empty() {
        return Ok(Vec::new());
    }

    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let ids = int_list_sql(rings_tx_ids, backend, &mut params);
    let sql = format!(
        "SELECT
            pm.rings_tx_id AS rings_tx_id,
            pm.message_index AS message_index,
            pm.view_tag AS view_tag,
            pm.payload AS payload
         FROM rings_messages pm
         WHERE pm.rings_tx_id IN ({ids})
         ORDER BY pm.rings_tx_id ASC, pm.message_index ASC"
    );

    let mut rows = tx
        .query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| RingsMessageRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.rings_tx_id, row.message_index));
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
    // "pt": this query returns transactions and orders by them, so the cursor
    // reads from the same table it sorts by.
    let condition = tx_cursor_sql_condition(
        "pt",
        cursor.slot,
        &signature,
        cursor.event_index,
        &[],
        backend,
        params,
    )?;
    Ok(format!("AND {condition}"))
}

fn shielded_tx_cursor_from_row(
    row: &MatchedRingsTxRow,
    kind: CursorKind,
) -> Result<Vec<u8>, PhotonApiError> {
    shielded_tx_cursor(row.slot, &row.signature, row.event_index, kind)
}

fn shielded_tx_cursor(
    slot: i64,
    signature: &[u8],
    event_index: i16,
    kind: CursorKind,
) -> Result<Vec<u8>, PhotonApiError> {
    let (slot, signature, event_index) = cursor_sort_key(slot, signature, event_index)?;
    let cursor = ShieldedTxCursor {
        slot,
        signature,
        event_index,
    };
    encode_cursor(kind, &cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::generated::{blocks, rings_transactions, rings_tx_nullifiers, transactions};
    use crate::migration::RingsMigrator;
    use sea_orm::{Database, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait;
    use zolana_indexer_api::{GetRingsByNullifiersRequest, Limit};

    fn hash(byte: u8) -> Hash {
        Hash::from([byte; 32])
    }

    async fn setup() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(7),
            parent_slot: Set(0),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![1; 32]),
            block_height: Set(1),
            block_time: Set(1),
        })
        .exec(&db)
        .await
        .unwrap();
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![1; 64]),
            slot: Set(7),
            error: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(1),
            signature: Set(vec![1; 64]),
            event_index: Set(0),
            slot: Set(7),
            rings_program_id: Set(vec![9; 32]),
            source_instruction_tag: Set(1),
            output_tree: Set(vec![8; 32]),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(&db)
        .await
        .unwrap();
        for (input_index, byte) in [3u8, 4].into_iter().enumerate() {
            rings_tx_nullifiers::Entity::insert(rings_tx_nullifiers::ActiveModel {
                nullifier_id: Default::default(),
                rings_tx_id: Set(1),
                slot: Set(7),
                input_index: Set(input_index as i16),
                nullifier_tree: Set(vec![7; 32]),
                input_queue_seq: Set(input_index as i64),
                nullifier: Set(vec![byte; 32]),
            })
            .exec(&db)
            .await
            .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn nullifier_lookup_hydrates_each_matching_transaction_once() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(3), hash(4)],
                cursor: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();

        assert_eq!(response.transactions.len(), 1);
        assert_eq!(response.transactions[0].nullifiers, vec![hash(3), hash(4)]);
    }

    #[tokio::test]
    async fn nullifier_lookup_returns_no_unmatched_transactions() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(5)],
                cursor: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(response.transactions.is_empty());
    }

    /// An unspent nullifier matches nothing, so without a reported position the
    /// caller rescans the whole stream on every sync.
    #[tokio::test]
    async fn an_empty_nullifier_page_still_reports_how_far_it_scanned() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(5)],
                cursor: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();

        assert!(response.transactions.is_empty());
        assert!(
            response.next_cursor.is_none(),
            "no rows, so no page to follow"
        );
        let scanned_through = response
            .scanned_through
            .expect("an exhausted scan reports its tip");

        // The same query from that position must still be empty.
        let resumed = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(5)],
                cursor: Some(scanned_through.clone()),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(resumed.transactions.is_empty());
        assert_eq!(
            resumed.scanned_through,
            Some(scanned_through),
            "a stream that has not moved reports the same tip"
        );
    }

    /// The position claims nothing matches at or before it, true only when the
    /// scan ran out of rows rather than out of room.
    ///
    /// Needs two matching transactions to be a real test: both fixture
    /// nullifiers belong to one transaction, so a limit of 1 returns a page that
    /// fills exactly and is not truncated. Over-fetching one row is what tells
    /// those two cases apart, where the old rule assumed the worse of them.
    #[tokio::test]
    async fn a_truncated_page_reports_no_scan_position() {
        let db = setup().await;
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![3; 64]),
            slot: Set(7),
            error: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(3),
            signature: Set(vec![3; 64]),
            event_index: Set(0),
            slot: Set(7),
            rings_program_id: Set(vec![9; 32]),
            source_instruction_tag: Set(1),
            output_tree: Set(vec![8; 32]),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_tx_nullifiers::Entity::insert(rings_tx_nullifiers::ActiveModel {
            nullifier_id: Default::default(),
            rings_tx_id: Set(3),
            slot: Set(7),
            input_index: Set(0),
            nullifier_tree: Set(vec![7; 32]),
            input_queue_seq: Set(9),
            nullifier: Set(vec![9; 32]),
        })
        .exec(&db)
        .await
        .unwrap();

        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(3), hash(9)],
                cursor: None,
                limit: Some(Limit::new(1).unwrap()),
            },
        )
        .await
        .unwrap();

        assert_eq!(response.transactions.len(), 1, "the limit was reached");
        assert!(
            response.next_cursor.is_some(),
            "another matching transaction is left, so the page must page"
        );
        assert!(
            response.scanned_through.is_none(),
            "the limit cut the scan short, so nothing can be claimed beyond it"
        );
    }

    /// The position must not skip a spend that lands after it.
    #[tokio::test]
    async fn resuming_from_a_scan_position_still_finds_a_later_spend() {
        let db = setup().await;
        let first = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(5)],
                cursor: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        let scanned_through = first
            .scanned_through
            .expect("a scan that reached the end reports where");

        // A later transaction spends the nullifier the caller is watching.
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(9),
            parent_slot: Set(7),
            parent_blockhash: Set(vec![1; 32]),
            blockhash: Set(vec![2; 32]),
            block_height: Set(2),
            block_time: Set(2),
        })
        .exec(&db)
        .await
        .unwrap();
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![2; 64]),
            slot: Set(9),
            error: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(2),
            signature: Set(vec![2; 64]),
            event_index: Set(0),
            slot: Set(9),
            rings_program_id: Set(vec![9; 32]),
            source_instruction_tag: Set(1),
            output_tree: Set(vec![8; 32]),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_tx_nullifiers::Entity::insert(rings_tx_nullifiers::ActiveModel {
            nullifier_id: Default::default(),
            rings_tx_id: Set(2),
            slot: Set(9),
            input_index: Set(0),
            nullifier_tree: Set(vec![7; 32]),
            // The setup already used seq 0 and 1 in this tree, and the pair
            // (tree, seq) is unique.
            input_queue_seq: Set(2),
            nullifier: Set(vec![5; 32]),
        })
        .exec(&db)
        .await
        .unwrap();

        let resumed = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                nullifiers: vec![hash(5)],
                cursor: Some(scanned_through),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            resumed.transactions.len(),
            1,
            "the spend landed after that position, so resuming there must still see it"
        );
    }
}
