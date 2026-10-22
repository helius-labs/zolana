use std::collections::BTreeMap;

use super::common::{
    after_sql_condition, bind_u64_as_i64, chain_position, ensure_after_indexed, hash_from_vec,
    int_list_sql, require_context, rings_output_slot_from_parts, signature_from_bytes, tags_sql,
    truncate_transactions, u16_from_i16, u64_from_i64, validate_nullifiers, validate_tags,
};
use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::indexer_context::{extract as extract_context, newest_unpaused_tree_id};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, FromQueryResult,
    Statement, TransactionTrait, Value,
};
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Cursor, GetRingsByNullifiersRequest, GetRingsByTagsRequest,
    GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsByTagsResponse, Hash,
    IndexedShieldedTransaction, RingsMessage, RingsOutputSlot, SerializablePubkey,
    ShieldedTransaction, TransactionEvents,
};
use zolana_interface::pda;

#[derive(FromQueryResult, Debug)]
pub(super) struct MatchedRingsTxRow {
    rings_tx_id: i64,
    slot: i64,
    signature: Vec<u8>,
    event_index: i16,
    tx_viewing_pk: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    proofless: bool,
    ring_config: Option<Vec<u8>>,
    ring_program_id: Option<Vec<u8>>,
}

#[derive(FromQueryResult, Debug)]
struct RingsOutputRow {
    rings_tx_id: i64,
    output_index: i16,
    view_tag: Vec<u8>,
    output_tree: Vec<u8>,
    tree_id: Option<i32>,
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

/// Just enough of a row to build a position from.
#[derive(FromQueryResult, Debug)]
struct ScanPositionRow {
    slot: i64,
    signature: Vec<u8>,
}

#[derive(FromQueryResult, Debug)]
struct RingsNullifierRow {
    rings_tx_id: i64,
    input_index: i16,
    nullifier: Vec<u8>,
}

pub async fn get_shielded_transactions_by_tags(
    conn: &DatabaseConnection,
    request: GetRingsByTagsRequest,
) -> Result<GetShieldedTransactionsByTagsResponse, PhotonApiError> {
    validate_tags(&request.tags, request.ring_program_id.as_ref())?;
    // The config account is derived, not looked up, so filtering by ring works
    // even for a ring whose registration this index never saw.
    let ring_config = request
        .ring_program_id
        .map(|program| pda::ring_auth(&program.0).0);
    get_shielded_transactions(
        conn,
        RingsQuery {
            values: &request.tags,
            after: request.after,
            limit: request.limit.unwrap_or_default().value(),
            match_by: MatchBy::Tags,
            ring_config,
            min_context_slot: request.min_context_slot,
        },
    )
    .await
}

pub async fn get_shielded_transactions_by_nullifiers(
    conn: &DatabaseConnection,
    request: GetRingsByNullifiersRequest,
) -> Result<GetShieldedTransactionsByNullifiersResponse, PhotonApiError> {
    validate_nullifiers(&request.nullifiers)?;
    get_shielded_transactions(
        conn,
        RingsQuery {
            values: &request.nullifiers,
            after: request.after,
            limit: request.limit.unwrap_or_default().value(),
            match_by: MatchBy::Nullifiers,
            ring_config: None,
            min_context_slot: request.min_context_slot,
        },
    )
    .await
}

#[derive(Clone, Copy)]
enum MatchBy {
    Tags,
    Nullifiers,
}

struct RingsQuery<'a> {
    values: &'a [Hash],
    after: Option<Cursor>,
    limit: u64,
    match_by: MatchBy,
    ring_config: Option<Pubkey>,
    min_context_slot: Option<u64>,
}

async fn get_shielded_transactions(
    conn: &DatabaseConnection,
    query: RingsQuery<'_>,
) -> Result<GetShieldedTransactionsByTagsResponse, PhotonApiError> {
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;
    let context = extract_context(&tx).await?;
    require_context(context.slot, query.min_context_slot, query.after)?;
    let output_tree_id = newest_unpaused_tree_id(&tx).await?;
    if let Some(after) = &query.after {
        ensure_after_indexed(&tx, after).await?;
    }
    let mut rows = fetch_matching_rings_transactions(&tx, &query).await?;
    let has_more = truncate_transactions(&mut rows, query.limit, |row| {
        chain_position(row.slot, &row.signature)
    })?;
    let cursor = if has_more {
        rows.last()
            .map(|row| chain_position(row.slot, &row.signature))
            .transpose()?
    } else {
        scan_position(&tx).await?.max(query.after)
    };
    let events = hydrate_shielded_transactions(&tx, rows).await?;
    let items = TransactionEvents::group(
        events.into_iter().map(|event| event.transaction).collect(),
        |event| (event.slot, event.tx_signature),
    );
    tx.commit().await?;
    Ok(GetShieldedTransactionsByTagsResponse {
        context,
        output_tree_id,
        items,
        cursor,
        has_more,
    })
}

/// The last position in the transaction stream.
///
/// Read inside the caller's transaction, so it describes the snapshot the scan
/// saw. `None` only when the table is empty.
///
/// Sound while positions are only appended: a row later inserted below this one
/// would be skipped by anyone resuming here.
pub(super) async fn scan_position(
    tx: &DatabaseTransaction,
) -> Result<Option<Cursor>, PhotonApiError> {
    let backend = tx.get_database_backend();
    // Not `ORDER BY slot, signature DESC LIMIT 1`: no index covers that
    // ordering, so it would sort the whole table. Pinning the slot first is an
    // index lookup on `idx_rings_transactions_slot_id`.
    let sql = "SELECT
            pt.slot AS slot,
            pt.signature AS signature
         FROM rings_transactions pt
         WHERE pt.slot = (SELECT MAX(slot) FROM rings_transactions)
         ORDER BY pt.signature DESC
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
    Ok(Some(chain_position(row.slot, &row.signature)?))
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
                row.tree_id,
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
                    event_index: Some(u16_from_i16(row.event_index, "event index")?),
                    tx_viewing_pk: row.tx_viewing_pk.map(Base64String),
                    salt: row.salt.map(Base64String),
                    output_slots: outputs_by_tx.remove(&row.rings_tx_id).unwrap_or_default(),
                    messages: messages_by_tx.remove(&row.rings_tx_id).unwrap_or_default(),
                    nullifiers: nullifiers_by_tx
                        .remove(&row.rings_tx_id)
                        .unwrap_or_default(),
                    proofless: row.proofless,
                    ring_config: row
                        .ring_config
                        .map(SerializablePubkey::try_from)
                        .transpose()?,
                    ring_program_id: row
                        .ring_program_id
                        .map(SerializablePubkey::try_from)
                        .transpose()?,
                },
            })
        })
        .collect()
}

fn match_by_sql(
    values: &[Hash],
    match_by: MatchBy,
    ring_config: Option<Pubkey>,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> String {
    match match_by {
        // Recipient tags are unknown until the deposit openings are decrypted.
        MatchBy::Tags if values.is_empty() && ring_config.is_some() => "TRUE".to_string(),
        MatchBy::Tags => {
            let output_filter = tags_sql(values, backend, params);
            let message_filter = tags_sql(values, backend, params);
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
            let nullifier_filter = tags_sql(values, backend, params);
            format!(
                "EXISTS (
                    SELECT 1
                    FROM rings_tx_nullifiers pn
                    WHERE pn.rings_tx_id = pt.rings_tx_id
                    AND pn.nullifier IN ({nullifier_filter})
                )"
            )
        }
    }
}

fn ring_filter_sql(
    ring_config: Option<Pubkey>,
    backend: DatabaseBackend,
    params: &mut Vec<Value>,
) -> String {
    match ring_config {
        Some(config) => {
            let bound = bind_sql_value(params, backend, config.to_bytes().to_vec());
            format!("AND pt.ring_config = {bound}")
        }
        None => String::new(),
    }
}

async fn fetch_matching_rings_transactions(
    tx: &DatabaseTransaction,
    query: &RingsQuery<'_>,
) -> Result<Vec<MatchedRingsTxRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let match_filter = match_by_sql(
        query.values,
        query.match_by,
        query.ring_config,
        backend,
        &mut params,
    );
    let after_filter = query
        .after
        .as_ref()
        .map(|after| after_sql_condition("pt", after, backend, &mut params))
        .transpose()?
        .map(|condition| format!("AND {condition}"))
        .unwrap_or_default();
    let selection_ring = ring_filter_sql(query.ring_config, backend, &mut params);
    let lookahead = bind_u64_as_i64(&mut params, backend, query.limit + 1)?;
    let result_ring = ring_filter_sql(query.ring_config, backend, &mut params);
    let sql = format!(
        "WITH selected AS (
        SELECT DISTINCT pt.slot, pt.signature FROM rings_transactions pt
        WHERE ({match_filter}) {after_filter} {selection_ring}
        ORDER BY pt.slot ASC, pt.signature ASC LIMIT {lookahead}
    ) SELECT pt.rings_tx_id, pt.slot, pt.signature, pt.event_index, pt.tx_viewing_pk,
        pt.salt, pt.proofless, pt.ring_config, rc.program_id AS ring_program_id
      FROM rings_transactions pt
      JOIN selected chosen ON chosen.slot = pt.slot AND chosen.signature = pt.signature
      LEFT JOIN ring_configs rc ON rc.ring_config = pt.ring_config
      WHERE TRUE {result_ring}
      ORDER BY pt.slot ASC, pt.signature ASC, pt.event_index ASC"
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
            tm.tree_id AS tree_id,
            po.leaf_index AS leaf_index,
            po.utxo_hash AS utxo_hash,
            pop.payload AS payload
         FROM rings_outputs po
         JOIN rings_output_payloads pop ON pop.output_id = po.output_id
         LEFT JOIN tree_metadata tm ON tm.tree_pubkey = po.output_tree
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::method::rings::get_encrypted_utxos_by_tags;
    use crate::dao::generated::{
        blocks, ring_configs, rings_output_payloads, rings_outputs, rings_transactions,
        rings_tx_nullifiers, transactions,
    };
    use crate::migration::RingsMigrator;
    use crate::monitor::tree_metadata_sync::{upsert_tree_metadata, TreeAccountData};
    use sea_orm::{Database, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait;
    use zolana_indexer_api::{GetRingsByNullifiersRequest, Limit};

    const OUTPUT_TREE: [u8; 32] = [8; 32];
    const OUTPUT_TREE_ID: u16 = 3;

    fn hash(byte: u8) -> Hash {
        Hash::from([byte; 32])
    }

    async fn setup() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        // `filter_by_known_trees` refuses to persist an output whose tree has
        // no metadata row, so a fixture without one is not a state the ingester
        // can produce.
        insert_output_tree_metadata(&db).await;
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
            ring_config: Set(Some(vec![9; 32])),
            source_instruction_tag: Set(1),
            output_tree: Set(OUTPUT_TREE.to_vec()),
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
                min_context_slot: None,
                nullifiers: vec![hash(3), hash(4)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.items.iter().flat_map(|item| &item.events).count(),
            1
        );
        assert_eq!(
            response
                .items
                .iter()
                .flat_map(|item| &item.events)
                .next()
                .expect("transaction item")
                .nullifiers,
            vec![hash(3), hash(4)]
        );
    }

    async fn insert_output_tree_metadata(db: &DatabaseConnection) {
        let tree = Pubkey::new_from_array(OUTPUT_TREE);
        let data = TreeAccountData {
            tree_id: OUTPUT_TREE_ID,
            paused: false,
            queue_pubkey: tree,
            root_history_capacity: 1,
            input_queue_zkp_batch_size: 1,
            height: 1,
            sequence_number: 0,
            next_index: 0,
        };
        upsert_tree_metadata(db, tree, &data, 7).await.unwrap();
    }

    /// Inserts one ring transaction whose `ring_config` is a real derived PDA,
    /// with the registration that maps it back to a program.
    async fn setup_ring(register: bool) -> (DatabaseConnection, Pubkey) {
        let db = setup().await;
        let ring_program = Pubkey::new_unique();
        let (ring_config, _) = pda::ring_auth(&ring_program);

        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![2; 64]),
            slot: Set(7),
            error: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(2),
            signature: Set(vec![2; 64]),
            event_index: Set(0),
            slot: Set(7),
            ring_config: Set(Some(ring_config.to_bytes().to_vec())),
            source_instruction_tag: Set(15),
            output_tree: Set(OUTPUT_TREE.to_vec()),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_outputs::Entity::insert(rings_outputs::ActiveModel {
            output_id: Set(2),
            rings_tx_id: Set(2),
            slot: Set(7),
            output_index: Set(0),
            output_tree: Set(OUTPUT_TREE.to_vec()),
            leaf_index: Set(2),
            view_tag: Set(hash(6).to_vec()),
            utxo_hash: Set(vec![6; 32]),
            signature: Set(Some(vec![2; 64])),
            event_index: Set(Some(0)),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_output_payloads::Entity::insert(rings_output_payloads::ActiveModel {
            output_id: Set(2),
            payload: Set(vec![1, 2, 3]),
        })
        .exec(&db)
        .await
        .unwrap();
        if register {
            ring_configs::Entity::insert(ring_configs::ActiveModel {
                ring_config: Set(ring_config.to_bytes().to_vec()),
                program_id: Set(ring_program.to_bytes().to_vec()),
                authority: Set(vec![5; 32]),
                slot: Set(7),
            })
            .exec(&db)
            .await
            .unwrap();
        }
        (db, ring_program)
    }

    #[tokio::test]
    async fn freshness_is_independent_of_the_history_boundary() {
        let db = setup().await;
        let mut request = GetRingsByNullifiersRequest {
            nullifiers: vec![hash(3)],
            after: None,
            limit: Some(Limit::new(1).unwrap()),
            min_context_slot: Some(8),
        };
        let error = get_shielded_transactions_by_nullifiers(&db, request.clone())
            .await
            .unwrap_err();
        let error: jsonrpsee::types::ErrorObjectOwned = error.into();
        assert_eq!(error.code(), -32016);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(error.data().unwrap().get()).unwrap()
                ["contextSlot"],
            7
        );
        request.min_context_slot = Some(7);
        let page = get_shielded_transactions_by_nullifiers(&db, request.clone())
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(!page.has_more);
        request.after = page.cursor;
        let empty = get_shielded_transactions_by_nullifiers(&db, request)
            .await
            .unwrap();
        assert!(empty.items.is_empty());
        assert_eq!(empty.cursor, page.cursor);
        assert!(!empty.has_more);
        // A nullifier checkpoint also resumes an unrelated tag stream.
        let tags = get_shielded_transactions_by_tags(
            &db,
            GetRingsByTagsRequest {
                tags: vec![hash(6)],
                after: page.cursor,
                limit: Some(Limit::new(1).unwrap()),
                min_context_slot: Some(7),
                ring_program_id: None,
            },
        )
        .await
        .unwrap();
        assert!(tags.items.is_empty());
        assert_eq!(tags.cursor, page.cursor);
    }

    #[tokio::test]
    async fn output_pages_keep_a_transaction_whole_and_use_lookahead() {
        let (db, ring) = setup_ring(false).await;
        rings_outputs::Entity::insert(rings_outputs::ActiveModel {
            output_id: Set(3),
            rings_tx_id: Set(2),
            slot: Set(7),
            output_index: Set(1),
            output_tree: Set(OUTPUT_TREE.to_vec()),
            leaf_index: Set(3),
            view_tag: Set(hash(6).to_vec()),
            utxo_hash: Set(vec![7; 32]),
            signature: Set(Some(vec![2; 64])),
            event_index: Set(Some(0)),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_output_payloads::Entity::insert(rings_output_payloads::ActiveModel {
            output_id: Set(3),
            payload: Set(vec![4]),
        })
        .exec(&db)
        .await
        .unwrap();
        let config = pda::ring_auth(&ring).0;
        insert_history_output(&db, 4, Some(config), zolana_event::tag::RING_DEPOSIT).await;
        let request = GetRingsByTagsRequest {
            tags: vec![hash(6), hash(24)],
            after: None,
            limit: Some(Limit::new(1).unwrap()),
            min_context_slot: Some(7),
            ring_program_id: None,
        };
        let first = get_encrypted_utxos_by_tags(&db, request.clone())
            .await
            .unwrap();
        assert_eq!(first.items.len(), 1);
        assert_eq!(first.items[0].outputs.len(), 2);
        assert!(first.has_more);
        let second = get_encrypted_utxos_by_tags(
            &db,
            GetRingsByTagsRequest {
                after: first.cursor,
                ..request
            },
        )
        .await
        .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].outputs.len(), 1);
        assert!(!second.has_more);
        assert!(second.cursor > first.cursor);
    }

    async fn tags_query(
        db: &DatabaseConnection,
        ring_program_id: Option<Pubkey>,
    ) -> Vec<ShieldedTransaction> {
        get_shielded_transactions_by_tags(
            db,
            GetRingsByTagsRequest {
                min_context_slot: None,
                tags: vec![hash(6)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
                ring_program_id: ring_program_id.map(SerializablePubkey::from),
            },
        )
        .await
        .unwrap()
        .items
        .iter()
        .flat_map(|item| &item.events)
        .cloned()
        .collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn a_registered_ring_resolves_to_its_program() {
        let (db, ring_program) = setup_ring(true).await;

        let found = tags_query(&db, None).await;
        let [tx] = found.as_slice() else {
            panic!("expected one transaction, got {}", found.len());
        };

        assert_eq!(
            tx.ring_config,
            Some(SerializablePubkey::from(pda::ring_auth(&ring_program).0))
        );
        assert_eq!(
            tx.ring_program_id,
            Some(SerializablePubkey::from(ring_program))
        );
    }

    /// The two fields differ precisely here: the transaction still reports the
    /// ring it observed, and only the resolution is missing.
    #[tokio::test]
    async fn an_unregistered_ring_still_reports_its_config() {
        let (db, ring_program) = setup_ring(false).await;

        let found = tags_query(&db, None).await;
        let [tx] = found.as_slice() else {
            panic!("expected one transaction, got {}", found.len());
        };

        assert_eq!(
            tx.ring_config,
            Some(SerializablePubkey::from(pda::ring_auth(&ring_program).0))
        );
        assert_eq!(tx.ring_program_id, None);
    }

    /// Filtering derives the config account, so it does not consult the
    /// registry and works for an unregistered ring too.
    #[tokio::test]
    async fn filtering_by_ring_selects_only_that_ring() {
        for registered in [true, false] {
            let (db, ring_program) = setup_ring(registered).await;

            assert_eq!(tags_query(&db, Some(ring_program)).await.len(), 1);
            assert!(tags_query(&db, Some(Pubkey::new_unique())).await.is_empty());
        }
    }

    async fn insert_history_output(
        db: &DatabaseConnection,
        id: u8,
        ring: Option<Pubkey>,
        source_tag: u8,
    ) {
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![id; 64]),
            slot: Set(7),
            error: Set(None),
        })
        .exec(db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(i64::from(id)),
            signature: Set(vec![id; 64]),
            event_index: Set(0),
            slot: Set(7),
            ring_config: Set(ring.map(|program| pda::ring_auth(&program).0.to_bytes().to_vec())),
            source_instruction_tag: Set(i16::from(source_tag)),
            output_tree: Set(vec![8; 32]),
            first_output_leaf_index: Set(i64::from(id)),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(source_tag == zolana_event::tag::RING_DEPOSIT),
        })
        .exec(db)
        .await
        .unwrap();
        rings_outputs::Entity::insert(rings_outputs::ActiveModel {
            output_id: Set(i64::from(id)),
            rings_tx_id: Set(i64::from(id)),
            slot: Set(7),
            output_index: Set(0),
            output_tree: Set(vec![8; 32]),
            leaf_index: Set(i64::from(id)),
            view_tag: Set(hash(id + 20).to_vec()),
            utxo_hash: Set(vec![id; 32]),
            signature: Set(Some(vec![id; 64])),
            event_index: Set(Some(0)),
        })
        .exec(db)
        .await
        .unwrap();
        rings_output_payloads::Entity::insert(rings_output_payloads::ActiveModel {
            output_id: Set(i64::from(id)),
            payload: Set(vec![id]),
        })
        .exec(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ring_history_pages_include_unknown_tag_deposits_and_merges_only_in_that_ring() {
        use crate::api::method::rings::get_encrypted_utxos_by_tags::get_encrypted_utxos_by_tags;
        use zolana_event::tag;

        let (db, ring) = setup_ring(false).await;
        insert_history_output(&db, 3, Some(ring), tag::RING_DEPOSIT).await;
        insert_history_output(&db, 4, Some(ring), tag::RING_MERGE_TRANSACT).await;
        insert_history_output(&db, 5, Some(Pubkey::new_unique()), tag::RING_DEPOSIT).await;
        insert_history_output(&db, 6, None, tag::DEPOSIT).await;
        let request = GetRingsByTagsRequest {
            min_context_slot: None,
            tags: vec![],
            after: None,
            limit: Some(Limit::new(2).unwrap()),
            ring_program_id: Some(SerializablePubkey::from(ring)),
        };

        // 1. Unknown recipient tags must not exclude ring deposits.
        let first = get_shielded_transactions_by_tags(&db, request.clone())
            .await
            .unwrap();
        assert_eq!(first.items.iter().flat_map(|item| &item.events).count(), 2);
        assert!(
            !first
                .items
                .iter()
                .flat_map(|item| &item.events)
                .next()
                .expect("transaction item")
                .proofless
        );
        assert!(
            first
                .items
                .iter()
                .flat_map(|item| &item.events)
                .nth(1)
                .expect("transaction item")
                .proofless
        );
        assert!(first.has_more);
        assert!(first
            .items
            .iter()
            .flat_map(|item| &item.events)
            .all(|tx| tx.ring_program_id.is_none()));

        // 2. Resumed pages must retain the ring filter.
        let second = get_shielded_transactions_by_tags(
            &db,
            GetRingsByTagsRequest {
                min_context_slot: None,
                after: first.cursor,
                ..request.clone()
            },
        )
        .await
        .unwrap();
        assert_eq!(second.items.iter().flat_map(|item| &item.events).count(), 1);
        assert_eq!(
            second
                .items
                .iter()
                .flat_map(|item| &item.events)
                .next()
                .expect("transaction item")
                .output_slots[0]
                .payload
                .0,
            vec![4]
        );
        let terminal = second.cursor.expect("terminal scan frontier");
        let resumed = get_shielded_transactions_by_tags(
            &db,
            GetRingsByTagsRequest {
                min_context_slot: None,
                after: Some(terminal),
                ..request.clone()
            },
        )
        .await
        .unwrap();
        assert!(resumed
            .items
            .iter()
            .flat_map(|item| &item.events)
            .next()
            .is_none());

        // 3. Output pages must retain the same ring filter.
        let outputs = get_encrypted_utxos_by_tags(&db, request.clone())
            .await
            .unwrap();
        assert_eq!(
            outputs.items.iter().flat_map(|item| &item.outputs).count(),
            2
        );
        assert!(outputs.has_more);
        let rest = get_encrypted_utxos_by_tags(
            &db,
            GetRingsByTagsRequest {
                min_context_slot: None,
                after: outputs.cursor,
                ..request.clone()
            },
        )
        .await
        .unwrap();
        assert_eq!(rest.items.iter().flat_map(|item| &item.outputs).count(), 1);
        assert_eq!(
            rest.items
                .iter()
                .flat_map(|item| &item.outputs)
                .next()
                .expect("transaction item")
                .output_slot
                .payload
                .0,
            vec![4]
        );
        assert!(rest.cursor.is_some());

        let unscoped = GetRingsByTagsRequest {
            min_context_slot: None,
            ring_program_id: None,
            ..request
        };
        assert!(matches!(
            get_shielded_transactions_by_tags(&db, unscoped.clone()).await,
            Err(PhotonApiError::ValidationError(_))
        ));
        assert!(matches!(
            get_encrypted_utxos_by_tags(&db, unscoped).await,
            Err(PhotonApiError::ValidationError(_))
        ));
        assert_eq!(tags_query(&db, Some(ring)).await.len(), 1);
    }

    #[tokio::test]
    async fn nullifier_lookup_returns_no_unmatched_transactions() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(response
            .items
            .iter()
            .flat_map(|item| &item.events)
            .next()
            .is_none());
    }

    /// An unspent nullifier matches nothing, so without a reported position the
    /// caller rescans the whole stream on every sync.
    #[tokio::test]
    async fn an_empty_nullifier_page_still_reports_how_far_it_scanned() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();

        assert!(response
            .items
            .iter()
            .flat_map(|item| &item.events)
            .next()
            .is_none());
        assert!(!response.has_more, "no matching transactions remain");
        let latest = response.cursor.expect("an exhausted scan reports its tip");

        // The same query from that position must still be empty.
        let resumed = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: Some(latest),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(resumed
            .items
            .iter()
            .flat_map(|item| &item.events)
            .next()
            .is_none());
        assert_eq!(
            resumed.cursor,
            Some(latest),
            "a stream that has not moved reports the same tip"
        );
    }

    /// The position claims nothing matches at or before it, true only when the
    /// scan ran out of rows rather than out of room.
    #[tokio::test]
    async fn an_exactly_full_terminal_page_has_no_continuation() {
        let db = setup().await;
        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(3), hash(4)],
                after: None,
                limit: Some(Limit::new(1).unwrap()),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            response.items.iter().flat_map(|item| &item.events).count(),
            1
        );
        assert!(
            !response.has_more,
            "exactly reaching the limit does not imply more transactions"
        );
        assert!(
            response.cursor.is_some(),
            "a truncated page names where the next one starts"
        );
    }

    /// The position must not skip a spend that lands after it.
    #[tokio::test]
    async fn resuming_from_a_scan_position_still_finds_a_later_spend() {
        let db = setup().await;
        let first = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        let latest = first
            .cursor
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
            ring_config: Set(None),
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
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: Some(latest),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            resumed.items.iter().flat_map(|item| &item.events).count(),
            1,
            "the spend landed after that position, so resuming there must still see it"
        );
    }

    /// The transaction order is shared by every stream, so a tip learned from
    /// the tag stream resumes the nullifier stream without a translation step.
    #[tokio::test]
    async fn a_position_from_one_stream_resumes_another() {
        let db = setup().await;
        let tags = get_shielded_transactions_by_tags(
            &db,
            GetRingsByTagsRequest {
                min_context_slot: None,
                tags: vec![hash(9)],
                after: None,
                limit: Some(Limit::new(10).unwrap()),
                ring_program_id: None,
            },
        )
        .await
        .unwrap();
        let latest = tags.cursor.expect("terminal page reports the tip");

        let resumed = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(3)],
                after: Some(latest),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(
            resumed
                .items
                .iter()
                .flat_map(|item| &item.events)
                .next()
                .is_none(),
            "the spend sits at the tip, so a resume from it sees nothing new"
        );
    }

    /// Rows below the first indexed block were never ingested, so a silent
    /// resume from that gap would skip them forever.
    #[tokio::test]
    async fn an_after_below_the_indexed_floor_is_rejected() {
        let db = setup().await;
        let result = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(5)],
                after: Some(Cursor::new(0, signature_from_bytes(&[1; 64]).unwrap().0)),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(PhotonApiError::ValidationError(message))
                if message.contains("history")
        ));
    }

    /// A page never splits a transaction. The second event of the boundary
    /// signature belongs to the same transaction item, so the position skips
    /// nothing on resume.
    #[tokio::test]
    async fn a_truncated_page_completes_its_boundary_signature() {
        let db = setup().await;
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(2),
            signature: Set(vec![1; 64]),
            event_index: Set(1),
            slot: Set(7),
            ring_config: Set(None),
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
            slot: Set(7),
            input_index: Set(0),
            nullifier_tree: Set(vec![7; 32]),
            input_queue_seq: Set(2),
            nullifier: Set(vec![10; 32]),
        })
        .exec(&db)
        .await
        .unwrap();

        let response = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(3)],
                after: None,
                limit: Some(Limit::new(1).unwrap()),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            response.items.iter().flat_map(|item| &item.events).count(),
            2,
            "both events of the boundary signature come back"
        );
        let next = response
            .cursor
            .expect("a truncated page names its boundary");

        let resumed = get_shielded_transactions_by_nullifiers(
            &db,
            GetRingsByNullifiersRequest {
                min_context_slot: None,
                nullifiers: vec![hash(3)],
                after: Some(next),
                limit: Some(Limit::new(10).unwrap()),
            },
        )
        .await
        .unwrap();
        assert!(
            resumed
                .items
                .iter()
                .flat_map(|item| &item.events)
                .next()
                .is_none(),
            "the boundary signature was completed, so nothing was left behind"
        );
    }
}
