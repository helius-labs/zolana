use super::common::bind_u64_as_i64;
use super::get_shielded_transactions_by_tags::{hydrate_shielded_transactions, MatchedRingsTxRow};
use crate::api::error::PhotonApiError;
use crate::common::bind_sql_value;
use crate::common::indexer_context::extract as extract_context;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, FromQueryResult, Statement,
    TransactionTrait,
};
use solana_signature::SIGNATURE_BYTES;
use zolana_indexer_api::{
    GetShieldedTransactionsBySignatureRequest, GetShieldedTransactionsBySignatureResponse,
    PAGE_LIMIT,
};

pub async fn get_shielded_transactions_by_signature(
    conn: &DatabaseConnection,
    request: GetShieldedTransactionsBySignatureRequest,
) -> Result<GetShieldedTransactionsBySignatureResponse, PhotonApiError> {
    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let matched_txs = fetch_rings_transactions_by_signature(&tx, request).await?;
    let transactions = hydrate_shielded_transactions(&tx, matched_txs).await?;
    tx.commit().await?;

    Ok(GetShieldedTransactionsBySignatureResponse {
        context,
        transactions,
    })
}

async fn fetch_rings_transactions_by_signature(
    tx: &DatabaseTransaction,
    request: GetShieldedTransactionsBySignatureRequest,
) -> Result<Vec<MatchedRingsTxRow>, PhotonApiError> {
    let backend = tx.get_database_backend();
    let mut params = Vec::new();
    let signature = bind_sql_value(
        &mut params,
        backend,
        Into::<[u8; SIGNATURE_BYTES]>::into(request.tx_signature.0).to_vec(),
    );
    let limit = bind_u64_as_i64(&mut params, backend, PAGE_LIMIT)?;
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
         WHERE pt.signature = {signature}
         ORDER BY pt.event_index ASC
         LIMIT {limit}"
    );

    tx.query_all(Statement::from_sql_and_values(backend, sql, params))
        .await?
        .into_iter()
        .map(|row| MatchedRingsTxRow::from_query_result(&row, ""))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}
