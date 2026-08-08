use crate::{api::error::PhotonApiError, dao::generated::blocks, migration::Expr};
use sea_orm::{DatabaseConnection, EntityTrait, FromQueryResult, QueryOrder, QuerySelect, Select};

use zolana_indexer_api::Context;

#[derive(FromQueryResult)]
struct ContextModel {
    block_time: i64,
    slot: i64,
}

#[derive(FromQueryResult)]
struct SlotModel {
    slot: i64,
}

/// Reads the newest block, rather than each column's maximum separately.
///
/// Every rings method calls this to stamp its response, so it runs on more or
/// less every request. It used to ask for `MAX(block_time), MAX(slot)` in one
/// query: `slot` is the primary key and would answer from `pk_blocks` alone,
/// but `block_time` has no index, and two aggregates over different columns
/// cannot both be served by an index scan -- so Postgres scanned the whole
/// `blocks` table, every time, holding a pool connection while it did.
///
/// Measured on devnet: 1.0-1.7s per call, rising to 2.2-2.4s an hour later as
/// the table grew, and it was the *only* statement in the slow-query log. It
/// pinned photon's connection pool flat at its ceiling and drove ALB target
/// response time to 2s while photon itself sat at 6% CPU.
///
/// Ordering by the primary key and taking one row is a backward index scan.
/// It also returns a coherent pair -- one real block's slot and time -- where
/// two independent maxima could report a slot and a time from different blocks.
fn latest_block() -> Select<blocks::Entity> {
    blocks::Entity::find()
        .select_only()
        .column(blocks::Column::BlockTime)
        .column(blocks::Column::Slot)
        .order_by_desc(blocks::Column::Slot)
}

pub async fn extract(conn: &DatabaseConnection) -> Result<Context, PhotonApiError> {
    let context = latest_block()
        .into_model::<ContextModel>()
        .one(conn)
        .await?
        .ok_or_else(|| PhotonApiError::RecordNotFound("No data has been indexed".to_string()))?;
    Ok(Context {
        block_time: context.block_time,
        slot: u64::try_from(context.slot).map_err(|_| {
            PhotonApiError::UnexpectedError(format!(
                "Invalid negative slot in database: {}",
                context.slot
            ))
        })?,
    })
}

pub async fn extract_slot(conn: &DatabaseConnection) -> Result<u64, PhotonApiError> {
    let model = blocks::Entity::find()
        .select_only()
        .column_as(Expr::col(blocks::Column::Slot).max(), "slot")
        .into_model::<SlotModel>()
        .one(conn)
        .await?
        .ok_or_else(|| PhotonApiError::RecordNotFound("No data has been indexed".to_string()))?;
    u64::try_from(model.slot).map_err(|_| {
        PhotonApiError::UnexpectedError(format!(
            "Invalid negative slot in database: {}",
            model.slot
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, QueryTrait};

    // This query runs on nearly every API response, so its plan matters more
    // than its shape. Aggregating over `block_time`, which has no index, made it
    // scan the whole `blocks` table -- 2.4s per call on devnet, and growing with
    // the table. Asserting on the generated SQL is what keeps a later "just add
    // MAX back, it reads better" from quietly reinstating a full scan.
    #[test]
    fn the_context_query_walks_the_primary_key_instead_of_aggregating() {
        let sql = latest_block().build(DatabaseBackend::Postgres).to_string();

        assert!(
            !sql.contains("MAX"),
            "context query must not aggregate -- MAX over the unindexed \
             block_time forces a sequential scan: {sql}"
        );
        assert!(
            sql.contains(r#"ORDER BY "blocks"."slot" DESC"#),
            "context query must walk the pk_blocks index backwards: {sql}"
        );
    }
}
