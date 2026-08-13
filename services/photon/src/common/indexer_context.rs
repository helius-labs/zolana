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
