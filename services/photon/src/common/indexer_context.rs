use crate::{api::error::PhotonApiError, dao::generated::blocks, migration::Expr};
use sea_orm::{DatabaseConnection, EntityTrait, FromQueryResult, QuerySelect};

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

/// Both aggregates come from one scan of `blocks`, so reporting the slot alongside
/// the block time costs nothing extra. The slot is what callers compare against to
/// decide whether the indexer has caught up to them.
pub async fn extract(conn: &DatabaseConnection) -> Result<Context, PhotonApiError> {
    let context = blocks::Entity::find()
        .select_only()
        .column_as(Expr::col(blocks::Column::BlockTime).max(), "block_time")
        .column_as(Expr::col(blocks::Column::Slot).max(), "slot")
        .into_model::<ContextModel>()
        .one(conn)
        .await?
        .ok_or_else(|| PhotonApiError::RecordNotFound("No data has been indexed".to_string()))?;
    Ok(Context {
        block_time: context.block_time,
        // A negative slot would mean a corrupt row; report "unknown" rather than
        // fabricating a value a freshness check would then trust.
        slot: u64::try_from(context.slot).ok(),
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
