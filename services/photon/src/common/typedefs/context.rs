use crate::{api::error::PhotonApiError, dao::generated::blocks, migration::Expr};
use sea_orm::{DatabaseConnection, EntityTrait, FromQueryResult, QuerySelect};

pub use zolana_indexer_api::Context;

#[derive(FromQueryResult)]
struct ContextModel {
    // Postgres and SQLite do not support u64 as a return type.
    slot: i64,
}

pub async fn extract(conn: &DatabaseConnection) -> Result<Context, PhotonApiError> {
    let context = blocks::Entity::find()
        .select_only()
        .column_as(Expr::col(blocks::Column::Slot).max(), "slot")
        .into_model::<ContextModel>()
        .one(conn)
        .await?
        .ok_or_else(|| PhotonApiError::RecordNotFound("No data has been indexed".to_string()))?;
    Ok(Context {
        slot: u64::try_from(context.slot).map_err(|_| {
            PhotonApiError::UnexpectedError(format!(
                "Invalid negative slot in database: {}",
                context.slot
            ))
        })?,
    })
}
