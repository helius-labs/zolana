use crate::{
    api::error::PhotonApiError,
    dao::generated::{blocks, tree_metadata},
    migration::Expr,
};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, Select,
};

use zolana_indexer_api::Context;

#[derive(FromQueryResult)]
struct ContextModel {
    block_time: i64,
    slot: i64,
}

#[derive(FromQueryResult)]
struct TreeIdModel {
    tree_id: Option<i32>,
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

/// The tree a client should append its next output to: the highest tree id the
/// pool has that is not paused.
///
/// A paused tree rejects every append -- the program's mutable tree load fails
/// with `TreeError::Paused` -- so the newest tree is not always a usable one.
/// `None` when no unpaused tree is known, which covers both "every tree is
/// paused" and "this indexer has not synced tree metadata yet"; a `paused` of
/// NULL is an unsynced row and is not counted as unpaused.
pub async fn newest_unpaused_tree_id(
    conn: &DatabaseConnection,
) -> Result<Option<u16>, PhotonApiError> {
    let model = tree_metadata::Entity::find()
        .select_only()
        .column_as(Expr::col(tree_metadata::Column::TreeId).max(), "tree_id")
        .filter(tree_metadata::Column::Paused.eq(false))
        .into_model::<TreeIdModel>()
        .one(conn)
        .await?;

    // The aggregate returns one row even with nothing to aggregate, so both the
    // missing row and the NULL maximum mean "no unpaused tree".
    let Some(tree_id) = model.and_then(|model| model.tree_id) else {
        return Ok(None);
    };

    u16::try_from(tree_id)
        .map(Some)
        .map_err(|_| PhotonApiError::UnexpectedError(format!("Invalid tree id in DB: {}", tree_id)))
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
