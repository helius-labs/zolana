use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::super::super::model::table::RingsOutputs;

/// Gives `rings_outputs` the columns the tag queries sort by, and an index
/// covering filter and sort together.
///
/// The tag queries filter on `rings_outputs.view_tag` but ordered by
/// `rings_transactions.slot, signature, event_index`. No index spans a join, so
/// the planner walked the transactions table and probed outputs per row, at a
/// cost that scaled with history rather than page size.
///
/// The columns are copies of `rings_transactions` values, the same tradeoff
/// `rings_outputs.slot` already makes: one more thing to write correctly at
/// ingest, for a sort that does not need the join.
#[derive(DeriveMigrationName)]
pub struct Migration;

const ORDERING_INDEX: &str = "idx_rings_outputs_view_tag_order";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !column_exists(manager, "signature").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsOutputs::Table)
                        .add_column(ColumnDef::new(RingsOutputs::Signature).binary_len(64))
                        .to_owned(),
                )
                .await?;
        }
        if !column_exists(manager, "event_index").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsOutputs::Table)
                        .add_column(ColumnDef::new(RingsOutputs::EventIndex).small_integer())
                        .to_owned(),
                )
                .await?;
        }

        // Backfill before indexing: the ordering is unusable until every row
        // has a position.
        //
        // Correlated subqueries rather than `UPDATE ... FROM`, which the SQLite
        // the migration tests run against does not share.
        let backend = manager.get_database_backend();
        manager
            .get_connection()
            .execute(Statement::from_string(
                backend,
                "UPDATE rings_outputs
                    SET signature = (
                            SELECT pt.signature FROM rings_transactions pt
                             WHERE pt.rings_tx_id = rings_outputs.rings_tx_id
                        ),
                        event_index = (
                            SELECT pt.event_index FROM rings_transactions pt
                             WHERE pt.rings_tx_id = rings_outputs.rings_tx_id
                        )
                  WHERE signature IS NULL OR event_index IS NULL",
            ))
            .await?;

        // Equality on view_tag first, then the sort key in sort order, so the
        // planner can seek and then walk.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(ORDERING_INDEX)
                    .table(RingsOutputs::Table)
                    .col(RingsOutputs::ViewTag)
                    .col(RingsOutputs::Slot)
                    .col(RingsOutputs::Signature)
                    .col(RingsOutputs::EventIndex)
                    .col(RingsOutputs::OutputIndex)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(ORDERING_INDEX)
                    .table(RingsOutputs::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RingsOutputs::Table)
                    .drop_column(RingsOutputs::EventIndex)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RingsOutputs::Table)
                    .drop_column(RingsOutputs::Signature)
                    .to_owned(),
            )
            .await
    }
}

async fn column_exists(manager: &SchemaManager<'_>, column: &str) -> Result<bool, DbErr> {
    let backend = manager.get_database_backend();
    let query = match backend {
        DbBackend::Sqlite => format!(
            "SELECT 1 FROM pragma_table_info('rings_outputs') WHERE name = '{column}' LIMIT 1"
        ),
        DbBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'rings_outputs' \
             AND column_name = '{column}' LIMIT 1"
        ),
        DbBackend::MySql => format!(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
             AND table_name = 'rings_outputs' \
             AND column_name = '{column}' LIMIT 1"
        ),
    };

    Ok(manager
        .get_connection()
        .query_one(Statement::from_string(backend, query))
        .await?
        .is_some())
}
