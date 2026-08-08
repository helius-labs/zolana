use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::super::super::model::table::RingsOutputs;

/// Give `rings_outputs` the columns the tag queries sort by, and an index that
/// covers filter and sort together.
///
/// `get_encrypted_utxos_by_tags` and `get_shielded_transactions_by_tags` filter
/// on `rings_outputs.view_tag` but order by `rings_transactions.slot,
/// signature, event_index`. No index can span a join, so Postgres walked
/// `rings_transactions` in slot order and probed outputs for each row. Measured
/// on devnet with the real cursor predicate, returning 101 rows: it examined
/// ~3540 transactions, discarded 3076 by filter, and got nothing back from 464
/// of 464 probes -- 1.854ms and 3440 buffers.
///
/// The cost scaled with transaction history rather than with the page size,
/// which is why sync time grew from 823ms to 4164ms on unchanged wallets inside
/// a single day, and why one query shape accounted for 17.16 of ~17.6 average
/// active sessions on a 2 vCPU instance.
///
/// With `signature` and `event_index` on the outputs table, the same page is an
/// index range scan that stops at LIMIT: 0.326ms and 661 buffers, and flat as
/// the tables grow.
///
/// These are copies of `rings_transactions` values. That is the same tradeoff
/// `rings_outputs.slot` already makes -- one more thing to write correctly at
/// ingest, in exchange for a query that does not need the join to sort.
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

        // Backfill before indexing: an index built over NULLs would have to be
        // rebuilt anyway, and the ordering is unusable until every row has one.
        //
        // Correlated subqueries rather than `UPDATE ... FROM`, which is Postgres
        // syntax the SQLite the migration tests run against does not share. One
        // pass over a table this size is cheap enough not to trade portability
        // for it.
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

        // Column order matters: equality on view_tag first, then the sort key in
        // sort order, so the planner can seek and then walk.
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
