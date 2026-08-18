use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::super::super::model::table::RingsTransactions;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Replace `rings_program_id` with `ring_config`.
    ///
    /// `rings_program_id` was bound to the pool's own program id, so every row
    /// held the same constant. The column is dropped rather than renamed: its
    /// bytes are not ring configs, and carrying them over would make "no ring"
    /// indistinguishable from a ring. Rows indexed before this stay NULL until
    /// reindexed -- the signed `ring_config` account is not recoverable from
    /// what was persisted.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The old column carries an index; drop it first so the column drop is
        // not blocked and no index survives pointing at a dropped column.
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_rings_transactions_program_slot_id")
                    .table(RingsTransactions::Table)
                    .to_owned(),
            )
            .await?;
        if column_exists(manager, "rings_program_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .drop_column(Alias::new("rings_program_id"))
                        .to_owned(),
                )
                .await?;
        }
        if !column_exists(manager, "ring_config").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .add_column(ColumnDef::new(RingsTransactions::RingConfig).binary_len(32))
                        .to_owned(),
                )
                .await?;
        }
        // Same shape as the index it replaces: the lookup is "this ring's
        // transactions, in order".
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rings_transactions_ring_config_slot_id")
                    .table(RingsTransactions::Table)
                    .col(RingsTransactions::RingConfig)
                    .col(RingsTransactions::Slot)
                    .col(RingsTransactions::RingsTxId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    /// Restores the column's shape, not its contents. The old constant is not
    /// worth reconstructing, so the restored column is nullable.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_rings_transactions_ring_config_slot_id")
                    .table(RingsTransactions::Table)
                    .to_owned(),
            )
            .await?;
        if column_exists(manager, "ring_config").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .drop_column(RingsTransactions::RingConfig)
                        .to_owned(),
                )
                .await?;
        }
        if !column_exists(manager, "rings_program_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .add_column(ColumnDef::new(Alias::new("rings_program_id")).binary_len(32))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

async fn column_exists(manager: &SchemaManager<'_>, column: &str) -> Result<bool, DbErr> {
    let backend = manager.get_database_backend();
    let query = match backend {
        DbBackend::Sqlite => format!(
            "SELECT 1 FROM pragma_table_info('rings_transactions') \
             WHERE name = '{column}' LIMIT 1"
        ),
        DbBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'rings_transactions' \
             AND column_name = '{column}' LIMIT 1"
        ),
        DbBackend::MySql => format!(
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
             AND table_name = 'rings_transactions' \
             AND column_name = '{column}' LIMIT 1"
        ),
    };

    Ok(manager
        .get_connection()
        .query_one(Statement::from_string(backend, query))
        .await?
        .is_some())
}
