use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::super::super::model::table::{RingsTransactions, RingsTxNullifiers};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if merge_view_tag_exists(manager).await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .drop_column(RingsTransactions::MergeViewTag)
                        .to_owned(),
                )
                .await?;
        }
        manager
            .create_index(
                Index::create()
                    .name("idx_rings_tx_nullifiers_nullifier")
                    .table(RingsTxNullifiers::Table)
                    .col(RingsTxNullifiers::Nullifier)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_rings_tx_nullifiers_nullifier")
                    .table(RingsTxNullifiers::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RingsTransactions::Table)
                    .add_column(ColumnDef::new(RingsTransactions::MergeViewTag).binary_len(32))
                    .to_owned(),
            )
            .await
    }
}

async fn merge_view_tag_exists(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    let backend = manager.get_database_backend();
    let query = match backend {
        DbBackend::Sqlite => {
            "SELECT 1 FROM pragma_table_info('rings_transactions') \
             WHERE name = 'merge_view_tag' LIMIT 1"
        }
        DbBackend::Postgres => {
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'rings_transactions' \
             AND column_name = 'merge_view_tag' LIMIT 1"
        }
        DbBackend::MySql => {
            "SELECT 1 FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
             AND table_name = 'rings_transactions' \
             AND column_name = 'merge_view_tag' LIMIT 1"
        }
    };

    Ok(manager
        .get_connection()
        .query_one(Statement::from_string(backend, query))
        .await?
        .is_some())
}
