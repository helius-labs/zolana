use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, DbBackend, Statement};

use super::super::super::model::table::RingsTransactions;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Borsh `Vec<SplTransfer>` for the event's public settlement legs.
    ///
    /// NULL is an event indexed before the column existed: the legs are not
    /// recoverable from the stored payload, so a client still reads them from
    /// the confirmed transaction. An empty encoding is an event that settled
    /// nothing. The two must stay distinct.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !column_exists(manager, "spl_transfers").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .add_column(
                            ColumnDef::new(RingsTransactions::SplTransfers)
                                .binary()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if column_exists(manager, "spl_transfers").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(RingsTransactions::Table)
                        .drop_column(RingsTransactions::SplTransfers)
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
