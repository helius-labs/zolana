use sea_orm_migration::prelude::*;

use super::super::super::model::table::RingsTransactions;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RingsTransactions::Table)
                    .add_column(ColumnDef::new(RingsTransactions::MergeViewTag).binary_len(32))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RingsTransactions::Table)
                    .drop_column(RingsTransactions::MergeViewTag)
                    .to_owned(),
            )
            .await
    }
}
