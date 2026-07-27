use sea_orm_migration::prelude::*;

use super::super::super::model::table::{RingsTransactions, RingsTxNullifiers};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RingsTransactions::Table)
                    .drop_column(RingsTransactions::MergeViewTag)
                    .to_owned(),
            )
            .await?;
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
