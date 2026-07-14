use sea_orm_migration::prelude::*;

use crate::migration::model::table::RingsTxNullifiers;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum TreeMetadata {
    Table,
    InputQueueZkpBatchSize,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .add_column(
                        ColumnDef::new(TreeMetadata::InputQueueZkpBatchSize)
                            .big_integer()
                            .not_null()
                            .default(
                                zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE
                                    as i64,
                            ),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rings_tx_nullifiers_tree_queue_seq")
                    .table(RingsTxNullifiers::Table)
                    .col(RingsTxNullifiers::NullifierTree)
                    .col(RingsTxNullifiers::InputQueueSeq)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_rings_tx_nullifiers_tree_queue_seq")
                    .table(RingsTxNullifiers::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .drop_column(TreeMetadata::InputQueueZkpBatchSize)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
