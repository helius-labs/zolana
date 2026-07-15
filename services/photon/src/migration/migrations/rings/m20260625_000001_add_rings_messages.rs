use sea_orm_migration::prelude::*;

use super::super::super::model::table::{RingsMessages, RingsTransactions};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RingsMessages::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RingsMessages::MessageId)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RingsMessages::RingsTxId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RingsMessages::Slot).big_integer().not_null())
                    .col(
                        ColumnDef::new(RingsMessages::MessageIndex)
                            .small_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RingsMessages::ViewTag)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(RingsMessages::Payload).binary().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("rings_messages_tx_fk")
                            .from(RingsMessages::Table, RingsMessages::RingsTxId)
                            .to(RingsTransactions::Table, RingsTransactions::RingsTxId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rings_messages_tx_message")
                    .table(RingsMessages::Table)
                    .col(RingsMessages::RingsTxId)
                    .col(RingsMessages::MessageIndex)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rings_messages_view_tag_slot_id")
                    .table(RingsMessages::Table)
                    .col(RingsMessages::ViewTag)
                    .col(RingsMessages::Slot)
                    .col(RingsMessages::MessageId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RingsMessages::Table).to_owned())
            .await
    }
}
