use sea_orm_migration::prelude::*;

use super::super::super::model::table::{SquadsKeyEvents, Transactions};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SquadsKeyEvents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SquadsKeyEvents::SquadsKeyEventId)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::Signature)
                            .binary_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::EventIndex)
                            .small_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::Slot)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::SquadsProgramId)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::SourceInstructionTag)
                            .small_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::EventKind)
                            .small_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::Account)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::Owner)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::KeyNonce)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::NewKeyNonce)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::OldStateHash)
                            .binary_len(32)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::RawEvent)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SquadsKeyEvents::ParseVersion)
                            .small_integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("squads_key_events_signature_fk")
                            .from(SquadsKeyEvents::Table, SquadsKeyEvents::Signature)
                            .to(Transactions::Table, Transactions::Signature)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_squads_key_events_signature_event")
                    .table(SquadsKeyEvents::Table)
                    .col(SquadsKeyEvents::Signature)
                    .col(SquadsKeyEvents::EventIndex)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // A key holder recovers by account, oldest key material first.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_squads_key_events_account_nonce_id")
                    .table(SquadsKeyEvents::Table)
                    .col(SquadsKeyEvents::Account)
                    .col(SquadsKeyEvents::KeyNonce)
                    .col(SquadsKeyEvents::SquadsKeyEventId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_squads_key_events_owner_slot_id")
                    .table(SquadsKeyEvents::Table)
                    .col(SquadsKeyEvents::Owner)
                    .col(SquadsKeyEvents::Slot)
                    .col(SquadsKeyEvents::SquadsKeyEventId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SquadsKeyEvents::Table).to_owned())
            .await
    }
}
