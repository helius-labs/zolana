use sea_orm_migration::prelude::*;

use super::super::super::model::table::RingConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// The ring registry: `ring_config` (the ring's `ring_auth` PDA) to the
    /// program that owns it.
    ///
    /// Append-only. The pool writes `program_id` once, at `create_ring_config`,
    /// where it is also the sole check that the config account is that program's
    /// `ring_auth` PDA; no later instruction rewrites it. So a row is never
    /// updated, and the mapping it records cannot change under it.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RingConfigs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RingConfigs::RingConfig)
                            .binary_len(32)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RingConfigs::ProgramId)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RingConfigs::Authority)
                            .binary_len(32)
                            .not_null(),
                    )
                    .col(ColumnDef::new(RingConfigs::Slot).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        // Resolving a transaction's ring to its program is the read this table
        // exists for; the reverse lookup uses the primary key.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_ring_configs_program_id")
                    .table(RingConfigs::Table)
                    .col(RingConfigs::ProgramId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RingConfigs::Table).to_owned())
            .await
    }
}
