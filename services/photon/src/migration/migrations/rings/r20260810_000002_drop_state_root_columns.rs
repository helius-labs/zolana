use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum TreeMetadata {
    Table,
    StateRoot,
    StateRootIndex,
}

/// Drop the single `(state_root, state_root_index)` pair added a migration
/// earlier.
///
/// It could only answer for the newest root. The chain appends a root on every
/// transaction with outputs, and photon serves proofs against whichever root it
/// has indexed, so by request time the stored pair usually described a root the
/// tree had already moved past -- leaving the index unanswerable a moment after
/// each sync.
///
/// The index now comes from an in-process cache of the whole root-history ring,
/// refreshed from the tree account on a miss. Nothing reads these columns.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .drop_column(TreeMetadata::StateRoot)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .drop_column(TreeMetadata::StateRootIndex)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .add_column(ColumnDef::new(TreeMetadata::StateRoot).binary().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .add_column(
                        ColumnDef::new(TreeMetadata::StateRootIndex)
                            .integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
