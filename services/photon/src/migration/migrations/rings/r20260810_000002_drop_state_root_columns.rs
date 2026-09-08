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
/// It could only answer for the newest root. The chain retains one final root
/// for each slot that updates the tree, while photon may serve proofs against
/// any retained root it has indexed. A single pair therefore cannot resolve an
/// older, still-valid proof root after the tree advances.
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
