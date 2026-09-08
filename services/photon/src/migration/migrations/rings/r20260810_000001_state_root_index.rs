use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum TreeMetadata {
    Table,
    StateRoot,
    StateRootIndex,
}

/// Record the UTXO tree's current root and the ring-buffer entry the chain keeps
/// it in, both read straight from the tree account.
///
/// A client must quote the root index alongside its proof, and the program uses
/// that index to load the root it verifies against. A local transaction count
/// cannot reproduce the chain's `root_history_cursor`: the state history adds
/// one entry per slot containing updates, overwriting that entry for later
/// updates in the same slot, while slots without updates add nothing. When the
/// two diverge, photon serves a correct root with an index pointing at a
/// different one, and proof verification fails with no indication that the
/// index is at fault.
///
/// Storing what the chain reports removes the second counter rather than trying
/// to keep it honest. Nullable because a tree that has not been synced yet has
/// no value to record, and serving no index is better than serving a guess.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
}
