use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum TreeMetadata {
    Table,
    StateRoot,
    StateRootIndex,
}

/// Record the UTXO tree's current root and the ring-buffer slot the chain keeps
/// it in, both read straight from the tree account.
///
/// A client must quote the root index alongside its proof, and the program uses
/// that index to load the root it verifies against. photon used to derive the
/// index from a sequence number it counted itself, once per indexed
/// transaction, which only matches the chain's `root_history_cursor` for as
/// long as the two happen to advance in step. They diverged, and the failure is
/// silent: photon serves a correct root with an index pointing at a different
/// one, and every proof fails verification with no indication that an index is
/// at fault.
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
