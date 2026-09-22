use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum TreeMetadata {
    Table,
    TreeId,
    Paused,
}

/// Record the raw `u16` tree id the tree account carries, and whether the chain
/// has that tree paused.
///
/// Both land together because both are read off the same already-parsed
/// `TreeAccount` in `process_rings_tree_account`, and because the id alone is
/// not enough to answer "where should this client append?". A paused tree
/// rejects every append (`TreeAccount::from_account_view_mut` returns
/// `TreeError::Paused`), so naming the newest tree without checking its state
/// would send every wallet at a tree that cannot accept them.
///
/// Both columns are nullable on purpose, and deliberately not backfilled. Tree
/// id `0` is a valid id and `false` is a valid state, so a `NOT NULL DEFAULT`
/// could not be told apart from a row that has not been synced yet.
/// `sync_tree_metadata` is a full `get_program_accounts` scan that runs at every
/// startup, before the API serves, so every row gains both values on the next
/// boot without a data migration.
///
/// One `alter_table` per column: SQLite adds a single column per statement.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .add_column(ColumnDef::new(TreeMetadata::TreeId).integer().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .add_column(ColumnDef::new(TreeMetadata::Paused).boolean().null())
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
                    .drop_column(TreeMetadata::TreeId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TreeMetadata::Table)
                    .drop_column(TreeMetadata::Paused)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
