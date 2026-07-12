use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, Statement},
};

use crate::migration::model::table::{Blocks, IndexedTrees, StateTrees, Transactions};

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn execute_sql(manager: &SchemaManager<'_>, sql: &str) -> Result<(), DbErr> {
    manager
        .get_connection()
        .execute(Statement::from_string(
            manager.get_database_backend(),
            sql.to_string(),
        ))
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(StateTrees::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(StateTrees::Tree).binary().not_null())
                    .col(ColumnDef::new(StateTrees::TreeKind).integer().not_null())
                    .col(ColumnDef::new(StateTrees::NodeIdx).big_integer().not_null())
                    .col(ColumnDef::new(StateTrees::LeafIdx).big_integer())
                    .col(ColumnDef::new(StateTrees::Level).big_integer().not_null())
                    .col(ColumnDef::new(StateTrees::Hash).binary().not_null())
                    .col(ColumnDef::new(StateTrees::Seq).big_integer())
                    .primary_key(
                        Index::create()
                            .name("pk_state_trees")
                            .col(StateTrees::Tree)
                            .col(StateTrees::TreeKind)
                            .col(StateTrees::NodeIdx),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("state_trees_tree_leaf_idx")
                    .table(StateTrees::Table)
                    .col(StateTrees::Tree)
                    .col(StateTrees::TreeKind)
                    .col(StateTrees::LeafIdx)
                    .unique()
                    .to_owned(),
            )
            .await?;
        execute_sql(
            manager,
            "CREATE INDEX IF NOT EXISTS state_trees_hash_idx ON state_trees (hash) WHERE level = 0",
        )
        .await?;

        manager
            .create_table(
                Table::create()
                    .table(IndexedTrees::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IndexedTrees::Tree).binary().not_null())
                    .col(
                        ColumnDef::new(IndexedTrees::LeafIndex)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(IndexedTrees::Value).binary().not_null())
                    .col(
                        ColumnDef::new(IndexedTrees::NextIndex)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(IndexedTrees::NextValue).binary().not_null())
                    .col(ColumnDef::new(IndexedTrees::Seq).big_integer())
                    .primary_key(
                        Index::create()
                            .name("pk_indexed_trees")
                            .col(IndexedTrees::Tree)
                            .col(IndexedTrees::LeafIndex),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("indexed_trees_tree_value_idx")
                    .table(IndexedTrees::Table)
                    .col(IndexedTrees::Tree)
                    .col(IndexedTrees::Value)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Blocks::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Blocks::Slot).big_integer().not_null())
                    .col(ColumnDef::new(Blocks::ParentSlot).big_integer().not_null())
                    .col(ColumnDef::new(Blocks::ParentBlockhash).binary().not_null())
                    .col(ColumnDef::new(Blocks::Blockhash).binary().not_null())
                    .col(ColumnDef::new(Blocks::BlockHeight).big_integer().not_null())
                    .col(ColumnDef::new(Blocks::BlockTime).big_integer().not_null())
                    .primary_key(Index::create().name("pk_blocks").col(Blocks::Slot))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Transactions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Transactions::Signature).binary().not_null())
                    .col(ColumnDef::new(Transactions::Slot).big_integer().not_null())
                    .col(ColumnDef::new(Transactions::Error).text())
                    .primary_key(
                        Index::create()
                            .name("pk_transactions")
                            .col(Transactions::Signature),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("transactions_slot_fk")
                            .from(Transactions::Table, Transactions::Slot)
                            .to(Blocks::Table, Blocks::Slot)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("transactions_slot_signature_idx")
                    .table(Transactions::Table)
                    .col(Transactions::Slot)
                    .col(Transactions::Signature)
                    .unique()
                    .to_owned(),
            )
            .await?;

        create_tree_metadata(manager).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("tree_metadata"))
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(Transactions::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Blocks::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(IndexedTrees::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(StateTrees::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

async fn create_tree_metadata(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Alias::new("tree_metadata");
    manager
        .create_table(
            Table::create()
                .table(table.clone())
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("tree_pubkey"))
                        .binary_len(32)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Alias::new("queue_pubkey"))
                        .binary_len(32)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("height")).integer().not_null())
                .col(
                    ColumnDef::new(Alias::new("root_history_capacity"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("sequence_number"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("next_index"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("last_synced_slot"))
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("idx_tree_metadata_queue_pubkey")
                .table(table.clone())
                .col(Alias::new("queue_pubkey"))
                .to_owned(),
        )
        .await?;

    Ok(())
}
