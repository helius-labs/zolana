use sea_orm_migration::prelude::*;

use super::super::super::model::table::RingsOutputs;

/// Indexes `rings_outputs` by leaf hash within its tree.
///
/// `getMerkleProofs` resolves each requested leaf with `output_tree = ? AND
/// utxo_hash IN (...)`. The only index starting with `output_tree` continues
/// with `leaf_index`, and a deployment usually has one tree, so the lookup read
/// every output the tree ever had: on devnet-e (253k outputs) a parallel
/// sequential scan of 8 ms per call against 0.04 ms with this index, and the
/// cost grew with the tree. Under load it saturated the database at ~28
/// transfers/s, since every spend proves its inputs through this lookup.
///
/// Not unique: uniqueness of a UTXO hash is the program's concern, and a
/// unique index would turn any historical duplicate into a failed migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

const UTXO_HASH_INDEX: &str = "idx_rings_outputs_tree_utxo_hash";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(UTXO_HASH_INDEX)
                    .table(RingsOutputs::Table)
                    .col(RingsOutputs::OutputTree)
                    .col(RingsOutputs::UtxoHash)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(UTXO_HASH_INDEX)
                    .table(RingsOutputs::Table)
                    .to_owned(),
            )
            .await
    }
}
