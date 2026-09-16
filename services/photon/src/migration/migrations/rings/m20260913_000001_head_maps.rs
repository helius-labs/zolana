use sea_orm_migration::prelude::*;

/// Creates persistent head state and the journal needed for fork recovery.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            "CREATE TABLE ring_head_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            format!(
                "CREATE TABLE ring_head_maps (program {blob} PRIMARY KEY, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_head_pending (program {blob} PRIMARY KEY, slot BIGINT NOT NULL, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_head_members (program {blob} NOT NULL, member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            "CREATE TABLE ring_head_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "ring_head_blocks",
            "ring_head_members",
            "ring_head_pending",
            "ring_head_maps",
            "ring_head_cursor",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM state_trees WHERE tree_kind = 3")
            .await?;
        Ok(())
    }
}
