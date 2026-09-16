use sea_orm_migration::prelude::*;

/// Persists key registry state and its fork recovery journal.
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
            "CREATE TABLE key_registry_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            format!(
                "CREATE TABLE key_registry_maps (program {blob} PRIMARY KEY, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE key_registry_pending (program {blob} PRIMARY KEY, slot BIGINT NOT NULL, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE key_registry_members (program {blob} NOT NULL, member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            "CREATE TABLE key_registry_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "key_registry_blocks",
            "key_registry_members",
            "key_registry_pending",
            "key_registry_maps",
            "key_registry_cursor",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM state_trees WHERE tree_kind = 4")
            .await?;
        Ok(())
    }
}
