use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const REGISTRY_TREE_KIND: i32 = 3;

/// The key registry becomes the member registry, a new tree layout, so every ring
/// projection row goes and the projector reindexes from its start slot.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for table in ["ring_key_registry_members", "ring_key_registry_roots"] {
            conn.execute_unprepared(&format!("DROP TABLE IF EXISTS {table}"))
                .await?;
        }
        for sql in [
            format!(
                "CREATE TABLE ring_member_registry_roots (program {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_member_registry_members (program {blob} NOT NULL, \
                 member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            format!("DELETE FROM state_trees WHERE tree_kind = {REGISTRY_TREE_KIND}"),
            "DELETE FROM ring_projection_pending".to_string(),
            "DELETE FROM ring_projection_blocks".to_string(),
            "DELETE FROM ring_projection_cursor".to_string(),
        ] {
            conn.execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for table in ["ring_member_registry_members", "ring_member_registry_roots"] {
            conn.execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        for sql in [
            format!(
                "CREATE TABLE ring_key_registry_roots (program {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_key_registry_members (program {blob} NOT NULL, \
                 member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            format!("DELETE FROM state_trees WHERE tree_kind = {REGISTRY_TREE_KIND}"),
            "DELETE FROM ring_projection_pending".to_string(),
            "DELETE FROM ring_projection_blocks".to_string(),
            "DELETE FROM ring_projection_cursor".to_string(),
        ] {
            conn.execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}
