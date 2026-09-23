use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const KEY_REGISTRY_TREE_KIND: i32 = 3;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        for sql in [
            "CREATE TABLE ring_projection_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            "CREATE TABLE ring_projection_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            format!(
                "CREATE TABLE ring_projection_pending (program {blob} PRIMARY KEY, \
                 slot BIGINT NOT NULL, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_key_registry_roots (program {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_key_registry_members (program {blob} NOT NULL, \
                 member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            format!(
                "CREATE TABLE ring_spend_record_rings (program {blob} PRIMARY KEY, fault TEXT)"
            ),
            format!(
                "CREATE TABLE ring_spend_records (program {blob} NOT NULL, member {blob} NOT NULL, \
                 nullifier {blob} NOT NULL, signature {blob} NOT NULL, event_index INTEGER NOT NULL, \
                 output_index INTEGER NOT NULL, slot BIGINT NOT NULL, PRIMARY KEY(program, member))"
            ),
            "CREATE INDEX ring_spend_records_nullifier ON ring_spend_records(program, nullifier)"
                .to_string(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for table in [
            "ring_spend_records",
            "ring_spend_record_rings",
            "ring_key_registry_members",
            "ring_key_registry_roots",
            "ring_projection_pending",
            "ring_projection_blocks",
            "ring_projection_cursor",
        ] {
            conn.execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        conn.execute_unprepared(&format!(
            "DELETE FROM state_trees WHERE tree_kind = {KEY_REGISTRY_TREE_KIND}"
        ))
        .await?;
        Ok(())
    }
}
