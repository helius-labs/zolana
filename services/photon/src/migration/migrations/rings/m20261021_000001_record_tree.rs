use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const BINARY_REGISTRY_TREE_KIND: i32 = 3;
const RECORD_TABLES: [&str; 5] = [
    "ring_registries",
    "ring_registry_roots",
    "ring_records",
    "ring_record_nodes",
    "ring_record_queue",
];
const BINARY_TABLES: [&str; 2] = ["ring_member_registry_members", "ring_member_registry_roots"];

/// Drops every ring projection row, the projector reindexes every ring from its start slot.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let mut statements = BINARY_TABLES
            .map(|table| format!("DROP TABLE IF EXISTS {table}"))
            .to_vec();
        statements.extend([
            format!("DELETE FROM state_trees WHERE tree_kind = {BINARY_REGISTRY_TREE_KIND}"),
            format!(
                "CREATE TABLE ring_registries (program {blob} PRIMARY KEY, state TEXT NOT NULL, \
                 pruned BIGINT NOT NULL DEFAULT 0)"
            ),
            format!(
                "CREATE TABLE ring_registry_roots (program {blob} NOT NULL, \
                 applied BIGINT NOT NULL, root {blob} NOT NULL, next_index BIGINT NOT NULL, \
                 slot BIGINT NOT NULL, history_index BIGINT NOT NULL, \
                 PRIMARY KEY(program, applied))"
            ),
            format!(
                "CREATE TABLE ring_records (program {blob} NOT NULL, leaf_index BIGINT NOT NULL, \
                 applied BIGINT NOT NULL, member {blob} NOT NULL, next_member {blob} NOT NULL, \
                 lists BIGINT NOT NULL, escrow_key {blob} NOT NULL, seal TEXT, \
                 PRIMARY KEY(program, leaf_index, applied))"
            ),
            "CREATE INDEX ring_records_member ON ring_records(program, member, applied)".into(),
            "CREATE INDEX ring_records_applied ON ring_records(program, applied)".into(),
            format!(
                "CREATE TABLE ring_record_nodes (program {blob} NOT NULL, level BIGINT NOT NULL, \
                 position BIGINT NOT NULL, applied BIGINT NOT NULL, hash {blob} NOT NULL, \
                 PRIMARY KEY(program, level, position, applied))"
            ),
            "CREATE INDEX ring_record_nodes_applied ON ring_record_nodes(program, applied)".into(),
            format!(
                "CREATE TABLE ring_record_queue (program {blob} NOT NULL, position BIGINT NOT NULL, \
                 member {blob} NOT NULL, mask BIGINT NOT NULL, value BIGINT NOT NULL, \
                 escrow_key {blob} NOT NULL, slot BIGINT NOT NULL, chain {blob} NOT NULL, \
                 seal TEXT, PRIMARY KEY(program, position))"
            ),
        ]);
        execute(manager, statements).await?;
        reset_index(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let mut statements = RECORD_TABLES
            .map(|table| format!("DROP TABLE {table}"))
            .to_vec();
        statements.extend([
            format!(
                "CREATE TABLE ring_member_registry_roots (program {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_member_registry_members (program {blob} NOT NULL, \
                 member {blob} NOT NULL, leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
        ]);
        execute(manager, statements).await?;
        reset_index(manager).await
    }
}

fn blob(manager: &SchemaManager<'_>) -> &'static str {
    match manager.get_database_backend() {
        sea_orm::DatabaseBackend::Postgres => "BYTEA",
        _ => "BLOB",
    }
}

async fn execute(manager: &SchemaManager<'_>, statements: Vec<String>) -> Result<(), DbErr> {
    for sql in statements {
        manager.get_connection().execute_unprepared(&sql).await?;
    }
    Ok(())
}

async fn reset_index(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    for table in [
        "custom_ring_pending",
        "custom_ring_blocks",
        "custom_ring_cursor",
    ] {
        manager
            .get_connection()
            .execute_unprepared(&format!("DELETE FROM {table}"))
            .await?;
    }
    Ok(())
}
