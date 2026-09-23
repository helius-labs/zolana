use sea_orm::Statement;
use sea_orm_migration::prelude::*;

use super::m20260913_000001_head_maps;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let conn = manager.get_connection();
        for sql in [
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
            conn.execute_unprepared(&sql).await?;
        }
        // Records written before this migration exist only in chain history.
        replay_from_start(manager).await?;
        for table in [
            "ring_head_map_members",
            "ring_head_map_roots",
            "ring_head_blocks",
            "ring_head_members",
            "ring_head_pending",
            "ring_head_maps",
            "ring_head_cursor",
        ] {
            conn.execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let conn = manager.get_connection();
        m20260913_000001_head_maps::Migration.up(manager).await?;
        for sql in [
            format!(
                "CREATE TABLE ring_head_map_roots (program {blob} PRIMARY KEY, state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE ring_head_map_members (program {blob} NOT NULL, member {blob} NOT NULL, \
                 leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ),
            "DROP TABLE ring_spend_records".to_string(),
            "DROP TABLE ring_spend_record_rings".to_string(),
        ] {
            conn.execute_unprepared(&sql).await?;
        }
        replay_from_start(manager).await
    }
}

fn blob(manager: &SchemaManager<'_>) -> &'static str {
    match manager.get_database_backend() {
        sea_orm::DatabaseBackend::Postgres => "BYTEA",
        _ => "BLOB",
    }
}

/// Keeps the stored start slot and clears every projected row.
async fn replay_from_start(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let Some(row) = conn
        .query_one(Statement::from_string(
            backend,
            "SELECT state FROM ring_projection_cursor WHERE id=1".to_string(),
        ))
        .await?
    else {
        return Ok(());
    };
    let raw: String = row.try_get("", "state")?;
    let cursor: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| DbErr::Migration(error.to_string()))?;
    let start = cursor["start_slot"]
        .as_u64()
        .ok_or_else(|| DbErr::Migration("ring projection has no start slot".into()))?;
    for sql in [
        "DELETE FROM ring_key_registry_members",
        "DELETE FROM ring_key_registry_roots",
        "DELETE FROM ring_projection_blocks",
        "DELETE FROM ring_projection_pending",
        "DELETE FROM state_trees WHERE tree_kind IN (3,4)",
    ] {
        conn.execute_unprepared(sql).await?;
    }
    let cursor = serde_json::json!({
        "start_slot": start, "scanned_slot": start, "tip": null,
        "revision": 0, "ready": false,
    });
    conn.execute(Statement::from_sql_and_values(
        backend,
        "UPDATE ring_projection_cursor SET state=$1 WHERE id=1",
        [cursor.to_string().into()],
    ))
    .await?;
    Ok(())
}
