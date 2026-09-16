use sea_orm::Statement;
use sea_orm_migration::prelude::*;

/// Rebuilds incompatible projection journals and preserves indexed SPP state.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let mut start = None;
        // 1. Replay must start from the earliest stored cursor.
        for table in ["ring_head_cursor", "key_registry_cursor"] {
            if let Some(row) = conn
                .query_one(Statement::from_string(
                    conn.get_database_backend(),
                    format!("SELECT state FROM {table} WHERE id=1"),
                ))
                .await?
            {
                let raw: String = row.try_get("", "state")?;
                let cursor: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|error| DbErr::Migration(error.to_string()))?;
                let slot = cursor["start_slot"].as_u64().ok_or_else(|| {
                    DbErr::Migration("legacy projection has no start slot".into())
                })?;
                start = Some(start.map_or(slot, |existing: u64| existing.min(slot)));
            }
        }
        if let Some(mut start) = start {
            // SQLite may retry after one legacy cursor was already cleared.
            if let Some(row) = conn
                .query_one(Statement::from_string(
                    conn.get_database_backend(),
                    "SELECT state FROM ring_projection_cursor WHERE id=1".to_string(),
                ))
                .await?
            {
                let raw: String = row.try_get("", "state")?;
                let cursor: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|error| DbErr::Migration(error.to_string()))?;
                let persisted_start = cursor["start_slot"].as_u64().ok_or_else(|| {
                    DbErr::Migration("unified projection has no start slot".into())
                })?;
                start = start.min(persisted_start);
            }
            // 2. Incompatible journals require replay from a shared start slot.
            for table in [
                "ring_head_map_members",
                "ring_head_map_roots",
                "ring_key_registry_members",
                "ring_key_registry_roots",
                "ring_projection_blocks",
                "ring_projection_pending",
            ] {
                conn.execute_unprepared(&format!("DELETE FROM {table}"))
                    .await?;
            }
            conn.execute_unprepared("DELETE FROM state_trees WHERE tree_kind IN (3,4)")
                .await?;
            let cursor = serde_json::json!({
                "start_slot": start, "scanned_slot": start, "tip": null,
                "revision": 0, "ready": false,
            });
            conn.execute(Statement::from_sql_and_values(
                conn.get_database_backend(),
                // The earliest checkpoint must survive interrupted migration.
                "INSERT INTO ring_projection_cursor(id,state) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                [cursor.to_string().into()],
            ))
            .await?;
        }
        // 3. Rollback needs the legacy schemas with no stale projection state.
        for table in [
            "ring_head_cursor",
            "ring_head_maps",
            "ring_head_pending",
            "ring_head_members",
            "ring_head_blocks",
            "key_registry_cursor",
            "key_registry_maps",
            "key_registry_pending",
            "key_registry_members",
            "key_registry_blocks",
        ] {
            conn.execute_unprepared(&format!("DELETE FROM {table}"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Earlier migrations own the projection schemas.
        Ok(())
    }
}
