pub use sea_orm_migration::prelude::*;

mod migrations;
mod model;

pub struct RingsMigrator;

#[async_trait::async_trait]
impl MigratorTrait for RingsMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        migrations::rings::get_rings_migrations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, Statement};

    #[tokio::test]
    async fn rings_migrator_creates_rings_product_tables() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();

        assert!(table_exists(&db, "state_trees").await);
        assert!(table_exists(&db, "indexed_trees").await);
        assert!(table_exists(&db, "tree_metadata").await);
        assert!(table_exists(&db, "rings_transactions").await);
    }

    #[tokio::test]
    async fn rings_migrator_can_roll_back() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        RingsMigrator::down(&db, None).await.unwrap();

        assert!(!table_exists(&db, "rings_transactions").await);
        assert!(!table_exists(&db, "state_trees").await);
    }

    #[tokio::test]
    async fn legacy_ring_projection_upgrade_replays_from_earliest_start_and_preserves_spp() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, Some(13)).await.unwrap();
        for (table, start) in [("ring_head_cursor", 20), ("key_registry_cursor", 10)] {
            let cursor = serde_json::json!({"start_slot": start, "scanned_slot": 90,
                "tip": null, "revision": 400, "ready": true});
            db.execute(Statement::from_sql_and_values(
                db.get_database_backend(),
                format!("INSERT INTO {table}(id,state) VALUES(1,$1)"),
                [cursor.to_string().into()],
            ))
            .await
            .unwrap();
        }
        for kind in [1, 3, 4] {
            db.execute(Statement::from_sql_and_values(db.get_database_backend(),
                "INSERT INTO state_trees(tree,tree_kind,node_idx,level,hash,seq) VALUES($1,$2,1,40,$3,7)",
                vec![vec![1u8; 32].into(), kind.into(), vec![2u8; 32].into()],
            )).await.unwrap();
        }
        RingsMigrator::up(&db, None).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SELECT state FROM ring_projection_cursor WHERE id=1".to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        let cursor: serde_json::Value =
            serde_json::from_str(&row.try_get::<String>("", "state").unwrap()).unwrap();
        assert_eq!(cursor["start_slot"], 10);
        assert_eq!(cursor["scanned_slot"], 10);
        assert_eq!(cursor["ready"], false);
        assert!(cursor["tip"].is_null());
        let rows = db
            .query_all(Statement::from_string(
                db.get_database_backend(),
                "SELECT tree_kind,hash,seq FROM state_trees".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<i32>("", "tree_kind").unwrap(), 1);
        assert_eq!(
            rows[0].try_get::<Vec<u8>>("", "hash").unwrap(),
            vec![2u8; 32]
        );
        assert_eq!(rows[0].try_get::<i64>("", "seq").unwrap(), 7);
        RingsMigrator::up(&db, None).await.unwrap();
        RingsMigrator::down(&db, None).await.unwrap();
    }

    #[tokio::test]
    async fn an_already_unified_projection_keeps_its_cursor_on_compatibility_upgrade() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, Some(14)).await.unwrap();
        let cursor = serde_json::json!({"start_slot": 17, "scanned_slot": 99,
            "tip": null, "revision": 500, "ready": false})
        .to_string();
        db.execute(Statement::from_sql_and_values(
            db.get_database_backend(),
            "INSERT INTO ring_projection_cursor(id,state) VALUES(1,$1)",
            [cursor.clone().into()],
        ))
        .await
        .unwrap();
        for prefix in ["ring_head", "key_registry"] {
            for suffix in ["cursor", "maps", "pending", "members", "blocks"] {
                db.execute_unprepared(&format!("DROP TABLE {prefix}_{suffix}"))
                    .await
                    .unwrap();
            }
        }
        db.execute_unprepared("DELETE FROM seaql_migrations WHERE version IN ('m20260913_000001_head_maps', 'm20260914_000001_key_registry')").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SELECT state FROM ring_projection_cursor WHERE id=1".to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "state").unwrap(), cursor);
    }

    #[tokio::test]
    async fn interrupted_compatibility_upgrade_keeps_the_earliest_persisted_start() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, Some(14)).await.unwrap();
        // A cleared cursor can leave an unrecorded migration.
        for (table, start) in [("ring_projection_cursor", 10), ("key_registry_cursor", 20)] {
            let cursor = serde_json::json!({"start_slot": start, "scanned_slot": start,
                "tip": null, "revision": 0, "ready": false});
            db.execute(Statement::from_sql_and_values(
                db.get_database_backend(),
                format!("INSERT INTO {table}(id,state) VALUES(1,$1)"),
                [cursor.to_string().into()],
            ))
            .await
            .unwrap();
        }
        RingsMigrator::up(&db, None).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SELECT state FROM ring_projection_cursor WHERE id=1".to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        let cursor: serde_json::Value =
            serde_json::from_str(&row.try_get::<String>("", "state").unwrap()).unwrap();
        assert_eq!(cursor["start_slot"], 10);
        assert_eq!(cursor["scanned_slot"], 10);
        assert_eq!(cursor["ready"], false);
        RingsMigrator::up(&db, None).await.unwrap();
    }

    async fn table_exists(
        db: &sea_orm_migration::sea_orm::DatabaseConnection,
        table: &str,
    ) -> bool {
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                format!(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = '{}'",
                    table
                ),
            ))
            .await
            .unwrap()
            .unwrap();
        let count: i64 = row.try_get("", "count").unwrap();
        count > 0
    }
}
