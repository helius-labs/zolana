use photon_indexer::migration::{migrate_up, MigratorTrait, RingsMigrator};
use sea_orm::SqlxSqliteConnector;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

async fn database() -> (std::path::PathBuf, SqlitePool) {
    let path = std::env::temp_dir().join(format!(
        "photon-migrations-{}-{}.db",
        std::process::id(),
        rand::random::<u64>()
    ));
    let pool = SqlitePoolOptions::new()
        .min_connections(10)
        .max_connections(10)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    (path, pool)
}

async fn assert_migrated(pool: &SqlitePool) {
    let versions: Vec<String> =
        sqlx::query_scalar("SELECT version FROM seaql_migrations ORDER BY rowid")
            .fetch_all(pool)
            .await
            .unwrap();
    let expected: Vec<String> = RingsMigrator::migrations()
        .iter()
        .map(|migration| migration.name().to_owned())
        .collect();
    assert_eq!(versions, expected, "Every migration must be recorded");

    let removed_columns: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM pragma_table_info('rings_transactions') WHERE name = 'merge_view_tag'
         UNION ALL
         SELECT name FROM pragma_table_info('tree_metadata')
         WHERE name IN ('state_root', 'state_root_index')",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(removed_columns, Vec::<String>::new());
}

#[tokio::test]
async fn fresh_pooled_wal_migrations_complete_repeatedly() {
    for _ in 0..50 {
        let (path, pool) = database().await;
        let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool.clone());
        migrate_up(&db, None).await.unwrap();
        assert_migrated(&pool).await;
        db.close().await.unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn pooled_wal_migrations_resume_before_each_column_removal() {
    for steps in [5, 8] {
        let (path, pool) = database().await;
        let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool.clone());
        migrate_up(&db, Some(steps)).await.unwrap();
        migrate_up(&db, None).await.unwrap();
        migrate_up(&db, None).await.unwrap();
        assert_migrated(&pool).await;
        db.close().await.unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn failed_sqlite_migrations_roll_back_schema_and_records() {
    let (path, pool) = database().await;
    let db = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool.clone());
    migrate_up(&db, Some(5)).await.unwrap();
    sqlx::query(
        "CREATE INDEX idx_rings_tx_nullifiers_nullifier ON rings_tx_nullifiers (nullifier)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let error = migrate_up(&db, None).await.unwrap_err();
    assert!(error.to_string().contains("already exists"), "{error}");
    let state: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM seaql_migrations),
                (SELECT COUNT(*) FROM pragma_table_info('rings_transactions')
                 WHERE name = 'merge_view_tag')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, (5, 1), "Failed DROP must leave the schema unchanged");

    sqlx::query("DROP INDEX idx_rings_tx_nullifiers_nullifier")
        .execute(&pool)
        .await
        .unwrap();
    migrate_up(&db, None).await.unwrap();
    assert_migrated(&pool).await;
    db.close().await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sqlite_migration_cli_supports_the_full_lifecycle() {
    let (path, pool) = database().await;
    let url = format!("sqlite://{}", path.display());
    for arguments in [
        vec!["up", "--num", "5"],
        vec![],
        vec!["down", "--num", "1"],
        vec!["up"],
        vec!["fresh"],
        vec!["refresh"],
        vec!["status"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_photon-migration"))
            .args(["--database-url", &url])
            .args(&arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_migrated(&pool).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_photon-migration"))
        .args(["--database-url", &url, "reset"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM seaql_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "Reset must roll back every migration");
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}
