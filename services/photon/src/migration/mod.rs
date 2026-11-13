pub use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseConnection, DbBackend, TransactionTrait};

mod migrations;
mod model;

pub struct RingsMigrator;

pub async fn migrate_up(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr> {
    if db.get_database_backend() == DbBackend::Sqlite {
        // SQLite caches schema per connection. Keep schema reads and DDL on the
        // same connection so an ADD followed by a DROP sees the updated schema.
        let transaction = db.begin().await?;
        RingsMigrator::up(&transaction, steps).await?;
        transaction.commit().await
    } else {
        RingsMigrator::up(db, steps).await
    }
}

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
