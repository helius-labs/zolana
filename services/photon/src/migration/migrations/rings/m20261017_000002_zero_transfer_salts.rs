use sea_orm_migration::prelude::*;

use super::super::super::model::table::RingsTransactions;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// The parser previously collapsed an all-zero salt into NULL, even when a
    /// viewing key was present. Restore those bytes without replaying history.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let query = Query::update()
            .table(RingsTransactions::Table)
            .value(RingsTransactions::Salt, vec![0u8; 16])
            .and_where(Expr::col(RingsTransactions::Salt).is_null())
            .and_where(Expr::col(RingsTransactions::TxViewingPk).is_not_null())
            .to_owned();
        manager
            .get_connection()
            .execute(manager.get_database_backend().build(&query))
            .await?;
        Ok(())
    }

    // This repairs data. Rolling back the schema must not discard it again.
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::sea_orm::{Database, Statement};

    #[tokio::test]
    async fn restores_only_missing_salts_with_a_viewing_key() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE rings_transactions (id INTEGER, salt BLOB, tx_viewing_pk BLOB)",
        )
        .await
        .unwrap();
        db.execute_unprepared(
            "INSERT INTO rings_transactions VALUES
             (1, NULL, X'01'), (2, X'02', X'01'), (3, NULL, NULL)",
        )
        .await
        .unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        Migration.down(&manager).await.unwrap();
        let rows = db
            .query_all(Statement::from_string(
                db.get_database_backend(),
                "SELECT salt FROM rings_transactions ORDER BY id".to_owned(),
            ))
            .await
            .unwrap();
        let salts: Vec<Option<Vec<u8>>> = rows
            .iter()
            .map(|row| row.try_get("", "salt").unwrap())
            .collect();
        assert_eq!(salts, vec![Some(vec![0; 16]), Some(vec![2]), None]);
    }
}
