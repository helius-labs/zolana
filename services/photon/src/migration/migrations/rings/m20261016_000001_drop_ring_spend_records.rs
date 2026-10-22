use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The ring projection no longer tracks spend records, the tables go with them.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for table in ["ring_spend_records", "ring_spend_record_rings"] {
            conn.execute_unprepared(&format!("DROP TABLE IF EXISTS {table}"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
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
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}
