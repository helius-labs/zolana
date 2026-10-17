use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The custom ring indexer's own tables, renamed with the module. The
/// `ring_key_registry_*` and `ring_spend_record*` tables are named after their
/// content and keep their names.
const TABLES: [(&str, &str); 3] = [
    ("ring_projection_cursor", "custom_ring_cursor"),
    ("ring_projection_blocks", "custom_ring_blocks"),
    ("ring_projection_pending", "custom_ring_pending"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (from, to) in TABLES {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE {from} RENAME TO {to}"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (from, to) in TABLES {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE {to} RENAME TO {from}"))
                .await?;
        }
        Ok(())
    }
}
