use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

struct Projection {
    prefix: &'static str,
    tree_kind: i32,
}

const PROJECTIONS: [Projection; 2] = [
    Projection {
        prefix: "ring_head_map",
        tree_kind: 3,
    },
    Projection {
        prefix: "ring_key_registry",
        tree_kind: 4,
    },
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        let mut statements = vec![
            "CREATE TABLE ring_projection_cursor (id INTEGER PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            "CREATE TABLE ring_projection_blocks (slot BIGINT PRIMARY KEY, state TEXT NOT NULL)"
                .to_string(),
            format!(
                "CREATE TABLE ring_projection_pending (program {blob} PRIMARY KEY, \
                 slot BIGINT NOT NULL, state TEXT NOT NULL)"
            ),
        ];
        for Projection { prefix, .. } in PROJECTIONS {
            statements.push(format!(
                "CREATE TABLE {prefix}_roots (program {blob} PRIMARY KEY, state TEXT NOT NULL)"
            ));
            statements.push(format!(
                "CREATE TABLE {prefix}_members (program {blob} NOT NULL, member {blob} NOT NULL, \
                 leaf_index BIGINT NOT NULL, state TEXT NOT NULL, \
                 PRIMARY KEY(program, member), UNIQUE(program, leaf_index))"
            ));
        }
        for sql in statements {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut statements = Vec::new();
        for Projection { prefix, tree_kind } in PROJECTIONS {
            statements.push(format!("DROP TABLE {prefix}_members"));
            statements.push(format!("DROP TABLE {prefix}_roots"));
            statements.push(format!(
                "DELETE FROM state_trees WHERE tree_kind = {tree_kind}"
            ));
        }
        statements.extend(
            [
                "DROP TABLE ring_projection_pending",
                "DROP TABLE ring_projection_blocks",
                "DROP TABLE ring_projection_cursor",
            ]
            .map(String::from),
        );
        for sql in statements {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}
