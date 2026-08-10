use sea_orm_migration::MigrationTrait;

pub mod m20260616_000001_add_rings_tables;
pub mod m20260625_000001_add_rings_messages;
pub mod m20260710_000001_add_rings_merge_view_tag;
pub mod m20260727_000001_remove_rings_merge_view_tag;
pub mod r20260617_000001_init;
pub mod r20260624_000001_nullifier_queue_metadata;
pub mod r20260810_000001_state_root_index;
pub mod r20260810_000002_drop_state_root_columns;

pub fn get_rings_migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![
        Box::new(r20260617_000001_init::Migration),
        Box::new(m20260616_000001_add_rings_tables::Migration),
        Box::new(r20260624_000001_nullifier_queue_metadata::Migration),
        Box::new(m20260625_000001_add_rings_messages::Migration),
        Box::new(m20260710_000001_add_rings_merge_view_tag::Migration),
        Box::new(m20260727_000001_remove_rings_merge_view_tag::Migration),
        Box::new(r20260810_000001_state_root_index::Migration),
        Box::new(r20260810_000002_drop_state_root_columns::Migration),
    ]
}
