use sea_orm_migration::MigrationTrait;

pub mod m20260616_000001_add_rings_tables;
pub mod r20260617_000001_init;
pub mod r20260624_000001_nullifier_queue_metadata;

pub fn get_rings_migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![
        Box::new(r20260617_000001_init::Migration),
        Box::new(m20260616_000001_add_rings_tables::Migration),
        Box::new(r20260624_000001_nullifier_queue_metadata::Migration),
    ]
}
