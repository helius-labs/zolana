use super::{leaf_node, MAX_SQL_INSERTS};
use crate::dao::generated::ring_configs;
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::RingConfigUpdate;
use sea_orm::{
    sea_query::OnConflict, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set,
};

pub(super) async fn persist_ring_configs(
    txn: &DatabaseTransaction,
    updates: &[RingConfigUpdate],
) -> Result<(), IngesterError> {
    if updates.is_empty() {
        return Ok(());
    }

    let models = updates
        .iter()
        .map(|update| {
            Ok(ring_configs::ActiveModel {
                ring_config: Set(update.ring_config.to_vec()),
                program_id: Set(update.program_id.to_vec()),
                authority: Set(update.authority.to_vec()),
                slot: Set(leaf_node::i64_from_u64(update.slot, "ring config slot")?),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    for chunk in models.chunks(MAX_SQL_INSERTS) {
        // A config account is created once and its `program_id` never changes,
        // so a replay is the same row rather than an update.
        let query = ring_configs::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::column(ring_configs::Column::RingConfig)
                    .do_nothing()
                    .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist ring configs: {}", e))
        })?;
    }

    Ok(())
}
