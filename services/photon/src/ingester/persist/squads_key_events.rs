use super::{leaf_node, MAX_SQL_INSERTS};
use crate::dao::generated::squads_key_events;
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::SquadsKeyEventUpdate;
use sea_orm::{
    sea_query::OnConflict, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryTrait, Set,
};

pub(super) async fn persist_squads_key_events(
    txn: &DatabaseTransaction,
    key_events: &[SquadsKeyEventUpdate],
) -> Result<(), IngesterError> {
    if key_events.is_empty() {
        return Ok(());
    }

    let models = key_events
        .iter()
        .map(|event| {
            Ok(squads_key_events::ActiveModel {
                squads_key_event_id: Default::default(),
                signature: Set(Into::<[u8; 64]>::into(event.signature).to_vec()),
                event_index: Set(event.event_index),
                slot: Set(leaf_node::i64_from_u64(
                    event.slot,
                    "squads key event slot",
                )?),
                squads_program_id: Set(event.squads_program_id.to_vec()),
                source_instruction_tag: Set(event.source_instruction_tag),
                event_kind: Set(event.event_kind),
                account: Set(event.account.to_vec()),
                owner: Set(event.owner.to_vec()),
                key_nonce: Set(leaf_node::i64_from_u64(
                    event.key_nonce,
                    "squads key event nonce",
                )?),
                new_key_nonce: Set(event
                    .new_key_nonce
                    .map(|nonce| leaf_node::i64_from_u64(nonce, "squads new key nonce"))
                    .transpose()?),
                old_state_hash: Set(event.old_state_hash.map(|hash| hash.to_vec())),
                raw_event: Set(event.raw_event.clone()),
                parse_version: Set(event.parse_version),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    for chunk in models.chunks(MAX_SQL_INSERTS) {
        let query = squads_key_events::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([
                    squads_key_events::Column::Signature,
                    squads_key_events::Column::EventIndex,
                ])
                .do_nothing()
                .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist squads key events: {}", e))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::generated::{blocks, transactions};
    use crate::migration::RingsMigrator;
    use sea_orm::{ColumnTrait, Database, DatabaseConnection, QueryFilter, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use solana_signature::Signature;

    const SIGNATURE: [u8; 64] = [3; 64];
    const ACCOUNT: [u8; 32] = [4; 32];

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();

        let txn = db.begin().await.unwrap();
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(7),
            parent_slot: Set(6),
            block_time: Set(0),
            blockhash: Set(vec![1; 32]),
            parent_blockhash: Set(vec![2; 32]),
            block_height: Set(7),
        })
        .exec(&txn)
        .await
        .unwrap();
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(SIGNATURE.to_vec()),
            slot: Set(7),
            error: Set(None),
        })
        .exec(&txn)
        .await
        .unwrap();
        txn.commit().await.unwrap();

        db
    }

    fn key_event(event_index: i16, key_nonce: u64) -> SquadsKeyEventUpdate {
        SquadsKeyEventUpdate {
            signature: Signature::from(SIGNATURE),
            event_index,
            slot: 7,
            squads_program_id: [5; 32],
            source_instruction_tag: 14,
            event_kind: 1,
            account: ACCOUNT,
            owner: [6; 32],
            key_nonce,
            new_key_nonce: Some(key_nonce + 1),
            old_state_hash: Some([7; 32]),
            raw_event: vec![1, 2, 3],
            parse_version: 1,
        }
    }

    /// The pre-rotation material must be reachable from the account address
    /// alone, which is all a returning key holder has.
    #[tokio::test]
    async fn persisted_key_events_are_queryable_by_account() {
        let db = setup_test_db().await;
        let txn = db.begin().await.unwrap();

        persist_squads_key_events(&txn, &[key_event(0, 1), key_event(1, 2)])
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let rows = squads_key_events::Entity::find()
            .filter(squads_key_events::Column::Account.eq(ACCOUNT.to_vec()))
            .all(&db)
            .await
            .unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key_nonce, 1);
        assert_eq!(rows[0].new_key_nonce, Some(2));
        assert_eq!(rows[0].raw_event, vec![1, 2, 3]);
    }

    /// Reindexing the same slot must not duplicate an event.
    #[tokio::test]
    async fn reinserting_the_same_event_is_a_no_op() {
        let db = setup_test_db().await;

        for _ in 0..2 {
            let txn = db.begin().await.unwrap();
            persist_squads_key_events(&txn, &[key_event(0, 1)])
                .await
                .unwrap();
            txn.commit().await.unwrap();
        }

        let rows = squads_key_events::Entity::find().all(&db).await.unwrap();

        assert_eq!(rows.len(), 1);
    }
}
