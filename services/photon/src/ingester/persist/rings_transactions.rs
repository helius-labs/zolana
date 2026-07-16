use super::{leaf_node, MAX_SQL_INSERTS};
use crate::dao::generated::{
    rings_messages, rings_output_payloads, rings_outputs, rings_transaction_payloads,
    rings_transactions, rings_tx_nullifiers,
};
use crate::ingester::error::IngesterError;
use crate::ingester::parser::state_update::RingsTransactionUpdate;
use itertools::Itertools;
use sea_orm::{
    sea_query::OnConflict, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    QueryFilter, QueryTrait, Set,
};
use std::collections::HashMap;

pub(super) async fn persist_rings_transactions(
    txn: &DatabaseTransaction,
    rings_updates: &[RingsTransactionUpdate],
) -> Result<(), IngesterError> {
    if rings_updates.is_empty() {
        return Ok(());
    }

    let transaction_models = rings_updates
        .iter()
        .map(|update| {
            Ok(rings_transactions::ActiveModel {
                rings_tx_id: Default::default(),
                signature: Set(Into::<[u8; 64]>::into(update.signature).to_vec()),
                event_index: Set(update.event_index),
                slot: Set(leaf_node::i64_from_u64(
                    update.slot,
                    "rings transaction slot",
                )?),
                rings_program_id: Set(update.rings_program_id.to_vec()),
                source_instruction_tag: Set(update.source_instruction_tag),
                output_tree: Set(update.output_tree.to_vec()),
                first_output_leaf_index: Set(leaf_node::i64_from_u64(
                    update.first_output_leaf_index,
                    "first output leaf index",
                )?),
                tx_viewing_pk: Set(update.tx_viewing_pk.clone()),
                salt: Set(update.salt.clone()),
                proofless: Set(update.proofless),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    for chunk in transaction_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_transactions::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([
                    rings_transactions::Column::Signature,
                    rings_transactions::Column::EventIndex,
                ])
                .do_nothing()
                .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist rings transactions: {}", e))
        })?;
    }

    let signatures = rings_updates
        .iter()
        .map(|update| Into::<[u8; 64]>::into(update.signature).to_vec())
        .unique()
        .collect::<Vec<_>>();

    let persisted_transactions = rings_transactions::Entity::find()
        .filter(rings_transactions::Column::Signature.is_in(signatures))
        .all(txn)
        .await?;
    let rings_tx_ids = persisted_transactions
        .iter()
        .map(|row| ((row.signature.clone(), row.event_index), row.rings_tx_id))
        .collect::<HashMap<_, _>>();

    let mut payload_models = Vec::new();
    let mut output_models = Vec::new();
    let mut message_models = Vec::new();
    let mut nullifier_models = Vec::new();

    for update in rings_updates {
        let signature = Into::<[u8; 64]>::into(update.signature).to_vec();
        let rings_tx_id = *rings_tx_ids
            .get(&(signature, update.event_index))
            .ok_or_else(|| {
                IngesterError::DatabaseError(format!(
                    "Missing persisted rings transaction {}:{}",
                    update.signature, update.event_index
                ))
            })?;

        payload_models.push(rings_transaction_payloads::ActiveModel {
            rings_tx_id: Set(rings_tx_id),
            encrypted_utxos: Set(update.encrypted_utxos.clone()),
            raw_event: Set(update.raw_event.clone()),
            parse_version: Set(update.parse_version),
        });

        for output in &update.outputs {
            output_models.push(rings_outputs::ActiveModel {
                output_id: Default::default(),
                rings_tx_id: Set(rings_tx_id),
                slot: Set(leaf_node::i64_from_u64(update.slot, "rings output slot")?),
                output_index: Set(output.output_index),
                output_tree: Set(output.output_tree.to_vec()),
                leaf_index: Set(leaf_node::i64_from_u64(
                    output.leaf_index,
                    "output leaf index",
                )?),
                view_tag: Set(output.view_tag.to_vec()),
                utxo_hash: Set(output.utxo_hash.to_vec()),
            });
        }

        for message in &update.messages {
            message_models.push(rings_messages::ActiveModel {
                message_id: Default::default(),
                rings_tx_id: Set(rings_tx_id),
                slot: Set(leaf_node::i64_from_u64(update.slot, "rings message slot")?),
                message_index: Set(message.message_index),
                view_tag: Set(message.view_tag.to_vec()),
                payload: Set(message.payload.clone()),
            });
        }

        for nullifier in &update.nullifiers {
            nullifier_models.push(rings_tx_nullifiers::ActiveModel {
                nullifier_id: Default::default(),
                rings_tx_id: Set(rings_tx_id),
                slot: Set(leaf_node::i64_from_u64(
                    update.slot,
                    "rings nullifier slot",
                )?),
                input_index: Set(nullifier.input_index),
                nullifier_tree: Set(nullifier.nullifier_tree.to_vec()),
                input_queue_seq: Set(leaf_node::i64_from_u64(
                    nullifier.input_queue_seq,
                    "input queue sequence",
                )?),
                nullifier: Set(nullifier.nullifier.to_vec()),
            });
        }
    }

    for chunk in payload_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_transaction_payloads::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::column(rings_transaction_payloads::Column::RingsTxId)
                    .update_columns([
                        rings_transaction_payloads::Column::EncryptedUtxos,
                        rings_transaction_payloads::Column::RawEvent,
                        rings_transaction_payloads::Column::ParseVersion,
                    ])
                    .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!(
                "Failed to persist rings transaction payloads: {}",
                e
            ))
        })?;
    }

    for chunk in output_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_outputs::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([
                    rings_outputs::Column::RingsTxId,
                    rings_outputs::Column::OutputIndex,
                ])
                .do_nothing()
                .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist rings outputs: {}", e))
        })?;
    }

    for chunk in message_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_messages::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([
                    rings_messages::Column::RingsTxId,
                    rings_messages::Column::MessageIndex,
                ])
                .do_nothing()
                .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist rings messages: {}", e))
        })?;
    }

    let persisted_rings_tx_ids = rings_tx_ids.values().copied().unique().collect::<Vec<_>>();
    let persisted_outputs = rings_outputs::Entity::find()
        .filter(rings_outputs::Column::RingsTxId.is_in(persisted_rings_tx_ids))
        .all(txn)
        .await?;
    let output_ids = persisted_outputs
        .iter()
        .map(|row| ((row.rings_tx_id, row.output_index), row.output_id))
        .collect::<HashMap<_, _>>();

    let mut output_payload_models = Vec::new();
    for update in rings_updates {
        let signature = Into::<[u8; 64]>::into(update.signature).to_vec();
        let rings_tx_id = *rings_tx_ids
            .get(&(signature, update.event_index))
            .ok_or_else(|| {
                IngesterError::DatabaseError(format!(
                    "Missing persisted rings transaction {}:{}",
                    update.signature, update.event_index
                ))
            })?;

        for output in &update.outputs {
            let output_id = *output_ids
                .get(&(rings_tx_id, output.output_index))
                .ok_or_else(|| {
                    IngesterError::DatabaseError(format!(
                        "Missing persisted rings output {}:{}:{}",
                        update.signature, update.event_index, output.output_index
                    ))
                })?;

            output_payload_models.push(rings_output_payloads::ActiveModel {
                output_id: Set(output_id),
                payload: Set(output.payload.clone()),
            });
        }
    }

    for chunk in output_payload_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_output_payloads::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::column(rings_output_payloads::Column::OutputId)
                    .update_column(rings_output_payloads::Column::Payload)
                    .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist rings output payloads: {}", e))
        })?;
    }

    for chunk in nullifier_models.chunks(MAX_SQL_INSERTS) {
        let query = rings_tx_nullifiers::Entity::insert_many(chunk.to_vec())
            .on_conflict(
                OnConflict::columns([
                    rings_tx_nullifiers::Column::RingsTxId,
                    rings_tx_nullifiers::Column::InputIndex,
                ])
                .do_nothing()
                .to_owned(),
            )
            .build(txn.get_database_backend());
        txn.execute(query).await.map_err(|e| {
            IngesterError::DatabaseError(format!("Failed to persist rings nullifiers: {}", e))
        })?;
    }

    Ok(())
}
