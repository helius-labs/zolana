use super::types::{
    GetNullifierQueueElementsRequest, GetNullifierQueueElementsResponse, NullifierQueueElement,
};
use crate::api::error::PhotonApiError;
use crate::common::typedefs::context::Context;
use crate::common::typedefs::hash::Hash;
use crate::dao::generated::rings_tx_nullifiers;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};

/// Return queued nullifier values for `tree_account` with `input_queue_seq >=
/// start_seq`, ordered ascending, up to `limit` elements.
///
/// The nullifier tree forester replays these into its reference indexed Merkle
/// tree to build batch address-append proofs; the on-chain queue keeps only
/// bloom filters and hash chains, so the raw values must come from the indexer.
pub async fn get_nullifier_queue_elements(
    conn: &DatabaseConnection,
    request: GetNullifierQueueElementsRequest,
) -> Result<GetNullifierQueueElementsResponse, PhotonApiError> {
    let context = Context::extract(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let tree_bytes = request.tree_account.to_bytes_vec();
    let start_seq = i64::try_from(request.start_seq).map_err(|_| {
        PhotonApiError::ValidationError(format!("start_seq {} is too large", request.start_seq))
    })?;

    let rows = rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::NullifierTree.eq(tree_bytes))
        .filter(rings_tx_nullifiers::Column::InputQueueSeq.gte(start_seq))
        .order_by_asc(rings_tx_nullifiers::Column::InputQueueSeq)
        .limit(request.limit)
        .all(&tx)
        .await?;

    let elements = rows
        .into_iter()
        .map(|row| {
            let seq = u64::try_from(row.input_queue_seq).map_err(|_| {
                PhotonApiError::UnexpectedError(format!(
                    "negative input_queue_seq {}",
                    row.input_queue_seq
                ))
            })?;
            let value: [u8; 32] = row.nullifier.try_into().map_err(|bytes: Vec<u8>| {
                PhotonApiError::UnexpectedError(format!(
                    "nullifier length {} != 32",
                    bytes.len()
                ))
            })?;
            Ok(NullifierQueueElement {
                seq,
                value: Hash::from(value),
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;

    tx.commit().await?;

    Ok(GetNullifierQueueElementsResponse { context, elements })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::typedefs::serializable_pubkey::SerializablePubkey;
    use crate::dao::generated::{blocks, rings_transactions, transactions};
    use crate::migration::RingsMigrator;
    use sea_orm::{Database, DatabaseConnection, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait;

    fn nullifier(byte: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = byte;
        value
    }

    async fn setup(tree: SerializablePubkey, count: u64) -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();

        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(7),
            parent_slot: Set(0),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![1; 32]),
            block_height: Set(1),
            block_time: Set(1),
        })
        .exec(&db)
        .await
        .unwrap();
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(vec![1; 64]),
            slot: Set(7),
            error: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(1),
            signature: Set(vec![1; 64]),
            event_index: Set(0),
            slot: Set(7),
            rings_program_id: Set([9u8; 32].to_vec()),
            source_instruction_tag: Set(1),
            output_tree: Set(tree.to_bytes_vec()),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(&db)
        .await
        .unwrap();

        for seq in 0..count {
            rings_tx_nullifiers::Entity::insert(rings_tx_nullifiers::ActiveModel {
                nullifier_id: Default::default(),
                rings_tx_id: Set(1),
                slot: Set(7),
                input_index: Set(i16::try_from(seq).unwrap()),
                nullifier_tree: Set(tree.to_bytes_vec()),
                input_queue_seq: Set(i64::try_from(seq).unwrap()),
                nullifier: Set(nullifier(u8::try_from(seq + 1).unwrap()).to_vec()),
            })
            .exec(&db)
            .await
            .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn returns_ordered_queued_values() {
        let tree = SerializablePubkey::new_unique();
        let db = setup(tree, 3).await;

        let response = get_nullifier_queue_elements(
            &db,
            GetNullifierQueueElementsRequest {
                tree_account: tree,
                start_seq: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();

        let seqs: Vec<u64> = response.elements.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
        assert_eq!(response.elements[0].value, Hash::from(nullifier(1)));
        assert_eq!(response.elements[2].value, Hash::from(nullifier(3)));
    }

    #[tokio::test]
    async fn honors_start_seq_and_limit() {
        let tree = SerializablePubkey::new_unique();
        let db = setup(tree, 5).await;

        let from_two = get_nullifier_queue_elements(
            &db,
            GetNullifierQueueElementsRequest {
                tree_account: tree,
                start_seq: 2,
                limit: 10,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            from_two.elements.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );

        let capped = get_nullifier_queue_elements(
            &db,
            GetNullifierQueueElementsRequest {
                tree_account: tree,
                start_seq: 0,
                limit: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            capped.elements.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[tokio::test]
    async fn filters_by_tree() {
        let tree = SerializablePubkey::new_unique();
        let db = setup(tree, 3).await;

        let other = get_nullifier_queue_elements(
            &db,
            GetNullifierQueueElementsRequest {
                tree_account: SerializablePubkey::new_unique(),
                start_seq: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();
        assert!(other.elements.is_empty());
    }
}
