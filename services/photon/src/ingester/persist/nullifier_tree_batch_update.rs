use crate::common::rings_tree::RingsTreeKind;
use crate::dao::generated::{indexed_trees, rings_tx_nullifiers, state_trees};
use crate::ingester::error::IngesterError;
use crate::ingester::parser::{
    state_update::{IndexedTreeLeafUpdate, NullifierTreeBatchUpdate, RawIndexedElement},
    tree_info::TreeInfo,
};
use crate::ingester::persist::indexed_merkle_tree::{
    compute_nullifier_range_node_hash, get_zeroeth_nullifier_exclusion_range,
};
use crate::ingester::persist::leaf_node::{i64_from_u64, u64_from_i64, usize_from_i64};
use crate::ingester::persist::persisted_indexed_merkle_tree::persist_indexed_tree_updates;
use num_bigint::BigUint;
use sea_orm::{
    ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
};
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;

struct ReconstructedBatch {
    updates: HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
}

pub async fn persist_nullifier_tree_batch_updates(
    txn: &DatabaseTransaction,
    batch_updates: &[NullifierTreeBatchUpdate],
    tree_info_cache: &HashMap<Pubkey, TreeInfo>,
) -> Result<(), IngesterError> {
    for batch_update in batch_updates {
        persist_nullifier_tree_batch_update(txn, batch_update, tree_info_cache).await?;
    }

    Ok(())
}

async fn persist_nullifier_tree_batch_update(
    txn: &DatabaseTransaction,
    batch_update: &NullifierTreeBatchUpdate,
    tree_info_cache: &HashMap<Pubkey, TreeInfo>,
) -> Result<(), IngesterError> {
    let tree_info = tree_info_cache.get(&batch_update.tree).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Tree metadata not found for nullifier batch update tree {}",
            batch_update.tree
        ))
    })?;

    if let Some(root) = current_root(txn, batch_update.tree).await? {
        if root.hash == batch_update.new_root.to_vec() {
            return Ok(());
        }
    }

    let batch_seq = next_root_sequence(txn, batch_update.tree).await?;
    let reconstructed = reconstruct_batch_updates(txn, batch_update, tree_info, batch_seq).await?;
    persist_indexed_tree_updates(txn, reconstructed.updates, tree_info_cache).await?;
    verify_reconstructed_root(txn, batch_update).await
}

async fn reconstruct_batch_updates(
    txn: &DatabaseTransaction,
    batch_update: &NullifierTreeBatchUpdate,
    tree_info: &TreeInfo,
    batch_seq: u64,
) -> Result<ReconstructedBatch, IngesterError> {
    let tree_bytes = batch_update.tree.to_bytes().to_vec();
    let mut batch_elements = HashMap::new();
    let processed_count = current_nullifier_count(txn, batch_update.tree).await?;
    let batch_size = batch_size_for_update(tree_info);
    let window = reconstruction_window(batch_update, batch_size)?;
    let queued_nullifiers =
        queued_nullifiers_for_batch(txn, batch_update.tree, processed_count, window).await?;
    let mut updates = HashMap::new();

    for (offset, nullifier) in queued_nullifiers.into_iter().enumerate() {
        let offset = u64::try_from(offset).map_err(|_| {
            IngesterError::ParserError(format!(
                "Nullifier batch offset {} does not fit in u64",
                offset
            ))
        })?;
        // One sequence step per zkp batch, so a folded run leaves the sequence
        // numbers the same batches settled one at a time would leave.
        let leaf_seq = batch_seq.checked_add(offset / batch_size).ok_or_else(|| {
            IngesterError::ParserError(format!(
                "Nullifier sequence overflow for tree {}",
                batch_update.tree
            ))
        })?;
        let leaf_seq_column = Some(i64_from_u64(leaf_seq, "nullifier batch sequence")?);
        let nullifier = fixed_32(nullifier.nullifier, "queued nullifier")?;
        ensure_value_is_new(txn, batch_update.tree, &batch_elements, &nullifier).await?;
        let new_leaf_index = processed_count
            .checked_add(offset)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Nullifier leaf index overflow for tree {}",
                    batch_update.tree
                ))
            })?;
        let mut low_element =
            low_element_for_value(txn, batch_update.tree, &batch_elements, &nullifier).await?;
        let low_leaf_index = u64_from_i64(low_element.leaf_index, "low element leaf index")?;

        let old_next_index = low_element.next_index;
        let old_next_value = low_element.next_value.clone();
        low_element.next_index = i64_from_u64(new_leaf_index, "new nullifier leaf index")?;
        low_element.next_value = nullifier.to_vec();
        low_element.seq = leaf_seq_column;

        let new_element = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: i64_from_u64(new_leaf_index, "new nullifier leaf index")?,
            value: nullifier.to_vec(),
            next_index: old_next_index,
            next_value: old_next_value,
            seq: leaf_seq_column,
        };

        batch_elements.insert(low_leaf_index, low_element.clone());
        batch_elements.insert(new_leaf_index, new_element.clone());
        insert_leaf_update(&mut updates, batch_update, &low_element, leaf_seq)?;
        insert_leaf_update(&mut updates, batch_update, &new_element, leaf_seq)?;
    }

    Ok(ReconstructedBatch { updates })
}

/// Leaves one instruction appends. A fold advances the tree by its whole run
/// and publishes only the root after it, so a narrower window reconstructs a
/// root the chain never had and wedges the ingester.
fn reconstruction_window(
    batch_update: &NullifierTreeBatchUpdate,
    batch_size: u64,
) -> Result<u64, IngesterError> {
    batch_size
        .checked_mul(u64::from(batch_update.run))
        .ok_or_else(|| {
            IngesterError::ParserError(format!(
                "Nullifier batch window overflow for tree {} at run {}",
                batch_update.tree, batch_update.run
            ))
        })
}

fn batch_size_for_update(tree_info: &TreeInfo) -> u64 {
    if tree_info.input_queue_zkp_batch_size == 0 {
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE
    } else {
        tree_info.input_queue_zkp_batch_size
    }
}

async fn current_nullifier_count(
    txn: &DatabaseTransaction,
    tree: Pubkey,
) -> Result<u64, IngesterError> {
    indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
        .order_by_desc(indexed_trees::Column::LeafIndex)
        .one(txn)
        .await?
        .map(|row| u64_from_i64(row.leaf_index, "indexed leaf index"))
        .transpose()
        .map(|count| count.unwrap_or(0))
}

async fn queued_nullifiers_for_batch(
    txn: &DatabaseTransaction,
    tree: Pubkey,
    start_queue_seq: u64,
    window: u64,
) -> Result<Vec<rings_tx_nullifiers::Model>, IngesterError> {
    let rows = rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::NullifierTree.eq(tree.to_bytes().to_vec()))
        .filter(
            rings_tx_nullifiers::Column::InputQueueSeq
                .gte(i64_from_u64(start_queue_seq, "input queue sequence")?),
        )
        .order_by_asc(rings_tx_nullifiers::Column::InputQueueSeq)
        .limit(window)
        .all(txn)
        .await?;

    let actual_len = u64::try_from(rows.len()).map_err(|_| {
        IngesterError::ParserError(format!(
            "Queued nullifier row count {} does not fit in u64",
            rows.len()
        ))
    })?;
    if actual_len != window {
        return Err(IngesterError::ParserError(format!(
            "Cannot reconstruct nullifier batch for tree {} at queue seq {}: expected {} queued nullifiers, found {}",
            tree, start_queue_seq, window, actual_len
        )));
    }

    for (offset, row) in rows.iter().enumerate() {
        let expected_seq = start_queue_seq
            .checked_add(u64::try_from(offset).map_err(|_| {
                IngesterError::ParserError(format!(
                    "Nullifier batch offset {} does not fit in u64",
                    offset
                ))
            })?)
            .ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Input queue sequence overflow for tree {}",
                    tree
                ))
            })?;
        let actual_seq = u64_from_i64(row.input_queue_seq, "input queue sequence")?;
        if actual_seq != expected_seq {
            return Err(IngesterError::ParserError(format!(
                "Cannot reconstruct nullifier batch for tree {}: expected queue seq {}, found {}",
                tree, expected_seq, actual_seq
            )));
        }
    }

    Ok(rows)
}

async fn low_element_for_value(
    txn: &DatabaseTransaction,
    tree: Pubkey,
    batch_elements: &HashMap<u64, indexed_trees::Model>,
    value: &[u8; 32],
) -> Result<indexed_trees::Model, IngesterError> {
    let value_big = BigUint::from_bytes_be(value);
    let mut candidates = Vec::new();

    if let Some(db_element) = db_low_element(txn, tree, value).await? {
        let leaf_index = u64_from_i64(db_element.leaf_index, "indexed leaf index")?;
        if !batch_elements.contains_key(&leaf_index) {
            candidates.push(db_element);
        }
    } else if !batch_elements.contains_key(&0) {
        candidates.push(get_zeroeth_nullifier_exclusion_range(
            tree.to_bytes().to_vec(),
        ));
    }
    candidates.extend(batch_elements.values().cloned());

    let mut best: Option<(indexed_trees::Model, BigUint)> = None;

    for element in candidates {
        let element_value =
            BigUint::from_bytes_be(&fixed_32(element.value.clone(), "indexed value")?);
        let element_next_value =
            BigUint::from_bytes_be(&fixed_32(element.next_value.clone(), "indexed next value")?);
        if element_value < value_big && value_big < element_next_value {
            match &best {
                Some((_, best_value)) if element_value <= *best_value => {}
                _ => best = Some((element, element_value)),
            }
        }
    }

    best.map(|(element, _)| element).ok_or_else(|| {
        IngesterError::ParserError(
            "Queued nullifier does not fit any existing exclusion range".to_string(),
        )
    })
}

async fn db_low_element(
    txn: &DatabaseTransaction,
    tree: Pubkey,
    value: &[u8; 32],
) -> Result<Option<indexed_trees::Model>, IngesterError> {
    indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
        .filter(indexed_trees::Column::Value.lt(value.to_vec()))
        .order_by_desc(indexed_trees::Column::Value)
        .one(txn)
        .await
        .map_err(Into::into)
}

async fn ensure_value_is_new(
    txn: &DatabaseTransaction,
    tree: Pubkey,
    batch_elements: &HashMap<u64, indexed_trees::Model>,
    value: &[u8; 32],
) -> Result<(), IngesterError> {
    if batch_elements
        .values()
        .any(|element| element.value.as_slice() == value)
    {
        return Err(IngesterError::ParserError(
            "Queued nullifier already exists in indexed tree".to_string(),
        ));
    }

    let existing = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
        .filter(indexed_trees::Column::Value.eq(value.to_vec()))
        .one(txn)
        .await?;
    if existing.is_some() {
        return Err(IngesterError::ParserError(
            "Queued nullifier already exists in indexed tree".to_string(),
        ));
    }

    Ok(())
}

fn insert_leaf_update(
    updates: &mut HashMap<(Pubkey, u64), IndexedTreeLeafUpdate>,
    batch_update: &NullifierTreeBatchUpdate,
    element: &indexed_trees::Model,
    batch_seq: u64,
) -> Result<(), IngesterError> {
    let leaf_index = u64_from_i64(element.leaf_index, "indexed leaf index")?;
    let hash = compute_nullifier_range_node_hash(element)?;
    let update = IndexedTreeLeafUpdate {
        tree: batch_update.tree,
        tree_kind: RingsTreeKind::Nullifier,
        leaf: RawIndexedElement {
            value: fixed_32(element.value.clone(), "indexed value")?,
            next_index: usize_from_i64(element.next_index, "indexed next index")?,
            next_value: fixed_32(element.next_value.clone(), "indexed next value")?,
            index: usize_from_i64(element.leaf_index, "indexed leaf index")?,
        },
        hash: hash.0,
        seq: batch_seq,
        signature: batch_update.signature,
    };
    updates.insert((batch_update.tree, leaf_index), update);
    Ok(())
}

async fn next_root_sequence(txn: &DatabaseTransaction, tree: Pubkey) -> Result<u64, IngesterError> {
    let previous_root = current_root(txn, tree).await?;
    let previous_seq = previous_root
        .and_then(|root| root.seq)
        .map(|seq| u64_from_i64(seq, "root sequence"))
        .transpose()?
        .unwrap_or(0);

    previous_seq.checked_add(1).ok_or_else(|| {
        IngesterError::ParserError(format!("Root sequence overflow for tree {}", tree))
    })
}

async fn verify_reconstructed_root(
    txn: &DatabaseTransaction,
    batch_update: &NullifierTreeBatchUpdate,
) -> Result<(), IngesterError> {
    let root = current_root(txn, batch_update.tree).await?.ok_or_else(|| {
        IngesterError::DatabaseError(format!(
            "Missing reconstructed nullifier root for tree {}",
            batch_update.tree
        ))
    })?;

    if root.hash != batch_update.new_root.to_vec() {
        return Err(IngesterError::ParserError(format!(
            "Reconstructed nullifier root mismatch for tree {}: expected {:?}, got {:?}",
            batch_update.tree, batch_update.new_root, root.hash
        )));
    }

    Ok(())
}

async fn current_root(
    txn: &DatabaseTransaction,
    tree: Pubkey,
) -> Result<Option<state_trees::Model>, IngesterError> {
    state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(txn)
        .await
        .map_err(Into::into)
}

fn fixed_32(value: Vec<u8>, label: &str) -> Result<[u8; 32], IngesterError> {
    value.try_into().map_err(|value: Vec<u8>| {
        IngesterError::ParserError(format!(
            "{} length is {}, expected 32 bytes",
            label,
            value.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::generated::{blocks, rings_transactions, transactions};
    use crate::migration::RingsMigrator;
    use crate::monitor::tree_metadata_sync::{upsert_tree_metadata, TreeAccountData};
    use sea_orm::{Database, DatabaseConnection, Set, TransactionTrait};
    use sea_orm_migration::MigratorTrait;
    use solana_signature::Signature;

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        db
    }

    async fn insert_test_tree(db: &DatabaseConnection, tree: Pubkey) -> HashMap<Pubkey, TreeInfo> {
        let data = TreeAccountData {
            queue_pubkey: tree,
            root_history_capacity: RingsTreeKind::Nullifier.root_history_capacity(),
            input_queue_zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
            height: RingsTreeKind::Nullifier.tree_height(),
            sequence_number: 0,
            next_index: 0,
        };
        upsert_tree_metadata(db, tree, &data, 0).await.unwrap();

        HashMap::from([(
            tree,
            TreeInfo {
                tree,
                queue: tree,
                height: RingsTreeKind::Nullifier.tree_height(),
                root_history_capacity: RingsTreeKind::Nullifier.root_history_capacity(),
                input_queue_zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
            },
        )])
    }

    async fn insert_test_rings_transaction(
        tx: &DatabaseTransaction,
        rings_tx_id: i64,
        tree: Pubkey,
    ) {
        let signature = Into::<[u8; 64]>::into(Signature::from(
            [u8::try_from(rings_tx_id).unwrap_or(1); 64],
        ))
        .to_vec();
        if rings_tx_id == 1 {
            blocks::Entity::insert(blocks::ActiveModel {
                slot: Set(1),
                parent_slot: Set(0),
                parent_blockhash: Set(vec![0; 32]),
                blockhash: Set(vec![1; 32]),
                block_height: Set(1),
                block_time: Set(1),
            })
            .exec(tx)
            .await
            .unwrap();
        }
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(signature.clone()),
            slot: Set(1),
            error: Set(None),
        })
        .exec(tx)
        .await
        .unwrap();
        rings_transactions::Entity::insert(rings_transactions::ActiveModel {
            rings_tx_id: Set(rings_tx_id),
            signature: Set(signature),
            event_index: Set(0),
            slot: Set(1),
            rings_program_id: Set([9u8; 32].to_vec()),
            source_instruction_tag: Set(1),
            output_tree: Set(tree.to_bytes().to_vec()),
            first_output_leaf_index: Set(0),
            tx_viewing_pk: Set(None),
            salt: Set(None),
            proofless: Set(false),
        })
        .exec(tx)
        .await
        .unwrap();
    }

    async fn insert_queued_nullifiers(
        tx: &DatabaseTransaction,
        tree: Pubkey,
        rings_tx_id: i64,
        queue_seqs: std::ops::Range<u64>,
    ) {
        insert_test_rings_transaction(tx, rings_tx_id, tree).await;
        for (input_index, queue_seq) in queue_seqs.enumerate() {
            let mut nullifier = [0u8; 32];
            nullifier[24..].copy_from_slice(&(queue_seq + 1).to_be_bytes());
            let row = rings_tx_nullifiers::ActiveModel {
                nullifier_id: Default::default(),
                rings_tx_id: Set(rings_tx_id),
                slot: Set(1),
                input_index: Set(i16::try_from(input_index).unwrap()),
                nullifier_tree: Set(tree.to_bytes().to_vec()),
                input_queue_seq: Set(i64_from_u64(queue_seq, "input queue seq").unwrap()),
                nullifier: Set(nullifier.to_vec()),
            };
            rings_tx_nullifiers::Entity::insert(row)
                .exec(tx)
                .await
                .unwrap();
        }
    }

    fn batch_update(tree: Pubkey, new_root: [u8; 32], run: u32) -> NullifierTreeBatchUpdate {
        NullifierTreeBatchUpdate {
            tree,
            new_root,
            run,
            signature: Signature::from([8; 64]),
        }
    }

    #[tokio::test]
    async fn reconstructs_batch_from_contiguous_queued_nullifiers() {
        let db = setup_test_db().await;
        let tree = Pubkey::new_from_array([7; 32]);
        let tree_info_cache = insert_test_tree(&db, tree).await;
        let unfolded = batch_update(tree, [0; 32], 1);

        let tx = db.begin().await.unwrap();
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
        insert_queued_nullifiers(&tx, tree, 1, 0..batch_size).await;

        let reconstructed =
            reconstruct_batch_updates(&tx, &unfolded, tree_info_cache.get(&tree).unwrap(), 1)
                .await
                .unwrap();
        persist_indexed_tree_updates(&tx, reconstructed.updates, &tree_info_cache)
            .await
            .unwrap();

        insert_queued_nullifiers(&tx, tree, 2, batch_size..(batch_size * 2)).await;
        let reconstructed =
            reconstruct_batch_updates(&tx, &unfolded, tree_info_cache.get(&tree).unwrap(), 2)
                .await
                .unwrap();
        persist_indexed_tree_updates(&tx, reconstructed.updates, &tree_info_cache)
            .await
            .unwrap();

        let max_leaf = indexed_trees::Entity::find()
            .filter(indexed_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
            .order_by_desc(indexed_trees::Column::LeafIndex)
            .one(&tx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            u64_from_i64(max_leaf.leaf_index, "indexed leaf index").unwrap(),
            batch_size * 2
        );

        let root = current_root(&tx, tree).await.unwrap().unwrap();
        let already_applied = batch_update(tree, fixed_32(root.hash, "root hash").unwrap(), 1);
        persist_nullifier_tree_batch_update(&tx, &already_applied, &tree_info_cache)
            .await
            .unwrap();

        tx.rollback().await.unwrap();
    }

    /// A fold appends its whole run and publishes only the root after it. A
    /// window of one zkp batch reconstructs a root the chain never had, and the
    /// mismatch stops the ingester on the first folded transaction.
    #[tokio::test]
    async fn folded_run_reaches_the_root_of_the_whole_run() {
        let db = setup_test_db().await;
        let tree = Pubkey::new_from_array([7; 32]);
        let tree_info_cache = insert_test_tree(&db, tree).await;
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
        let run = 2u32;

        // Reference state: the same zkp batches settled one instruction at a time.
        let tx = db.begin().await.unwrap();
        for batch in 0..u64::from(run) {
            let rings_tx_id = i64::try_from(batch + 1).unwrap();
            let start = batch * batch_size;
            insert_queued_nullifiers(&tx, tree, rings_tx_id, start..(start + batch_size)).await;
            let reconstructed = reconstruct_batch_updates(
                &tx,
                &batch_update(tree, [0; 32], 1),
                tree_info_cache.get(&tree).unwrap(),
                batch + 1,
            )
            .await
            .unwrap();
            persist_indexed_tree_updates(&tx, reconstructed.updates, &tree_info_cache)
                .await
                .unwrap();
        }
        let unfolded_root = current_root(&tx, tree).await.unwrap().unwrap();
        let expected_root = fixed_32(unfolded_root.hash, "root hash").unwrap();
        assert_eq!(unfolded_root.seq, Some(i64::from(run)));
        tx.rollback().await.unwrap();

        let tx = db.begin().await.unwrap();
        insert_queued_nullifiers(&tx, tree, 1, 0..batch_size).await;
        insert_queued_nullifiers(&tx, tree, 2, batch_size..(batch_size * 2)).await;
        persist_nullifier_tree_batch_update(
            &tx,
            &batch_update(tree, expected_root, run),
            &tree_info_cache,
        )
        .await
        .unwrap();

        let folded_root = current_root(&tx, tree).await.unwrap().unwrap();
        assert_eq!(folded_root.hash, expected_root.to_vec());
        // One sequence step per zkp batch, so a reader cannot tell a fold from
        // the run of updates it replaces.
        assert_eq!(folded_root.seq, unfolded_root.seq);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_non_contiguous_queue_rows() {
        let db = setup_test_db().await;
        let tree = Pubkey::new_from_array([7; 32]);
        let tx = db.begin().await.unwrap();
        insert_test_rings_transaction(&tx, 1, tree).await;
        let row = rings_tx_nullifiers::ActiveModel {
            nullifier_id: Default::default(),
            rings_tx_id: sea_orm::Set(1),
            slot: sea_orm::Set(1),
            input_index: sea_orm::Set(0),
            nullifier_tree: sea_orm::Set(tree.to_bytes().to_vec()),
            input_queue_seq: sea_orm::Set(1),
            nullifier: sea_orm::Set([1u8; 32].to_vec()),
        };
        rings_tx_nullifiers::Entity::insert(row)
            .exec(&tx)
            .await
            .unwrap();

        let err =
            queued_nullifiers_for_batch(&tx, tree, 0, ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE)
                .await
                .unwrap_err();

        assert!(format!("{err}").contains("expected 250 queued nullifiers"));
        tx.rollback().await.unwrap();
    }
}
