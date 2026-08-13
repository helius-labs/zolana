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
    sea_query::Expr, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use solana_pubkey::Pubkey;
use std::collections::HashMap;

#[derive(Debug)]
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
    if !tree_info_cache.contains_key(&batch_update.tree) {
        return Err(IngesterError::ParserError(format!(
            "Tree metadata not found for nullifier batch update tree {}",
            batch_update.tree
        )));
    }

    if let Some(root) = current_root(txn, batch_update.tree).await? {
        if root.hash == batch_update.new_root.to_vec() {
            return reconcile_root_sequence(txn, batch_update, &root).await;
        }
    }

    let batch_seq = batch_update.sequence_number;
    let reconstructed = reconstruct_batch_updates(txn, batch_update, batch_seq).await?;
    persist_indexed_tree_updates(txn, reconstructed.updates, tree_info_cache).await?;
    verify_reconstructed_root(txn, batch_update).await
}

async fn reconstruct_batch_updates(
    txn: &DatabaseTransaction,
    batch_update: &NullifierTreeBatchUpdate,
    batch_seq: u64,
) -> Result<ReconstructedBatch, IngesterError> {
    let tree_bytes = batch_update.tree.to_bytes().to_vec();
    let mut batch_elements = HashMap::new();
    let processed_count = current_nullifier_count(txn, batch_update.tree).await?;
    // The event reports every zkp batch the instruction applied, which is more
    // than one whenever it unblocked proofs cached out of order. All of them
    // must be replayed before the root is comparable.
    let appended_count = batch_update.appended_count();
    if appended_count == 0 {
        return Err(IngesterError::ParserError(format!(
            "Batch append event for tree {} applied no zkp batches",
            batch_update.tree
        )));
    }
    let queued_nullifiers =
        queued_nullifiers_for_batch(txn, batch_update.tree, processed_count, appended_count)
            .await?;
    let mut updates = HashMap::new();

    for (offset, nullifier) in queued_nullifiers.into_iter().enumerate() {
        let nullifier = fixed_32(nullifier.nullifier, "queued nullifier")?;
        ensure_value_is_new(txn, batch_update.tree, &batch_elements, &nullifier).await?;
        let new_leaf_index = processed_count
            .checked_add(u64::try_from(offset).map_err(|_| {
                IngesterError::ParserError(format!(
                    "Nullifier batch offset {} does not fit in u64",
                    offset
                ))
            })?)
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
        low_element.seq = Some(i64_from_u64(batch_seq, "nullifier batch sequence")?);

        let new_element = indexed_trees::Model {
            tree: tree_bytes.clone(),
            leaf_index: i64_from_u64(new_leaf_index, "new nullifier leaf index")?,
            value: nullifier.to_vec(),
            next_index: old_next_index,
            next_value: old_next_value,
            seq: Some(i64_from_u64(batch_seq, "nullifier batch sequence")?),
        };

        batch_elements.insert(low_leaf_index, low_element.clone());
        batch_elements.insert(new_leaf_index, new_element.clone());
        insert_leaf_update(&mut updates, batch_update, &low_element, batch_seq)?;
        insert_leaf_update(&mut updates, batch_update, &new_element, batch_seq)?;
    }

    Ok(ReconstructedBatch { updates })
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
    appended_count: u64,
) -> Result<Vec<rings_tx_nullifiers::Model>, IngesterError> {
    let rows = rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::NullifierTree.eq(tree.to_bytes().to_vec()))
        .filter(
            rings_tx_nullifiers::Column::InputQueueSeq
                .gte(i64_from_u64(start_queue_seq, "input queue sequence")?),
        )
        .order_by_asc(rings_tx_nullifiers::Column::InputQueueSeq)
        .limit(appended_count)
        .all(txn)
        .await?;

    let actual_len = u64::try_from(rows.len()).map_err(|_| {
        IngesterError::ParserError(format!(
            "Queued nullifier row count {} does not fit in u64",
            rows.len()
        ))
    })?;
    if actual_len != appended_count {
        return Err(IngesterError::ParserError(format!(
            "Cannot reconstruct nullifier batch for tree {} at queue seq {}: expected {} queued nullifiers, found {}",
            tree, start_queue_seq, appended_count, actual_len
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

/// Bring the recorded sequence number in line with the chain for a root photon
/// already holds.
///
/// "Already applied" and "already correct" are not the same thing. The tree can
/// hold exactly the right root while the sequence number stored beside it was
/// counted per event rather than per applied zkp batch, and it is that number
/// the API turns into the root index a client quotes. Without this, a drifted
/// index is unrecoverable: replaying the event short-circuits on the matching
/// root and changes nothing, so the only repair left is a full reindex.
async fn reconcile_root_sequence(
    txn: &DatabaseTransaction,
    batch_update: &NullifierTreeBatchUpdate,
    root: &state_trees::Model,
) -> Result<(), IngesterError> {
    let recorded = root
        .seq
        .map(|seq| u64_from_i64(seq, "root sequence"))
        .transpose()?;
    if recorded == Some(batch_update.sequence_number) {
        return Ok(());
    }

    log::info!(
        "Repairing nullifier root sequence for tree {}: recorded {:?}, chain reports {}",
        batch_update.tree,
        recorded,
        batch_update.sequence_number
    );

    state_trees::Entity::update_many()
        .col_expr(
            state_trees::Column::Seq,
            Expr::value(i64_from_u64(batch_update.sequence_number, "root sequence")?),
        )
        .filter(state_trees::Column::Tree.eq(batch_update.tree.to_bytes().to_vec()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .exec(txn)
        .await?;

    Ok(())
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
    use zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;

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

    /// Queue `count` nullifiers at consecutive input queue sequences from 0.
    async fn seed_queued_nullifiers(tx: &DatabaseTransaction, tree: Pubkey, count: u64) {
        insert_test_rings_transaction(tx, 1, tree).await;
        for seq in 0..count {
            let mut nullifier = [0u8; 32];
            nullifier[24..].copy_from_slice(&(seq + 1).to_be_bytes());
            let row = rings_tx_nullifiers::ActiveModel {
                nullifier_id: Default::default(),
                rings_tx_id: Set(1),
                slot: Set(1),
                input_index: Set(i16::try_from(seq).unwrap_or(0)),
                nullifier_tree: Set(tree.to_bytes().to_vec()),
                input_queue_seq: Set(i64_from_u64(seq, "input queue seq").unwrap()),
                nullifier: Set(nullifier.to_vec()),
            };
            rings_tx_nullifiers::Entity::insert(row)
                .exec(tx)
                .await
                .unwrap();
        }
    }

    fn batch_event(
        tree: Pubkey,
        num_update: u32,
        sequence_number: u64,
    ) -> NullifierTreeBatchUpdate {
        NullifierTreeBatchUpdate {
            tree,
            new_root: [0; 32],
            zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
            num_update,
            sequence_number,
            signature: Signature::from([8; 64]),
        }
    }

    /// Apply one event covering `num_update` zkp batches at the chain sequence
    /// number it reports, and return the root it leaves behind. Skips
    /// `verify_reconstructed_root`, which needs a real root from chain; these
    /// tests compare reconstructions against each other.
    async fn apply_event(
        tx: &DatabaseTransaction,
        tree: Pubkey,
        tree_info_cache: &HashMap<Pubkey, TreeInfo>,
        num_update: u32,
        sequence_number: u64,
    ) -> Vec<u8> {
        let batch_update = batch_event(tree, num_update, sequence_number);
        let reconstructed = reconstruct_batch_updates(tx, &batch_update, sequence_number)
            .await
            .unwrap();
        persist_indexed_tree_updates(tx, reconstructed.updates, tree_info_cache)
            .await
            .unwrap();
        current_root(tx, tree).await.unwrap().unwrap().hash
    }

    async fn root_seq(tx: &DatabaseTransaction, tree: Pubkey) -> u64 {
        let root = current_root(tx, tree).await.unwrap().unwrap();
        u64_from_i64(root.seq.unwrap(), "root seq").unwrap()
    }

    #[tokio::test]
    async fn reconstructs_batch_from_contiguous_queued_nullifiers() {
        let db = setup_test_db().await;
        let tree = Pubkey::new_from_array([7; 32]);
        let tree_info_cache = insert_test_tree(&db, tree).await;
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;

        let tx = db.begin().await.unwrap();
        seed_queued_nullifiers(&tx, tree, batch_size * 2).await;

        apply_event(&tx, tree, &tree_info_cache, 1, 1).await;
        apply_event(&tx, tree, &tree_info_cache, 1, 2).await;

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

        // An event whose root photon already holds is a no-op, not a replay.
        let root = current_root(&tx, tree).await.unwrap().unwrap();
        let already_applied = NullifierTreeBatchUpdate {
            new_root: fixed_32(root.hash, "root hash").unwrap(),
            signature: Signature::from([9; 64]),
            ..batch_event(tree, 1, 2)
        };
        persist_nullifier_tree_batch_update(&tx, &already_applied, &tree_info_cache)
            .await
            .unwrap();
        assert_eq!(root_seq(&tx, tree).await, 2);

        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn replaying_an_applied_event_repairs_a_drifted_sequence() {
        // Recovery path for an index that has already drifted. The tree holds
        // the right root, so reconstruction is skipped, but the sequence stored
        // beside it is short -- which is what a client turns into a root index.
        // Replaying the event has to correct it, or the only repair left is a
        // full reindex.
        let db = setup_test_db().await;
        let tree = Pubkey::new_from_array([7; 32]);
        let tree_info_cache = insert_test_tree(&db, tree).await;
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;

        let tx = db.begin().await.unwrap();
        seed_queued_nullifiers(&tx, tree, batch_size * 2).await;

        // Applied as one cascade of two, but recorded with the sequence a
        // per-event counter would have produced: one short.
        let hash = apply_event(&tx, tree, &tree_info_cache, 2, 1).await;
        assert_eq!(root_seq(&tx, tree).await, 1);

        let replayed = NullifierTreeBatchUpdate {
            new_root: fixed_32(hash, "root hash").unwrap(),
            signature: Signature::from([9; 64]),
            ..batch_event(tree, 2, 2)
        };
        persist_nullifier_tree_batch_update(&tx, &replayed, &tree_info_cache)
            .await
            .unwrap();

        assert_eq!(root_seq(&tx, tree).await, 2);

        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_lands_the_same_tree_as_the_batches_applied_one_at_a_time() {
        // The regression this file exists for: a proof cached out of order makes
        // the program apply several zkp batches under one event. Photon must
        // reach the root the chain reached, which is the root after all of them,
        // not after the first.
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
        let tree = Pubkey::new_from_array([7; 32]);

        let sequential_db = setup_test_db().await;
        let sequential_cache = insert_test_tree(&sequential_db, tree).await;
        let sequential_tx = sequential_db.begin().await.unwrap();
        seed_queued_nullifiers(&sequential_tx, tree, batch_size * 3).await;
        for seq in 1..=3 {
            apply_event(&sequential_tx, tree, &sequential_cache, 1, seq).await;
        }
        let sequential_root = current_root(&sequential_tx, tree)
            .await
            .unwrap()
            .unwrap()
            .hash;

        // One event applying all three, at the sequence number the chain reports
        // after the last of them.
        let cascade_db = setup_test_db().await;
        let cascade_cache = insert_test_tree(&cascade_db, tree).await;
        let cascade_tx = cascade_db.begin().await.unwrap();
        seed_queued_nullifiers(&cascade_tx, tree, batch_size * 3).await;
        let cascade_root = apply_event(&cascade_tx, tree, &cascade_cache, 3, 3).await;

        assert_eq!(cascade_root, sequential_root);

        // The root index a client must quote is `seq % root_history_capacity`,
        // and on chain that pointer moves once per applied batch. If a cascade
        // advanced it once instead of three times, the two runs would disagree
        // here and every client proof would be checked against the wrong root.
        assert_eq!(
            root_seq(&cascade_tx, tree).await,
            root_seq(&sequential_tx, tree).await
        );
        assert_eq!(root_seq(&cascade_tx, tree).await, 3);

        let max_leaf = indexed_trees::Entity::find()
            .filter(indexed_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
            .order_by_desc(indexed_trees::Column::LeafIndex)
            .one(&cascade_tx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            u64_from_i64(max_leaf.leaf_index, "indexed leaf index").unwrap(),
            batch_size * 3
        );

        sequential_tx.rollback().await.unwrap();
        cascade_tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn cascade_needs_every_batch_of_queued_nullifiers() {
        // Only two batches are queued, so a three-batch cascade cannot be
        // reconstructed. It must fail loudly rather than apply what it has and
        // report a root that does not match.
        let batch_size = ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
        let tree = Pubkey::new_from_array([7; 32]);
        let db = setup_test_db().await;
        insert_test_tree(&db, tree).await;

        let tx = db.begin().await.unwrap();
        seed_queued_nullifiers(&tx, tree, batch_size * 2).await;

        let err = reconstruct_batch_updates(&tx, &batch_event(tree, 3, 3), 3)
            .await
            .unwrap_err();

        assert!(
            format!("{err}").contains("expected 750 queued nullifiers, found 500"),
            "unexpected error: {err}"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_event_that_applied_no_batches() {
        let tree = Pubkey::new_from_array([7; 32]);
        let db = setup_test_db().await;
        let tx = db.begin().await.unwrap();

        let err = reconstruct_batch_updates(&tx, &batch_event(tree, 0, 1), 1)
            .await
            .unwrap_err();

        assert!(
            format!("{err}").contains("applied no zkp batches"),
            "unexpected error: {err}"
        );
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
            rings_tx_id: Set(1),
            slot: Set(1),
            input_index: Set(0),
            nullifier_tree: Set(tree.to_bytes().to_vec()),
            input_queue_seq: Set(1),
            nullifier: Set([1u8; 32].to_vec()),
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
