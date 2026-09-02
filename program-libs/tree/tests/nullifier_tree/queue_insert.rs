use rand::{Rng, SeedableRng};
use zolana_tree::nullifier_tree::{
    access::{
        get_merkle_tree_account_size,
        test_utils::{init_tree_account_data, load_tree_account_data},
    },
    batch::BatchState,
    constants::NUM_BATCHES,
    error::NullifierTreeError,
};

fn random_nullifier(rng: &mut rand::prelude::StdRng) -> [u8; 32] {
    let mut value: [u8; 32] = rng.gen();
    value[0] = 0;
    value
}

fn insert_rnd_addresses<const ZKP: usize>(
    account_data: &mut [u8],
    count: u64,
    rng: &mut rand::prelude::StdRng,
) -> Result<(), NullifierTreeError> {
    let tree = load_tree_account_data::<ZKP>(account_data)?;
    for _ in 0..count {
        let address = random_nullifier(rng);
        tree.insert_nullifier_into_queue(&address)?;
    }
    Ok(())
}

/// A reused batch must cover the queue index range one full rotation
/// (`NUM_BATCHES * batch_size`) after its previous start, keeping the
/// indexer-visible start_index consistent with the init-time invariant
/// `start_index = batch_size * i + next_index`.
#[test]
fn test_reused_batch_start_index_advances_by_one_rotation() {
    let batch_size = 2;
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<1>()];
    let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
    // An AddressV2 tree seeds next_index = 1, so batch 0 starts at queue index 1.
    let init_start_index = 1;
    let tree = init_tree_account_data::<1>(&mut account_data, batch_size, batch_size, 40).unwrap();
    assert_eq!(tree.batches.first().unwrap().start_index, init_start_index);

    // Fill batch 0, then mark it inserted so it becomes reusable.
    for _ in 0..batch_size {
        tree.insert_nullifier_into_queue(&random_nullifier(rng))
            .unwrap();
    }
    let batch = tree.batches.get_mut(0).unwrap();
    batch.mark_as_inserted_in_merkle_tree().unwrap();
    assert_eq!(batch.get_state(), BatchState::Inserted);
    assert_eq!(
        batch.reclaimable_sequence().unwrap(),
        init_start_index - 1 + batch_size
    );

    // Fill batch 1, which returns the cursor to batch 0.
    for _ in 0..batch_size {
        tree.insert_nullifier_into_queue(&random_nullifier(rng))
            .unwrap();
    }
    assert_eq!(tree.currently_processing_batch_index, 0);

    // The next insert reuses batch 0 one full rotation ahead.
    tree.insert_nullifier_into_queue(&random_nullifier(rng))
        .unwrap();
    let batch = tree.batches.first().unwrap();
    assert_eq!(batch.get_state(), BatchState::Fill);
    assert_eq!(
        batch.start_index,
        init_start_index + NUM_BATCHES as u64 * batch_size
    );
}

/// Queued values reserve leaves ahead of the tree, so the queue must reject an
/// insert once the reserved leaf index reaches tree capacity.
#[test]
fn test_queue_rejects_insert_at_tree_capacity() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<200>()];
    let height = 4;
    let tree_capacity = 2u64.pow(height);
    let tree = init_tree_account_data::<200>(&mut account_data, 200, 1, height).unwrap();
    // 1. The init element occupies leaf 0, so capacity - 1 leaves remain.
    assert_eq!(tree.remaining_queue_capacity().unwrap(), tree_capacity - 1);

    let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
    insert_rnd_addresses::<200>(&mut account_data, tree_capacity - 2, rng).unwrap();
    // 2. one free leaf left
    let tree = load_tree_account_data::<200>(&mut account_data).unwrap();
    assert_eq!(tree.remaining_queue_capacity().unwrap(), 1);

    // 3. the last value fills the last leaf
    insert_rnd_addresses::<200>(&mut account_data, 1, rng).unwrap();
    let tree = load_tree_account_data::<200>(&mut account_data).unwrap();
    assert_eq!(tree.remaining_queue_capacity().unwrap(), 0);

    // 4. one more value does not fit and must be rejected.
    assert_eq!(
        tree.insert_nullifier_into_queue(&random_nullifier(rng))
            .unwrap_err(),
        NullifierTreeError::TreeIsFull
    );
}

/// A queue insert advances the queue's next index only. The tree's next index
/// moves when a batch is applied, not when a value is queued.
#[test]
fn test_queue_insert_advances_queue_index_only() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
    let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
    let tree = init_tree_account_data::<5>(&mut account_data, 5, 1, 40).unwrap();

    let previous_next_index = tree.next_index;
    let previous_queue_next_index = tree.queue_next_index;
    tree.insert_nullifier_into_queue(&random_nullifier(rng))
        .unwrap();
    assert_eq!(tree.next_index, previous_next_index);
    assert_eq!(tree.queue_next_index, previous_queue_next_index + 1);
}
