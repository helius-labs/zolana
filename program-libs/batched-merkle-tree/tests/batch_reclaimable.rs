#![cfg(feature = "test-only")]

use zolana_batched_merkle_tree::{
    access::{
        get_merkle_tree_account_size,
        test_utils::{init_tree_account_data, load_tree_account_data},
    },
    batch::BatchState,
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::NullifierTreeError,
    layout::TreeType,
    layout::{CachedTreeUpdate, NullifierTreeLayout},
};

const ZKP: usize = 4;
const BATCH_SIZE: u64 = 4;
const ZKP_BATCH_SIZE: u64 = 1;
const TREE_PUBKEY: [u8; 32] = [7u8; 32];

fn account_data() -> Vec<u8> {
    vec![0u8; get_merkle_tree_account_size::<ZKP>()]
}

fn init_tree(data: &mut [u8]) {
    init_tree_account_data::<ZKP>(
        data,
        BATCH_SIZE,
        ZKP_BATCH_SIZE,
        40,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap();
}

fn load_tree(data: &mut [u8]) -> &mut NullifierTreeLayout<ZKP> {
    load_tree_account_data::<ZKP>(data).unwrap()
}

fn nullifier(i: u8) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[31] = i;
    value
}

fn root(i: u8) -> [u8; 32] {
    [i; 32]
}

fn insert(data: &mut [u8], values: impl IntoIterator<Item = u8>) -> Vec<u64> {
    let tree = load_tree(data);
    values
        .into_iter()
        .map(|i| tree.insert_nullifier_into_queue(&nullifier(i)).unwrap())
        .collect()
}

fn apply_update(data: &mut [u8], batch_index: usize, new_root: [u8; 32]) {
    let old_root = load_tree(data).get_root().unwrap();
    let zkp_index = load_tree(data)
        .metadata
        .queue_batches
        .batches
        .get(batch_index)
        .unwrap()
        .get_num_inserted_zkps() as usize;
    {
        let layout: &mut NullifierTreeLayout<ZKP> = wincode::deserialize_mut(data).unwrap();
        *layout
            .cached_tree_updates
            .get_mut(batch_index)
            .unwrap()
            .get_mut(zkp_index)
            .unwrap() = CachedTreeUpdate {
            old_root,
            new_root,
            occupied: 1,
        };
    }
    let tree = load_tree(data);
    let event = tree
        .apply_cached_tree_updates(TREE_PUBKEY)
        .unwrap()
        .unwrap();
    assert_eq!(event.num_update, 1);
    assert_eq!(event.new_root, new_root);
}

fn assert_roots(data: &mut [u8], expected: [Option<[u8; 32]>; ZKP]) {
    let tree = load_tree(data);
    for (slot, expected) in tree.root_history.roots.iter().zip(expected.iter()) {
        assert_eq!(*slot, expected.unwrap_or([0u8; 32]));
    }
}

#[test]
fn fully_applied_successor_advances_watermark_after_natural_root_overwrite() {
    let mut data = account_data();
    init_tree(&mut data);

    assert_eq!(insert(&mut data, 1..=4), vec![0, 1, 2, 3]);
    for i in 1..=4u8 {
        apply_update(&mut data, 0, root(i));
    }
    {
        let tree = load_tree(&mut data);
        let batch = tree.metadata.queue_batches.batches.first().unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
        assert_eq!(batch.sequence_number, 0);
        assert_eq!(batch.root_index, 0);
        assert_eq!(batch.reclaimable_sequence().unwrap(), BATCH_SIZE);
        assert!(!batch.is_reclaimable(tree.metadata.close_before_index));
        assert_eq!(tree.metadata.close_before_index, 0);
    }

    assert_eq!(insert(&mut data, [5]), vec![4]);
    apply_update(&mut data, 1, root(5));
    assert_eq!(load_tree(&mut data).metadata.close_before_index, 0);
    assert_roots(
        &mut data,
        [Some(root(4)), Some(root(5)), Some(root(2)), Some(root(3))],
    );

    assert_eq!(insert(&mut data, [6]), vec![5]);
    apply_update(&mut data, 1, root(6));
    assert_eq!(load_tree(&mut data).metadata.close_before_index, 0);

    assert_eq!(insert(&mut data, [7]), vec![6]);
    apply_update(&mut data, 1, root(7));
    assert_eq!(load_tree(&mut data).metadata.close_before_index, 0);

    assert_eq!(insert(&mut data, [8]), vec![7]);
    apply_update(&mut data, 1, root(8));
    {
        let tree = load_tree(&mut data);
        assert_eq!(tree.metadata.close_before_index, BATCH_SIZE);
        let batches = &tree.metadata.queue_batches.batches;
        assert!(batches
            .first()
            .unwrap()
            .is_reclaimable(tree.metadata.close_before_index));
        assert!(!batches
            .get(1)
            .unwrap()
            .is_reclaimable(tree.metadata.close_before_index));
    }
    assert_roots(
        &mut data,
        [Some(root(8)), Some(root(5)), Some(root(6)), Some(root(7))],
    );

    assert_eq!(insert(&mut data, [9]), vec![8]);
    let tree = load_tree(&mut data);
    let reused = tree.metadata.queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
}

#[test]
fn inserted_batch_reuse_does_not_wait_for_successor_to_be_fully_applied() {
    let mut data = account_data();
    init_tree(&mut data);

    assert_eq!(insert(&mut data, 1..=8), (0..8).collect::<Vec<_>>());
    for i in 1..=4u8 {
        apply_update(&mut data, 0, root(i));
    }
    {
        let tree = load_tree(&mut data);
        let batches = &tree.metadata.queue_batches.batches;
        assert_eq!(batches.first().unwrap().get_state(), BatchState::Inserted);
        assert_eq!(batches.get(1).unwrap().get_state(), BatchState::Full);
        assert_eq!(
            tree.metadata.queue_batches.currently_processing_batch_index,
            0
        );
        assert_eq!(tree.metadata.close_before_index, 0);
    }
    assert_eq!(insert(&mut data, [9]), vec![8]);
    {
        let tree = load_tree(&mut data);
        let reused = tree.metadata.queue_batches.batches.first().unwrap();
        assert_eq!(reused.get_state(), BatchState::Fill);
        assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
        assert_eq!(reused.get_num_inserted_elements(), 1);
    }
    assert_eq!(load_tree(&mut data).metadata.close_before_index, 0);
    assert_roots(
        &mut data,
        [Some(root(4)), Some(root(1)), Some(root(2)), Some(root(3))],
    );

    apply_update(&mut data, 1, root(5));
    assert_eq!(load_tree(&mut data).metadata.close_before_index, 0);
    assert_roots(
        &mut data,
        [Some(root(4)), Some(root(5)), Some(root(2)), Some(root(3))],
    );

    for i in 6..=8u8 {
        apply_update(&mut data, 1, root(i));
        let expected_watermark = if i == 8 { BATCH_SIZE } else { 0 };
        assert_eq!(
            load_tree(&mut data).metadata.close_before_index,
            expected_watermark
        );
    }
    assert_roots(
        &mut data,
        [Some(root(8)), Some(root(5)), Some(root(6)), Some(root(7))],
    );
    let tree = load_tree(&mut data);
    let reused = tree.metadata.queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
}

#[test]
fn full_queue_rejects_inserts_until_the_pending_batch_is_applied() {
    let mut data = account_data();
    init_tree(&mut data);

    assert_eq!(insert(&mut data, 1..=8), (0..8).collect::<Vec<_>>());
    {
        let tree = load_tree(&mut data);
        let queue = &tree.metadata.queue_batches;
        assert_eq!(queue.batches.first().unwrap().get_state(), BatchState::Full);
        assert_eq!(queue.batches.get(1).unwrap().get_state(), BatchState::Full);
        assert_eq!(queue.currently_processing_batch_index, 0);
        assert_eq!(tree.next_queued_leaf_index().unwrap(), 1 + 2 * BATCH_SIZE);
        assert_eq!(
            tree.remaining_queue_capacity().unwrap(),
            tree.metadata.capacity - (1 + 2 * BATCH_SIZE)
        );
    }

    let before = data.clone();
    assert_eq!(
        load_tree(&mut data)
            .insert_nullifier_into_queue(&nullifier(9))
            .unwrap_err(),
        NullifierTreeError::BatchNotReady
    );
    assert_eq!(data, before);

    for i in 1..=4u8 {
        apply_update(&mut data, 0, root(i));
    }
    assert_eq!(insert(&mut data, [9]), vec![8]);
    let tree = load_tree(&mut data);
    let reused = tree.metadata.queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
    assert_eq!(tree.next_queued_leaf_index().unwrap(), 2 + 2 * BATCH_SIZE);
}
