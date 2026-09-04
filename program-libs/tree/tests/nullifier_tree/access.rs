use crate::common::{init_tree_account_data, load_tree_account_data};
use zolana_tree::nullifier_tree::{
    access::get_merkle_tree_account_size,
    batch::{Batch, CachedTreeUpdate},
    constants::NUM_BATCHES,
    error::NullifierTreeError,
    layout::NullifierTreeLayout,
};

const ZKP_BATCHES: usize = 5;

fn assert_corrupt_layout_rejected(
    corrupt: impl FnOnce(&mut NullifierTreeLayout<ZKP_BATCHES>),
    expected: NullifierTreeError,
) {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<ZKP_BATCHES>()];
    init_tree_account_data::<ZKP_BATCHES>(&mut account_data, 5, 1, 4).unwrap();
    corrupt(wincode::deserialize_mut(&mut account_data).unwrap());
    assert_eq!(
        load_tree_account_data::<ZKP_BATCHES>(&mut account_data).unwrap_err(),
        expected
    );
}

#[test]
fn test_init_invalid_account_size() {
    let mut account_data = vec![0u8; 200];
    let layout = init_tree_account_data::<5>(&mut account_data, 10, 10, 40);
    assert_eq!(
        layout.err().unwrap(),
        NullifierTreeError::InvalidAccountSize
    );
}

#[test]
fn test_cached_tree_update_region_layout_and_size() {
    let update_size = core::mem::size_of::<CachedTreeUpdate>();
    assert_eq!(update_size, 65);

    const ZKP: usize = 4;
    let full = get_merkle_tree_account_size::<ZKP>();
    let cached_tree_update_bytes = NUM_BATCHES * ZKP * update_size;

    let mut old_sized = vec![0u8; full - cached_tree_update_bytes];
    let layout = init_tree_account_data::<ZKP>(&mut old_sized, 4, 1, 40);
    assert_eq!(
        layout.err().unwrap(),
        NullifierTreeError::InvalidAccountSize
    );
}

#[test]
fn test_state_struct_sizes() {
    const ZKP: usize = 4;
    const HASH_CHAINS: usize = ZKP * 32;
    const CACHED_TREE_UPDATES: usize = ZKP * 65;
    // A batch is padded to the alignment of its metadata words.
    const BATCH: usize = 448;
    const ROOT_HISTORY: usize = 8 + ZKP * 32;
    assert_eq!(
        (56 + HASH_CHAINS + CACHED_TREE_UPDATES).next_multiple_of(8),
        BATCH
    );
    assert_eq!(core::mem::size_of::<Batch<ZKP>>(), BATCH);
    assert_eq!(
        get_merkle_tree_account_size::<ZKP>(),
        72 + ROOT_HISTORY + NUM_BATCHES * BATCH
    );
}

#[test]
fn test_tree_is_full() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
    let tree = init_tree_account_data::<5>(&mut account_data, 5, 1, 4).unwrap();
    // 1. empty tree is not full
    assert!(!tree.tree_is_full(1));
    tree.next_index = tree.capacity - 2;
    assert!(!tree.tree_is_full(1));
    // A batch of 2 fills the last two leaves exactly: not full.
    assert!(!tree.tree_is_full(2));
    // A batch of 3 would write past the last leaf: full.
    assert!(tree.tree_is_full(3));
    tree.next_index = tree.capacity - 1;
    // The final leaf still fits a single value (or a batch of 1).
    assert!(!tree.tree_is_full(1));
    assert!(tree.tree_is_full(2));
    tree.next_index = tree.capacity;
    assert!(tree.tree_is_full(1));
    tree.next_index = tree.capacity + 1;
    assert!(tree.tree_is_full(1));
    tree.next_index = u64::MAX;
    assert!(tree.tree_is_full(1));
}

#[test]
fn corrupt_batch_state_and_counters_are_rejected_on_load() {
    assert_corrupt_layout_rejected(
        |layout| layout.batches[0].set_raw_state(3),
        NullifierTreeError::InvalidBatchState,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.batches[0].set_num_full_zkp_batches(6),
        NullifierTreeError::InvalidBatchConfiguration,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.batches[0].set_num_inserted(1),
        NullifierTreeError::InvalidBatchConfiguration,
    );
    assert_corrupt_layout_rejected(
        |layout| {
            layout.batches[0].set_cached_tree_update(
                0,
                CachedTreeUpdate {
                    occupied: 2,
                    ..CachedTreeUpdate::default()
                },
            );
        },
        NullifierTreeError::InvalidBatchConfiguration,
    );
}

#[test]
fn corrupt_tree_and_queue_progress_are_rejected_on_load() {
    assert_corrupt_layout_rejected(
        |layout| layout.sequence_number = 1,
        NullifierTreeError::InvalidIndex,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.close_before_index = 1,
        NullifierTreeError::InvalidIndex,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.queue_next_index += 1,
        NullifierTreeError::InvalidBatchConfiguration,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.currently_processing_batch_index = 1,
        NullifierTreeError::InvalidBatchConfiguration,
    );
    assert_corrupt_layout_rejected(
        |layout| layout.batches[1].start_index += 1,
        NullifierTreeError::InvalidBatchConfiguration,
    );
}
