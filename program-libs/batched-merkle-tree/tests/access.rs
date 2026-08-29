use zolana_batched_merkle_tree::{
    access::{get_merkle_tree_account_size, test_utils::init_tree_account_data},
    constants::NUM_BATCHES,
    errors::NullifierTreeError,
    layout::{CachedTreeUpdate, TreeType},
};

#[test]
fn test_init_invalid_account_size() {
    let mut account_data = vec![0u8; 200];
    let layout =
        init_tree_account_data::<5>(&mut account_data, 10, 10, 40, TreeType::AddressV2, None);
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
    let cached_tree_update_bytes = core::mem::size_of::<[[CachedTreeUpdate; ZKP]; 2]>();
    assert_eq!(cached_tree_update_bytes, 2 * ZKP * update_size);

    let mut old_sized = vec![0u8; full - cached_tree_update_bytes];
    let layout = init_tree_account_data::<ZKP>(&mut old_sized, 4, 1, 40, TreeType::AddressV2, None);
    assert_eq!(
        layout.err().unwrap(),
        NullifierTreeError::InvalidAccountSize
    );
}

#[test]
fn test_state_struct_sizes() {
    const ZKP: usize = 4;
    const HASH_CHAINS: usize = ZKP * 32;
    const ROOT_HISTORY: usize = 8 + ZKP * 32;
    const CACHED_TREE_UPDATES: usize = NUM_BATCHES * ZKP * 65;
    assert_eq!(
        core::mem::size_of::<zolana_batched_merkle_tree::batch::Batch<ZKP>>(),
        72 + HASH_CHAINS
    );
    assert_eq!(
        core::mem::size_of::<zolana_batched_merkle_tree::layout::QueueBatches<ZKP>>(),
        192 + NUM_BATCHES * HASH_CHAINS
    );
    assert_eq!(
        get_merkle_tree_account_size::<ZKP>(),
        240 + NUM_BATCHES * HASH_CHAINS + ROOT_HISTORY + CACHED_TREE_UPDATES
    );
}

#[test]
fn test_tree_is_full() {
    let mut account_data = vec![0u8; get_merkle_tree_account_size::<5>()];
    let tree =
        init_tree_account_data::<5>(&mut account_data, 5, 1, 4, TreeType::AddressV2, None).unwrap();
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
