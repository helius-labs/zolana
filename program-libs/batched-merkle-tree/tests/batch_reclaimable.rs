use solana_address::Address;
use zolana_batched_merkle_tree::{
    batch::BatchState,
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    merkle_tree_metadata::TreeType,
    zero_copy::{CachedTreeUpdate, TreeAccountLayout},
};

const ZKP: usize = 4;
const BATCH_SIZE: u64 = 4;
const ZKP_BATCH_SIZE: u64 = 1;

type Tree<'a> = BatchedMerkleTreeAccount<'a, ZKP>;

fn account_data() -> Vec<u8> {
    vec![0u8; get_merkle_tree_account_size::<ZKP>()]
}

fn init_tree<'a>(data: &'a mut [u8], pubkey: &Address) -> Tree<'a> {
    Tree::init(
        data,
        pubkey,
        BATCH_SIZE,
        ZKP_BATCH_SIZE,
        40,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap()
}

fn load_tree<'a>(data: &'a mut [u8], pubkey: &Address) -> Tree<'a> {
    Tree::address_from_bytes(data, pubkey).unwrap()
}

fn nullifier(i: u8) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[31] = i;
    value
}

fn root(i: u8) -> [u8; 32] {
    [i; 32]
}

fn insert(data: &mut [u8], pubkey: &Address, values: impl IntoIterator<Item = u8>) -> Vec<u64> {
    let mut tree = load_tree(data, pubkey);
    values
        .into_iter()
        .map(|i| tree.insert_nullifier_into_queue(&nullifier(i)).unwrap())
        .collect()
}

fn apply_update(data: &mut [u8], pubkey: &Address, batch_index: usize, new_root: [u8; 32]) {
    let old_root = load_tree(data, pubkey).get_root().unwrap();
    let zkp_index = load_tree(data, pubkey)
        .get_metadata()
        .queue_batches
        .batches
        .get(batch_index)
        .unwrap()
        .get_num_inserted_zkps() as usize;
    {
        let layout: &mut TreeAccountLayout<ZKP> = wincode::deserialize_mut(data).unwrap();
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
    let mut tree = load_tree(data, pubkey);
    let event = tree.apply_cached_tree_updates().unwrap().unwrap();
    assert_eq!(event.num_update, 1);
    assert_eq!(event.new_root, new_root);
}

fn assert_roots(data: &mut [u8], pubkey: &Address, expected: [Option<[u8; 32]>; ZKP]) {
    let tree = load_tree(data, pubkey);
    for (slot, expected) in tree.root_history().iter().zip(expected.iter()) {
        assert_eq!(*slot, expected.unwrap_or([0u8; 32]));
    }
}

#[test]
fn fully_applied_successor_advances_watermark_after_natural_root_overwrite() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    init_tree(&mut data, &pubkey);

    assert_eq!(insert(&mut data, &pubkey, 1..=4), vec![0, 1, 2, 3]);
    for i in 1..=4u8 {
        apply_update(&mut data, &pubkey, 0, root(i));
    }
    {
        let tree = load_tree(&mut data, &pubkey);
        let batch = tree.get_metadata().queue_batches.batches.first().unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
        assert_eq!(batch.sequence_number, 0);
        assert_eq!(batch.root_index, 0);
        assert_eq!(batch.reclaimable_sequence().unwrap(), BATCH_SIZE);
        assert!(!batch.is_reclaimable(tree.close_before_index));
        assert_eq!(tree.close_before_index, 0);
    }

    assert_eq!(insert(&mut data, &pubkey, [5]), vec![4]);
    apply_update(&mut data, &pubkey, 1, root(5));
    assert_eq!(load_tree(&mut data, &pubkey).close_before_index, 0);
    assert_roots(
        &mut data,
        &pubkey,
        [Some(root(4)), Some(root(5)), Some(root(2)), Some(root(3))],
    );

    assert_eq!(insert(&mut data, &pubkey, [6]), vec![5]);
    apply_update(&mut data, &pubkey, 1, root(6));
    assert_eq!(load_tree(&mut data, &pubkey).close_before_index, 0);

    assert_eq!(insert(&mut data, &pubkey, [7]), vec![6]);
    apply_update(&mut data, &pubkey, 1, root(7));
    assert_eq!(load_tree(&mut data, &pubkey).close_before_index, 0);

    assert_eq!(insert(&mut data, &pubkey, [8]), vec![7]);
    apply_update(&mut data, &pubkey, 1, root(8));
    {
        let tree = load_tree(&mut data, &pubkey);
        assert_eq!(tree.close_before_index, BATCH_SIZE);
        let batches = &tree.get_metadata().queue_batches.batches;
        assert!(batches
            .first()
            .unwrap()
            .is_reclaimable(tree.close_before_index));
        assert!(!batches
            .get(1)
            .unwrap()
            .is_reclaimable(tree.close_before_index));
    }
    assert_roots(
        &mut data,
        &pubkey,
        [Some(root(8)), Some(root(5)), Some(root(6)), Some(root(7))],
    );

    assert_eq!(insert(&mut data, &pubkey, [9]), vec![8]);
    let tree = load_tree(&mut data, &pubkey);
    let reused = tree.get_metadata().queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
}

#[test]
fn inserted_batch_reuse_does_not_wait_for_successor_to_be_fully_applied() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    init_tree(&mut data, &pubkey);

    assert_eq!(
        insert(&mut data, &pubkey, 1..=8),
        (0..8).collect::<Vec<_>>()
    );
    for i in 1..=4u8 {
        apply_update(&mut data, &pubkey, 0, root(i));
    }
    {
        let tree = load_tree(&mut data, &pubkey);
        let batches = &tree.get_metadata().queue_batches.batches;
        assert_eq!(batches.first().unwrap().get_state(), BatchState::Inserted);
        assert_eq!(batches.get(1).unwrap().get_state(), BatchState::Full);
        assert_eq!(
            tree.get_metadata()
                .queue_batches
                .currently_processing_batch_index,
            0
        );
        assert_eq!(tree.close_before_index, 0);
    }
    assert_eq!(insert(&mut data, &pubkey, [9]), vec![8]);
    {
        let tree = load_tree(&mut data, &pubkey);
        let reused = tree.get_metadata().queue_batches.batches.first().unwrap();
        assert_eq!(reused.get_state(), BatchState::Fill);
        assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
        assert_eq!(reused.get_num_inserted_elements(), 1);
    }
    assert_eq!(load_tree(&mut data, &pubkey).close_before_index, 0);
    assert_roots(
        &mut data,
        &pubkey,
        [Some(root(4)), Some(root(1)), Some(root(2)), Some(root(3))],
    );

    apply_update(&mut data, &pubkey, 1, root(5));
    assert_eq!(load_tree(&mut data, &pubkey).close_before_index, 0);
    assert_roots(
        &mut data,
        &pubkey,
        [Some(root(4)), Some(root(5)), Some(root(2)), Some(root(3))],
    );

    for i in 6..=8u8 {
        apply_update(&mut data, &pubkey, 1, root(i));
        let expected_watermark = if i == 8 { BATCH_SIZE } else { 0 };
        assert_eq!(
            load_tree(&mut data, &pubkey).close_before_index,
            expected_watermark
        );
    }
    assert_roots(
        &mut data,
        &pubkey,
        [Some(root(8)), Some(root(5)), Some(root(6)), Some(root(7))],
    );
    let tree = load_tree(&mut data, &pubkey);
    let reused = tree.get_metadata().queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
}

#[test]
fn full_queue_rejects_inserts_until_the_pending_batch_is_applied() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    init_tree(&mut data, &pubkey);

    assert_eq!(
        insert(&mut data, &pubkey, 1..=8),
        (0..8).collect::<Vec<_>>()
    );
    {
        let tree = load_tree(&mut data, &pubkey);
        let queue = &tree.get_metadata().queue_batches;
        assert_eq!(queue.batches.first().unwrap().get_state(), BatchState::Full);
        assert_eq!(queue.batches.get(1).unwrap().get_state(), BatchState::Full);
        assert_eq!(queue.currently_processing_batch_index, 0);
        assert_eq!(tree.next_queued_leaf_index().unwrap(), 1 + 2 * BATCH_SIZE);
        assert_eq!(
            tree.remaining_queue_capacity().unwrap(),
            tree.capacity - (1 + 2 * BATCH_SIZE)
        );
    }

    let before = data.clone();
    assert_eq!(
        load_tree(&mut data, &pubkey)
            .insert_nullifier_into_queue(&nullifier(9))
            .unwrap_err(),
        BatchedMerkleTreeError::BatchNotReady
    );
    assert_eq!(data, before);

    for i in 1..=4u8 {
        apply_update(&mut data, &pubkey, 0, root(i));
    }
    assert_eq!(insert(&mut data, &pubkey, [9]), vec![8]);
    let tree = load_tree(&mut data, &pubkey);
    let reused = tree.get_metadata().queue_batches.batches.first().unwrap();
    assert_eq!(reused.get_state(), BatchState::Fill);
    assert_eq!(reused.start_index, 1 + 2 * BATCH_SIZE);
    assert_eq!(reused.get_num_inserted_elements(), 1);
    assert_eq!(tree.next_queued_leaf_index().unwrap(), 2 + 2 * BATCH_SIZE);
}
