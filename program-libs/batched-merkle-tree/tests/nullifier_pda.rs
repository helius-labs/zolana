#![cfg(feature = "test-only")]

use zolana_batched_merkle_tree::{
    access::{
        get_merkle_tree_account_size,
        test_utils::{init_tree_account_data, load_tree_account_data},
    },
    batch::Batch,
    constants::{NULLIFIER_TREE_INIT_ROOT_40, NUM_BATCHES},
    errors::NullifierTreeError,
    layout::NullifierTreeLayout,
    layout::QueueBatches,
    layout::{BatchedMerkleTreeMetadata, TreeType},
};
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

const ZKP: usize = 4;
const BATCH_SIZE: u64 = 4;
const ZKP_BATCH_SIZE: u64 = 1;

fn account_data() -> Vec<u8> {
    vec![0u8; get_merkle_tree_account_size::<ZKP>()]
}

fn init_tree(data: &mut [u8]) -> &mut NullifierTreeLayout<ZKP> {
    init_tree_account_data::<ZKP>(
        data,
        BATCH_SIZE,
        ZKP_BATCH_SIZE,
        40,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap()
}

fn load_tree(data: &mut [u8]) -> &mut NullifierTreeLayout<ZKP> {
    load_tree_account_data::<ZKP>(data).unwrap()
}

fn nullifier(i: u8) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[31] = i;
    value
}

#[test]
fn state_struct_sizes() {
    const HASH_CHAINS: usize = ZKP * 32;
    assert_eq!(core::mem::size_of::<Batch<ZKP>>(), 72 + HASH_CHAINS);
    assert_eq!(
        core::mem::size_of::<QueueBatches<ZKP>>(),
        192 + NUM_BATCHES * HASH_CHAINS
    );
    assert_eq!(
        core::mem::size_of::<BatchedMerkleTreeMetadata<ZKP>>(),
        240 + NUM_BATCHES * HASH_CHAINS
    );
}

/// A single-slot root history seeds its only slot and wraps the cursor back to
/// zero. Writing an unwrapped `1` would leave the cursor out of range, so the
/// tree would initialize but never load again.
#[test]
fn single_slot_root_history_initializes_and_reloads() {
    let mut data = vec![0u8; get_merkle_tree_account_size::<1>()];

    let tree = init_tree_account_data::<1>(
        &mut data,
        ZKP_BATCH_SIZE,
        ZKP_BATCH_SIZE,
        40,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap();
    assert_eq!(tree.get_root(), Some(NULLIFIER_TREE_INIT_ROOT_40));

    let reloaded = load_tree_account_data::<1>(&mut data).unwrap();
    assert_eq!(reloaded.get_root(), Some(NULLIFIER_TREE_INIT_ROOT_40));
}

#[test]
fn derived_root_history_must_match_one_batch_of_zkp_updates() {
    let mut wrong_derived_capacity = account_data();
    assert_eq!(
        init_tree_account_data::<ZKP>(
            &mut wrong_derived_capacity,
            BATCH_SIZE + ZKP_BATCH_SIZE,
            ZKP_BATCH_SIZE,
            40,
            TreeType::AddressV2,
            Some(NULLIFIER_TREE_INIT_ROOT_40),
        )
        .unwrap_err(),
        NullifierTreeError::InvalidRootHistoryCapacity
    );

    let mut wrong_cache_count = vec![0u8; get_merkle_tree_account_size::<5>()];
    assert_eq!(
        init_tree_account_data::<5>(
            &mut wrong_cache_count,
            BATCH_SIZE,
            ZKP_BATCH_SIZE,
            40,
            TreeType::AddressV2,
            Some(NULLIFIER_TREE_INIT_ROOT_40),
        )
        .unwrap_err(),
        NullifierTreeError::InvalidRootHistoryCapacity
    );
}

#[test]
fn malformed_root_history_and_batch_metadata_are_rejected_on_load() {
    let mut bad_root_cursor = account_data();
    init_tree(&mut bad_root_cursor);
    let layout: &mut NullifierTreeLayout<ZKP> =
        wincode::deserialize_mut(&mut bad_root_cursor).unwrap();
    layout.root_history.current_index = ZKP as u64;
    assert_eq!(
        load_tree_account_data::<ZKP>(&mut bad_root_cursor).unwrap_err(),
        NullifierTreeError::InvalidRootHistoryCapacity
    );

    let mut invalid_reserved = account_data();
    init_tree(&mut invalid_reserved);
    let layout: &mut NullifierTreeLayout<ZKP> =
        wincode::deserialize_mut(&mut invalid_reserved).unwrap();
    layout.metadata.queue_batches.reserved = 0;
    assert_eq!(
        load_tree_account_data::<ZKP>(&mut invalid_reserved).unwrap_err(),
        NullifierTreeError::InvalidBatchConfiguration
    );

    let mut inconsistent_batch = account_data();
    init_tree(&mut inconsistent_batch);
    let layout: &mut NullifierTreeLayout<ZKP> =
        wincode::deserialize_mut(&mut inconsistent_batch).unwrap();
    layout.metadata.queue_batches.batches[0].batch_size += 1;
    assert_eq!(
        load_tree_account_data::<ZKP>(&mut inconsistent_batch).unwrap_err(),
        NullifierTreeError::InvalidBatchConfiguration
    );
}

#[test]
fn insert_returns_sequential_queue_indices() {
    let mut data = account_data();
    let tree = init_tree(&mut data);
    for i in 0..3u8 {
        assert_eq!(
            tree.insert_nullifier_into_queue(&nullifier(i + 1)).unwrap(),
            i as u64
        );
    }
    assert_eq!(tree.metadata.queue_batches.next_index, 3);
}

#[test]
fn non_canonical_values_are_rejected() {
    let mut data = account_data();
    init_tree(&mut data);
    let before = data.clone();

    let tree = load_tree(&mut data);
    for value in [BN254_SCALAR_MODULUS_BE, [0xff; 32]] {
        assert_eq!(
            tree.insert_nullifier_into_queue(&value).unwrap_err(),
            NullifierTreeError::NonCanonicalFieldElement
        );
    }
    assert_eq!(data, before);

    let mut modulus_minus_one = BN254_SCALAR_MODULUS_BE;
    modulus_minus_one[31] = 0;
    let tree = load_tree(&mut data);
    assert_eq!(
        tree.insert_nullifier_into_queue(&modulus_minus_one)
            .unwrap(),
        0
    );
}

#[test]
fn queue_index_mismatch_is_rejected() {
    let mut data = account_data();
    init_tree(&mut data);

    let tree = load_tree(&mut data);
    tree.metadata.queue_batches.next_index += 1;
    assert_eq!(
        tree.insert_nullifier_into_queue(&nullifier(1)).unwrap_err(),
        NullifierTreeError::QueueIndexMismatch
    );
}
