#![cfg(feature = "test-only")]

use solana_address::Address;
use zolana_batched_merkle_tree::{
    batch::Batch,
    constants::{NULLIFIER_MARKER_SEED, NULLIFIER_MARKER_SIZE, NULLIFIER_TREE_INIT_ROOT_40},
    errors::BatchedMerkleTreeError,
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    merkle_tree_metadata::{BatchedMerkleTreeMetadata, TreeType},
    nullifier_marker::{host, nullifier_marker_seeds, NullifierMarker},
    queue_batch_metadata::QueueBatches,
};
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

const RH: usize = 10;
const ZKP: usize = 4;
const BATCH_SIZE: u64 = 4;
const ZKP_BATCH_SIZE: u64 = 1;

type Tree<'a> = BatchedMerkleTreeAccount<'a, RH, ZKP>;

fn account_data() -> Vec<u8> {
    vec![0u8; get_merkle_tree_account_size::<RH, ZKP>()]
}

fn init_tree<'a>(data: &'a mut [u8], pubkey: &Address) -> Tree<'a> {
    Tree::init(
        data,
        pubkey,
        RH as u32,
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

#[test]
fn state_struct_sizes() {
    assert_eq!(core::mem::size_of::<Batch>(), 72);
    assert_eq!(core::mem::size_of::<QueueBatches>(), 192);
    assert_eq!(core::mem::size_of::<BatchedMerkleTreeMetadata>(), 240);
}

#[test]
fn marker_payload_size_and_seeds() {
    let marker = NullifierMarker {
        queue_index: 7,
        bump: 254,
    };
    assert_eq!(borsh::to_vec(&marker).unwrap().len(), NULLIFIER_MARKER_SIZE);
    assert!(!marker.is_closable(7));
    assert!(marker.is_closable(8));

    let tree = [1u8; 32];
    let value = nullifier(9);
    let seeds = nullifier_marker_seeds(&tree, &value);
    assert_eq!(seeds, [NULLIFIER_MARKER_SEED, &tree[..], &value[..]]);
    assert_eq!(NULLIFIER_MARKER_SEED, b"nullifier");
}

#[test]
fn insert_returns_queue_index_and_reserves_marker() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    let mut tree = init_tree(&mut data, &pubkey);
    for i in 0..3u8 {
        let value = nullifier(i + 1);
        assert_eq!(tree.insert_nullifier_into_queue(&value).unwrap(), i as u64);
        assert!(host::contains(&pubkey.to_bytes(), &value));
        assert_eq!(
            host::queue_index(&pubkey.to_bytes(), &value),
            Some(i as u64)
        );
    }
    assert_eq!(tree.get_metadata().queue_batches.next_index, 3);
}

#[test]
fn duplicate_insert_fails_without_mutation() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    let value = nullifier(1);
    init_tree(&mut data, &pubkey)
        .insert_nullifier_into_queue(&value)
        .unwrap();
    let before = data.clone();

    let mut tree = load_tree(&mut data, &pubkey);
    assert_eq!(
        tree.insert_nullifier_into_queue(&value).unwrap_err(),
        BatchedMerkleTreeError::NonInclusionCheckFailed
    );
    assert_eq!(data, before);
    assert_eq!(host::queue_index(&pubkey.to_bytes(), &value), Some(0));
}

#[test]
fn close_before_watermark_fails() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    let value = nullifier(1);
    let tree_key = pubkey.to_bytes();
    let queue_index = init_tree(&mut data, &pubkey)
        .insert_nullifier_into_queue(&value)
        .unwrap();

    let tree = load_tree(&mut data, &pubkey);
    assert_eq!(tree.close_before_index, 0);
    assert_eq!(
        tree.close_nullifier_marker_host(&value).unwrap_err(),
        BatchedMerkleTreeError::NullifierMarkerNotClosable
    );
    assert!(host::contains(&tree_key, &value));

    assert_eq!(
        host::close(&tree_key, &value, queue_index).unwrap_err(),
        BatchedMerkleTreeError::NullifierMarkerNotClosable
    );
    host::close(&tree_key, &value, queue_index + 1).unwrap();
    assert!(!host::contains(&tree_key, &value));
    assert_eq!(
        host::close(&tree_key, &value, queue_index + 1).unwrap_err(),
        BatchedMerkleTreeError::NullifierMarkerMissing
    );
}

#[test]
fn non_canonical_values_are_rejected() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    init_tree(&mut data, &pubkey);
    let before = data.clone();

    let mut tree = load_tree(&mut data, &pubkey);
    for value in [BN254_SCALAR_MODULUS_BE, [0xff; 32]] {
        assert_eq!(
            tree.insert_nullifier_into_queue(&value).unwrap_err(),
            BatchedMerkleTreeError::NonCanonicalFieldElement
        );
        assert!(!host::contains(&pubkey.to_bytes(), &value));
    }
    assert_eq!(data, before);

    let mut modulus_minus_one = BN254_SCALAR_MODULUS_BE;
    modulus_minus_one[31] = 0;
    let mut tree = load_tree(&mut data, &pubkey);
    assert_eq!(
        tree.insert_nullifier_into_queue(&modulus_minus_one)
            .unwrap(),
        0
    );
}

#[test]
fn queue_index_mismatch_is_rejected() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    init_tree(&mut data, &pubkey);
    let value = nullifier(1);

    let mut tree = load_tree(&mut data, &pubkey);
    tree.get_metadata_mut().queue_batches.next_index += 1;
    assert_eq!(
        tree.insert_nullifier_into_queue(&value).unwrap_err(),
        BatchedMerkleTreeError::QueueIndexMismatch
    );
    assert!(!host::contains(&pubkey.to_bytes(), &value));
}

#[test]
fn reinit_clears_stale_reservations() {
    let pubkey = Address::new_unique();
    let value = nullifier(1);
    {
        let mut data = account_data();
        init_tree(&mut data, &pubkey)
            .insert_nullifier_into_queue(&value)
            .unwrap();
    }
    assert!(host::contains(&pubkey.to_bytes(), &value));

    let mut data = account_data();
    let mut tree = init_tree(&mut data, &pubkey);
    assert!(!host::contains(&pubkey.to_bytes(), &value));
    assert_eq!(tree.insert_nullifier_into_queue(&value).unwrap(), 0);
}

#[test]
fn markers_are_keyed_by_tree() {
    let value = nullifier(1);
    let first = Address::new_unique();
    let second = Address::new_unique();
    let mut first_data = account_data();
    let mut second_data = account_data();
    assert_eq!(
        init_tree(&mut first_data, &first)
            .insert_nullifier_into_queue(&value)
            .unwrap(),
        0
    );
    assert_eq!(
        init_tree(&mut second_data, &second)
            .insert_nullifier_into_queue(&value)
            .unwrap(),
        0
    );
    host::clear_tree(&first.to_bytes());
    assert!(!host::contains(&first.to_bytes(), &value));
    assert!(host::contains(&second.to_bytes(), &value));
}
