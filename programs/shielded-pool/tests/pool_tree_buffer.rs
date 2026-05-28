//! Buffer-level coverage of the combined-account pool-tree init, state-append,
//! and address-tree queue paths against an in-memory account buffer — no
//! Solana runtime needed.

use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_hasher::{Hasher, Poseidon};
use light_sparse_merkle_tree::SparseMerkleTree;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, append_state_leaves, current_nullifier_next_index,
    current_nullifier_root_index, current_state_root_index, init_pool_tree_account,
    nullifier_root_by_index, pool_tree_account_size, push_nullifier_root,
    push_nullifier_root_with_next_index, state_next_index_offset, state_root_by_index,
    state_root_offset, ADDRESS_SUB_TREE_OFFSET, DISCRIMINATOR_OFFSET, INITIAL_NULLIFIER_ROOT,
    STATE_HEIGHT,
};

const OWNER: pinocchio::Address = pinocchio::Address::new_from_array([1u8; 32]);
const TREE: pinocchio::Address = pinocchio::Address::new_from_array([2u8; 32]);

/// Allocate an 8-byte-aligned buffer (Solana account data is always aligned;
/// Vec<u8> isn't guaranteed to be).
fn allocate_buffer() -> Vec<u8> {
    let size = pool_tree_account_size();
    let words = size.div_ceil(8);
    // Vec<u64> is 8-byte aligned; reinterpret its allocation as Vec<u8>.
    let mut v: Vec<u64> = vec![0u64; words];
    let ptr = v.as_mut_ptr() as *mut u8;
    let cap = v.capacity() * 8;
    std::mem::forget(v);
    unsafe { Vec::from_raw_parts(ptr, size, cap) }
}

fn read_state_next_index(bytes: &[u8]) -> u64 {
    let off = state_next_index_offset();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(buf)
}

fn read_state_root(bytes: &[u8]) -> [u8; 32] {
    let off = state_root_offset();
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[off..off + 32]);
    root
}

#[test]
fn init_writes_combined_layout() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    // Combined discriminator written as u64 LE.
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&buf[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + 8]);
    assert_eq!(u64::from_le_bytes(disc), 1);

    // State sub-tree zero state.
    assert_eq!(read_state_next_index(&buf), 0);
    let expected_zero_root = <Poseidon as Hasher>::zero_bytes()[STATE_HEIGHT];
    assert_eq!(read_state_root(&buf), expected_zero_root);
    assert_eq!(current_state_root_index(&buf).unwrap(), 0);
    assert_eq!(state_root_by_index(&buf, 0).unwrap(), expected_zero_root);
    assert_eq!(current_nullifier_root_index(&buf).unwrap(), 0);
    assert_eq!(current_nullifier_next_index(&buf).unwrap(), 1);
    assert_eq!(
        nullifier_root_by_index(&buf, 0).unwrap(),
        INITIAL_NULLIFIER_ROOT
    );

    // Address sub-tree slice openable via upstream's loader.
    let address_slice = address_sub_tree_slice_mut(&mut buf).unwrap();
    let tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &TREE).unwrap();
    let owner_bytes: [u8; 32] = tree
        .get_metadata()
        .metadata
        .access_metadata
        .owner
        .to_bytes();
    assert_eq!(owner_bytes, [1u8; 32]);
}

#[test]
fn append_state_leaf_matches_reference() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let new_root = append_state_leaves(&mut buf, &[[7u8; 32]]).unwrap();
    assert_eq!(read_state_next_index(&buf), 1);
    assert_eq!(read_state_root(&buf), new_root);

    let mut reference = SparseMerkleTree::<Poseidon, STATE_HEIGHT>::new_empty();
    reference.append([7u8; 32]);
    assert_eq!(new_root, reference.root());
    assert_eq!(current_state_root_index(&buf).unwrap(), 1);
    assert_eq!(state_root_by_index(&buf, 1).unwrap(), new_root);
}

#[test]
fn append_state_batch_advances_next_index() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i + 1; 32]).collect();
    append_state_leaves(&mut buf, &leaves).unwrap();
    assert_eq!(read_state_next_index(&buf), 4);
    assert_eq!(current_state_root_index(&buf).unwrap(), 1);
}

#[test]
fn state_root_history_rejects_unknown_indices() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();
    append_state_leaves(&mut buf, &[[1u8; 32]]).unwrap();

    assert!(state_root_by_index(&buf, 2).is_err());
}

#[test]
fn nullifier_root_history_updates_and_rejects_unknown_indices() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let next_root = [9u8; 32];
    push_nullifier_root(&mut buf, next_root).unwrap();
    assert_eq!(current_nullifier_root_index(&buf).unwrap(), 1);
    assert_eq!(
        nullifier_root_by_index(&buf, 0).unwrap(),
        INITIAL_NULLIFIER_ROOT
    );
    assert_eq!(nullifier_root_by_index(&buf, 1).unwrap(), next_root);
    assert_eq!(current_nullifier_next_index(&buf).unwrap(), 1);
    push_nullifier_root_with_next_index(&mut buf, [8u8; 32], 11).unwrap();
    assert_eq!(current_nullifier_root_index(&buf).unwrap(), 2);
    assert_eq!(current_nullifier_next_index(&buf).unwrap(), 11);
    assert_eq!(nullifier_root_by_index(&buf, 2).unwrap(), [8u8; 32]);
    assert!(nullifier_root_by_index(&buf, 3).is_err());
    assert!(push_nullifier_root(&mut buf, [0u8; 32]).is_err());
}

#[test]
fn address_queue_inserts_persist() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let slot: u64 = 11;
    {
        let address_slice = address_sub_tree_slice_mut(&mut buf).unwrap();
        let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &TREE).unwrap();
        tree.insert_address_into_queue(&[5u8; 32], &slot).unwrap();
        tree.insert_address_into_queue(&[6u8; 32], &slot).unwrap();
        assert_eq!(tree.get_metadata().queue_batches.next_index, 2);
    }
    let address_slice = address_sub_tree_slice_mut(&mut buf).unwrap();
    let tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &TREE).unwrap();
    assert_eq!(tree.get_metadata().queue_batches.next_index, 2);
}

#[test]
fn state_and_address_dont_clobber() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    append_state_leaves(&mut buf, &[[1u8; 32], [2u8; 32]]).unwrap();
    let slot: u64 = 1;
    {
        let address_slice = address_sub_tree_slice_mut(&mut buf).unwrap();
        let mut tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &TREE).unwrap();
        tree.insert_address_into_queue(&[9u8; 32], &slot).unwrap();
    }
    assert_eq!(read_state_next_index(&buf), 2);
    let address_slice = address_sub_tree_slice_mut(&mut buf).unwrap();
    let tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &TREE).unwrap();
    assert_eq!(tree.get_metadata().queue_batches.next_index, 1);
}

#[test]
fn init_rejects_undersized_buffer() {
    let mut buf = vec![0u8; 16];
    assert!(init_pool_tree_account(&mut buf, &OWNER, &TREE).is_err());
}

#[test]
fn append_rejects_wrong_discriminator() {
    let mut buf = allocate_buffer();
    init_pool_tree_account(&mut buf, &OWNER, &TREE).unwrap();
    buf[DISCRIMINATOR_OFFSET] ^= 0xff;
    assert!(append_state_leaves(&mut buf, &[[1u8; 32]]).is_err());
}

#[test]
fn address_sub_tree_offset_is_aligned() {
    // Address sub-tree must start on an 8-byte-aligned offset for zero-copy.
    assert_eq!(ADDRESS_SUB_TREE_OFFSET % 8, 0);
}
