//! Unit-level coverage of the state-tree init + append-batch path against an
//! in-memory account buffer (no Solana runtime needed). The processor adds
//! the AccountView wrapping on top of these primitives.

use light_concurrent_merkle_tree::zero_copy::ConcurrentMerkleTreeZeroCopyMut;
use light_hasher::Poseidon;
use shielded_pool_program::instructions::create_state_tree::init::{
    init_state_tree_account, state_tree_size, HEIGHT,
};

const CANOPY_DEPTH: usize = 4;

fn allocate_buffer() -> Vec<u8> {
    vec![0u8; state_tree_size(CANOPY_DEPTH)]
}

#[test]
fn init_then_open_zero_copy() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf, CANOPY_DEPTH).unwrap();

    let tree =
        ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_mut(&mut buf)
            .unwrap();
    assert_eq!(tree.next_index(), 0);
    assert_eq!(tree.sequence_number(), 0);
}

#[test]
fn append_single_leaf_advances_state() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf, CANOPY_DEPTH).unwrap();

    let mut tree =
        ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_mut(&mut buf)
            .unwrap();
    tree.append(&[1u8; 32]).unwrap();
    assert_eq!(tree.next_index(), 1);
    assert_eq!(tree.sequence_number(), 1);
}

#[test]
fn append_batch_advances_by_len() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf, CANOPY_DEPTH).unwrap();

    let mut tree =
        ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_mut(&mut buf)
            .unwrap();
    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
    let refs: Vec<&[u8; 32]> = leaves.iter().collect();
    tree.append_batch(&refs).unwrap();

    assert_eq!(tree.next_index(), 4);
}

#[test]
fn init_rejects_undersized_buffer() {
    let mut buf = vec![0u8; 16];
    assert!(init_state_tree_account(&mut buf, CANOPY_DEPTH).is_err());
}
