//! Unit-level coverage of the state-tree init + append path against an
//! in-memory account buffer (no Solana runtime needed). The processor adds
//! the AccountView wrapping on top of these primitives.

use light_hasher::{Hasher, Poseidon};
use light_sparse_merkle_tree::SparseMerkleTree;
use shielded_pool_program::instructions::create_state_tree::init::{
    append_leaves_to_account, init_state_tree_account, state_tree_discriminator, HEIGHT,
    NEXT_INDEX_OFFSET, ROOT_OFFSET, STATE_TREE_ACCOUNT_SIZE, SUBTREES_OFFSET,
};

fn allocate_buffer() -> Vec<u8> {
    vec![0u8; STATE_TREE_ACCOUNT_SIZE]
}

fn read_next_index(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[NEXT_INDEX_OFFSET..ROOT_OFFSET]);
    u64::from_le_bytes(buf)
}

fn read_root(bytes: &[u8]) -> [u8; 32] {
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[ROOT_OFFSET..SUBTREES_OFFSET]);
    root
}

#[test]
fn init_writes_zero_state() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf).unwrap();

    assert_eq!(buf[0], state_tree_discriminator());
    assert_eq!(read_next_index(&buf), 0);

    let expected_zero_root = <Poseidon as Hasher>::zero_bytes()[HEIGHT];
    assert_eq!(read_root(&buf), expected_zero_root);
}

#[test]
fn append_single_leaf_advances_state() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf).unwrap();

    let leaves = [[1u8; 32]];
    let new_root = append_leaves_to_account(&mut buf, &leaves).unwrap();

    assert_eq!(read_next_index(&buf), 1);
    assert_eq!(read_root(&buf), new_root);

    // Compare with a fresh in-memory SparseMerkleTree to confirm parity.
    let mut reference = SparseMerkleTree::<Poseidon, HEIGHT>::new_empty();
    reference.append(leaves[0]);
    assert_eq!(read_root(&buf), reference.root());
}

#[test]
fn append_batch_advances_by_len() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf).unwrap();

    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i + 1; 32]).collect();
    append_leaves_to_account(&mut buf, &leaves).unwrap();

    assert_eq!(read_next_index(&buf), 4);
}

#[test]
fn append_persists_across_loads() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf).unwrap();

    append_leaves_to_account(&mut buf, &[[1u8; 32], [2u8; 32]]).unwrap();
    let mid_root = read_root(&buf);

    append_leaves_to_account(&mut buf, &[[3u8; 32]]).unwrap();
    assert_eq!(read_next_index(&buf), 3);
    assert_ne!(read_root(&buf), mid_root);
}

#[test]
fn init_rejects_undersized_buffer() {
    let mut buf = vec![0u8; 16];
    assert!(init_state_tree_account(&mut buf).is_err());
}

#[test]
fn append_rejects_wrong_discriminator() {
    let mut buf = allocate_buffer();
    init_state_tree_account(&mut buf).unwrap();
    buf[0] ^= 0xff;
    assert!(append_leaves_to_account(&mut buf, &[[1u8; 32]]).is_err());
}
