//! Buffer-level coverage of the address-tree init helper against an in-memory
//! account buffer (no Solana runtime needed).

use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use shielded_pool_program::instructions::create_address_tree::init::{
    address_tree_account_size, init_address_tree_account, AddressTreeAccountError,
};

const OWNER: pinocchio::Address = pinocchio::Address::new_from_array([1u8; 32]);
const TREE: pinocchio::Address = pinocchio::Address::new_from_array([2u8; 32]);

fn allocate_buffer() -> Vec<u8> {
    vec![0u8; address_tree_account_size()]
}

#[test]
fn init_writes_loadable_address_tree_state() {
    let mut buf = allocate_buffer();
    init_address_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let tree = BatchedMerkleTreeAccount::address_from_bytes(&mut buf, &TREE)
        .expect("init bytes must be loadable as a batched address tree");
    let metadata = tree.get_metadata();
    // Compressed-account's Pubkey wraps [u8; 32]; round-trip via to_bytes.
    let owner_bytes: [u8; 32] = metadata.metadata.access_metadata.owner.to_bytes();
    assert_eq!(owner_bytes, [1u8; 32]);
}

#[test]
fn init_rejects_undersized_buffer() {
    let mut buf = vec![0u8; 16];
    assert_eq!(
        init_address_tree_account(&mut buf, &OWNER, &TREE),
        Err(AddressTreeAccountError::BufferTooSmall),
    );
}

#[test]
fn address_tree_account_size_is_nonzero() {
    assert!(address_tree_account_size() > 0);
}
