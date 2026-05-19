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

#[test]
fn batch_update_rejects_garbage_proof_on_empty_queue() {
    // No addresses have been inserted, so the pending batch isn't ready.
    // update_tree_from_address_queue must error before any proof check.
    let mut buf = allocate_buffer();
    init_address_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let mut tree = BatchedMerkleTreeAccount::address_from_bytes(&mut buf, &TREE).unwrap();
    let inputs = light_batched_merkle_tree::merkle_tree::InstructionDataBatchNullifyInputs {
        new_root: [1u8; 32],
        compressed_proof:
            light_compressed_account::instruction_data::compressed_proof::CompressedProof {
                a: [0u8; 32],
                b: [0u8; 64],
                c: [0u8; 32],
            },
    };
    assert!(tree.update_tree_from_address_queue(inputs).is_err());
}

#[test]
fn insert_advances_queue_next_index() {
    let mut buf = allocate_buffer();
    init_address_tree_account(&mut buf, &OWNER, &TREE).unwrap();

    let slot: u64 = 7;
    {
        let mut tree = BatchedMerkleTreeAccount::address_from_bytes(&mut buf, &TREE).unwrap();
        let initial_next_index = tree.get_metadata().queue_batches.next_index;
        tree.insert_address_into_queue(&[3u8; 32], &slot).unwrap();
        tree.insert_address_into_queue(&[4u8; 32], &slot).unwrap();
        assert_eq!(
            tree.get_metadata().queue_batches.next_index,
            initial_next_index + 2
        );
    }

    // Reload the tree to confirm the queue counter persisted to bytes.
    let tree = BatchedMerkleTreeAccount::address_from_bytes(&mut buf, &TREE).unwrap();
    assert_eq!(tree.get_metadata().queue_batches.next_index, 2);
}
