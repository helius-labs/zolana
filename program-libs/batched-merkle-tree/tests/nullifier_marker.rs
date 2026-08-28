use solana_address::Address;
use zolana_batched_merkle_tree::{
    batch::Batch,
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    merkle_tree_metadata::{BatchedMerkleTreeMetadata, TreeType},
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
fn insert_returns_sequential_queue_indices() {
    let pubkey = Address::new_unique();
    let mut data = account_data();
    let mut tree = init_tree(&mut data, &pubkey);
    for i in 0..3u8 {
        assert_eq!(
            tree.insert_nullifier_into_queue(&nullifier(i + 1)).unwrap(),
            i as u64
        );
    }
    assert_eq!(tree.get_metadata().queue_batches.next_index, 3);
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

    let mut tree = load_tree(&mut data, &pubkey);
    tree.get_metadata_mut().queue_batches.next_index += 1;
    assert_eq!(
        tree.insert_nullifier_into_queue(&nullifier(1)).unwrap_err(),
        BatchedMerkleTreeError::QueueIndexMismatch
    );
}
