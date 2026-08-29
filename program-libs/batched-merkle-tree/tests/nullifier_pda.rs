use solana_address::Address;
use zolana_batched_merkle_tree::{
    batch::Batch,
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    merkle_tree_metadata::{BatchedMerkleTreeMetadata, TreeType, ADDRESS_MERKLE_TREE_TYPE_V2},
    queue_batch_metadata::QueueBatches,
    zero_copy::{TreeAccountLayout, ZeroCopyError},
};
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

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
    tree_from_bytes(data, pubkey).unwrap()
}

fn tree_from_bytes<'a, const ZKP: usize>(
    data: &'a mut [u8],
    pubkey: &Address,
) -> Result<BatchedMerkleTreeAccount<'a, ZKP>, BatchedMerkleTreeError> {
    let layout: &'a mut TreeAccountLayout<ZKP> =
        wincode::deserialize_mut(data).map_err(|_| ZeroCopyError::Size)?;
    if layout.metadata.tree_type != ADDRESS_MERKLE_TREE_TYPE_V2 {
        return Err(MerkleTreeMetadataError::InvalidTreeType.into());
    }
    BatchedMerkleTreeAccount::validate_layout(layout)?;
    Ok(BatchedMerkleTreeAccount::from_layout(pubkey, layout))
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

/// A single-slot root history seeds its only slot and wraps the cursor back to
/// zero. Writing an unwrapped `1` would leave the cursor out of range, so the
/// tree would initialize but never load again.
#[test]
fn single_slot_root_history_initializes_and_reloads() {
    let pubkey = Address::new_unique();
    let mut data = vec![0u8; get_merkle_tree_account_size::<1>()];

    let tree = BatchedMerkleTreeAccount::<1>::init(
        &mut data,
        &pubkey,
        ZKP_BATCH_SIZE,
        ZKP_BATCH_SIZE,
        40,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap();
    assert_eq!(tree.get_root(), Some(NULLIFIER_TREE_INIT_ROOT_40));

    let reloaded = tree_from_bytes::<1>(&mut data, &pubkey).unwrap();
    assert_eq!(reloaded.get_root(), Some(NULLIFIER_TREE_INIT_ROOT_40));
}

#[test]
fn derived_root_history_must_match_one_batch_of_zkp_updates() {
    let pubkey = Address::new_unique();

    let mut wrong_derived_capacity = account_data();
    assert_eq!(
        Tree::init(
            &mut wrong_derived_capacity,
            &pubkey,
            BATCH_SIZE + ZKP_BATCH_SIZE,
            ZKP_BATCH_SIZE,
            40,
            TreeType::AddressV2,
            Some(NULLIFIER_TREE_INIT_ROOT_40),
        )
        .unwrap_err(),
        MerkleTreeMetadataError::InvalidRootHistoryCapacity.into()
    );

    let mut wrong_cache_count = vec![0u8; get_merkle_tree_account_size::<5>()];
    assert_eq!(
        BatchedMerkleTreeAccount::<5>::init(
            &mut wrong_cache_count,
            &pubkey,
            BATCH_SIZE,
            ZKP_BATCH_SIZE,
            40,
            TreeType::AddressV2,
            Some(NULLIFIER_TREE_INIT_ROOT_40),
        )
        .unwrap_err(),
        MerkleTreeMetadataError::InvalidRootHistoryCapacity.into()
    );
}

#[test]
fn malformed_root_history_and_batch_metadata_are_rejected_on_load() {
    let pubkey = Address::new_unique();

    let mut bad_root_cursor = account_data();
    init_tree(&mut bad_root_cursor, &pubkey);
    let layout: &mut TreeAccountLayout<ZKP> =
        wincode::deserialize_mut(&mut bad_root_cursor).unwrap();
    layout.root_history.current_index = ZKP as u64;
    assert_eq!(
        tree_from_bytes::<ZKP>(&mut bad_root_cursor, &pubkey).unwrap_err(),
        MerkleTreeMetadataError::InvalidRootHistoryCapacity.into()
    );

    let mut invalid_reserved = account_data();
    init_tree(&mut invalid_reserved, &pubkey);
    let layout: &mut TreeAccountLayout<ZKP> =
        wincode::deserialize_mut(&mut invalid_reserved).unwrap();
    layout.metadata.queue_batches.reserved = 0;
    assert_eq!(
        tree_from_bytes::<ZKP>(&mut invalid_reserved, &pubkey).unwrap_err(),
        BatchedMerkleTreeError::InvalidBatchConfiguration
    );

    let mut inconsistent_batch = account_data();
    init_tree(&mut inconsistent_batch, &pubkey);
    let layout: &mut TreeAccountLayout<ZKP> =
        wincode::deserialize_mut(&mut inconsistent_batch).unwrap();
    layout.metadata.queue_batches.batches[0].batch_size += 1;
    assert_eq!(
        tree_from_bytes::<ZKP>(&mut inconsistent_batch, &pubkey).unwrap_err(),
        BatchedMerkleTreeError::InvalidBatchConfiguration
    );
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
