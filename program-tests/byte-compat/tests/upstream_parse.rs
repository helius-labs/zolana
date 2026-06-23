//! Proof that accounts written by our `light-batched-merkle-tree` fork are
//! byte-identical to upstream crates.io `light-batched-merkle-tree 0.11`.
//!
//! The Photon indexer parses our on-chain accounts with upstream 0.11. These
//! tests initialize an address tree account with our crate, then parse the
//! SAME bytes with upstream and assert the parse succeeds and the decoded
//! fields match. One case uses a small valid config, the other the production
//! address-tree config.

use solana_address::Address as Pubkey;
use zolana_batched::constants::{
    ADDRESS_TREE_DEFAULT_BLOOM, ADDRESS_TREE_DEFAULT_NUM_ITERS, ADDRESS_TREE_DEFAULT_RH,
    ADDRESS_TREE_DEFAULT_ZKP, ADDRESS_TREE_INIT_ROOT_40, DEFAULT_ADDRESS_BATCH_SIZE,
    DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
};
use zolana_merkle_tree_metadata::{merkle_tree::MerkleTreeMetadata, TreeType};

const ADDRESS_HEIGHT: u32 = 40;

#[test]
fn upstream_parses_our_address_tree() {
    // Small valid config: RH=10, NUM_ITERS=3, BLOOM=1000 bytes (1000 % 4 == 0,
    // keeps every [u64; N] header 8-aligned), ZKP=4 (= batch_size / zkp_batch_size = 4 / 1).
    assert_upstream_parses::<10, 3, 1000, 4>(4, 1);
}

#[test]
fn upstream_parses_production_address_tree() {
    assert_upstream_parses::<
        ADDRESS_TREE_DEFAULT_RH,
        ADDRESS_TREE_DEFAULT_NUM_ITERS,
        ADDRESS_TREE_DEFAULT_BLOOM,
        ADDRESS_TREE_DEFAULT_ZKP,
    >(DEFAULT_ADDRESS_BATCH_SIZE, DEFAULT_ADDRESS_ZKP_BATCH_SIZE);
}

fn assert_upstream_parses<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    batch_size: u64,
    zkp_batch_size: u64,
) {
    use zolana_batched::merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount};

    let mut account_data = vec![0u8; get_merkle_tree_account_size::<RH, NUM_ITERS, BLOOM, ZKP>()];
    let pubkey = Pubkey::new_unique();

    // Capture our seeded root history and metadata after init.
    let (our_root_history, our_metadata) = {
        let account = BatchedMerkleTreeAccount::<RH, NUM_ITERS, BLOOM, ZKP>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
            RH as u32,
            batch_size,
            zkp_batch_size,
            ADDRESS_HEIGHT,
            TreeType::AddressV2,
            None,
        )
        .expect("our init");
        (account.root_history().to_vec(), *account.get_metadata())
    };

    // Parse the SAME bytes with upstream 0.11.
    let upstream_pubkey = upstream_pubkey(&pubkey);
    let upstream = upstream_batched::merkle_tree::BatchedMerkleTreeAccount::address_from_bytes(
        &mut account_data,
        &upstream_pubkey,
    )
    .expect("upstream parses our address tree account");

    let upstream_meta = upstream.get_metadata();

    // Metadata fields must match.
    assert_eq!(
        upstream_meta.root_history_capacity, our_metadata.root_history_capacity,
        "root_history_capacity mismatch"
    );
    assert_eq!(
        upstream_meta.sequence_number, our_metadata.sequence_number,
        "sequence_number mismatch"
    );
    assert_eq!(
        upstream_meta.next_index, our_metadata.next_index,
        "next_index mismatch"
    );
    assert_eq!(
        upstream_meta.queue_batches.batch_size, our_metadata.queue_batches.batch_size,
        "queue batch_size mismatch"
    );
    assert_eq!(
        upstream_meta.queue_batches.zkp_batch_size, our_metadata.queue_batches.zkp_batch_size,
        "queue zkp_batch_size mismatch"
    );
    assert_eq!(
        upstream_meta.tree_type, our_metadata.tree_type,
        "tree_type mismatch"
    );

    // Root history must match element by element.
    assert_eq!(
        upstream.root_history.len(),
        our_root_history.len(),
        "root_history length mismatch"
    );
    for (i, our_root) in our_root_history.iter().enumerate() {
        let upstream_root = upstream
            .get_root_by_index(i)
            .unwrap_or_else(|| panic!("upstream missing root at index {i}"));
        assert_eq!(upstream_root, our_root, "root mismatch at index {i}");
    }

    // The seeded sentinel root must be the first one and survive the round trip.
    assert_eq!(
        upstream.get_root_by_index(0),
        Some(&ADDRESS_TREE_INIT_ROOT_40),
        "seeded address sentinel root mismatch"
    );
}

/// Bridge a workspace `solana_address::Address` to the upstream crate's
/// `light_compressed_account::pubkey::Pubkey`. Bytes are identical, so a byte
/// round trip is always valid.
fn upstream_pubkey(pubkey: &Pubkey) -> light_compressed_account::pubkey::Pubkey {
    light_compressed_account::pubkey::Pubkey::from(pubkey.to_bytes())
}
